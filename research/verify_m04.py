"""Verify preserved M04 hashes, binary bindings, wipe loops and timing arithmetic."""
import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path
import tarfile
import tempfile
from analyze_delivery_timing import analyze
from inspect_m03_binary import parse_disassembly, inventory, resolve_elf_relocations, tool, linux_path
from review_m04_wipes import NAME, wipe_coverage

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def same(a, b):
    if isinstance(a, dict):
        return isinstance(b, dict) and a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return isinstance(b, list) and len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if isinstance(a, float):
        return isinstance(b, (int, float)) and math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-20)
    return a == b


def verify(run, recheck_disassembly=False):
    manifest = json.loads((run / "provenance.json").read_text())
    for name, expected in manifest["output_sha256"].items():
        path = (run / name).resolve()
        require(path.is_relative_to(run.resolve()), "unsafe snapshot member")
        require(digest(path.read_bytes()) == expected, f"snapshot checksum differs: {name}")
    with tarfile.open(run / "sources.tar.gz", "r:gz") as archive:
        members = {m.name: m for m in archive.getmembers() if m.isfile()}
        require(members.keys() == manifest["source_sha256"].keys(), "source inventory differs")
        for name, member in members.items():
            require(digest(archive.extractfile(member).read()) == manifest["source_sha256"][name], f"source checksum differs: {name}")
    inspected = 0
    for audit in sorted((run / "audit").iterdir()):
        binary = gzip.decompress((audit / "binary.gz").read_bytes())
        summary = json.loads((audit / "summary.json").read_text())
        require(digest(binary) == summary["binary_sha256"], "binary.gz and audit summary disagree")
        raw = gzip.decompress((audit / "disassembly.txt.gz").read_bytes()).decode()
        functions = parse_disassembly(raw)
        if binary[:4] == b"\x7fELF":
            resolve_elf_relocations(functions, (audit / "relocations.txt").read_text())
        calculated = inventory(functions)
        for name in ("R1_core", "all_code", "directly_reachable", "core_functions", "reachable_functions"):
            require(calculated[name] == summary[name], f"binary inventory differs: {audit.name}/{name}")
        start = raw.index(f"<{NAME}>:")
        body = raw[start:raw.index("\n\n", start)]
        wipes = json.loads((audit / "wipes.json").read_text())
        require(wipe_coverage(body) == wipes["normal_return_scratch_wipes"], "wipe addresses differ")
        require(digest(body.encode()) == wipes["function_disassembly_sha256"], "wipe body hash differs")
        require(wipes["binary_sha256"] == summary["binary_sha256"], "wipe/binary binding differs")
        if audit.name.endswith("-delivered"):
            platform = audit.name.split("-")[0]
            package = run / "distribution" / platform / "package" / "bin" / ("kem1536.exe" if platform == "windows" else "kem1536")
            require(package.read_bytes() == binary, "delivered executable differs from reviewed bytes")
        if recheck_disassembly:
            # Keep this diagnostic file in ignored generated space; never execute it.
            with tempfile.NamedTemporaryFile(dir=ROOT / "artifacts/generated", suffix=".m04-binary", delete=False) as file:
                file.write(binary)
                temporary = Path(file.name)
            fresh = tool("objdump", "-d", "-C", "--no-show-raw-insn", linux_path(temporary)).decode()
            require(parse_disassembly(fresh) == parse_disassembly(raw), "fresh objdump instructions differ")
        inspected += 1
    for platform in ("windows", "linux"):
        with gzip.open(run / "timing" / (platform + ".jsonl.gz"), "rt") as stream:
            recomputed = analyze(json.loads(line) for line in stream)
        saved = json.loads((run / "timing" / (platform + ".json")).read_text())
        saved.pop("input_sha256")  # Original uncompressed stream hash, retained in its receipt.
        require(same(recomputed, saved), "timing arithmetic differs")
        build = json.loads((run / "distribution" / platform / "result.json").read_text())
        require(build["provenance"]["two_isolated_builds_identical_in_reference_run"], "two-build identity was not obtained")
        reference = json.loads((run / "distribution" / platform / "package/validation/release-003-build-provenance.json").read_text())
        require(reference["two_isolated_builds_identical"], "referenced build proof missing")
        require(reference["binary_sha256"] == build["provenance"]["binary_sha256"], "repackaged binary differs")
    smoke = json.loads((run / "fuzz-summary.json").read_text())
    require(smoke["all_four_budgets_reached"] and smoke["standard_library_rebuilt"], "fuzz completion absent")
    require(len(smoke["results"]) == 4 and all(r["CPU_seconds"] >= 60 for r in smoke["results"].values()), "fuzz CPU budget missing")
    with tarfile.open(run / "fuzz-smoke.tar.gz", "r:gz") as archive:
        for target, row in smoke["results"].items():
            measured = []
            for member in archive.getmembers():
                if member.name.startswith(target + "/segment-") and member.name.endswith("-usage.json"):
                    usage = json.loads(archive.extractfile(member).read())
                    require(usage["exit_code"] == 0, "a fuzz segment failed")
                    measured.append(usage["user_seconds"] + usage["system_seconds"])
            require(measured and math.isclose(sum(measured), row["CPU_seconds"], abs_tol=1e-8), "fuzz resource usage differs")
            require(digest(archive.extractfile("bin/" + target).read()) == smoke["binary_sha256"][target], "fuzz binary differs")
    api = json.loads((run / "api-fuzz-supplement/summary.json").read_text())
    require(api["executions_after_initialization"] > 0, "API mutation phase was not reached")
    require(api["results"]["api_sequence"]["CPU_seconds"] >= 60, "API mutation CPU budget missing")
    require(api["binary_sha256"] == smoke["binary_sha256"]["api_sequence"], "API supplement used another binary")
    return {"hashes_verified": len(manifest["output_sha256"]), "source_files_verified": len(manifest["source_sha256"]),
            "full_binary_inventories_recomputed": inspected, "delivered_binaries_bound_to_audits": 2,
            "timing_observations_recomputed": 32000, "fresh_objdump_replay": recheck_disassembly,
            "constant_time_proved": False, "full_concrete_CCA_proof": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=ROOT / "results/engine/m04-001")
    parser.add_argument("--recheck-disassembly", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify(args.run.resolve(), args.recheck_disassembly), indent=2))


if __name__ == "__main__":
    main()
