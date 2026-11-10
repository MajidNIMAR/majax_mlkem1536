"""Freeze and replay M06 byte regressions, binary inventories and timing evidence.

This verifies finite evidence. It is not a semantic compiler proof, a complete
indirect-call analysis, a constant-time proof or an erasure proof.
"""

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil

from analyze_delivery_timing import analyze
from inspect_m03_binary import inventory, parse_disassembly, resolve_elf_relocations
from review_m06_binary import review as review_ntt
from confirm_m06_builds import comparison_bytes

ROOT = Path(__file__).resolve().parents[1]
HOSTS = ("windows", "linux")
ARITHMETIC = ("Polynomial::forward_into", "NttPolynomial::multiply_add_assign",
              "NttPolynomial::inverse_into", "engine_poly::transform")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def check_files(root, expected):
    root = root.resolve()
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
              and p != root / "provenance.json"}
    require(actual == set(expected), "M06 snapshot inventory differs")
    for name, checksum in expected.items():
        path = (root / name).resolve()
        require(path.is_relative_to(root), "M06 member escapes snapshot")
        require(digest(path) == checksum, f"M06 checksum differs: {name}")


def check_regression(regression):
    require(regression["profile"] == "KEM1536-DEV-Q7681-R1", "wrong regression profile")
    require(set(regression["platforms"]) == set(HOSTS), "two regression hosts required")
    for host in HOSTS:
        row = regression["platforms"][host]
        require(row["compared_to_frozen_M01"] == {"dev-vectors": 1000, "dev-rejection-vectors": 10000},
                f"incomplete vector/rejection regression: {host}")
        require(row["all_fields_equal"] is True, "byte equality absent")
        require(row["frozen_M02_mutations_compared"] == 10000, "mutation panel incomplete")
        require(row["formats"]["inputs"] == 20000, "format panel incomplete")
    require(regression["platforms"]["windows"]["formats"] == regression["platforms"]["linux"]["formats"],
            "host format decisions differ")


def verify(run):
    run = run.resolve()
    manifest = read(run / "provenance.json")
    check_files(run, manifest["output_sha256"])
    regression = read(run / "regression.json")
    check_regression(regression)
    builds = read(run / "builds.json")
    require(builds["profile"] == regression["profile"], "build/regression profiles differ")
    required_includes = {"references/manifest.json"}
    for dataset in ("ML-KEM-keyGen-FIPS203", "ML-KEM-encapDecap-FIPS203", "ML-KEM-encapDecap-FIPS203-tr1"):
        required_includes.update(f"vectors/nist-acvp/{dataset}/{name}.json" for name in ("prompt", "expectedResults"))
    closed = read(run / "closed-input-builds.json")
    require(required_includes <= set(closed["source_sha256"]), "compiled public witness includes absent")
    for name in set(builds["source_sha256"]) & set(regression["source_sha256"]):
        require(builds["source_sha256"][name] == regression["source_sha256"][name], "regression source differs from build")
    confirmation = read(run / "build-confirmation.json")
    require(digest(run / "builds.json") == confirmation["first_builds_json_sha256"] and
            digest(run / "closed-input-builds.json") == confirmation["second_builds_json_sha256"], "build confirmation receipt differs")
    for name, checksum in builds["source_sha256"].items():
        require(closed["source_sha256"].get(name) == checksum, "common build source differs")
    capture = read(run / "timing/capture.json")
    for name, expected in closed["source_sha256"].items():
        path = (run / "sources" / name).resolve()
        require(path.is_relative_to(run / "sources") and digest(path) == expected,
                f"compiled M06 source differs: {name}")
    inspected = 0
    for host in HOSTS:
        for kind in ("research", "delivered"):
            folder = run / "audit" / f"{host}-{kind}"
            binary = gzip.decompress((folder / "binary.gz").read_bytes())
            summary = read(folder / "summary.json")
            checksum = hashlib.sha256(binary).hexdigest()
            require(checksum == summary["binary_sha256"] == builds["builds"][host][kind]["sha256"],
                    "audited executable differs from built bytes")
            if kind == "research":
                require(checksum == regression["binary_sha256"][host], "regression used another executable")
            text = gzip.decompress((folder / "disassembly.txt.gz").read_bytes()).decode()
            functions = parse_disassembly(text)
            if binary[:4] == b"\x7fELF":
                resolve_elf_relocations(functions, (folder / "relocations.txt").read_text())
            calculated = inventory(functions)
            for name in ("all_code", "R1_core", "directly_reachable", "core_functions", "reachable_functions"):
                require(calculated[name] == summary[name], f"binary inventory differs: {host}/{kind}/{name}")
            for suffix in ARITHMETIC:
                matching = [row for name, row in functions.items()
                            if name.startswith("kem1536::engine_poly::") and name.endswith(suffix)]
                require(len(matching) == 1, f"M06 arithmetic symbol absent or ambiguous: {suffix}")
                require(not matching[0]["divisions"], f"division found in {suffix}")
            require(not any("Polynomial::multiply_into" in name for name in functions),
                    "test-only old multiplication present in production/research binary")
            require(review_ntt(folder) == read(folder / "ntt-review.json"), "bounded NTT review differs")
            inspected += 1
        for kind in ("research", "delivered", "timing"):
            first_path = (run / "audit" / f"{host}-{kind}" / "binary.gz" if kind != "timing" else
                          run / "timing" / f"{host}-binary.gz")
            first_binary = gzip.decompress(first_path.read_bytes())
            rebuilt = gzip.decompress((run / "rebuilt-binaries" / f"{host}-{kind}.gz").read_bytes())
            require(hashlib.sha256(rebuilt).hexdigest() == closed["builds"][host][kind]["sha256"],
                    "rebuilt bytes differ from recorded build")
            first_normal, first_metadata = comparison_bytes(first_binary, host)
            second_normal, second_metadata = comparison_bytes(rebuilt, host)
            require(first_normal == second_normal, "rebuilt code/data differs outside allowed PE metadata")
            require(confirmation["platforms"][host]["build_comparisons"][kind] ==
                    dict(byte_identical=first_binary == rebuilt,
                         comparison_sha256=hashlib.sha256(first_normal).hexdigest(),
                         first_metadata=first_metadata, second_metadata=second_metadata, binaries_modified=False),
                    "build comparison statistics differ")
            require(digest(run / "build-logs" / host / f"{kind}-build.log") ==
                    closed["builds"][host][kind]["log_sha256"], "build log differs")
            require(digest(run / "initial-build-logs" / host / f"{kind}-build.log") ==
                    builds["builds"][host][kind]["log_sha256"], "initial build log differs")
        require((run / "initial-build-logs" / host / "rustc.txt").read_bytes() ==
                (run / "build-logs" / host / "rustc.txt").read_bytes(), "build compiler descriptions differ")
        plain = gzip.decompress((run / "timing" / f"{host}.jsonl.gz").read_bytes())
        calculated = analyze(json.loads(line) for line in plain.splitlines())
        saved = read(run / "timing" / f"{host}.json")
        require(all(saved.get(k) == v for k, v in calculated.items()), "M06 timing statistics differ")
        require(saved["input_sha256"] == hashlib.sha256(plain).hexdigest(), "M06 timing input differs")
        measured = capture["hosts"][host]
        timing_bytes = gzip.decompress((run / "timing" / f"{host}-binary.gz").read_bytes())
        require(hashlib.sha256(timing_bytes).hexdigest() == measured["binary_sha256"] ==
                builds["builds"][host]["timing"]["sha256"], "timing binary differs")
        require(measured["raw_sha256"] == saved["input_sha256"], "timing capture receipt differs")
        fresh_path = run / "timing" / f"{host}-self-test.json"
        require(digest(fresh_path) == measured["self_test_sha256"], "fresh delivery self-test differs")
        fresh = read(fresh_path)
        require(fresh["profile"] == builds["profile"] and fresh["fresh_round_trips"] == 16
                and fresh["implicit_rejections_checked"] == 16 and fresh["secrets_printed"] is False,
                "fresh delivery self-test panel incomplete")
        confirmed = confirmation["platforms"][host]
        require(confirmed["self_test_binary_sha256_before"] == confirmed["self_test_binary_sha256_after"] ==
                builds["builds"][host]["delivered"]["sha256"], "confirmed self-test used another binary")
        fresh = confirmed["fresh_self_test"]
        require(fresh["fresh_round_trips"] == fresh["implicit_rejections_checked"] == 16
                and fresh["secrets_printed"] is False, "confirmed delivery self-test incomplete")
    bridge = read(run / "bridge/summary.json")
    require(bridge["source_contract"]["realization"] == "M06-destination-owned-NTT-accumulated-1",
            "certificate bridge is not for M06")
    for name in ("crates/kem1536/src/dev_kem.rs", "crates/kem1536/src/engine_poly.rs"):
        require(bridge["input_sha256"][name] == builds["source_sha256"][name], "certificate bridge source differs")
    require(bridge["input_sha256"]["research/verify_r1_certificate_bridge.py"] ==
            digest(run / "review-tools/verify_r1_certificate_bridge.py"), "bridge verifier differs")
    return dict(hashes_verified=len(manifest["output_sha256"]), full_binary_inventories_recomputed=inspected,
                vectors_per_host=1000, rejections_per_host=10000, mutations_per_host=10000,
                formats_per_host=20000, timing_observations_recomputed=32000,
                constant_time_proved=False, all_copies_erased_proved=False, full_concrete_CCA_proof=False)


def freeze(output):
    output = output.resolve()
    require(output.parent == ROOT / "results/engine" and not output.exists(), "new engine snapshot required")
    generated = ROOT / "artifacts/generated"
    validation = generated / "m06-validation-002"
    require((validation / "builds.json").is_file(), "M06 validation builds are not complete")
    output.mkdir()
    shutil.copytree(validation / "sources", output / "sources")
    shutil.copyfile(generated / "m06-validation-001/builds.json", output / "builds.json")
    shutil.copyfile(validation / "builds.json", output / "closed-input-builds.json")
    shutil.copyfile(generated / "m06-build-confirmation.json", output / "build-confirmation.json")
    for host in HOSTS:
        for kind in ("research", "delivered", "timing"):
            suffix = ".exe" if host == "windows" else ""
            destination = output / "rebuilt-binaries" / f"{host}-{kind}.gz"
            destination.parent.mkdir(exist_ok=True)
            with destination.open("xb") as raw:
                with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
                    compressed.write((validation / host / (kind + suffix)).read_bytes())
        for name in ("research-build.log", "delivered-build.log", "timing-build.log", "rustc.txt"):
            destination = output / "build-logs" / host / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(validation / host / name, destination)
            destination = output / "initial-build-logs" / host / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(generated / "m06-validation-001" / host / name, destination)
    shutil.copyfile(generated / "m06-regression-001/summary.json", output / "regression.json")
    (output / "timing").mkdir()
    for host in HOSTS:
        for kind in ("research", "delivered"):
            shutil.copytree(generated / f"m06-audit-{host}-{kind}", output / "audit" / f"{host}-{kind}")
        source = generated / f"m06-{host}-timing.jsonl"
        with (output / "timing" / f"{host}.jsonl.gz").open("xb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
                compressed.write(source.read_bytes())
        shutil.copyfile(generated / f"m06-{host}-timing.json", output / "timing" / f"{host}.json")
        shutil.copyfile(generated / f"m06-{host}-self-test.json", output / "timing" / f"{host}-self-test.json")
        suffix = ".exe" if host == "windows" else ""
        with (output / "timing" / f"{host}-binary.gz").open("xb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
                compressed.write((generated / "m06-validation-001" / host / ("timing" + suffix)).read_bytes())
    shutil.copyfile(generated / "m06-timing-capture.json", output / "timing" / "capture.json")
    shutil.copytree(generated / "m06-certificate-bridge-001", output / "bridge")
    for name in ("m06-windows-check.log", "m06-linux-tests.log"):
        (output / "checks").mkdir(exist_ok=True)
        shutil.copyfile(generated / name, output / "checks" / name)
    for name in ("verify_m06.py", "build_m06_validation.py", "capture_m06_timing.py", "validate_m04_engine.py",
                 "validate_hardening_m02.py", "analyze_delivery_timing.py", "inspect_m03_binary.py",
                 "verify_r1_certificate_bridge.py", "test_r1_certificate_bridge.py", "test_verify_m06.py",
                 "review_m06_binary.py", "test_review_m06_binary.py", "confirm_m06_builds.py"):
        destination = output / "review-tools" / name
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "research" / name, destination)
    save(output / "provenance.json", dict(created_utc=datetime.now(timezone.utc).isoformat(),
         base_engine_commit="693c6a305b5143b9b00b912353bbae153cad4e4f",
         output_sha256={p.relative_to(output).as_posix(): digest(p) for p in sorted(output.rglob("*")) if p.is_file()},
         scope="finite M06 regression, disassembly inventories and timing; separate benchmark/fuzz snapshots",
         constant_time_proved=False, full_concrete_CCA_proof=False))
    return verify(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--freeze", type=Path)
    group.add_argument("--run", type=Path, default=ROOT / "results/engine/m06-001")
    args = parser.parse_args()
    print(json.dumps(freeze(args.freeze) if args.freeze else verify(args.run), indent=2))
