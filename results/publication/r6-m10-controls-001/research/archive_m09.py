"""Seal and data-only replay the complete M09 development evidence.

Archives have bounded, link-free inventories. Selected data-only readers
use a temporary owned mirror; no engine, compiler or network is executed.
"""
import argparse
import gzip
import hashlib
import io
import itertools
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

from run_m07 import require, read, save, utc
from m09_chunks import sha, open_archive
from run_m08 import validate_memory
from verify_r1_certificate_bridge import verify_static_contract
from analyze_delivery_timing import analyze as timing_analysis
from validate_hardening_m02 import mutations, oracle
from export_publication import safe_name as portable_name
from archive_m07 import BoundedReader

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {"qualification": "m09-final-002", "distribution": "m09-distribution-002",
          "cli-review": "m09-lifecycle-cli-002", "consumer-review": "m09-lifecycle-consumer-002",
          "scalar-review": "m09-scalar-review-002", "fuzz": "m09-fuzz-003",
          "fuzz-postprocess": "m09-fuzz-postprocess-001",
          "controls": "m09-controls-001",
          "rejected": ("m09-final-001", "m09-distribution-001", "m09-lifecycle-cli-001",
                       "m09-lifecycle-consumer-001", "m09-lifecycle-review-001", "m09-check-001", "m09-fuzz-001",
                       "m09-fuzz-002")}
LINKS = ("results/engine/m09-poly-001/provenance.json", "results/engine/m09-poly-002/provenance.json",
         "results/security/m09-001/provenance.json")
MAX_MEMBER, MAX_TOTAL = 64 * 1024 * 1024, 512 * 1024 * 1024
MAX_MEMBERS, MAX_METADATA = 25000, 32 * 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_name(name):
    require(type(name) is str and name, "unsafe evidence member")
    portable_name(name)
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name
            and "\\" not in name and all(part not in ("", ".", "..") and ":" not in part
                                         for part in name.split("/")), "unsafe evidence member")
    return name


def members(path):
    result, total, spellings = {}, 0, {}
    with open_archive(path) as physical, gzip.GzipFile(fileobj=physical, mode="rb") as compressed:
        with tarfile.open(fileobj=BoundedReader(compressed, MAX_TOTAL + MAX_METADATA), mode="r|") as archive:
            for entry in archive:
                name = safe_name(entry.name)
                require(len(result) < MAX_MEMBERS, "archive member count exceeds budget")
                require(entry.isfile() and name not in result and 0 <= entry.size <= MAX_MEMBER,
                        "duplicate, linked, or oversized member")
                parts = name.split("/")
                for length in range(1, len(parts)+1):
                    spelling = "/".join(parts[:length])
                    kind = "file" if length == len(parts) else "directory"
                    key = spelling.casefold()
                    require(key not in spellings or spellings[key] == (spelling, kind),
                            "case alias or file/directory collision")
                    spellings[key] = (spelling, kind)
                total += entry.size
                require(total <= MAX_TOTAL, "archive expansion budget exceeded")
                raw = archive.extractfile(entry).read(entry.size + 1)
                require(len(raw) == entry.size, "archive member truncated")
                result[name] = raw
    require(result, "empty evidence archive")
    return result


def inventory(raws):
    return {name: {"sha256": digest(raw), "bytes": len(raw)} for name, raw in sorted(raws.items())}


def parsed(raws, name):
    return json.loads(raws[safe_name(name)])


def data_reader(raws, callback):
    parent = ROOT / "target/m09-capsule-data-reader"
    require(parent.resolve().is_relative_to(ROOT.resolve()), "temporary mirror escapes workspace")
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="replay-", dir=parent) as temporary:
        folder = Path(temporary)
        require(folder.resolve().parent == parent.resolve(), "temporary mirror escapes owned parent")
        for name, raw in raws.items():
            target = folder.joinpath(*safe_name(name).split("/"))
            require(target.resolve().is_relative_to(folder.resolve()), "mirror member escapes parent")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        return callback(folder)


def capture_controls():
    folder = ROOT / "artifacts/generated/m09-controls-001"
    require(not folder.exists(), "new reader-control capture required")
    paths = list((ROOT / "research").glob("*.py"))
    paths.extend((ROOT / "results/publication/r6-m08-controls-001").glob("*.py"))
    paths.extend(ROOT / name for name in ("scripts/dev.ps1", "scripts/dev.sh", ".github/workflows/ci.yml",
        "README.md", "SECURITY.md", "docs/RAPPORT_RECHERCHE.md", "docs/JOURNAL_RECHERCHE.md",
        "docs/FEUILLE_DE_ROUTE_MOTEUR.md", "docs/REVUE_CYCLE_SECRET_M09.md", "docs/REVUE_EXTERNE_M09.md",
        "docs/SECURITE_M09.md", "docs/PROTOCOLE_M09_MOTEUR.md", "docs/PROTOCOLE_M09_QUALIFICATION.md",
        "docs/ADDENDUM_M09_SCALAIRE.md"))
    folder.mkdir()
    expected = {}
    for path in sorted(set(paths)):
        name = path.relative_to(ROOT).as_posix()
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = path.read_bytes()
        target.write_bytes(raw)
        expected[name] = digest(raw)
    save(folder / "control-manifest.json", {"schema": "m09-reader-control-closure-v1", "sha256": expected,
        "scope": "All first-party top-level Python research controls/readers and selected workflow/research documents; historical data and linked capsules remain separately inventoried."})
    require(all(sha(ROOT / name) == checksum for name, checksum in expected.items()), "live controls changed during capture")


def qualification_scope(raws):
    source = parsed(raws, "source.json")
    actual = {name.removeprefix("source/"): digest(raw) for name, raw in raws.items() if name.startswith("source/")}
    require(actual == source["source_sha256"], "M09 full source closure changed")
    contract = verify_static_contract(raws["source/crates/kem1536/src/dev_kem.rs"].decode("utf-8"))
    require(contract["realization"] == "M09-typed-noise-destination-message-1"
            and contract["reviewed_source_anchors"] == 62, "M09 bridge realization differs")
    validation = parsed(raws, "validation.json")
    require(validation["source_manifest_sha256"] == digest(raws["source.json"])
            and validation["historical_campaign_credit"] == 0
            and validation["fresh_fuzzing_credit_seconds"] == 0, "qualification credit/source differs")
    counts, timing = {}, {}
    for host in ("windows", "linux"):
        build = parsed(raws, host + "/build.json")
        require(build["source_manifest_sha256"] == digest(raws["source.json"]), "build/source binding changed")
        require(set(build["binaries"]) == {"delivered", "research", "consumer", "latency", "timing", "probe"},
                "six image kinds required")
        for row in build["binaries"].values():
            require(row["exit_code"] == 0 and digest(raws[safe_name(row["path"])]) == row["sha256"]
                    and "release: 1.91.1" in row["rustc"], "original compiled image differs")
        result = validation["hosts"][host]
        require(result["regression"]["compared_to_frozen_M01"] == {"dev-vectors": 1000, "dev-rejection-vectors": 10000}
                and result["mutation"]["cases"] == 10000 and result["formats"]["inputs"] == 20000,
                "full finite qualification counts missing")
        require(result["CLI"]["fresh_round_trips"] == result["CLI"]["implicit_rejections_checked"] == 16,
                "CLI native smoke missing")
        for kind, count in (("dev-vectors", 1000), ("dev-rejection-vectors", 10000), ("dev-mutations", 10000)):
            with gzip.GzipFile(fileobj=io.BytesIO(raws[f"validation/{host}/{kind}.jsonl.gz"])) as stream:
                require(sum(1 for _ in stream) == count, "captured regression stream count differs")
        for operation, historical in (("dev-vectors", "r1-001/vectors.jsonl.gz"),
                                       ("dev-rejection-vectors", "r1-rejections-001/rejections.jsonl.gz")):
            saved = raws["validation-inputs/results/engine/" + historical]
            require(digest(saved) == sha(ROOT / "results/engine" / historical), "historical input differs")
            with gzip.GzipFile(fileobj=io.BytesIO(raws[f"validation/{host}/{operation}.jsonl.gz"])) as current:
                with gzip.GzipFile(fileobj=io.BytesIO(saved)) as expected:
                    for left, right in itertools.zip_longest(current, expected):
                        require(left is not None and right is not None and json.loads(left) == json.loads(right),
                                "full historical R1 byte comparison differs")
        memory = [json.loads(line) for line in raws[f"validation/{host}/memory.stdout"].splitlines()]
        require(validate_memory(memory, 3) == result["memory"], "M09 memory summary differs")
        measurements = [json.loads(line) for line in raws[f"timing/{host}/observations.jsonl"].splitlines()]
        timing[host] = timing_analysis(measurements)
        require(timing[host] == parsed(raws, f"timing/{host}/analysis.json"), "timing summary differs")
        counts[host] = {"vectors": 1000, "rejections": 10000, "mutations": 10000, "formats": 20000,
                        "timing_observations": len(measurements), "memory_observations": len(memory)}
    for action in ("validate", "timing"):
        after = parsed(raws, f"qualification-adapter/{action}-001/after.json")
        require(after["child_exit_code"] == 0 and after["exit_code_known"] is True
                and after["status"] == "PASS" and after["error"] is None
                and after["postflight_error"] is None, "qualification adapter did not complete successfully")
    with gzip.GzipFile(fileobj=io.BytesIO(raws["validation/windows/dev-mutations.jsonl.gz"])) as stream:
        require(mutations(stream, oracle()) == validation["hosts"]["windows"]["mutation"],
                "independent mutation oracle differs")
    with gzip.GzipFile(fileobj=io.BytesIO(raws["validation/windows/dev-mutations.jsonl.gz"])) as windows:
        with gzip.GzipFile(fileobj=io.BytesIO(raws["validation/linux/dev-mutations.jsonl.gz"])) as linux:
            for left, right in itertools.zip_longest(windows, linux):
                require(left is not None and right is not None and json.loads(left) == json.loads(right),
                        "cross-OS mutation bytes differ")
    from m09_final_measure import evaluate_raws
    measures = evaluate_raws(raws)
    require(measures == parsed(raws, "measurements/evaluation.json") and measures["all_budgets_passed"] is True,
            "full KEM performance/memory acceptance differs")
    return {"contract": contract, "counts": counts,
            "performance_memory_budgets_passed": measures["all_budgets_passed"],
            "timing_threshold_crossings": {host: result["threshold_crossings"] for host, result in timing.items()}}


def create(output):
    require(output.parent == ROOT / "results/engine" and not output.exists(), "new engine capsule required")
    capture_controls()
    output.mkdir()
    groups = {}
    for name, generated in GROUPS.items():
        roots = generated if isinstance(generated, tuple) else (generated,)
        paths = []
        for root in roots:
            folder = ROOT / "artifacts/generated" / root
            paths.extend(((root + "/" if isinstance(generated, tuple) else "")
                          + p.relative_to(folder).as_posix(), p)
                         for p in sorted(folder.rglob("*")) if p.is_file())
        require(paths and not any(p.is_symlink() for _, p in paths), "complete ordinary group required")
        expected = {relative: {"sha256": sha(p), "bytes": p.stat().st_size} for relative, p in paths}
        target = output / (name + ".tar.gz")
        with target.open("xb") as stream, gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative, path in paths:
                    relative = safe_name(relative)
                    info = tarfile.TarInfo(relative)
                    info.size, info.mtime, info.mode = path.stat().st_size, 0, 0o644
                    with path.open("rb") as raw:
                        archive.addfile(info, raw)
        require(inventory(members(target)) == expected, "archive write changed bytes")
        groups[name] = {"archive": target.name, "archive_sha256": sha(target), "files": expected}
    links = {name: sha(ROOT / name) for name in LINKS}
    save(output / "provenance.json", {"schema": "m09-engine-capsule-v1", "created_utc": utc(),
        "groups": groups, "linked_provenance_sha256": links,
        "external_review_performed": False, "historical_time_recredited": False})
    report = verify(output)
    save(output / "verification.json", report)
    return report


def verify(output):
    if (output / "archive-parts.json").exists():
        from m09_chunks import verify as verify_chunks
        verify_chunks(output)
    provenance = read(output / "provenance.json")
    require(provenance["schema"] == "m09-engine-capsule-v1" and set(provenance["groups"]) == set(GROUPS),
            "capsule scope differs")
    require(provenance["external_review_performed"] is False and provenance["historical_time_recredited"] is False,
            "invalid external/historical claim")
    reports, count = {}, 0
    cache = {}
    def recover_group(name):
        if name not in cache:
            record = provenance["groups"][name]
            path = output / safe_name(record["archive"])
            require(path.parent == output and sha(path) == record["archive_sha256"], "capsule archive differs")
            data = members(path)
            require(inventory(data) == record["files"], "capsule physical inventory differs")
            cache[name] = data
        return cache[name]
    qualified = recover_group("qualification")
    qualified_source_sha = digest(qualified["source.json"])
    qualified_images = {host: parsed(qualified, host + "/build.json")["binaries"] for host in ("windows", "linux")}
    for name, record in provenance["groups"].items():
        data = recover_group(name)
        count += len(data)
        if name == "qualification":
            reports[name] = qualification_scope(data)
        elif name == "distribution":
            from m09_distribution import verify as distribution_verify
            require(parsed(data, "result.json")["source_manifest_sha256"] == qualified_source_sha,
                    "distribution and qualification source differ")
            for host in ("windows", "linux"):
                require(parsed(data, host + "/package/provenance.json")["binary_sha256"]
                        == qualified_images[host]["delivered"]["sha256"], "distribution original differs from qualified CLI")
            reports[name] = data_reader(data, distribution_verify)
        elif name in ("cli-review", "consumer-review"):
            from m09_lifecycle_inventory import verify as inventory_verify
            collection = parsed(data, "collection.json")
            kind = "delivered" if name == "cli-review" else "consumer"
            require(collection["source_manifest_sha256"] == qualified_source_sha and collection["binary_kind"] == kind,
                    "review and qualification source/kind differ")
            for host in ("windows", "linux"):
                require(collection["images"][host]["sha256"] == qualified_images[host][kind]["sha256"],
                        "review does not concern qualified image")
            reports[name] = data_reader(data, inventory_verify)
        elif name == "scalar-review":
            from m09_scalar_review import verify as scalar_verify
            reviewed = parsed(data, "review.json")
            require(reviewed["source_manifest_sha256"] == qualified_source_sha, "scalar review source differs")
            require(reviewed["rejected_review_provenance_sha256"]
                    == digest(recover_group("rejected")["m09-lifecycle-review-001/provenance.json"]),
                    "scalar correction is not linked to the retained rejected finding")
            for role, kind in (("cli", "delivered"), ("consumer", "consumer")):
                for host in ("windows", "linux"):
                    require(reviewed["images"][role + "-" + host]["binary_sha256"] == qualified_images[host][kind]["sha256"],
                            "scalar review image differs")
            combined = {}
            for prefix, group in (("review", "scalar-review"), ("cli", "cli-review"), ("consumer", "consumer-review")):
                combined.update({prefix + "/" + member: raw for member, raw in recover_group(group).items()})
            reports[name] = data_reader(combined, lambda folder: scalar_verify(folder / "review", folder / "cli", folder / "consumer"))
        elif name == "rejected":
            from m09_lifecycle_review import verify as rejected_verify
            def replay_rejection(folder):
                return rejected_verify(folder / "m09-lifecycle-review-001",
                                       folder / "m09-lifecycle-cli-001", folder / "m09-lifecycle-consumer-001")
            reports[name] = data_reader(data, replay_rejection)
        elif name == "fuzz":
            from m09_fuzz_smoke import verify_raws as verify_fuzz
            require(parsed(data, "config.json")["candidate_source_manifest_sha256"] == qualified_source_sha,
                    "new fuzzing source differs from qualified source")
            reports[name] = verify_fuzz(data)
        elif name == "fuzz-postprocess":
            receipt = parsed(data, "receipt.json")
            require(receipt["status"] == "PASS" and receipt["source_inputs_unchanged"] is True
                    and receipt["new_fuzzer_runs"] == receipt["new_builds"] == 0,
                    "postprocessing scope differs")
            require(receipt["output_sha256"] == {path: digest(raw) for path, raw in data.items() if path != "receipt.json"},
                    "postprocessing control/result differs")
            require(receipt["source_inventory_sha256"] == {path: digest(raw) for path, raw in recover_group("fuzz").items()},
                    "postprocessing did not use the retained new fuzz acquisition")
            from m09_fuzz_smoke import verify_raws as verify_fuzz
            require(parsed(data, "verification.json") == verify_fuzz(recover_group("fuzz")), "postprocessing conclusion differs")
            reports[name] = {"new_fuzzer_runs": 0, "new_builds": 0, "original_acquisition_unchanged": True}
        elif name == "controls":
            manifest = parsed(data, "control-manifest.json")
            require(manifest["schema"] == "m09-reader-control-closure-v1"
                    and {path: digest(raw) for path, raw in data.items() if path != "control-manifest.json"}
                    == manifest["sha256"], "reader/control closure differs")
            required = {"research/archive_m09.py", "research/m09_final_measure.py", "research/m09_distribution.py",
                        "research/m09_lifecycle_inventory.py", "research/m09_scalar_review.py",
                        "research/verify_r1_certificate_bridge.py", "research/m09_source_contract.py"}
            require(required <= set(manifest["sha256"]), "required replay reader absent")
            reports[name] = {"source_controls_and_documents": len(manifest["sha256"])}
        else:
            reports[name] = {"members": len(data)}
    require(set(provenance["linked_provenance_sha256"]) == set(LINKS), "linked capsule scope differs")
    for name, expected in provenance["linked_provenance_sha256"].items():
        require(sha(ROOT / safe_name(name)) == expected, "linked scientific capsule differs")
    result = {"schema": "m09-engine-verification-v1", "physical_members": count, "groups": reports,
              "new_binary_or_compiler_executed": False, "external_audit": False, "C01_closed": False}
    if (output / "verification.json").exists():
        require(read(output / "verification.json") == result, "saved capsule conclusion differs")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify"))
    parser.add_argument("--output", type=Path, default=ROOT / "results/engine/m09-001")
    args = parser.parse_args()
    output = args.output.resolve()
    print(json.dumps(create(output) if args.action == "create" else verify(output), indent=2))


if __name__ == "__main__":
    main()
