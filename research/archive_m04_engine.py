"""Preserve completed M04 evidence in a new immutable engine snapshot."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "artifacts/generated"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_sources(destination):
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    names = sorted({n for n in names if n and (n.startswith(("crates/", "profiles/", "vectors/", ".cargo/", "examples/r1-channel-demo/", "comparisons/engine-pair/"))
                    or n.startswith("fuzz/fixtures/")
                    or n in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "LICENSE", "NOTICE", "SECURITY.md", "references/manifest.json")
                    or (n.startswith(("research/", "scripts/", "docs/")) and any(x in n.lower() for x in ("m04", "engine_pair", "r1_certificate", "delivery_timing"))))})
    hashes = {}
    with destination.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as stream, tarfile.open(fileobj=stream, mode="w|") as archive:
        for name in names:
            path = ROOT / name
            info = archive.gettarinfo(str(path), arcname=name)
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            info.mode = 0o644
            with path.open("rb") as source:
                archive.addfile(info, source)
            hashes[name] = sha(path)
    return hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.parent != ROOT / "results/engine":
        raise ValueError("new results/engine snapshot required")
    distribution = GENERATED / "m04-distribution/release-004"
    builds = GENERATED / "m04-distribution/release-003"
    fuzz = GENERATED / "m04-fuzz-smoke"
    if not (fuzz / "summary.json").exists():
        raise ValueError("all four fuzz targets must finish before archiving")
    output.mkdir()

    def copy(source, destination):
        destination = output / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    for name in ("windows-research", "linux-research", "windows-delivered", "linux-delivered"):
        shutil.copytree(GENERATED / ("m04-audit-" + name), output / "audit" / name)
        wipe = "m04-" + name.replace("-research", "") + "-wipes.json"
        copy(GENERATED / wipe, "audit/" + name + "/wipes.json")
    copy(GENERATED / "m04-regression-001/summary.json", "regression.json")
    for platform in ("windows", "linux"):
        source = GENERATED / ("m04-" + platform + "-delivery-timing.jsonl")
        dest = output / "timing" / (platform + ".jsonl.gz")
        dest.parent.mkdir(exist_ok=True)
        with source.open("rb") as plain, dest.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as z:
            shutil.copyfileobj(plain, z)
        copy(GENERATED / ("m04-" + platform + "-delivery-timing-summary.json"), "timing/" + platform + ".json")
        copy(distribution / platform / "result.json", "distribution/" + platform + "/result.json")
        for name in ("environment.json", "native-dependencies.txt"):
            copy(builds / platform / name, "distribution/" + platform + "/" + name)
        shutil.copytree(distribution / platform / "package", output / "distribution" / platform / "package",
                        ignore=shutil.ignore_patterns("source.tar.gz"))
    for name in ("source-manifest.json", "compiled-input-equality.json"):
        copy(distribution / name, "distribution/" + name)
    shutil.copytree(GENERATED / "m04-indirect-review", output / "indirect-review")
    copy(GENERATED / "m04-root-review.json", "independent-review/review.json")
    for name in ("windows", "linux"):
        copy(GENERATED / ("m04-root-review-" + name + "-multiply.txt"), "independent-review/" + name + "-multiply.txt")
    for revision, folder in (("ntt", "ntt-001"), ("schoolbook", "schoolbook-002")):
        source = GENERATED / "m04-pair" / folder
        for name in ("snapshot.json", "paired-comparison.json"):
            if (source / name).exists():
                copy(source / name, "comparison/" + revision + "/" + name)
        for backend in ("native", "portable"):
            for name in ("build.json", "measure.json", "measure.jsonl", "measure.stderr", "measure.usage.txt", "tests.log", "clippy.log", "format.log"):
                copy(source / backend / name, "comparison/" + revision + "/" + backend + "/" + name)
    for name in ("m04-full-check.log", "m04-full-check-final.log", "m04-linux-build.log", "m04-research-tests-final.log", "m04-research-tests-reviewed.log",
                 "m04-example-linux.log", "m04-example-linux-release.log", "m04-example-windows-clippy.log", "m04-example-windows-release.log"):
        copy(GENERATED / name, "evidence/" + name)
    for platform in ("windows", "linux"):
        name = "m04-delivery-contract-corrected-" + platform + ".log"
        copy(GENERATED / name, "evidence/" + name)
    # The corpus and initial sources are already frozen by the smoke controller;
    # retain its complete small run rather than cherry-picking successful logs.
    with (output / "fuzz-smoke.tar.gz").open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as z, tarfile.open(fileobj=z, mode="w|") as archive:
        for path in sorted(fuzz.rglob("*")):
            if path.is_file():
                info = archive.gettarinfo(str(path), arcname=path.relative_to(fuzz).as_posix())
                info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
                with path.open("rb") as source:
                    archive.addfile(info, source)
    copy(fuzz / "summary.json", "fuzz-summary.json")
    supplement = GENERATED / "m04-fuzz-api-supplement"
    require_supplement = supplement / "summary.json"
    if not require_supplement.exists():
        raise ValueError("API mutation supplement must finish before archiving")
    shutil.copytree(supplement, output / "api-fuzz-supplement")
    copy(GENERATED / "m04-api-supplement-controller.py", "api-fuzz-supplement/controller.py")
    hashes = archive_sources(output / "sources.tar.gz")
    regression = json.loads((output / "regression.json").read_text())
    smoke = json.loads((output / "fuzz-summary.json").read_text())
    api_smoke = json.loads((output / "api-fuzz-supplement/summary.json").read_text())
    summary = {"profile": "KEM1536-DEV-Q7681-R1", "created_utc": datetime.now(timezone.utc).isoformat(),
               "core_source_commit": "78f5faff017d99a2b323efda17f37a3146f63340",
               "formats_and_vector_bytes_changed": False, "regression_platforms": list(regression["platforms"]),
               "vectors_per_platform": 1000, "rejections_per_platform": 10000, "mutations_per_platform": 10000,
               "format_inputs_per_platform": 20000, "timing_observations_per_platform": 16000,
               "comparison_observations": 24000, "research_tests_final": 115,
               "M03_A01_fixed_for_delivered_binaries": True, "two_isolated_builds_identical_per_target": True,
               "host_isolated_or_different_build_machines": False, "full_concrete_CCA_proof": False,
               "constant_time_proved": False, "all_secret_copies_erased_proved": False,
               "historical_long_fuzz_applies_to_this_NTT": False, "smoke": smoke,
               "API_mutation_supplement": api_smoke,
               "total_M04_fuzz_CPU_seconds": smoke["total_CPU_seconds"] + api_smoke["results"]["api_sequence"]["CPU_seconds"]}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    provenance = {"source_sha256": hashes, "output_sha256": {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob("*")) if p.is_file()}}
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"snapshot": str(output), "preserved_files": len(provenance["output_sha256"]), "source_files": len(hashes)}, indent=2))


if __name__ == "__main__":
    main()
