"""Freeze, build and measure the two real repositories under one toolchain.

Preparation works on Windows or Linux; build/smoke/measure run on Linux.
Only a short smoke is intended while the independent fuzz campaign is active.
Each phase preserves its files and refuses to replace an existing result.
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_OLD_COMMIT = "3dd7c91b5ec9777fd1afc09db198d00dc0deca88"
TOOLCHAIN = "1.93.0"
OLD = ROOT / ".tools/comparison/mlkem1024-demo"
PAIR = Path("comparisons/engine-pair")
DEFAULT_OUTPUT = ROOT / "artifacts/generated/m04-pair/smoke-001"
CONTROLLER_SOURCE_BYTES = Path(__file__).read_bytes()


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def preserve_controller(destination, phase):
    path = destination / f"controller-{phase}.py"
    digest = hashlib.sha256(CONTROLLER_SOURCE_BYTES).hexdigest()
    if path.exists():
        if sha(path) != digest:
            raise ValueError("this phase was started with a different controller version")
    else:
        with path.open("xb") as stream:
            stream.write(CONTROLLER_SOURCE_BYTES)
    return digest


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def capture(command, cwd=None, env=None):
    return subprocess.check_output(command, cwd=cwd, env=env, text=True, encoding="utf-8").strip()


def locks(path):
    """Read package identities/checksums without a Python TOML dependency."""
    packages = {}
    for block in path.read_text(encoding="utf-8").split("[[package]]")[1:]:
        values = dict(re.findall(r'^([a-z_]+)\s*=\s*("[^"\n]*")\s*$', block, re.MULTILINE))
        values = {name: json.loads(value) for name, value in values.items()}
        if "checksum" in values:
            packages[(values["name"], values["version"])] = values["checksum"]
    return packages


def lock_relation(reference, common):
    left, right = locks(reference), locks(common)
    matching = sorted(set(left) & set(right))
    if any(left[key] != right[key] for key in matching):
        raise ValueError("same package/version has different registry checksum")
    return {"reference_registry_packages": len(left),
            "exact_versions_and_checksums_retained": len(matching),
            "reference_versions_absent_from_common_lock":
                [{"package": name, "version": version} for name, version in sorted(set(left) - set(right))],
            "all_reference_versions_retained": set(left).issubset(right)}


def prepare(destination):
    if capture(["git", "-C", str(OLD), "rev-parse", "HEAD"]) != EXPECTED_OLD_COMMIT:
        raise ValueError("original repository is not at the pinned commit")
    if capture(["git", "-C", str(OLD), "status", "--porcelain"]):
        raise ValueError("original repository has local changes")
    common_lock = ROOT / PAIR / "Cargo.lock"
    if not common_lock.is_file():
        raise FileNotFoundError("generate the independent comparison Cargo.lock first")
    files = {ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "profiles/kem1536-p0.toml",
             ROOT / "references/manifest.json", ROOT / "fuzz/fixtures/cases.bin"}
    for base in (ROOT / "crates", ROOT / PAIR):
        files.update(path for path in base.rglob("*") if path.is_file()
                     and path.suffix in (".rs", ".toml", ".lock") and "target" not in path.parts)
    # These sources are not executed as part of the measured benchmark. Keeping
    # them makes the captured workspace's include_bytes! targets reconstructible.
    files.update(path for path in (ROOT / "vectors/nist-acvp").rglob("*") if path.is_file())
    old_files = capture(["git", "-C", str(OLD), "ls-files", "engine", "LICENSE", "NOTICE",
                         "THIRD_PARTY_NOTICES.md", "LICENSES"]).splitlines()
    files.update(OLD / name for name in old_files)
    snapshot = destination / "sources/NIST"
    initial = {path: sha(path) for path in sorted(files)}
    destination.mkdir(parents=True, exist_ok=False)
    for source, digest in initial.items():
        target = snapshot / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if sha(target) != digest or sha(source) != digest:
            raise ValueError("source changed during snapshot; preserve this failed run and use a new directory")
    # Detect concurrent arithmetic edits also when their file was copied early.
    if any(sha(source) != digest for source, digest in initial.items()):
        raise ValueError("source changed during snapshot; a new run is required")
    shutil.copyfile(__file__, destination / "runner.py")
    dependencies = {
        "original": lock_relation(OLD / "engine/Cargo.lock", common_lock),
        "R1_production_workspace": lock_relation(ROOT / "Cargo.lock", common_lock),
    }
    if not dependencies["original"]["all_reference_versions_retained"]:
        raise ValueError("the original backend's locked registry versions must be retained")
    manifest = {
        "schema": 1, "created_utc": now(), "original_commit": EXPECTED_OLD_COMMIT,
        "R1_git_commit": capture(["git", "rev-parse", "HEAD"], cwd=ROOT),
        "R1_worktree_may_include_uncommitted_changes": True,
        "R1_exact_source_is_the_snapshot_not_only_the_git_commit": True,
        "R1_implementation_variant": "R1-current",
        "snapshot_base": "sources/NIST", "comparison_manifest": (PAIR / "Cargo.toml").as_posix(),
        "toolchain": TOOLCHAIN, "production_rust_toolchain_modified": False,
        "source_sha256": {source.relative_to(ROOT).as_posix(): digest for source, digest in initial.items()},
        "runner_sha256": sha(destination / "runner.py"),
        "dependency_lock_relation": dependencies,
    }
    write_new(destination / "snapshot.json", manifest)
    return {"snapshot_files": len(initial), "dependency_lock_relation": dependencies}


def prepare_schoolbook(destination, parent):
    """Change exactly the two frozen M02 arithmetic/caller source files."""
    manifest, parent_snapshot = verify_snapshot(parent)
    if parent.resolve() == destination.resolve():
        raise ValueError("schoolbook comparison requires a distinct output")
    old_provenance_path = ROOT / "results/engine/hardening-001/provenance.json"
    old_provenance = read(old_provenance_path)
    replacements = {
        "crates/kem1536/src/dev_kem.rs": "a21bb340bd5af3c4983f1f76b59ef542aea67edf4c62ad7ff23e8205612cb564",
        "crates/kem1536/src/engine_poly.rs": "e16599a7d711f045ece773216a508c573907e37217906082e3a8e61192dba8d9",
    }
    for relative, expected in replacements.items():
        archived = "results/engine/hardening-001/sources/" + relative
        if sha(ROOT / archived) != expected or old_provenance["input_sha256"][archived] != expected:
            raise ValueError("frozen M02 comparison source does not match its provenance")
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(parent_snapshot, destination / manifest["snapshot_base"])
    snapshot = destination / manifest["snapshot_base"]
    overrides = {}
    for relative, expected in replacements.items():
        archived = "results/engine/hardening-001/sources/" + relative
        overrides[relative] = {"parent_snapshot_sha256": manifest["source_sha256"][relative],
                               "archive_source": archived, "archive_sha256": expected}
        shutil.copyfile(ROOT / archived, snapshot / relative)
        manifest["source_sha256"][relative] = expected
    shutil.copyfile(__file__, destination / "runner.py")
    manifest.update({
        "created_utc": now(), "R1_implementation_variant": "R1-schoolbook-M02",
        "runner_sha256": sha(destination / "runner.py"),
        "parent_NTT_snapshot_sha256": sha(parent / "snapshot.json"),
        "only_two_engine_source_files_replaced_from_M02": overrides,
        "M02_provenance_sha256": sha(old_provenance_path),
        "non_arithmetic_sources_and_common_driver_identical_to_parent": True,
    })
    write_new(destination / "snapshot.json", manifest)
    verify_snapshot(destination)
    return {"snapshot_files": len(manifest["source_sha256"]), "R1_variant": "R1-schoolbook-M02",
            "replaced_files": list(replacements), "parent_snapshot_sha256": manifest["parent_NTT_snapshot_sha256"]}


def verify_snapshot(destination):
    manifest = read(destination / "snapshot.json")
    snapshot = destination / manifest["snapshot_base"]
    if manifest["toolchain"] != TOOLCHAIN or manifest["original_commit"] != EXPECTED_OLD_COMMIT:
        raise ValueError("source/toolchain policy drift")
    for relative, expected in manifest["source_sha256"].items():
        path = (snapshot / relative).resolve()
        if not path.is_relative_to(snapshot.resolve()) or sha(path) != expected:
            raise ValueError(f"snapshot source changed: {relative}")
    if sha(destination / "runner.py") != manifest["runner_sha256"]:
        raise ValueError("frozen runner changed")
    return manifest, snapshot


def linux_environment(destination):
    if sys.platform != "linux":
        raise RuntimeError("run build/smoke/measure with the project-local Linux toolchain under WSL")
    env = os.environ.copy()
    for key in list(env):
        if key in ("CARGO_ENCODED_RUSTFLAGS", "CFLAGS", "CXXFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER") or key.startswith("CARGO_PROFILE_RELEASE_"):
            env.pop(key)
    env.update({
        "CARGO_HOME": str(ROOT / ".tools/linux-cargo"),
        "RUSTUP_HOME": str(ROOT / ".tools/linux-rustup"),
        "RUSTUP_TOOLCHAIN": TOOLCHAIN,
        "CARGO_TARGET_DIR": str(destination / "target"),
        "CARGO_BUILD_JOBS": "2",
        "RUSTFLAGS": "-C target-cpu=x86-64",
        "PATH": str(ROOT / ".tools/linux-cargo/bin") + ":/usr/local/bin:/usr/bin:/bin",
    })
    return env


def command_logged(command, path, env, cwd):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        completed = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stream, stderr=subprocess.STDOUT, timeout=900)
    if completed.returncode:
        raise RuntimeError(f"command failed; preserved diagnostics: {path}")


def build(destination, backends, build_cache=None):
    manifest, snapshot = verify_snapshot(destination)
    env = linux_environment(destination)
    if build_cache is not None:
        build_cache = build_cache.resolve()
        if not build_cache.is_relative_to((ROOT / "artifacts/generated/m04-pair").resolve()):
            raise ValueError("comparison build cache must remain below artifacts/generated/m04-pair")
        env["CARGO_TARGET_DIR"] = str(build_cache)
    cargo = str(ROOT / ".tools/linux-cargo/bin/cargo")
    tool = capture(["rustc", "-Vv"], env=env)
    if not tool.startswith("rustc 1.93.0 "):
        raise ValueError("the common comparison compiler must be Rust 1.93.0")
    result = {}
    for backend in backends:
        directory = destination / backend
        directory.mkdir(exist_ok=False)
        args = ["--manifest-path", str(snapshot / PAIR / "Cargo.toml"), "--no-default-features"]
        if backend == "native":
            args += ["--features", "native"]
        command_logged([cargo, "fmt", "--manifest-path", str(snapshot / PAIR / "Cargo.toml"), "--", "--check"],
                       directory / "format.log", env, snapshot)
        command_logged([cargo, "test", "--locked", "--release", *args, "--all-targets"],
                       directory / "tests.log", env, snapshot)
        command_logged([cargo, "clippy", "--locked", "--release", *args, "--all-targets", "--", "-D", "warnings"],
                       directory / "clippy.log", env, snapshot)
        command_logged([cargo, "build", "--locked", "--release", *args], directory / "build.log", env, snapshot)
        executable = directory / "kem-engine-pair"
        shutil.copyfile(Path(env["CARGO_TARGET_DIR"]) / "release/kem-engine-pair", executable)
        executable.chmod(0o755)
        metadata = {
            "created_utc": now(), "rustc_verbose": tool,
            "cargo": capture([cargo, "-V"], env=env),
            "gcc": capture(["gcc", "-dumpfullversion"], env=env),
            "backend_feature": backend, "binary_sha256": sha(executable),
            "binary_bytes": executable.stat().st_size,
            "RUSTFLAGS": env["RUSTFLAGS"], "Cargo_build_jobs": 2,
            "release_profile": {"opt_level": 3, "codegen_units": 1, "lto": "thin", "panic": "abort", "strip": False},
            "comparison_lock_sha256": sha(snapshot / PAIR / "Cargo.lock"),
            "build_cache_directory": env["CARGO_TARGET_DIR"],
            "snapshot_manifest_sha256": sha(destination / "snapshot.json"),
            "deterministic_testing_feature": False,
        }
        write_new(directory / "build.json", metadata)
        result[backend] = {"binary_sha256": metadata["binary_sha256"], "tests": "passed", "clippy": "passed"}
    verify_snapshot(destination)
    return result


def machine_state(cpu):
    state = {"utc": now(), "platform": platform.platform(), "processor": platform.machine(),
             "cpu_affinity_requested": cpu, "load_average": list(os.getloadavg()),
             "allowed_cpus": sorted(os.sched_getaffinity(0))}
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    state["cpu_model"] = next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("model name")), "unknown")
    state["process_cpu_snapshot"] = capture(["ps", "-eo", "pid,ppid,pcpu,comm", "--sort=-pcpu"])
    progress = ROOT / "artifacts/generated/m03-long-001/progress.json"
    if progress.exists():
        live = read(progress)
        state["concurrent_fuzzing"] = {
            "updated_utc": live.get("updated_utc"),
            "worker_statuses": {name: row.get("status") for name, row in live.get("workers", {}).items()},
        }
    return state


def validate_measurements(path):
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    metadata = [row for row in records if row["kind"] == "metadata"]
    if len(metadata) != 1:
        raise ValueError("one metadata row required")
    config = metadata[0]["configuration"]
    groups = defaultdict(list)
    coordinates = defaultdict(set)
    for row in records:
        if row["kind"] != "observation":
            continue
        key = (row["engine"], row["operation"])
        coordinate = (row["series"], row["iteration"])
        if coordinate in coordinates[key] or not isinstance(row["nanoseconds"], int) or row["nanoseconds"] < 0:
            raise ValueError("duplicate or invalid timing observation")
        coordinates[key].add(coordinate)
        groups[key].append(row["nanoseconds"])
    expected_keys = {(engine, operation) for engine in ("R1", "original-ML-KEM-1024")
                     for operation in ("keygen", "encaps", "decaps")}
    expected_coordinates = {(series, iteration) for series in range(config["series"])
                            for iteration in range(config["observations_per_operation_and_series"])}
    summaries = [row for row in records if row["kind"] == "summary"]
    if set(groups) != expected_keys or len(summaries) != 6:
        raise ValueError("missing or extra engine/operation group")
    seen_summaries = set()
    for summary in summaries:
        key = (summary["engine"], summary["operation"])
        if key in seen_summaries or key not in expected_keys or coordinates[key] != expected_coordinates:
            raise ValueError("summary or sample coverage mismatch")
        seen_summaries.add(key)
        values = sorted(groups[key])
        expected = {
            "observations": len(values), "median_nanoseconds": statistics.median(values),
            "p95_nanoseconds_nearest_rank": values[math.ceil(0.95 * len(values)) - 1],
            "minimum_nanoseconds": min(values), "maximum_nanoseconds": max(values),
        }
        if any(summary[field] != value for field, value in expected.items()):
            raise ValueError("summary does not match all raw timings")
    if any(row["kind"] not in ("metadata", "observation", "summary") for row in records):
        raise ValueError("unexpected output type")
    return {"metadata": metadata[0], "raw_observations": sum(map(len, groups.values())),
            "summaries": summaries, "all_samples_retained": True}


def measure(destination, backends, phase, cpu, series, warmups, observations):
    source_manifest, _ = verify_snapshot(destination)
    env = linux_environment(destination)
    controller_digest = preserve_controller(destination, phase)
    result = {}
    for backend in backends:
        directory = destination / backend
        built = read(directory / "build.json")
        binary = directory / "kem-engine-pair"
        if sha(binary) != built["binary_sha256"]:
            raise ValueError("measurement binary differs from the captured build")
        state = machine_state(cpu)
        if cpu not in state["allowed_cpus"]:
            raise ValueError("chosen CPU is outside the available affinity set")
        raw = directory / f"{phase}.jsonl"
        stderr = directory / f"{phase}.stderr"
        usage = directory / f"{phase}.usage.txt"
        command = ["/usr/bin/time", "-f", "%U %S %M", "-o", str(usage),
                   "taskset", "--cpu-list", str(cpu), str(binary), str(series), str(warmups), str(observations)]
        started = time.perf_counter()
        with raw.open("x", encoding="utf-8", newline="\n") as stdout, stderr.open("x", encoding="utf-8", newline="\n") as errors:
            process = subprocess.run(command, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=errors, timeout=900)
        elapsed = time.perf_counter() - started
        if process.returncode:
            raise RuntimeError(f"measurement failed; diagnostics preserved in {directory}")
        validation = validate_measurements(raw)
        original_backend = validation["metadata"]["engines"][1]["backend"]
        if backend == "portable" and original_backend != "portable-clean":
            raise ValueError("portable measurement unexpectedly selected a native backend")
        usage_fields = usage.read_text(encoding="utf-8").split()
        report = {
            "phase": phase, "created_utc": now(), "build_sha256": sha(directory / "build.json"),
            "controller_sha256": controller_digest,
            "engine_labels": {"R1": source_manifest.get("R1_implementation_variant", "R1-current"),
                              "original-ML-KEM-1024": "original-ML-KEM-1024"},
            "binary_sha256": sha(binary), "raw_sha256": sha(raw),
            "configuration": {"series": series, "warmups": warmups, "observations_per_series": observations},
            "elapsed_wall_seconds": elapsed, "CPU_user_seconds": float(usage_fields[0]),
            "CPU_system_seconds": float(usage_fields[1]), "process_max_RSS_KiB": int(usage_fields[2]),
            "RSS_is_combined_process_not_per_engine_memory": True,
            "state_before": state, "state_after": machine_state(cpu),
            "uncontended_performance_claim": False,
            "validation": validation,
        }
        write_new(directory / f"{phase}.json", report)
        result[backend] = {"raw_observations": validation["raw_observations"],
                           "original_backend": original_backend, "all_round_trips_checked": True,
                           "phase": phase, "uncontended_performance_claim": False}
    return result


def verify(destination):
    manifest, _ = verify_snapshot(destination)
    output = {"snapshot_files": len(manifest["source_sha256"]), "backends": {}}
    for backend in ("native", "portable"):
        directory = destination / backend
        if not (directory / "build.json").exists():
            continue
        built = read(directory / "build.json")
        if (sha(directory / "kem-engine-pair") != built["binary_sha256"]
                or sha(destination / "snapshot.json") != built["snapshot_manifest_sha256"]):
            raise ValueError("build provenance mismatch")
        phases = {}
        for phase in ("smoke", "measure"):
            report_path = directory / f"{phase}.json"
            if not report_path.exists():
                continue
            report = read(report_path)
            if (sha(directory / f"{phase}.jsonl") != report["raw_sha256"]
                    or sha(directory / "build.json") != report["build_sha256"]
                    or sha(destination / f"controller-{phase}.py") != report["controller_sha256"]):
                raise ValueError("measurement provenance mismatch")
            if validate_measurements(directory / f"{phase}.jsonl") != report["validation"]:
                raise ValueError("independent summary replay differs")
            phases[phase] = report["validation"]["raw_observations"]
        output["backends"][backend] = phases
    return output


def compare_runs(ntt_run, schoolbook_run):
    """Compare only the deliberately paired source and measurement contracts."""
    ntt_manifest, _ = verify_snapshot(ntt_run)
    old_manifest, _ = verify_snapshot(schoolbook_run)
    verify(ntt_run)
    verify(schoolbook_run)
    if old_manifest.get("parent_NTT_snapshot_sha256") != sha(ntt_run / "snapshot.json"):
        raise ValueError("schoolbook run was not derived from this NTT snapshot")
    if set(ntt_manifest["source_sha256"]) != set(old_manifest["source_sha256"]):
        raise ValueError("paired snapshots do not contain the same source file set")
    differences = {name for name, digest in ntt_manifest["source_sha256"].items()
                   if old_manifest["source_sha256"].get(name) != digest}
    if differences != {"crates/kem1536/src/dev_kem.rs", "crates/kem1536/src/engine_poly.rs"}:
        raise ValueError("more than the two declared engine files differ")
    rows = []
    raw_hashes = {}
    total = 0
    for backend in ("native", "portable"):
        left = read(ntt_run / backend / "measure.json")
        right = read(schoolbook_run / backend / "measure.json")
        left_build = read(ntt_run / backend / "build.json")
        right_build = read(schoolbook_run / backend / "build.json")
        for key in ("rustc_verbose", "cargo", "gcc", "RUSTFLAGS", "release_profile", "comparison_lock_sha256"):
            if left_build[key] != right_build[key]:
                raise ValueError(f"comparison build contract differs: {key}")
        if left["configuration"] != right["configuration"]:
            raise ValueError("paired measurements use different counts or warmups")
        for key in ("cpu_affinity_requested", "cpu_model"):
            if left["state_before"][key] != right["state_before"][key]:
                raise ValueError(f"paired measurements use different machine conditions: {key}")
        if left["validation"]["metadata"] != right["validation"]["metadata"]:
            raise ValueError("driver/engine formats or declared backend differ")
        summaries_left = {(row["engine"], row["operation"]): row for row in left["validation"]["summaries"]}
        summaries_right = {(row["engine"], row["operation"]): row for row in right["validation"]["summaries"]}
        for key in sorted(summaries_left):
            current, old = summaries_left[key], summaries_right[key]
            rows.append({
                "backend_mode": backend, "engine": key[0], "operation": key[1],
                "NTT_process": current, "schoolbook_process": old,
                "median_ratio_schoolbook_process_over_NTT_process": old["median_nanoseconds"] / current["median_nanoseconds"],
                "p95_ratio_schoolbook_process_over_NTT_process": old["p95_nanoseconds_nearest_rank"] / current["p95_nanoseconds_nearest_rank"],
                "interpretation": "engine revision ratio" if key[0] == "R1" else "unchanged backend control between separate processes",
            })
        for label, run in (("NTT", ntt_run), ("schoolbook", schoolbook_run)):
            raw_hashes[f"{label}/{backend}/measure.jsonl"] = sha(run / backend / "measure.jsonl")
        total += left["validation"]["raw_observations"] + right["validation"]["raw_observations"]
    result = {
        "created_utc": now(), "NTT_snapshot_sha256": sha(ntt_run / "snapshot.json"),
        "schoolbook_snapshot_sha256": sha(schoolbook_run / "snapshot.json"),
        "same_driver_toolchain_profile_lock_and_non_arithmetic_sources": True,
        "only_replaced_sources": sorted(differences), "raw_observations": total,
        "configuration": left["configuration"], "raw_sha256": raw_hashes, "comparisons": rows,
        "host_fully_isolated": False, "pure_NTT_causal_isolation": False,
        "security_superiority_inferred": False,
    }
    write_new(ntt_run / "paired-comparison.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("prepare", "build", "smoke", "measure", "verify", "compare"), required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--backend", choices=("both", "native", "portable"), default="both")
    parser.add_argument("--cpu", type=int, default=10)
    parser.add_argument("--series", type=int)
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--observations", type=int)
    parser.add_argument("--schoolbook-of", type=Path, help="prepare a copy of a frozen NTT run, replacing only the two pinned M02 engine sources")
    parser.add_argument("--build-cache", type=Path, help="optional shared Cargo build cache below artifacts/generated/m04-pair; frozen executables remain separate")
    parser.add_argument("--compare-with", type=Path, help="schoolbook run deliberately derived from the NTT output run")
    args = parser.parse_args()
    destination = args.output.resolve()
    allowed = (ROOT / "artifacts/generated/m04-pair").resolve()
    if not destination.is_relative_to(allowed) or destination == allowed:
        raise ValueError("outputs must remain in a run below artifacts/generated/m04-pair")
    backends = ["native", "portable"] if args.backend == "both" else [args.backend]
    if args.phase == "prepare":
        result = prepare_schoolbook(destination, args.schoolbook_of.resolve()) if args.schoolbook_of else prepare(destination)
    elif args.phase == "build":
        result = build(destination, backends, args.build_cache)
    elif args.phase == "verify":
        result = verify(destination)
    elif args.phase == "compare":
        if args.compare_with is None:
            raise ValueError("compare requires --compare-with <schoolbook run>")
        result = compare_runs(destination, args.compare_with.resolve())
    else:
        smoke = args.phase == "smoke"
        series = args.series if args.series is not None else (2 if smoke else 5)
        warmups = args.warmups if args.warmups is not None else (3 if smoke else 100)
        observations = args.observations if args.observations is not None else (10 if smoke else 1000)
        if smoke and (series > 2 or warmups > 3 or observations > 10):
            raise ValueError("smoke is deliberately capped; use an explicitly authorized measure phase for larger runs")
        result = measure(destination, backends, args.phase, args.cpu, series, warmups, observations)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
