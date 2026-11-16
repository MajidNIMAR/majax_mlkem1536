"""Finite M07 ASan/std-rebuilt campaign, gated on accepted memory and latency.

The measured candidate is copied unchanged, with the current four fuzz
harnesses attached by hash. Existing M04/M06 controllers are reused without
editing them. Every campaign, compiler target, log and receipt is new.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys

from run_m04_fuzz_smoke import TARGETS, run_target, statistics as fuzz_statistics
from run_m06_fuzz import inspect_post_init

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
CONTROLLERS = ("run_m07_fuzz.py", "run_m04_fuzz_smoke.py", "run_m06_fuzz.py")
SKIP_FUZZ_PARTS = {"target", "corpus", "artifacts", "coverage"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def ordinary(path, directory=False):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
            f"links/reparse points are forbidden in campaign inputs: {path}")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            f"ordinary {'directory' if directory else 'file'} required: {path}")


def inventory(folder):
    ordinary(folder, directory=True)
    result = {}
    for parent, directories, files in os.walk(folder, followlinks=False):
        for name in directories:
            ordinary(Path(parent) / name, directory=True)
        for name in files:
            path = Path(parent) / name
            ordinary(path)
            result[path.relative_to(folder).as_posix()] = sha(path)
    return dict(sorted(result.items()))


def safe_name(name):
    path = PurePosixPath(name)
    require(type(name) is str and not path.is_absolute() and "\\" not in name
            and all(part not in {"", ".", "..", ".git"} and ":" not in part for part in name.split("/")),
            "unsafe candidate source member")
    return path


def owned(path, parent):
    path = Path(os.path.abspath(path))
    require(".." not in path.parts and path.parent == parent and path.name.startswith("m07"),
            f"new direct M07 child required below {parent}")
    current = ROOT
    for part in path.relative_to(ROOT).parts[:-1]:
        current /= part
        ordinary(current, directory=True)
    return path


def bind_inputs(measurements):
    """Read-only acceptance/source gate; no output or compiler target is created."""
    measurements = owned(measurements, ROOT / "artifacts/generated")
    ordinary(measurements, directory=True)
    marker = measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"
    require(marker.is_file(), "wait for MEMORY_AND_LATENCY_ACCEPTED.json before build/run")
    ordinary(marker)
    accepted = read(marker)
    manifest_path = measurements / "candidate-source.json"
    ordinary(manifest_path)
    require(accepted.get("profile") == PROFILE and accepted.get("accepted") is True,
            "candidate memory and latency have not been accepted")
    require(accepted.get("candidate_source_manifest_sha256") == sha(manifest_path),
            "acceptance marker is not bound to this candidate source manifest")
    manifest = read(manifest_path)
    require(manifest.get("profile") == PROFILE and type(manifest.get("source_sha256")) is dict,
            "invalid measured candidate source manifest")
    for name in manifest["source_sha256"]:
        safe_name(name)
    source = measurements / "candidate-source"
    require(inventory(source) == manifest["source_sha256"], "measured candidate source changed")
    fuzz_files = {}
    ordinary(ROOT / "fuzz", directory=True)
    for parent, directories, files in os.walk(ROOT / "fuzz", followlinks=False):
        directories[:] = sorted(name for name in directories if name not in SKIP_FUZZ_PARTS)
        for name in directories:
            ordinary(Path(parent) / name, directory=True)
        for name in files:
            path = Path(parent) / name
            ordinary(path)
            relative = path.relative_to(ROOT).as_posix()
            checksum = sha(path)
            if relative in manifest["source_sha256"]:
                require(checksum == manifest["source_sha256"][relative], "fuzz attachment conflicts with measured source")
            fuzz_files[relative] = checksum
    required = {"fuzz/Cargo.toml", "fuzz/Cargo.lock", "fuzz/src/lib.rs", "fuzz/fixtures/cases.bin"}
    required.update(f"fuzz/fuzz_targets/{name}.rs" for name in TARGETS)
    require(required <= set(fuzz_files), "complete four-harness fuzz sources are required")
    return {"measurements": measurements, "marker": marker, "manifest": manifest_path,
            "acceptance_marker_sha256": sha(marker), "candidate_source_manifest_sha256": sha(manifest_path),
            "source": source, "source_sha256": manifest["source_sha256"], "fuzz_sha256": fuzz_files}


def environment(target):
    result = dict(os.environ, CARGO_HOME=str(ROOT / ".tools/linux-cargo"),
                  RUSTUP_HOME=str(ROOT / ".tools/linux-rustup"),
                  RUSTUP_TOOLCHAIN="1.91.1-x86_64-unknown-linux-gnu", RUSTUP_AUTO_INSTALL="0",
                  RUSTC_BOOTSTRAP="1", CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true",
                  CARGO_TARGET_DIR=str(target),
                  ASAN_OPTIONS="detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1")
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER",
                 "RUSTC_WORKSPACE_WRAPPER", "RUSTDOCFLAGS", "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS"):
        result.pop(name, None)
    for name in list(result):
        if name.startswith("CARGO_PROFILE_RELEASE_"):
            result.pop(name)
    result["PATH"] = str(ROOT / ".tools/linux-cargo/bin") + ":/usr/local/bin:/usr/bin:/bin"
    return result


def require_post_init(post):
    require(set(post["targets"]) == set(TARGETS) and post["all_four_have_post_INITED_execution"],
            "CPU budget reached without post-INITED work; retain and supplement separately")
    for row in post["targets"].values():
        count = 0
        require(bool(row["segments"]), "empty fuzz segment list")
        for segment in row["segments"]:
            initial, final = segment["INITED_counter"], segment["final_executed_units_counter"]
            require(segment["INITED_line_unique"] and type(initial) is int and type(final) is int
                    and 0 <= initial <= final, "invalid INITED/final execution counters")
            count += final - initial
        require(count > 0 and count == row["executions_after_INITED"], "post-INITED counter differs")


def execute(out, measurements, target, cpu, budget):
    require(sys.platform == "linux" and cpu in os.sched_getaffinity(0), "valid Linux CPU required")
    require(type(budget) is int and 30 <= budget <= 120, "declare 30..120 CPU seconds per harness")
    out = owned(out, ROOT / "artifacts/generated")
    target = owned(target, ROOT / "target")
    require(not out.exists() and not target.exists(), "new campaign and compiler target directories required")
    bound = bind_inputs(measurements)  # Must precede any mutation or compiler invocation.
    out.mkdir()
    try:
        shutil.copytree(bound["source"], out / "source")
        for name, checksum in bound["fuzz_sha256"].items():
            destination = out / "source" / name
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            require(sha(destination) == checksum, "fuzz source attachment changed")
        source_hashes = inventory(out / "source")
        require(all(source_hashes[name] == checksum for name, checksum in bound["source_sha256"].items()),
                "measured compiled source closure was not preserved")
        controls = out / "controls"
        controls.mkdir()
        for name in CONTROLLERS:
            shutil.copyfile(ROOT / "research" / name, controls / name)
        controller_hashes = inventory(controls)
        shutil.copyfile(bound["marker"], out / "accepted-marker.json")
        shutil.copyfile(bound["manifest"], out / "candidate-source.json")
        require(sha(out / "accepted-marker.json") == bound["acceptance_marker_sha256"]
                and sha(out / "candidate-source.json") == bound["candidate_source_manifest_sha256"],
                "acceptance gate changed while copying")
        copied_marker = read(out / "accepted-marker.json")
        require(copied_marker.get("profile") == PROFILE and copied_marker.get("accepted") is True
                and copied_marker.get("candidate_source_manifest_sha256") == bound["candidate_source_manifest_sha256"],
                "copied acceptance gate is not valid")
        seeds = {}
        for name in TARGETS:
            origin = ROOT / "artifacts/generated/m03-seeds-final" / name
            seed_hashes = inventory(origin)
            require(0 < len(seed_hashes) <= 128 and all("/" not in member for member in seed_hashes),
                    "compact, flat synthetic seed corpus required")
            destination = out / "initial-corpus" / name
            destination.mkdir(parents=True)
            for member, checksum in seed_hashes.items():
                path = destination / checksum
                if not path.exists():
                    shutil.copyfile(origin / member, path)
            seeds[name] = {"origin": origin.relative_to(ROOT).as_posix(), "origin_sha256": seed_hashes,
                           "distinct_inputs": len(list(destination.iterdir())), "sha256": inventory(destination)}
        env = environment(target)
        cargo = str(ROOT / ".tools/linux-cargo/bin/cargo")
        rustc = str(ROOT / ".tools/linux-cargo/bin/rustc")
        versions = {"rustc": subprocess.check_output([rustc, "-Vv"], env=env, text=True),
                    "cargo_fuzz": subprocess.check_output([cargo, "fuzz", "--version"], env=env, text=True)}
        require("release: 1.91.1" in versions["rustc"], "unexpected M07 fuzz compiler")
        command = ["taskset", "-c", str(cpu), cargo, "fuzz", "build", "--fuzz-dir", str(out / "source/fuzz"),
                   "--target-dir", str(target), "--build-std"]
        save(out / "config.json", {"schema": 1, "profile": PROFILE, "started_utc": utc(),
             "candidate_source_manifest_sha256": sha(out / "candidate-source.json"),
             "acceptance_marker_sha256": sha(out / "accepted-marker.json"),
             "measured_source_sha256": bound["source_sha256"], "attached_fuzz_sha256": bound["fuzz_sha256"],
             "source_sha256": source_hashes, "controller_sha256": controller_hashes,
             "initial_corpus": seeds, "versions": versions, "build_command": command,
             "CPU_seconds_per_harness": budget, "sequential_CPU": cpu, "ASAN_OPTIONS": env["ASAN_OPTIONS"],
             "std_rebuild_requested": True, "offline_build": True, "research_vectors_feature_enabled": False,
             "historical_fuzz_CPU_seconds_credited": 0, "source_line_coverage_measured": False})
        lock_sha = sha(out / "source/fuzz/Cargo.lock")
        with (out / "build.log").open("xb") as log:
            subprocess.run(command, cwd=out / "source", env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        require(sha(out / "source/fuzz/Cargo.lock") == lock_sha, "frozen fuzz lock changed during build")
        require(inventory(out / "source") == source_hashes, "build changed frozen candidate sources")
        (out / "bin").mkdir()
        binaries = {}
        for name in TARGETS:
            destination = out / "bin" / name
            shutil.copyfile(target / "x86_64-unknown-linux-gnu/release" / name, destination)
            destination.chmod(0o700)
            binaries[name] = sha(destination)
        rebuilt = sorted((target / "x86_64-unknown-linux-gnu/release/deps").glob("libstd-*.rlib"))
        require(rebuilt, "rebuilt standard library rlib absent")
        save(out / "built.json", {"binary_sha256": binaries, "frozen_fuzz_lock_sha256": lock_sha,
             "rebuilt_std_rlib_sha256": {path.name: sha(path) for path in rebuilt}})
        results = {name: run_target(index, out, env, cpu, budget) for index, name in enumerate(TARGETS)}
        save(out / "fuzz-summary.json", {"finished_utc": utc(), "results": results,
             "total_CPU_seconds": sum(item["CPU_seconds"] for item in results.values()),
             "all_four_budgets_reached": all(item["CPU_seconds"] >= budget for item in results.values()),
             "standard_library_rebuilt": True, "source_line_coverage_measured": False,
             "independent_oracle_replayed": False, "historical_fuzz_time_transferred": False})
        require(not (out / "supplemental-summary.json").exists(), "supplements need a separate declared M07 campaign")
        post = inspect_post_init(out)
        save(out / "post-init.json", post)
        require_post_init(post)
        result = verify(out)
        save(out / "verification.json", result)
        return result
    except BaseException as error:
        if not (out / "failure.json").exists():
            save(out / "failure.json", {"at_utc": utc(), "error_type": type(error).__name__,
                 "error": str(error), "evidence_preserved": True})
        raise


def verify_segments(folder, item, budget, affinity):
    require(item["status"] == "complete" and item["budget_CPU_seconds"] == budget
            and item["sequential_affinity_CPU"] == affinity and item["defects_observed"] is False,
            "target budget, affinity or completion scope differs")
    records = item["segments"]
    require(type(records) is list and bool(records)
            and [row["segment"] for row in records] == list(range(len(records)))
            and all(type(row["segment"]) is int for row in records), "segments must be unique and contiguous")
    expected = {"summary.json"} | {f"segment-{row['segment']:03d}{suffix}" for row in records
                                  for suffix in (".log", "-usage.json", "-result.json")}
    require({path.name for path in folder.iterdir() if path.is_file()} == expected,
            "segment file inventory differs")
    require(read(folder / "summary.json") == item, "target summary differs")
    cpu, executions = 0.0, 0
    for record in records:
        segment = record["segment"]
        require(read(folder / f"segment-{segment:03d}-result.json") == record, "segment receipt differs")
        usage = read(folder / f"segment-{segment:03d}-usage.json")
        require(usage == record["resource_usage"] and record["exit_code"] == usage["exit_code"] == 0,
                "resource receipt or successful exit differs")
        require(all(type(usage[field]) in (int, float) and math.isfinite(usage[field]) and usage[field] >= 0
                    for field in ("user_seconds", "system_seconds", "wall_seconds")), "invalid CPU or wall accounting")
        cpu += usage["user_seconds"] + usage["system_seconds"]
        stats = fuzz_statistics(folder / f"segment-{segment:03d}.log")
        require(type(stats.get("executions")) is int and stats["executions"] >= 0
                and all(record.get(key) == value for key, value in stats.items()), "raw libFuzzer counters differ")
        executions += stats["executions"]
    require(type(item["CPU_seconds"]) in (int, float) and math.isfinite(item["CPU_seconds"])
            and abs(cpu - item["CPU_seconds"]) < 1e-9 and cpu >= budget, "CPU budget not reached")
    require(executions == item["executions_including_repeated_seeds"], "execution total differs from raw logs")
    return cpu


def verify(out):
    config, built, summary = (read(out / name) for name in ("config.json", "built.json", "fuzz-summary.json"))
    require(config["profile"] == PROFILE and config["historical_fuzz_CPU_seconds_credited"] == 0,
            "wrong M07 scope")
    require(type(config["CPU_seconds_per_harness"]) is int and 30 <= config["CPU_seconds_per_harness"] <= 120,
            "invalid declared finite CPU budget")
    require(type(config["sequential_CPU"]) is int and config["sequential_CPU"] >= 0
            and config["std_rebuild_requested"] is True and config["offline_build"] is True
            and config["research_vectors_feature_enabled"] is False and config["source_line_coverage_measured"] is False,
            "compiler and measurement scope flags differ")
    require(sha(out / "accepted-marker.json") == config["acceptance_marker_sha256"]
            and sha(out / "candidate-source.json") == config["candidate_source_manifest_sha256"], "candidate acceptance binding differs")
    marker, manifest = read(out / "accepted-marker.json"), read(out / "candidate-source.json")
    require(marker["profile"] == manifest["profile"] == PROFILE and marker["accepted"] is True
            and marker["candidate_source_manifest_sha256"] == config["candidate_source_manifest_sha256"], "unaccepted candidate")
    require(manifest["source_sha256"] == config["measured_source_sha256"], "measured source map differs")
    require(inventory(out / "source") == config["source_sha256"] and inventory(out / "controls") == config["controller_sha256"],
            "frozen source or controllers changed")
    require(all(config["source_sha256"][name] == checksum for name, checksum in config["measured_source_sha256"].items())
            and all(config["source_sha256"][name] == checksum for name, checksum in config["attached_fuzz_sha256"].items()),
            "compiled candidate or fuzz attachment differs")
    require(sha(out / "source/fuzz/Cargo.lock") == built["frozen_fuzz_lock_sha256"]
            and bool(built["rebuilt_std_rlib_sha256"]), "frozen lock or rebuilt std receipt absent")
    require(set(built["binary_sha256"]) == set(TARGETS) and set(summary["results"]) == set(TARGETS), "four-target panel required")
    require(summary["standard_library_rebuilt"] is True and summary["all_four_budgets_reached"] is True
            and summary["historical_fuzz_time_transferred"] is False
            and summary["independent_oracle_replayed"] is False
            and summary["source_line_coverage_measured"] is False, "campaign scope differs")
    total = 0.0
    for name in TARGETS:
        require(sha(out / "bin" / name) == built["binary_sha256"][name], "fuzz executable changed")
        require(inventory(out / "initial-corpus" / name) == config["initial_corpus"][name]["sha256"], "seed snapshot changed")
        item = summary["results"][name]
        require(not item["defects_observed"] and not any((out / name / "failures").iterdir()), "defect or failing input recorded")
        cpu = verify_segments(out / name, item, config["CPU_seconds_per_harness"], config["sequential_CPU"])
        total += cpu
        require(len(list((out / name / "corpus").iterdir())) == item["final_distinct_corpus_inputs"], "corpus inventory differs")
    require(abs(total - summary["total_CPU_seconds"]) < 1e-9, "total CPU accounting differs")
    require(not (out / "supplemental-summary.json").exists(), "supplements need a separate declared M07 campaign")
    post = inspect_post_init(out)
    require(post == read(out / "post-init.json"), "post-INITED evidence differs")
    require_post_init(post)
    return {"profile": PROFILE, "total_CPU_seconds": total, "candidate_and_harness_hashes_verified": True,
            "all_four_have_post_INITED_execution": True, "historical_CPU_seconds_credited": 0,
            "source_line_coverage_measured": False, "long_campaign_completed": False,
            "independent_oracle_replayed": False, "secrets_printed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify"))
    parser.add_argument("--measurements", type=Path, default=ROOT / "artifacts/generated/m07-001")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m07-fuzz-001")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/m07-fuzz-001")
    parser.add_argument("--cpu", type=int, default=10)
    parser.add_argument("--cpu-seconds", type=int, default=60)
    args = parser.parse_args()
    if args.action == "run":
        out = owned(args.output, ROOT / "artifacts/generated")
        result = execute(out, args.measurements, args.target_dir, args.cpu, args.cpu_seconds)
    else:
        result = verify(args.output.resolve())
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
