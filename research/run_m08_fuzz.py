"""Long finite M08 ASan/std-rebuilt campaign, gated on accepted measurements.

The measured candidate is copied unchanged, with the current four fuzz
harnesses attached by hash. Existing M04/M06 controllers are reused without
editing them. Every campaign, compiler target, log and receipt is new.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
import time

sys.dont_write_bytecode = True

from run_m04_fuzz_smoke import TARGETS, statistics as fuzz_statistics
from run_m06_fuzz import inspect_post_init
from run_m07_fuzz import require_post_init, verify_segments

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
CONTROLLERS = ("run_m08_fuzz.py", "postprocess_m08_fuzz.py", "replay_m08_fuzz_corpus.py",
               "run_m07_fuzz.py", "run_m04_fuzz_smoke.py", "run_m06_fuzz.py")
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
    require(".." not in path.parts and path.parent == parent and path.name.startswith("m08"),
            f"new direct M08 child required below {parent}")
    current = ROOT
    for part in path.relative_to(ROOT).parts[:-1]:
        current /= part
        ordinary(current, directory=True)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        ordinary(path, directory=True)  # Also rejects dangling links/junctions.
    return path


def check_plan(plan):
    require(plan.get("schema") == "m08-fuzz-plan-v1" and plan.get("profile") == PROFILE,
            "wrong declared M08 fuzz plan")
    require(type(plan.get("CPU_seconds_per_harness")) is int and plan["CPU_seconds_per_harness"] == 1800,
            "M08 requires exactly 1800 declared CPU seconds per harness")
    cpus = plan.get("affinity_CPU_by_harness")
    require(type(cpus) is dict and set(cpus) == set(TARGETS)
            and all(type(cpu) is int and cpu >= 0 for cpu in cpus.values())
            and len(set(cpus.values())) == len(TARGETS), "four distinct declared CPU affinities required")
    require(plan.get("parallel_workers") == 4 and type(plan["parallel_workers"]) is int
            and type(plan.get("historical_fuzz_CPU_seconds_credited")) is int
            and plan["historical_fuzz_CPU_seconds_credited"] == 0,
            "four concurrent workers and no historical CPU credit required")
    require(type(plan.get("max_segment_wall_seconds")) is int and plan["max_segment_wall_seconds"] == 600,
            "declare the 600-second segment wall cap")
    return cpus


def bind_inputs(measurements, plan_path):
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
    ordinary(plan_path)
    plan = read(plan_path)
    check_plan(plan)
    require(accepted.get("fuzz_plan_sha256") == sha(plan_path), "acceptance marker is not bound to the declared fuzz plan")
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
            "plan_path": plan_path, "plan": plan,
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
    result["LC_ALL"], result["LANG"] = "C", "C"
    return result


def run_target(index, output, env, cpu, budget, wall_cap):
    """Run one independently accounted native worker; never infer CPU from wall time."""
    name = TARGETS[index]
    folder = output / name
    folder.mkdir()
    corpus, failures = folder / "corpus", folder / "failures"
    shutil.copytree(output / "initial-corpus" / name, corpus)
    failures.mkdir()
    segments, total = [], 0.0
    while total < budget:
        segment = len(segments)
        wall_limit = max(5, min(wall_cap, math.ceil(budget - total)))
        log = folder / f"segment-{segment:03d}.log"
        usage = folder / f"segment-{segment:03d}-usage.json"
        command = ["/usr/bin/time", "-f",
                   '{"user_seconds":%U,"system_seconds":%S,"peak_RSS_KiB":%M,"wall_seconds":%e,"exit_code":%x}',
                   "-o", str(usage), "taskset", "-c", str(cpu), str(output / "bin" / name), str(corpus),
                   f"-artifact_prefix={failures}/", f"-seed={5080101 + index * 100 + segment}",
                   f"-max_total_time={wall_limit}", "-max_len=16384", "-rss_limit_mb=2048",
                   "-timeout=60", "-print_final_stats=1", "-use_value_profile=1"]
        started = time.monotonic()
        started_utc = utc()
        with log.open("xb") as stream:
            process = subprocess.run(command, cwd=output / "source", env=env, stdout=stream, stderr=subprocess.STDOUT)
        try:
            measured = json.loads(usage.read_text().splitlines()[-1])
        except (OSError, ValueError, IndexError):
            measured = {}
        item = dict(segment=segment, command=command, exit_code=process.returncode,
                    started_utc=started_utc, finished_utc=utc(),
                    wall_observed_seconds=time.monotonic() - started, resource_usage=measured,
                    **fuzz_statistics(log))
        segments.append(item)
        save(folder / f"segment-{segment:03d}-result.json", item)
        require(process.returncode == 0 and measured and not any(failures.iterdir()),
                f"{name} failed; raw logs and defects preserved")
        require(all(type(measured.get(field)) in (int, float) and math.isfinite(measured[field])
                    and measured[field] >= 0 for field in ("user_seconds", "system_seconds", "wall_seconds")),
                "invalid measured CPU/wall accounting")
        require(measured["user_seconds"] + measured["system_seconds"] > 0, "zero CPU progress cannot reach a declared budget")
        total += measured["user_seconds"] + measured["system_seconds"]
        print(json.dumps({"target": name, "segment": segment, "CPU_seconds": total,
                          "goal_CPU_seconds": budget, "affinity_CPU": cpu}), flush=True)
    result = {"status": "complete", "CPU_seconds": total, "budget_CPU_seconds": budget,
              "sequential_affinity_CPU": cpu, "segments": segments,
              "executions_including_repeated_seeds": sum(s.get("executions", 0) for s in segments),
              "final_corpus_files": len(list(corpus.iterdir())), "defects_observed": False}
    save(folder / "summary.json", result)
    return result


def harvest_inventory(out):
    result = {}
    for name in TARGETS:
        raw = inventory(out / name / "corpus")
        require(all("/" not in member for member in raw), "flat raw corpus required")
        by_content = {}
        for member, checksum in raw.items():
            by_content.setdefault(checksum, []).append(member)
        result[name] = {"raw_files_sha256": raw, "raw_file_count": len(raw),
                        "unique_content_count": len(by_content), "content_sha256_to_raw_members": by_content}
    return result


def harvest(out):
    """Preserve raw files while freezing one SHA256-named file per byte string."""
    description = harvest_inventory(out)
    root = out / "harvested-corpus"
    root.mkdir()
    for name in TARGETS:
        destination = root / name
        destination.mkdir()
        for checksum, members in description[name]["content_sha256_to_raw_members"].items():
            shutil.copyfile(out / name / "corpus" / members[0], destination / checksum)
            require(sha(destination / checksum) == checksum, "raw corpus changed while harvesting")
    require(harvest_inventory(out) == description, "raw corpus changed during deduplication")
    save(out / "harvest.json", {"fuzz_summary_sha256": sha(out / "fuzz-summary.json"), "targets": description,
         "raw_inputs_preserved": True, "deduplication_basis": "identical complete input bytes/SHA256, independently per harness"})


def verify_harvest(out):
    saved = read(out / "harvest.json")
    description = harvest_inventory(out)
    require(saved["targets"] == description and saved["fuzz_summary_sha256"] == sha(out / "fuzz-summary.json")
            and saved["raw_inputs_preserved"] is True, "raw/harvested corpus provenance differs")
    for name in TARGETS:
        hashes = description[name]["content_sha256_to_raw_members"]
        require(inventory(out / "harvested-corpus" / name) == {checksum: checksum for checksum in sorted(hashes)},
                "deduplicated harvested corpus changed")
    return {name: description[name]["unique_content_count"] for name in TARGETS}


def original_campaign_root(config):
    command = config["build_command"]
    require(command.count("--fuzz-dir") == 1, "one source directory required in the build receipt")
    index = command.index("--fuzz-dir")
    require(index + 1 < len(command), "build source directory absent")
    source = PurePosixPath(command[index + 1])
    require(source.is_absolute() and source.parts[-2:] == ("source", "fuzz")
            and ".." not in source.parts and "\\" not in str(source), "invalid original campaign source path")
    return source.parents[1]


def check_worker_command(record, config, name, segment, cpu_before):
    origin = original_campaign_root(config)
    folder = origin / name
    cpu = config["affinity_CPU_by_harness"][name]
    wall = max(5, min(config["max_segment_wall_seconds"], math.ceil(config["CPU_seconds_per_harness"] - cpu_before)))
    expected = ["/usr/bin/time", "-f",
                '{"user_seconds":%U,"system_seconds":%S,"peak_RSS_KiB":%M,"wall_seconds":%e,"exit_code":%x}',
                "-o", str(folder / f"segment-{segment:03d}-usage.json"), "taskset", "-c", str(cpu),
                str(origin / "bin" / name), str(folder / "corpus"),
                f"-artifact_prefix={folder / 'failures'}/", f"-seed={5080101 + TARGETS.index(name) * 100 + segment}",
                f"-max_total_time={wall}", "-max_len=16384", "-rss_limit_mb=2048", "-timeout=60",
                "-print_final_stats=1", "-use_value_profile=1"]
    require(record["command"] == expected, "worker executable/corpus/usage/affinity command differs from bound campaign")


def execute(out, measurements, target, plan_path):
    require(sys.platform == "linux", "Linux/WSL required")
    out = owned(out, ROOT / "artifacts/generated")
    target = owned(target, ROOT / "target")
    require(not out.exists() and not target.exists(), "new campaign and compiler target directories required")
    bound = bind_inputs(measurements, plan_path)  # Precedes mutation/compiler invocation.
    plan, cpus = bound["plan"], check_plan(bound["plan"])
    require(set(cpus.values()) <= os.sched_getaffinity(0), "declared CPU unavailable")
    budget = plan["CPU_seconds_per_harness"]
    out.mkdir()
    try:
        shutil.copytree(bound["source"], out / "source")
        for name, checksum in bound["fuzz_sha256"].items():
            destination = out / "source" / name
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            require(sha(destination) == checksum, "fuzz source attachment changed")
        replay_harness = "crates/kem1536-bench/src/bin/m06-replay.rs"
        require((out / "source" / replay_harness).is_file()
                and sha(out / "source" / replay_harness) == sha(ROOT / replay_harness),
                "measured source must include the unchanged replay consumer")
        oracle_source = ROOT / "results/engine/r1-001/sources/research/kem_r1_reference.py"
        oracle_path = "oracle/kem_r1_reference.py"
        expected_oracle = read(ROOT / "results/engine/r1-001/provenance.json")["input_sha256"][oracle_source.relative_to(ROOT).as_posix()]
        require(sha(oracle_source) == expected_oracle, "historical independent oracle changed")
        (out / "source/oracle").mkdir()
        shutil.copyfile(oracle_source, out / "source" / oracle_path)
        require(sha(out / "source" / oracle_path) == expected_oracle, "oracle copy changed")
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
        shutil.copyfile(bound["plan_path"], out / "fuzz-plan.json")
        require(sha(out / "accepted-marker.json") == bound["acceptance_marker_sha256"]
                and sha(out / "candidate-source.json") == bound["candidate_source_manifest_sha256"],
                "acceptance gate changed while copying")
        copied_marker = read(out / "accepted-marker.json")
        require(copied_marker.get("profile") == PROFILE and copied_marker.get("accepted") is True
                and copied_marker.get("candidate_source_manifest_sha256") == bound["candidate_source_manifest_sha256"],
                "copied acceptance gate is not valid")
        require(copied_marker["fuzz_plan_sha256"] == sha(out / "fuzz-plan.json"), "copied fuzz plan changed")
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
        sysroot = Path(subprocess.check_output([rustc, "--print", "sysroot"], env=env, text=True).strip())
        versions["compiler_binary_sha256"] = sha(sysroot / "bin/rustc")
        versions["cargo_fuzz_binary_sha256"] = sha(ROOT / ".tools/linux-cargo/bin/cargo-fuzz")
        require("release: 1.91.1" in versions["rustc"], "unexpected M08 fuzz compiler")
        require(versions["cargo_fuzz"].strip() == "cargo-fuzz 0.13.1", "unexpected M08 fuzz driver")
        build_cpus = ",".join(str(cpu) for cpu in sorted(cpus.values()))
        command = ["taskset", "-c", build_cpus, cargo, "fuzz", "build", "--fuzz-dir", str(out / "source/fuzz"),
                   "--target-dir", str(target), "--build-std"]
        save(out / "config.json", {"schema": 1, "profile": PROFILE, "started_utc": utc(),
             "candidate_source_manifest_sha256": sha(out / "candidate-source.json"),
             "acceptance_marker_sha256": sha(out / "accepted-marker.json"),
             "measured_source_sha256": bound["source_sha256"], "attached_fuzz_sha256": bound["fuzz_sha256"],
             "source_sha256": source_hashes, "controller_sha256": controller_hashes,
             "initial_corpus": seeds, "versions": versions, "build_command": command,
             "CPU_seconds_per_harness": budget, "affinity_CPU_by_harness": cpus,
             "parallel_workers": 4, "max_segment_wall_seconds": plan["max_segment_wall_seconds"],
             "declared_plan_sha256": sha(out / "fuzz-plan.json"), "oracle_sha256": expected_oracle,
             "parallel_execution_is_not_host_wide_isolation": True,
             "build_CPU_set": sorted(cpus.values()), "build_Cargo_jobs": 2,
             "ASAN_OPTIONS": env["ASAN_OPTIONS"],
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
        results, failures = {}, {}
        print(json.dumps({"phase": "four_native_workers_starting", "CPU_seconds_per_harness": budget,
                          "affinity_CPU_by_harness": cpus, "historical_CPU_credited": 0}), flush=True)
        with ThreadPoolExecutor(max_workers=4) as workers:
            futures = {workers.submit(run_target, index, out, env, cpus[name], budget,
                                      plan["max_segment_wall_seconds"]): name for index, name in enumerate(TARGETS)}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as error:
                    failures[name] = {"type": type(error).__name__, "error": str(error)}
                    print(json.dumps({"target": name, "failure": failures[name], "raw_evidence_preserved": True}), flush=True)
        results = {name: results[name] for name in TARGETS if name in results}
        save(out / "fuzz-summary.json", {"finished_utc": utc(), "results": results,
             "total_CPU_seconds": sum(item["CPU_seconds"] for item in results.values()),
             "all_four_budgets_reached": set(results) == set(TARGETS) and all(item["CPU_seconds"] >= budget for item in results.values()),
             "worker_failures": failures, "parallel_workers": 4,
             "standard_library_rebuilt": True, "source_line_coverage_measured": False,
             "independent_oracle_replayed": False, "historical_fuzz_time_transferred": False})
        require(not failures and set(results) == set(TARGETS), "one or more native workers failed; evidence retained")
        harvest(out)
        require(not (out / "supplemental-summary.json").exists(), "supplements need a separate declared M08 campaign")
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


def verify(out):
    config, built, summary = (read(out / name) for name in ("config.json", "built.json", "fuzz-summary.json"))
    require(config["profile"] == PROFILE and config["historical_fuzz_CPU_seconds_credited"] == 0,
            "wrong M08 scope")
    plan = read(out / "fuzz-plan.json")
    cpus = check_plan(plan)
    require(config["CPU_seconds_per_harness"] == plan["CPU_seconds_per_harness"]
            and config["affinity_CPU_by_harness"] == cpus and config["parallel_workers"] == 4
            and config["max_segment_wall_seconds"] == plan["max_segment_wall_seconds"]
            and config["build_CPU_set"] == sorted(cpus.values()) and config["build_Cargo_jobs"] == 2
            and sha(out / "fuzz-plan.json") == config["declared_plan_sha256"], "declared execution plan differs")
    require(config["build_command"][:3] == ["taskset", "-c", ",".join(str(cpu) for cpu in sorted(cpus.values()))]
            and config["build_command"][-1] == "--build-std", "recorded std-rebuilt build command differs")
    require(config["std_rebuild_requested"] is True and config["offline_build"] is True
            and config["research_vectors_feature_enabled"] is False and config["source_line_coverage_measured"] is False,
            "compiler and measurement scope flags differ")
    require("release: 1.91.1" in config["versions"]["rustc"]
            and config["versions"]["cargo_fuzz"].strip() == "cargo-fuzz 0.13.1"
            and config["ASAN_OPTIONS"] == "detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1",
            "recorded instrumented toolchain/options differ")
    require(sha(out / "accepted-marker.json") == config["acceptance_marker_sha256"]
            and sha(out / "candidate-source.json") == config["candidate_source_manifest_sha256"], "candidate acceptance binding differs")
    marker, manifest = read(out / "accepted-marker.json"), read(out / "candidate-source.json")
    require(marker["profile"] == manifest["profile"] == PROFILE and marker["accepted"] is True
            and marker["candidate_source_manifest_sha256"] == config["candidate_source_manifest_sha256"]
            and marker["fuzz_plan_sha256"] == config["declared_plan_sha256"], "unaccepted candidate or plan")
    require(manifest["source_sha256"] == config["measured_source_sha256"], "measured source map differs")
    require(inventory(out / "source") == config["source_sha256"] and inventory(out / "controls") == config["controller_sha256"],
            "frozen source or controllers changed")
    require(all(config["source_sha256"][name] == checksum for name, checksum in config["measured_source_sha256"].items())
            and all(config["source_sha256"][name] == checksum for name, checksum in config["attached_fuzz_sha256"].items()),
            "compiled candidate or fuzz attachment differs")
    require(config["source_sha256"]["oracle/kem_r1_reference.py"] == config["oracle_sha256"], "independent oracle binding differs")
    require(sha(out / "source/fuzz/Cargo.lock") == built["frozen_fuzz_lock_sha256"]
            and bool(built["rebuilt_std_rlib_sha256"]), "frozen lock or rebuilt std receipt absent")
    require(set(built["binary_sha256"]) == set(TARGETS) and set(summary["results"]) == set(TARGETS), "four-target panel required")
    require(summary["standard_library_rebuilt"] is True and summary["all_four_budgets_reached"] is True
            and summary["historical_fuzz_time_transferred"] is False
            and summary["independent_oracle_replayed"] is False
            and summary["source_line_coverage_measured"] is False and summary["worker_failures"] == {}
            and summary["parallel_workers"] == 4, "campaign scope differs")
    total = 0.0
    for name in TARGETS:
        require(sha(out / "bin" / name) == built["binary_sha256"][name], "fuzz executable changed")
        require(inventory(out / "initial-corpus" / name) == config["initial_corpus"][name]["sha256"], "seed snapshot changed")
        item = summary["results"][name]
        require(not item["defects_observed"] and not any((out / name / "failures").iterdir()), "defect or failing input recorded")
        cpu = verify_segments(out / name, item, config["CPU_seconds_per_harness"], cpus[name])
        cpu_before = 0.0
        for index, segment in enumerate(item["segments"]):
            check_worker_command(segment, config, name, index, cpu_before)
            cpu_before += segment["resource_usage"]["user_seconds"] + segment["resource_usage"]["system_seconds"]
        total += cpu
        require(len(list((out / name / "corpus").iterdir())) == item["final_corpus_files"], "raw corpus inventory differs")
    require(abs(total - summary["total_CPU_seconds"]) < 1e-9, "total CPU accounting differs")
    require(not (out / "supplemental-summary.json").exists(), "supplements need a separate declared M08 campaign")
    post = inspect_post_init(out)
    require(post == read(out / "post-init.json"), "post-INITED evidence differs")
    require_post_init(post)
    harvested = verify_harvest(out)
    return {"profile": PROFILE, "total_CPU_seconds": total, "candidate_and_harness_hashes_verified": True,
            "all_four_have_post_INITED_execution": True, "historical_CPU_seconds_credited": 0,
            "source_line_coverage_measured": False, "long_campaign_completed": True,
            "independent_oracle_replayed": False, "harvested_unique_inputs_by_target": harvested,
            "secrets_printed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify"))
    parser.add_argument("--measurements", type=Path, default=ROOT / "artifacts/generated/m08-001")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m08-fuzz-001")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/m08-fuzz-001")
    parser.add_argument("--plan", type=Path, default=ROOT / "research/m08-fuzz-plan.json")
    args = parser.parse_args()
    if args.action == "run":
        out = owned(args.output, ROOT / "artifacts/generated")
        result = execute(out, args.measurements, args.target_dir, args.plan)
    else:
        result = verify(args.output.resolve())
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
