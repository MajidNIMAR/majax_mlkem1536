"""Isolated sequential M04 ASan/std-rebuilt smoke; never controls M03 workers.

Linux/WSL only. Sources, input corpora and binaries are frozen in a new output
directory; a distinct new Cargo target directory is mandatory. Durations use
GNU time user+system CPU, not elapsed host time. This is not a long campaign.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("import_public", "import_private", "decapsulate", "api_sequence")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    # Evidence files are append-only at the file level, never overwritten.
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def utc():
    return datetime.now(timezone.utc).isoformat()


def require(value, message):
    if not value:
        raise ValueError(message)


def frozen_source(output):
    destination = output / "source"
    destination.mkdir()
    files = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                                      "research/run_m04_fuzz_smoke.py")]
    for folder in ("crates", "profiles", "fuzz"):
        for path in (ROOT / folder).rglob("*"):
            parts = path.relative_to(ROOT / folder).parts
            if path.is_file() and not any(x in ("target", "corpus", "coverage", "artifacts") for x in parts):
                files.append(path)
    hashes = {}
    for path in sorted(files):
        name = path.relative_to(ROOT)
        copied = destination / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, copied)
        hashes[name.as_posix()] = sha(copied)
    return hashes


def initial_corpora(output):
    result = {}
    for name in TARGETS:
        dest = output / "initial-corpus" / name
        dest.mkdir(parents=True)
        origins = [ROOT / "artifacts/generated/m03-seeds-final" / name,
                   ROOT / "artifacts/generated/m03-long-001" / name / "corpus"]
        require(origins[0].is_dir(), "existing public synthetic M03 seeds required")
        source_counts = {}
        for origin in origins:
            count = 0
            if origin.is_dir():
                # M03 stays active: this is a finite read snapshot, not a claim
                # that its entire changing corpus was copied at a single instant.
                for path in sorted(origin.iterdir()):
                    if path.is_file():
                        value = path.read_bytes()
                        target = dest / hashlib.sha256(value).hexdigest()
                        if not target.exists():
                            with target.open("xb") as stream:
                                stream.write(value)
                        count += 1
            source_counts[origin.relative_to(ROOT).as_posix()] = count
        result[name] = {"source_files_read": source_counts,
                        "distinct_inputs": len(list(dest.iterdir())),
                        "input_sha256": {p.name: sha(p) for p in sorted(dest.iterdir())}}
    return result


def statistics(log):
    content = log.read_text(encoding="utf-8", errors="replace")
    values = {}
    for key, pattern in (("executions", r"stat::number_of_executed_units:\s*(\d+)"),
                         ("peak_rss_mb_libfuzzer", r"stat::peak_rss_mb:\s*(\d+)")):
        matches = re.findall(pattern, content)
        if matches:
            values[key] = int(matches[-1])
    edges = list(re.finditer(r"#(\d+)\s+\w+\s+cov:\s*(\d+)\s+ft:\s*(\d+)", content))
    if edges:
        values.update(coverage_edges=int(edges[-1][2]), features=int(edges[-1][3]))
    return values


def run_target(index, output, env, cpu, budget):
    name = TARGETS[index]
    folder = output / name
    folder.mkdir()
    corpus = folder / "corpus"
    shutil.copytree(output / "initial-corpus" / name, corpus)
    failures = folder / "failures"
    failures.mkdir()
    segments, total = [], 0.0
    while total < budget:
        segment = len(segments)
        wall_limit = max(5, min(60, math.ceil(budget - total)))
        log = folder / f"segment-{segment:03d}.log"
        usage = folder / f"segment-{segment:03d}-usage.json"
        command = ["/usr/bin/time", "-f",
                   '{"user_seconds":%U,"system_seconds":%S,"peak_RSS_KiB":%M,"wall_seconds":%e,"exit_code":%x}',
                   "-o", str(usage), "taskset", "-c", str(cpu), str(output / "bin" / name), str(corpus),
                   f"-artifact_prefix={failures}/", f"-seed={5040101 + index * 100 + segment}",
                   f"-max_total_time={wall_limit}", "-max_len=16384", "-rss_limit_mb=2048",
                   "-timeout=60", "-print_final_stats=1", "-use_value_profile=1"]
        started = time.monotonic()
        with log.open("xb") as stream:
            process = subprocess.run(command, cwd=output / "source", env=env,
                                     stdout=stream, stderr=subprocess.STDOUT)
        try:
            measured = json.loads(usage.read_text().splitlines()[-1])
        except (OSError, ValueError, IndexError):
            measured = {}
        total += measured.get("user_seconds", 0) + measured.get("system_seconds", 0)
        item = dict(segment=segment, command=command, exit_code=process.returncode,
                    wall_observed_seconds=time.monotonic() - started, resource_usage=measured,
                    **statistics(log))
        segments.append(item)
        save(folder / f"segment-{segment:03d}-result.json", item)
        require(process.returncode == 0 and measured and not any(failures.iterdir()),
                f"{name} failed; logs and defects preserved")
        print(json.dumps({"target": name, "segment": segment, "CPU_seconds": total,
                          "goal_CPU_seconds": budget}), flush=True)
    result = {"status": "complete", "CPU_seconds": total, "budget_CPU_seconds": budget,
              "sequential_affinity_CPU": cpu, "segments": segments,
              "executions_including_repeated_seeds": sum(s.get("executions", 0) for s in segments),
              "final_distinct_corpus_inputs": len(list(corpus.iterdir())), "defects_observed": False}
    save(folder / "summary.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/generated/m04-fuzz-smoke"))
    parser.add_argument("--target-dir", type=Path, default=Path("target/m04-fuzz"))
    parser.add_argument("--cpu", type=int, default=10)
    parser.add_argument("--cpu-seconds", type=int, default=60)
    parser.add_argument("--resume-pre-fuzz", action="store_true",
                        help="resume preserved sources/build after a controlled pre-fuzz interruption")
    parser.add_argument("--measurements-done", type=Path,
                        default=Path("artifacts/generated/m04-pair/MEASUREMENTS_DONE"),
                        help="benchmark completion marker required before any fuzz target starts")
    args = parser.parse_args()
    require(sys.platform == "linux", "requires Linux/WSL")
    out, target = args.output.resolve(), args.target_dir.resolve()
    require(out.is_relative_to(ROOT / "artifacts/generated"), "local evidence directory required")
    require(target.is_relative_to(ROOT / "target") and target.name.startswith("m04"), "isolated M04 target required")
    require(10 <= args.cpu_seconds <= 120 and args.cpu in os.sched_getaffinity(0), "invalid short budget/CPU")
    if args.resume_pre_fuzz:
        require((out / "config.json").is_file() and target.exists() and not (out / "summary.json").exists()
                and not any((out / name).exists() for name in TARGETS), "only a preserved pre-fuzz build can resume")
        previous = json.loads((out / "config.json").read_text())
        source_hashes, corpus = previous["source_sha256"], previous["initial_corpus"]
        for name, expected in source_hashes.items():
            require(sha(out / "source" / name) == expected, f"preserved source changed: {name}")
        copied_controller = out / "controller-phase2.py"
        require(not copied_controller.exists(), "resume controller already preserved")
        shutil.copyfile(Path(__file__).resolve(), copied_controller)
        save(out / "control-phase2.json", {"started_utc": utc(), "controller_sha256": sha(copied_controller),
             "previous_config_sha256": sha(out / "config.json"), "reason": "explicit benchmark completion barrier",
             "measurements_done": str(args.measurements_done.resolve()),
             "build": "repeat Cargo command on same frozen sources/isolated target; existing evidence retained"})
    else:
        require(not out.exists() and not target.exists(), "new evidence and target directories required")
        out.mkdir(parents=True)
        source_hashes = frozen_source(out)
        corpus = initial_corpora(out)
    env = dict(os.environ, CARGO_HOME=str(ROOT / ".tools/linux-cargo"),
               RUSTUP_HOME=str(ROOT / ".tools/linux-rustup"), RUSTC_BOOTSTRAP="1",
               RUSTUP_TOOLCHAIN="1.91.1-x86_64-unknown-linux-gnu", CARGO_BUILD_JOBS="2",
               CARGO_TARGET_DIR=str(target),
               ASAN_OPTIONS="detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1")
    env["PATH"] = str(ROOT / ".tools/linux-cargo/bin") + ":/usr/local/bin:/usr/bin:/bin"
    cargo = ROOT / ".tools/linux-cargo/bin/cargo"
    rustc = ROOT / ".tools/linux-cargo/bin/rustc"
    versions = {"rustc": subprocess.check_output([str(rustc), "-Vv"], env=env, text=True),
                "cargo_fuzz": subprocess.check_output([str(cargo), "fuzz", "--version"], env=env, text=True)}
    command = ["taskset", "-c", str(args.cpu), str(cargo), "fuzz", "build", "--fuzz-dir",
               str(out / "source/fuzz"), "--target-dir", str(target), "--build-std"]
    config = {"started_utc": utc(), "source_sha256": source_hashes, "initial_corpus": corpus,
              "versions": versions, "build_command": command, "target_dir": str(target),
              "ASAN_OPTIONS": env["ASAN_OPTIONS"], "CPU_seconds_per_target": args.cpu_seconds,
              "sequential_CPU": args.cpu, "standard_library_rebuild_requested": True,
              "research_vectors_feature_enabled": False, "M03_controlled_or_stopped": False}
    if not args.resume_pre_fuzz:
        config["measurements_done"] = str(args.measurements_done.resolve())
        save(out / "config.json", config)
    lock = out / "source/fuzz/Cargo.lock"
    lock_hash = sha(lock)
    try:
        print("Building isolated ASan targets with std rebuilt", flush=True)
        log_name = "build-phase2.log" if args.resume_pre_fuzz else "build.log"
        with (out / log_name).open("xb") as stream:
            subprocess.run(command, cwd=out / "source", env=env, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)
        require(sha(lock) == lock_hash, "frozen fuzz lock changed during build")
        bin_dir = out / "bin"
        bin_dir.mkdir()
        binary_hashes = {}
        for name in TARGETS:
            dest = bin_dir / name
            shutil.copyfile(target / "x86_64-unknown-linux-gnu/release" / name, dest)
            dest.chmod(0o700)
            binary_hashes[name] = sha(dest)
        std = sorted((target / "x86_64-unknown-linux-gnu/release/deps").glob("libstd-*.rlib"))
        require(std, "rebuilt target std rlib not found")
        save(out / "built-binaries.json", {"binary_sha256": binary_hashes,
             "rebuilt_std_rlib_sha256": {p.name: sha(p) for p in std}})
        marker = args.measurements_done.resolve()
        print(f"Waiting for benchmark completion marker: {marker}", flush=True)
        while not marker.is_file():
            time.sleep(1)
        save(out / "benchmark-barrier.json", {"passed_utc": utc(), "marker": str(marker),
             "marker_sha256": sha(marker), "no_fuzz_started_before_marker": True})
        results = {}
        for index, name in enumerate(TARGETS):
            results[name] = run_target(index, out, env, args.cpu, args.cpu_seconds)
        summary = {"finished_utc": utc(), "results": results,
                   "total_CPU_seconds": sum(r["CPU_seconds"] for r in results.values()),
                   "source_sha256": source_hashes, "binary_sha256": binary_hashes,
                   "standard_library_rebuilt": True, "all_four_budgets_reached": True,
                   "controlled_pre_fuzz_resume": args.resume_pre_fuzz,
                   "long_campaign_completed": False, "source_line_coverage_measured": False,
                   "independent_oracle_replayed_by_this_runner": False, "M03_untouched": True}
        save(out / "summary.json", summary)
        print(json.dumps({"status": "complete", "total_CPU_seconds": summary["total_CPU_seconds"]}), flush=True)
    except BaseException as error:
        failure_name = "failure-phase2.json" if args.resume_pre_fuzz else "failure.json"
        save(out / failure_name, {"at_utc": utc(), "error": str(error), "evidence_preserved": True})
        raise


if __name__ == "__main__":
    main()
