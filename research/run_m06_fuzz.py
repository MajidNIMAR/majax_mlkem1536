"""Finite M06 ASan/std-rebuilt campaign on the frozen measured candidate.

Four harnesses run sequentially after measurement and root timing barriers.
Coverage and independent Python replay are separate postprocessing steps.
The controller never stops or credits a historical campaign.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

from run_m04_fuzz_smoke import run_target, TARGETS

ROOT = Path(__file__).resolve().parents[1]


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def require(value, message):
    if not value:
        raise ValueError(message)


def inventory(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def env_for(target):
    env = dict(os.environ, CARGO_HOME=str(ROOT / ".tools/linux-cargo"), RUSTUP_HOME=str(ROOT / ".tools/linux-rustup"),
               RUSTUP_TOOLCHAIN="1.91.1-x86_64-unknown-linux-gnu", RUSTUP_AUTO_INSTALL="0", RUSTC_BOOTSTRAP="1",
               CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(target),
               ASAN_OPTIONS="detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1")
    env.pop("RUSTFLAGS", None)
    env["PATH"] = str(ROOT / ".tools/linux-cargo/bin") + ":/usr/local/bin:/usr/bin:/bin"
    return env


def seed_corpora(out):
    receipts = {}
    for name in TARGETS:
        destination = out / "initial-corpus" / name
        destination.mkdir(parents=True)
        origins = [ROOT / "artifacts/generated/m03-seeds-final" / name,
                   ROOT / "artifacts/generated/m03-long-001" / name / "corpus",
                   ROOT / "artifacts/generated/m04-fuzz-smoke" / name / "corpus"]
        require(origins[0].is_dir(), "public synthetic seeds required")
        origin_counts = {}
        for origin in origins:
            count = 0
            if origin.is_dir():
                for path in sorted(origin.iterdir()):
                    if path.is_file():
                        content = path.read_bytes()
                        copied = destination / hashlib.sha256(content).hexdigest()
                        if not copied.exists():
                            copied.write_bytes(content)
                        count += 1
            origin_counts[origin.relative_to(ROOT).as_posix()] = count
        receipts[name] = {"source_files_read": origin_counts, "distinct_inputs": len(list(destination.iterdir())),
                          "sha256": inventory(destination)}
    return receipts


def inspect_post_init(out):
    """A CPU budget alone is insufficient: retain actual post-INITED work."""
    summary = read(out / "fuzz-summary.json")
    supplement = read(out / "supplemental-summary.json") if (out / "supplemental-summary.json").exists() else None
    targets = {}
    for name in TARGETS:
        segments = []
        records = [(record, f"{name}/segment-{record['segment']:03d}.log", "main")
                   for record in summary["results"][name]["segments"]]
        if supplement and name in supplement["results"]:
            records += [(record, f"supplement-001/{name}/segment-{record['segment']:03d}.log", "supplement")
                        for record in supplement["results"][name]["segments"]]
        for record, relative_log, origin in records:
            log = out / relative_log
            text = log.read_text(errors="replace")
            initialized = list(re.finditer(r"#(\d+)\s+INITED\b", text))
            totals = re.findall(r"stat::number_of_executed_units:\s*(\d+)", text)
            initial = int(initialized[-1][1]) if len(initialized) == 1 else None
            final = int(totals[-1]) if totals else None
            after = text[initialized[-1].end():] if initialized else ""
            events = re.findall(r"#\d+\s+(NEW|REDUCE|pulse)\b", after)
            segments.append({"segment": record["segment"], "log_relative_path": relative_log, "origin": origin, "log_sha256": sha(log),
                "INITED_counter": initial, "final_executed_units_counter": final,
                "executions_after_INITED": max(0, final - initial) if final is not None and initial is not None else 0,
                "new_or_reduced_feature_events_after_INITED": events.count("NEW") + events.count("REDUCE"),
                "INITED_line_unique": len(initialized) == 1})
        count = sum(s["executions_after_INITED"] for s in segments)
        targets[name] = {"segments": segments, "executions_after_INITED": count,
                         "post_initialization_fuzzing_observed": count > 0,
                         "unique_mutated_inputs_not_counted": True}
    return {"targets": targets, "all_four_have_post_INITED_execution":
            all(t["post_initialization_fuzzing_observed"] for t in targets.values())}


def supplement_missing(out, cpu, budget):
    require(120 <= budget <= 600, "finite supplemental CPU budget required")
    before = inspect_post_init(out)
    missing = [name for name in TARGETS if not before["targets"][name]["post_initialization_fuzzing_observed"]]
    require(missing, "all targets already mutated after INITED")
    destination = out / "supplement-001"
    destination.mkdir()
    (destination / "source").mkdir()
    (destination / "bin").mkdir()
    seeds, binaries = {}, {}
    for name in missing:
        binary = destination / "bin" / name
        shutil.copyfile(out / "bin" / name, binary)
        binary.chmod(0o700)
        binaries[name] = sha(binary)
        require(binaries[name] == read(out / "built.json")["binary_sha256"][name], "supplement binary changed")
        origin = ROOT / "artifacts/generated/m03-seeds-final" / name
        seed_destination = destination / "initial-corpus" / name
        shutil.copytree(origin, seed_destination)
        require(0 < len(list(seed_destination.iterdir())) <= 128, "compact public base corpus required")
        seeds[name] = {"origin": str(origin.relative_to(ROOT)), "sha256": inventory(seed_destination)}
    shutil.copyfile(Path(__file__), destination / "controller.py")
    save(destination / "config.json", {"started_utc": utc(), "parent_config_sha256": sha(out / "config.json"),
         "binary_sha256": binaries, "same_M06_source_sha256": read(out / "config.json")["source_sha256"],
         "initial_corpus": seeds, "CPU_seconds_per_selected_harness": budget, "sequential_CPU": cpu,
         "reason": "main CPU budget reached without post-INITED execution; retained as observed"})
    env = env_for(ROOT / "target/m06-supplement-unused-build-path")
    results = {name: run_target(TARGETS.index(name), destination, env, cpu, budget) for name in missing}
    summary = {"finished_utc": utc(), "results": results, "total_CPU_seconds": sum(r["CPU_seconds"] for r in results.values()),
               "main_evidence_replaced": False}
    save(destination / "summary.json", summary)
    save(out / "supplemental-summary.json", summary)
    return inspect_post_init(out)


def prepare_and_run(out, measurements, target, cpu, budget):
    require(sys.platform == "linux" and cpu in os.sched_getaffinity(0), "valid Linux CPU required")
    require(120 <= budget <= 600, "declared finite budget of 120..600 CPU seconds per harness")
    require(not out.exists() and not target.exists(), "new campaign and target directories required")
    for marker in ("MEASUREMENTS_DONE", "ROOT_TIMING_DONE"):
        require((measurements / marker).is_file(), f"wait for {marker} before heavy fuzz build")
    measured = read(measurements / "build.json")["builds"]["candidate"]["source_sha256"]
    require(inventory(measurements / "candidate-source") == measured, "measured candidate changed")
    out.mkdir(parents=True)
    shutil.copytree(measurements / "candidate-source", out / "source")
    oracle = out / "source/oracle/kem_r1_reference.py"
    oracle.parent.mkdir()
    shutil.copyfile(ROOT / "results/engine/r1-001/sources/research/kem_r1_reference.py", oracle)
    for name in ("run_m06_fuzz.py", "replay_m06_fuzz_corpus.py", "run_m04_fuzz_smoke.py"):
        shutil.copyfile(ROOT / "research" / name, out / "source/research" / name)
    source_hashes = inventory(out / "source")
    corpus = seed_corpora(out)
    env = env_for(target)
    cargo = str(ROOT / ".tools/linux-cargo/bin/cargo")
    rustc = str(ROOT / ".tools/linux-cargo/bin/rustc")
    versions = {"rustc": subprocess.check_output([rustc, "-Vv"], env=env, text=True),
                "cargo_fuzz": subprocess.check_output([cargo, "fuzz", "--version"], env=env, text=True)}
    require("release: 1.91.1" in versions["rustc"], "unexpected fuzz compiler")
    command = ["taskset", "-c", str(cpu), cargo, "fuzz", "build", "--fuzz-dir", str(out / "source/fuzz"),
               "--target-dir", str(target), "--build-std"]
    save(out / "config.json", {"started_utc": utc(), "source_sha256": source_hashes, "initial_corpus": corpus,
        "candidate_measurement_build_sha256": sha(measurements / "build.json"), "versions": versions,
        "build_command": command, "CPU_seconds_per_harness": budget, "sequential_CPU": cpu,
        "std_rebuild_requested": True, "ASAN_OPTIONS": env["ASAN_OPTIONS"],
        "measurement_barrier_sha256": {name: sha(measurements / name) for name in ("MEASUREMENTS_DONE", "ROOT_TIMING_DONE")},
        "historical_fuzz_CPU_seconds_credited": 0, "research_vectors_feature_enabled": False})
    lock = out / "source/fuzz/Cargo.lock"
    lock_sha = sha(lock)
    with (out / "build.log").open("xb") as log:
        subprocess.run(command, cwd=out / "source", env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    require(sha(lock) == lock_sha, "fuzz build changed its frozen lock")
    (out / "bin").mkdir()
    binaries = {}
    for name in TARGETS:
        copied = out / "bin" / name
        shutil.copyfile(target / "x86_64-unknown-linux-gnu/release" / name, copied)
        copied.chmod(0o700)
        binaries[name] = sha(copied)
    rebuilt_std = sorted((target / "x86_64-unknown-linux-gnu/release/deps").glob("libstd-*.rlib"))
    require(rebuilt_std, "rebuilt std rlib is absent")
    save(out / "built.json", {"binary_sha256": binaries,
        "rebuilt_std_rlib_sha256": {p.name: sha(p) for p in rebuilt_std}, "frozen_lock_sha256": lock_sha})
    results = {name: run_target(i, out, env, cpu, budget) for i, name in enumerate(TARGETS)}
    save(out / "fuzz-summary.json", {"finished_utc": utc(), "results": results,
        "total_CPU_seconds": sum(r["CPU_seconds"] for r in results.values()),
        "all_four_budgets_reached": all(r["CPU_seconds"] >= budget for r in results.values()),
        "standard_library_rebuilt": True, "source_line_coverage_measured": False,
        "independent_oracle_replayed": False, "historical_fuzz_time_transferred": False})
    return {"all_four_budgets_reached": True, "postprocessing_still_required": True}


def prebuild_coverage(out, target, cpu):
    """Compile only, reproducing cargo-fuzz 0.13.1's checked local recipe."""
    require(sys.platform == "linux" and cpu in os.sched_getaffinity(0) and cpu != 10, "distinct valid prebuild CPU required")
    require(not target.exists(), "new separate coverage target required")
    env = env_for(target)
    recipe = ROOT / ".tools/linux-cargo/registry/src/index.crates.io-1949cf8c6b5b557f/cargo-fuzz-0.13.1/src/project.rs"
    flags = (" -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4"
             " -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table"
             " -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing"
             " -Cllvm-args=-simplifycfg-branch-fold-threshold=0 -Cinstrument-coverage"
             " -Zsanitizer=address -Cllvm-args=-sanitizer-coverage-stack-depth"
             " -Cdebug-assertions -Ccodegen-units=1")
    require("rustc 1.91.1" in subprocess.check_output([str(ROOT / ".tools/linux-cargo/bin/rustc"), "-V"], env=env, text=True), "coverage recipe is pinned to Rust 1.91.1")
    env["RUSTFLAGS"] = flags
    env["ASAN_OPTIONS"] += ":detect_odr_violation=0"
    command = ["taskset", "-c", str(cpu), str(ROOT / ".tools/linux-cargo/bin/cargo"), "build",
        "--locked", "--offline", "--manifest-path", str(out / "source/fuzz/Cargo.toml"),
        "--target", "x86_64-unknown-linux-gnu", "--release", "--config", 'profile.release.debug="line-tables-only"',
        "--bins", "--target-dir", str(target)]
    shutil.copyfile(Path(__file__), out / "coverage-prebuild-controller.py")
    save(out / "coverage-prebuild-request.json", {"started_utc": utc(), "command": command, "rustflags": flags,
         "cargo_fuzz_recipe_project_rs_sha256": sha(recipe), "CPU": cpu,
         "source_corpus_replayed": False, "may_overlap_active_fuzzing_after_measurements": True,
         "std_rebuilt_for_this_coverage_build": False})
    with (out / "coverage-prebuild.log").open("xb") as log:
        subprocess.run(command, cwd=out / "source", env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    save(out / "coverage-prebuild-result.json", {"finished_utc": utc(), "binary_sha256": {
         name: sha(target / "x86_64-unknown-linux-gnu/release" / name) for name in TARGETS}, "source_corpus_replayed": False})
    return {"coverage_binaries_prebuilt": 4, "corpus_executed": False}


def build_replay(out, target, cpu):
    harness_name = "crates/kem1536-bench/src/bin/m06-replay.rs"
    binary = out / "bin/m06-replay"
    receipt = out / "replay-build.json"
    if receipt.exists():
        recorded = read(receipt)
        require(sha(binary) == recorded["binary_sha256"] and sha(out / "source" / harness_name) == recorded["replay_harness_sha256"]
                and sha(ROOT / harness_name) == recorded["replay_harness_sha256"], "prebuilt replay binary or harness changed")
        return binary
    shutil.copyfile(ROOT / harness_name, out / "source" / harness_name)
    env = env_for(target)
    env.pop("RUSTC_BOOTSTRAP", None)
    command = ["taskset", "-c", str(cpu), str(ROOT / ".tools/linux-cargo/bin/cargo"), "build", "--locked", "--offline",
               "--release", "-p", "kem1536-bench", "--bin", "m06-replay"]
    shutil.copyfile(Path(__file__), out / "replay-prebuild-controller.py")
    with (out / "replay-build.log").open("xb") as log:
        subprocess.run(command, cwd=out / "source", env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    shutil.copyfile(target / "release/m06-replay", binary)
    binary.chmod(0o700)
    save(receipt, {"binary_sha256": sha(binary), "build_command": command, "CPU": cpu,
                  "additional_replay_harness": harness_name, "replay_harness_sha256": sha(out / "source" / harness_name),
                  "production_source_sha256": read(out / "config.json")["source_sha256"], "corpus_replayed_during_build": False})
    return binary


def postprocess(out, target):
    require((out / "fuzz-summary.json").is_file(), "completed finite campaign required")
    post_init = inspect_post_init(out)
    require(post_init["all_four_have_post_INITED_execution"], "CPU budget spent without post-INITED fuzzing; retain and supplement separately")
    save(out / "post-init.json", post_init)
    shutil.copyfile(Path(__file__), out / "postprocess-controller.py")
    save(out / "postprocess-controller.json", {"sha256": sha(out / "postprocess-controller.py"),
         "scope": "actual postprocessing controller, independent of the preserved launch controller"})
    (out / "coverage-bin").mkdir()
    env = env_for(target)
    cargo = str(ROOT / ".tools/linux-cargo/bin/cargo")
    rustc = str(ROOT / ".tools/linux-cargo/bin/rustc")
    sysroot = Path(subprocess.check_output([rustc, "--print", "sysroot"], env=env, text=True).strip())
    llvm = sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"
    coverage = {}
    cpu = read(out / "config.json")["sequential_CPU"]
    for name in TARGETS:
        corpora = [out / name / "corpus"]
        if (out / "supplement-001" / name / "corpus").is_dir():
            corpora.append(out / "supplement-001" / name / "corpus")
        command = ["taskset", "-c", str(cpu), cargo, "fuzz", "coverage", name, *map(str, corpora),
                   "--fuzz-dir", str(out / "source/fuzz"), "--target-dir", str(target), "--",
                   "-timeout=60", "-rss_limit_mb=2048"]
        with (out / f"{name}-coverage.log").open("xb") as log:
            subprocess.run(command, cwd=out / "source", env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        profile = out / "source/fuzz/coverage" / name / "coverage.profdata"
        binary = target / "x86_64-unknown-linux-gnu/release" / name
        coverage_binary = out / "coverage-bin" / name
        shutil.copyfile(binary, coverage_binary)
        copied_profile = out / f"{name}-coverage.profdata"
        shutil.copyfile(profile, copied_profile)
        raw = subprocess.check_output([str(llvm), "export", "-summary-only", str(binary), "-instr-profile=" + str(profile)], env=env)
        exported = json.loads(raw)
        save(out / f"{name}-coverage.json", exported)
        coverage[name] = [file for item in exported["data"] for file in item["files"]
                          if "/crates/kem1536/src/" in file["filename"]]
        save(out / f"{name}-coverage-receipt.json", {"command": command, "binary_sha256": sha(binary),
            "profdata_sha256": sha(copied_profile), "corpora_included": [str(p.relative_to(out)) for p in corpora], "LLVM_coverage_is_source_level": True,
            "libFuzzer_edges_are_not_source_line_coverage": True})
    save(out / "coverage-summary.json", coverage)
    # Let LLVM form the union using all four objects and merged counters.
    # Adding per-target numerators/denominators would count overlap twice.
    union_receipt = {"per_target_counts_summed": False, "source_union_validated": False}
    try:
        profdata = llvm.parent / "llvm-profdata"
        union_profile = out / "union-coverage.profdata"
        merge = [str(profdata), "merge", "-sparse", *[str(out / f"{n}-coverage.profdata") for n in TARGETS],
                 "-o", str(union_profile)]
        with (out / "union-coverage.log").open("xb") as log:
            subprocess.run(merge, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        union_command = [str(llvm), "export", "-summary-only", str(out / "coverage-bin" / TARGETS[0]),
                         *["-object=" + str(out / "coverage-bin" / n) for n in TARGETS[1:]],
                         "-instr-profile=" + str(union_profile)]
        exported = json.loads(subprocess.check_output(union_command, env=env))
        save(out / "union-coverage.json", exported)
        core_files = [f for item in exported["data"] for f in item["files"] if "/crates/kem1536/src/" in f["filename"]]
        by_name = {f["filename"]: f for f in core_files}
        require(len(by_name) == len(core_files), "duplicate file in LLVM union export")
        for files in coverage.values():
            for file in files:
                union = by_name[file["filename"]]["summary"]
                for kind in ("lines", "functions", "regions"):
                    require(union[kind]["covered"] >= file["summary"][kind]["covered"]
                            and union[kind]["count"] >= file["summary"][kind]["count"], "LLVM union is not a superset")
        union_receipt.update(source_union_validated=True, merge_command=merge, export_command=union_command,
                             profdata_sha256=sha(union_profile), core_files=core_files)
    except Exception as error:
        union_receipt.update(error_type=type(error).__name__, error=str(error),
                             interpretation="four separate exports remain the measured coverage; no union claimed")
    save(out / "union-coverage-receipt.json", union_receipt)
    # This executable is built from the same immutable production source and
    # exposes only deterministic synthetic fixture requests to the oracle.
    replay_binary = build_replay(out, target.parent / (target.name + "-replay"), cpu)
    def windows(path):
        return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
    shutil.copyfile(ROOT / "research/replay_m06_fuzz_corpus.py", out / "replay-controller.py")
    command = [str(ROOT / ".tools/research-venv/Scripts/python.exe"),
               windows(out / "replay-controller.py"), "--campaign", windows(out),
               "--linux-binary", str(replay_binary)]
    with (out / "oracle-replay.log").open("xb") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    save(out / "postprocess.json", {"finished_utc": utc(), "source_coverage_exported": True,
        "independent_python_replay_passed": True, "replay_request_count": read(out / "oracle-replay.json")["distinct_deterministic_requests"],
        "full_security_or_constant_time_claim": False})
    return verify(out, finished=False)


def verify(out, finished=True):
    for name, expected in read(out / "config.json")["source_sha256"].items():
        require(sha(out / "source" / name) == expected, f"frozen M06 input changed: {name}")
    config, summary = read(out / "config.json"), read(out / "fuzz-summary.json")
    require(summary["all_four_budgets_reached"] and not summary["historical_fuzz_time_transferred"], "budget not reached")
    for name, result in summary["results"].items():
        require(result["CPU_seconds"] >= config["CPU_seconds_per_harness"] and not result["defects_observed"], "campaign failed")
        require(not any((out / name / "failures").iterdir()), "fuzz defect is present")
        total = sum(s["resource_usage"]["user_seconds"] + s["resource_usage"]["system_seconds"] for s in result["segments"])
        require(abs(total - result["CPU_seconds"]) < 1e-9, "CPU accounting differs")
    require(read(out / "oracle-replay.json")["all_Rust_Python_outputs_equal"], "oracle replay failed")
    supplemental_cpu = 0.0
    if (out / "supplemental-summary.json").exists():
        supplemental = read(out / "supplemental-summary.json")
        for name, item in supplemental["results"].items():
            require(item["CPU_seconds"] >= read(out / "supplement-001/config.json")["CPU_seconds_per_selected_harness"]
                    and not item["defects_observed"], "supplemental budget or fuzz result failed")
        supplemental_cpu = supplemental["total_CPU_seconds"]
    require(inspect_post_init(out) == read(out / "post-init.json")
            and read(out / "post-init.json")["all_four_have_post_INITED_execution"], "post-INITED evidence differs")
    require(set(read(out / "coverage-summary.json")) == set(TARGETS), "source coverage incomplete")
    if finished:
        for name, expected in read(out / "provenance.json")["output_sha256"].items():
            member = (out / name).resolve()
            require(member.is_relative_to(out.resolve()) and sha(member) == expected, f"M06 checksum: {name}")
    return {"main_CPU_seconds": summary["total_CPU_seconds"], "supplemental_CPU_seconds": supplemental_cpu,
            "total_CPU_seconds": summary["total_CPU_seconds"] + supplemental_cpu, "all_four_budgets_reached": True,
            "source_coverage_exported": True, "independent_python_replay_passed": True}


def freeze(out):
    result = verify(out, finished=False)
    archive = ROOT / "results/engine/m06-fuzz-001"
    require(not archive.exists(), "never replace M06 fuzz evidence")
    # Preserve notices alongside retained diagnostic executables. The normal
    # engine dependency lock is unchanged from the existing M04 license bundle.
    inherited = ROOT / "results/engine/m04-001/distribution"
    require(sha(ROOT / "Cargo.lock") == read(inherited / "source-manifest.json")["files"]["Cargo.lock"],
            "review dependency notices for a changed engine lock")
    licenses = out / "licenses"
    shutil.copytree(inherited / "linux/package/licenses", licenses)
    for package in ("libfuzzer-sys-0.4.13", "arbitrary-1.5.0"):
        candidates = list((ROOT / ".tools/linux-cargo/registry/src").glob("*/" + package))
        require(len(candidates) == 1, "unique cached diagnostic package required for notices")
        texts = list(candidates[0].glob("LICENSE*"))
        require(texts, "diagnostic package license texts absent")
        for path in texts:
            destination = licenses / "diagnostic-dependencies" / package / path.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
    save(out / "licenses.json", {"output_sha256": inventory(licenses),
        "inherited_bundle": "results/engine/m04-001/distribution/linux/package/licenses",
        "engine_Cargo_lock_matches_inherited_bundle": True,
        "additional_packages": ["libfuzzer-sys 0.4.13", "arbitrary 1.5.0"],
        "vendored_libFuzzer_SPDX": "Apache-2.0 WITH LLVM-exception",
        "libFuzzer_notice_basis": "libfuzzer-sys-0.4.13/libfuzzer/FuzzerDriver.cpp header; Apache and LLVM-exception texts retained in toolchain/texts"})
    shutil.copyfile(Path(__file__), out / "freeze-controller.py")
    archive.mkdir(parents=True)
    # Build trees and transient per-input coverage files stay local. Preserve
    # source, instrumented binaries, final inputs, profiles and exported receipts.
    selected = ["source", "bin", "coverage-bin", "initial-corpus", "licenses", *TARGETS]
    if (out / "supplement-001").exists():
        selected.append("supplement-001")
    with tarfile.open(archive / "campaign.tar.gz", "w:gz") as bundle:
        def exclude_transient(member):
            if "/fuzz/coverage" in member.name:
                return None
            if member.isfile() and member.name.startswith(("bin/", "coverage-bin/", "supplement-001/bin/")):
                member.mode = 0o700
            return member
        for name in selected:
            bundle.add(out / name, arcname=name, filter=exclude_transient)
        for path in sorted(out.iterdir()):
            if path.is_file():
                bundle.add(path, arcname=path.name)
    retained_meta = ["config.json", "fuzz-summary.json", "post-init.json", "coverage-summary.json", "oracle-replay.json", "postprocess.json", "union-coverage-receipt.json", "licenses.json"]
    if (out / "union-coverage.json").exists():
        retained_meta.append("union-coverage.json")
    for name in retained_meta:
        shutil.copyfile(out / name, archive / name)
    save(archive / "provenance.json", {"finished_utc": utc(), "output_sha256": inventory(archive),
        "archive_members_sha256": {name: sha(out / name) for name in retained_meta},
        "historical_fuzz_CPU_seconds_credited": 0})
    return result


def verify_archive(archive):
    """Check retained bytes and recompute finite budget/coverage accounting."""
    receipt = read(archive / "provenance.json")
    for name, expected in receipt["output_sha256"].items():
        path = (archive / name).resolve()
        require(path.is_relative_to(archive.resolve()) and sha(path) == expected, f"archive checksum: {name}")
    with tarfile.open(archive / "campaign.tar.gz", "r:gz") as bundle:
        members = {m.name: m for m in bundle.getmembers() if m.isfile()}
        require(len(members) == sum(m.isfile() for m in bundle.getmembers()), "duplicate archive member")
        def data(name):
            return bundle.extractfile(members[name]).read()
        for name, expected in receipt["archive_members_sha256"].items():
            require(hashlib.sha256(data(name)).hexdigest() == expected, f"nested receipt differs: {name}")
        for name, expected in json.loads(data("licenses.json"))["output_sha256"].items():
            require(hashlib.sha256(data("licenses/" + name)).hexdigest() == expected, "retained diagnostic notice differs")
        config = json.loads(data("config.json"))
        for name, expected in config["source_sha256"].items():
            require(hashlib.sha256(data("source/" + name)).hexdigest() == expected, f"source differs: {name}")
        built = json.loads(data("built.json"))
        for name, expected in built["binary_sha256"].items():
            require(hashlib.sha256(data("bin/" + name)).hexdigest() == expected, f"fuzz binary differs: {name}")
        summary = json.loads(data("fuzz-summary.json"))
        post_init = json.loads(data("post-init.json"))
        require(post_init["all_four_have_post_INITED_execution"], "not every harness fuzzed beyond INITED")
        supplemental_info = json.loads(data("supplemental-summary.json")) if "supplemental-summary.json" in members else None
        total = 0.0
        corpus_counts = {}
        for name in TARGETS:
            result = summary["results"][name]
            cpu = sum(s["resource_usage"]["user_seconds"] + s["resource_usage"]["system_seconds"] for s in result["segments"])
            require(abs(cpu - result["CPU_seconds"]) < 1e-9 and cpu >= config["CPU_seconds_per_harness"], "archived CPU budget differs")
            require(all(s["exit_code"] == 0 for s in result["segments"]) and not result["defects_observed"], "archived segment failed")
            require(not any(n.startswith(name + "/failures/") for n in members), "archived fuzz defect exists")
            for s in result["segments"]:
                retained = json.loads(data(f"{name}/segment-{s['segment']:03d}-result.json"))
                require(retained == s, "segment summary differs from raw retained result")
            generated = 0
            expected_logs = [(s["segment"], f"{name}/segment-{s['segment']:03d}.log", "main") for s in result["segments"]]
            if supplemental_info and name in supplemental_info["results"]:
                expected_logs += [(s["segment"], f"supplement-001/{name}/segment-{s['segment']:03d}.log", "supplement")
                                  for s in supplemental_info["results"][name]["segments"]]
            require([(entry["segment"], entry["log_relative_path"], entry["origin"])
                     for entry in post_init["targets"][name]["segments"]] == expected_logs,
                    "post-INITED log inventory/origin is not bound to this harness")
            for entry in post_init["targets"][name]["segments"]:
                raw = data(entry["log_relative_path"])
                require(hashlib.sha256(raw).hexdigest() == entry["log_sha256"], "post-INITED log binding differs")
                text = raw.decode(errors="replace")
                starts = re.findall(r"#(\d+)\s+INITED\b", text)
                ends = re.findall(r"stat::number_of_executed_units:\s*(\d+)", text)
                require(entry["INITED_counter"] == (int(starts[-1]) if len(starts) == 1 else None)
                        and entry["final_executed_units_counter"] == (int(ends[-1]) if ends else None)
                        and entry["INITED_line_unique"] == (len(starts) == 1), "post-INITED raw counters differ")
                count = max(0, int(ends[-1]) - int(starts[-1])) if len(starts) == 1 and ends else 0
                require(count == entry["executions_after_INITED"], "post-INITED counter differs")
                generated += count
            require(generated > 0 and generated == post_init["targets"][name]["executions_after_INITED"], "no post-INITED execution")
            total += cpu
            coverage = json.loads(data(name + "-coverage.json"))
            require(coverage["type"] == "llvm.coverage.json.export", "not a real LLVM coverage export")
            require(any("/crates/kem1536/src/" in f["filename"] for item in coverage["data"] for f in item["files"]), "engine source absent from coverage")
            coverage_receipt = json.loads(data(name + "-coverage-receipt.json"))
            expected_corpora = [f"{name}/corpus"]
            if any(n.startswith(f"supplement-001/{name}/corpus/") for n in members):
                expected_corpora.append(f"supplement-001/{name}/corpus")
            require(coverage_receipt["corpora_included"] == expected_corpora, "coverage corpus binding differs")
            require(hashlib.sha256(data("coverage-bin/" + name)).hexdigest() == coverage_receipt["binary_sha256"], "coverage binary differs")
            require(hashlib.sha256(data(name + "-coverage.profdata")).hexdigest() == coverage_receipt["profdata_sha256"], "coverage profile differs")
            engine_files = [f for item in coverage["data"] for f in item["files"] if "/crates/kem1536/src/" in f["filename"]]
            require(engine_files == json.loads(data("coverage-summary.json"))[name], "source coverage summary differs")
            for file in engine_files:
                for category in ("lines", "functions", "regions"):
                    counts = file["summary"][category]
                    require(0 <= counts["covered"] <= counts["count"], "invalid source coverage counts")
            corpus_counts[name] = sum(n.startswith(name + "/corpus/") for n in members)
            require(corpus_counts[name] == result["final_distinct_corpus_inputs"], "final corpus inventory differs")
        require(abs(total - summary["total_CPU_seconds"]) < 1e-9, "total CPU accounting differs")
        oracle = json.loads(data("oracle-replay.json"))
        require(oracle["all_Rust_Python_outputs_equal"] and oracle["distinct_deterministic_requests"] > 0, "oracle evidence absent")
        require(oracle["corpus_files"] == corpus_counts, "oracle corpus inventory differs")
        require(oracle["oracle_sha256"] == config["source_sha256"]["oracle/kem_r1_reference.py"], "independent oracle source differs")
        require(hashlib.sha256(data("replay-controller.py")).hexdigest() == oracle["replay_controller_sha256"], "replay controller differs")
        supplemental_counts = {name: sum(n.startswith(f"supplement-001/{name}/corpus/") for n in members) for name in TARGETS}
        require(oracle["supplement_corpus_files"] == supplemental_counts, "oracle supplemental corpus differs")
        supplemental_cpu = 0.0
        if "supplemental-summary.json" in members:
            supplemental = json.loads(data("supplemental-summary.json"))
            supplemental_config = json.loads(data("supplement-001/config.json"))
            require(supplemental_config["parent_config_sha256"] == hashlib.sha256(data("config.json")).hexdigest(), "supplement parent differs")
            require(supplemental_config["same_M06_source_sha256"] == config["source_sha256"], "supplement source differs")
            for name, item in supplemental["results"].items():
                require(hashlib.sha256(data("supplement-001/bin/" + name)).hexdigest() == built["binary_sha256"][name], "supplement binary differs")
                cpu = sum(s["resource_usage"]["user_seconds"] + s["resource_usage"]["system_seconds"] for s in item["segments"])
                require(abs(cpu - item["CPU_seconds"]) < 1e-9 and cpu >= supplemental_config["CPU_seconds_per_selected_harness"], "supplement CPU differs")
                require(all(s["exit_code"] == 0 for s in item["segments"]) and not item["defects_observed"], "supplement failed")
                require(not any(n.startswith(f"supplement-001/{name}/failures/") for n in members), "supplement defect exists")
                require(supplemental_counts[name] == item["final_distinct_corpus_inputs"], "supplement corpus inventory differs")
                supplemental_cpu += cpu
            require(abs(supplemental_cpu - supplemental["total_CPU_seconds"]) < 1e-9, "supplement total CPU differs")
        replay = json.loads(data("replay-build.json"))
        require(hashlib.sha256(data("bin/m06-replay")).hexdigest() == replay["binary_sha256"], "oracle replay binary differs")
        require(replay["production_source_sha256"] == config["source_sha256"], "oracle replay source differs")
        require(hashlib.sha256(data("source/" + replay["additional_replay_harness"])).hexdigest() == replay["replay_harness_sha256"], "additional replay harness differs")
        union_receipt = json.loads(data("union-coverage-receipt.json"))
        require(not union_receipt["per_target_counts_summed"], "per-target counts cannot stand in for a union")
        full_coverage = gzip.decompress(data("union-coverage-full.json.gz"))
        function_receipt = json.loads(data("union-functions.json"))
        require(hashlib.sha256(full_coverage).hexdigest() == function_receipt["full_LLVM_json_sha256"], "full LLVM function export differs")
        require(hashlib.sha256(data("union-coverage.profdata")).hexdigest() == function_receipt["profile_sha256"], "function export profile differs")
        actual_functions = [row for item in json.loads(full_coverage)["data"] for row in item["functions"]
                            if any("/crates/kem1536/src/" in name for name in row["filenames"])]
        require([(row["name"], row["count"], row["filenames"]) for row in actual_functions] ==
                [(row["LLVM_name"], row["count"], row["filenames"]) for row in function_receipt["functions"]], "function counts differ from full LLVM export")
        require([row for row in function_receipt["functions"] if row["count"] == 0] == function_receipt["zero_count_functions"], "zero-count function list differs")
        if union_receipt["source_union_validated"]:
            require(hashlib.sha256(data("union-coverage.profdata")).hexdigest() == union_receipt["profdata_sha256"], "LLVM union profile differs")
            union_json = json.loads(data("union-coverage.json"))
            require(union_json["type"] == "llvm.coverage.json.export", "not an LLVM union export")
            union_files = [f for item in union_json["data"] for f in item["files"] if "/crates/kem1536/src/" in f["filename"]]
            require(union_files == union_receipt["core_files"], "LLVM union summary differs")
            by_name = {f["filename"]: f for f in union_files}
            require(len(by_name) == len(union_files), "duplicate source file in LLVM union")
            for files in json.loads(data("coverage-summary.json")).values():
                for file in files:
                    for kind in ("lines", "functions", "regions"):
                        counts = by_name[file["filename"]]["summary"][kind]
                        require(0 <= counts["covered"] <= counts["count"]
                                and counts["covered"] >= file["summary"][kind]["covered"]
                                and counts["count"] >= file["summary"][kind]["count"], "LLVM union lost a covered source region")
    return {"main_CPU_seconds": total, "supplemental_CPU_seconds": supplemental_cpu, "total_CPU_seconds": total + supplemental_cpu, "source_and_binary_hashes_verified": True,
            "source_coverage_exports": 4, "independent_replay_requests": oracle["distinct_deterministic_requests"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "prebuild-coverage", "prebuild-replay", "supplement", "inspect-init", "postprocess", "verify", "freeze", "verify-archive"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m06-fuzz-001")
    parser.add_argument("--measurements", type=Path, default=ROOT / "artifacts/generated/m06-measurements-001")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/m06-fuzz-001")
    parser.add_argument("--cpu", type=int, default=10)
    parser.add_argument("--cpu-seconds", type=int, default=120)
    args = parser.parse_args()
    out, target, measured = args.output.resolve(), args.target_dir.resolve(), args.measurements.resolve()
    require((out.is_relative_to(ROOT / "artifacts/generated") or
             (args.action == "verify-archive" and out.is_relative_to(ROOT / "results/engine")))
            and out.name.startswith("m06"), "M06 output required")
    require(target.is_relative_to(ROOT / "target") and target.name.startswith("m06"), "new M06 target required")
    if args.action == "verify-archive":
        result = verify_archive(out)
    elif args.action == "inspect-init":
        result = inspect_post_init(out)
    elif args.action == "supplement":
        result = supplement_missing(out, args.cpu, args.cpu_seconds)
    elif args.action == "prebuild-coverage":
        result = prebuild_coverage(out, target.parent / (target.name + "-coverage"), args.cpu)
    elif args.action == "prebuild-replay":
        result = str(build_replay(out, target.parent / (target.name + "-coverage-replay"), args.cpu))
    elif args.action == "run":
        result = prepare_and_run(out, measured, target, args.cpu, args.cpu_seconds)
    elif args.action == "postprocess":
        result = postprocess(out, target.parent / (target.name + "-coverage"))
    elif args.action == "verify":
        result = verify(out, finished=False)
    else:
        result = freeze(out)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
