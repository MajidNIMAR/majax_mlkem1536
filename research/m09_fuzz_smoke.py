"""Fresh finite M09 ASan/std-rebuilt smoke, no M08 campaign credit.

Linux/WSL coordinator. Each worker must accumulate 30 seconds of conservative
post-INITED CPU lower bounds. This includes the subsequent process interval,
not just mutation instructions. No LLVM source coverage or oracle replay.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time

from run_m08_fuzz import environment, inventory, read, require, save, sha, utc
from run_m04_fuzz_smoke import TARGETS, statistics as fuzz_statistics

ROOT = Path(__file__).resolve().parents[1]
CPUS = dict(zip(TARGETS, (8, 12, 14, 6), strict=True))
CONTROLS = ("m09_fuzz_smoke.py", "run_m08_fuzz.py", "run_m04_fuzz_smoke.py", "run_m06_fuzz.py",
            "run_m07_fuzz.py", "package_m08.py", "verify_m04_distribution.py")


def parse_init(log):
    text = log.decode("utf-8", errors="replace") if isinstance(log, bytes) else log
    initial = re.findall(r"#(\d+)\s+INITED\b", text)
    final = re.findall(r"stat::number_of_executed_units:\s*(\d+)", text)
    require(len(initial) == 1 and final, "one INITED and a final execution counter required")
    first, last = int(initial[0]), int(final[-1])
    require(last >= first, "execution counters decrease")
    return dict(INITED_counter=first, final_executed_units_counter=last, executions_after_INITED=last-first)


def cpu_lower(usage, init_cpu_upper):
    require(init_cpu_upper is None or (type(init_cpu_upper) in (int, float)
            and math.isfinite(init_cpu_upper) and init_cpu_upper >= 0), "invalid INIT CPU upper bound")
    for field in ("user_seconds", "system_seconds", "wall_seconds"):
        require(type(usage[field]) in (int, float) and math.isfinite(usage[field]) and usage[field] >= 0,
                "invalid GNU time accounting")
    # GNU time prints two decimals per CPU component; subtract .02 to cover
    # their combined rounding uncertainty conservatively.
    return 0.0 if init_cpu_upper is None else max(0.0, usage["user_seconds"]+usage["system_seconds"]-.02-init_cpu_upper)


def scalar_lock(data):
    """Cargo's four JSON-compatible package scalar fields, Python 3.10 too.

    Same restricted format as verify_m04_distribution.cargo_lock; not TOML.
    Resolution still comes from actual locked Cargo metadata.
    """
    packages = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", data)[1:]:
        fields = {}
        for key, value in re.findall(r'(?m)^(name|version|source|checksum) = ("[^\n]*")\s*$', block):
            require(key not in fields, "duplicate Cargo.lock scalar")
            fields[key] = json.loads(value)
        require({"name", "version"} <= fields.keys(), "unrecognized Cargo.lock package block")
        packages.append(fields)
    require(packages, "empty Cargo.lock package inventory")
    return dict(package=packages)


def observe_init_cpu(time_pid):
    """Bound the timed child's CPU at/after observing its INITED output line."""
    try:
        children = (Path("/proc")/str(time_pid)/"task"/str(time_pid)/"children").read_text().split()
        require(len(children) == 1, "one timed native child expected")
        raw = (Path("/proc")/children[0]/"stat").read_text()
        stat = raw.rsplit(") ", 1)[1].split()
        ticks = int(stat[11])+int(stat[12])  # fields 14/15, after fields 1/2.
        frequency = os.sysconf("SC_CLK_TCK")
        return dict(time_pid=time_pid, native_pid=int(children[0]), proc_stat=raw, observed_utc=utc(),
                    ticks_per_second=frequency, upper_seconds=(ticks+2)/frequency)
    except (OSError, ValueError, IndexError):
        return None  # No unobserved initialization CPU receives post-INIT credit.


def observed_init_cpu_upper(time_pid):
    observation = observe_init_cpu(time_pid)
    return None if observation is None else observation["upper_seconds"]


def run_worker(index, out, env):
    name, cpu = TARGETS[index], CPUS[TARGETS[index]]
    folder = out/name
    folder.mkdir()
    shutil.copytree(out/"initial-corpus"/name, folder/"corpus")
    (folder/"failures").mkdir()
    segments, credited = [], 0.0
    while credited < 30:
        require(len(segments) < 16, "no bounded post-INIT progress; stop with evidence")
        segment = len(segments)
        wall_request = max(5, min(30, math.ceil(30-credited)))
        log = folder/f"segment-{segment:03d}.log"
        usage_path = folder/f"segment-{segment:03d}-usage.json"
        command = ["/usr/bin/time", "-f", '{"user_seconds":%U,"system_seconds":%S,"peak_RSS_KiB":%M,"wall_seconds":%e,"exit_code":%x}',
                   "-o", str(usage_path), "taskset", "-c", str(cpu), str(out/"bin"/name), str(folder/"corpus"),
                   f"-artifact_prefix={folder/'failures'}/", f"-seed={5090201+index*100+segment}",
                   f"-max_total_time={wall_request}", "-max_len=16384", "-rss_limit_mb=2048", "-timeout=60",
                   "-print_final_stats=1", "-use_value_profile=1"]
        started, init_upper, init_observations, init_snapshot = utc(), None, 0, None
        with log.open("xb") as stream:
            with subprocess.Popen(command, cwd=out/"source", env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
                for line in child.stdout:
                    if re.search(rb"#\d+\s+INITED\b", line):
                        init_observations += 1
                        init_snapshot = observe_init_cpu(child.pid)
                        init_upper = None if init_snapshot is None else init_snapshot["upper_seconds"]
                    stream.write(line)
                code = child.wait()
        usage = json.loads(usage_path.read_text().splitlines()[-1])
        counters = parse_init(log.read_bytes())
        lower = cpu_lower(usage, init_upper)
        record = dict(segment=segment, command=command, exit_code=code, started_utc=started, finished_utc=utc(),
            binary_sha256=sha(out/"bin"/name), log_sha256=sha(log), usage_sha256=sha(usage_path), resource_usage=usage,
            INITED_observations=init_observations, observed_INITED_CPU_upper_seconds=init_upper,
            observed_INITED_proc_snapshot=init_snapshot,
            post_INITED_CPU_lower_seconds=lower, wall_limit_requested_seconds=wall_request,
            **counters, **fuzz_statistics(log))
        save(folder/f"segment-{segment:03d}-result.json", record)
        require(code == usage["exit_code"] == 0 and not any((folder/"failures").iterdir()), "fuzzer failed; logs and artifacts retained")
        require(init_observations == 1 and counters["executions_after_INITED"] > 0, "post-INIT mutation work absent")
        require(not re.search(rb"ERROR: (?:AddressSanitizer|LeakSanitizer)", log.read_bytes()), "sanitizer error observed")
        segments.append(record)
        credited += lower
        print(json.dumps(dict(target=name, segments=len(segments), post_INITED_CPU_lower_seconds=credited, budget=30)), flush=True)
    summary = dict(CPU_seconds=sum(s["resource_usage"]["user_seconds"]+s["resource_usage"]["system_seconds"] for s in segments),
        post_INITED_CPU_lower_seconds=credited, post_INITED_CPU_budget_seconds=30, affinity_CPU=cpu, segments=segments,
        executions_after_INITED_including_repetitions=sum(s["executions_after_INITED"] for s in segments),
        final_corpus_sha256=inventory(folder/"corpus"), defects_observed=False)
    save(folder/"summary.json", summary)
    return summary


def collect_notices(out, env, compiler_sha):
    """Verify the same fuzz graph/toolchain and copy license TEXTS only."""
    from package_m08 import diagnostic_records
    old = ROOT/"artifacts/generated/m08-diagnostic-notices-001"
    notice = read(old/"notices.json")
    require(notice["compiler_binary_sha256"] == compiler_sha, "M08 notice toolchain differs")
    require(sha(out/"source/fuzz/Cargo.lock") == notice["groups"]["fuzz"]["lock_sha256"], "fuzz lock differs from licensed graph")
    command = [str(ROOT/".tools/linux-cargo/bin/cargo"), "metadata", "--locked", "--offline", "--format-version", "1",
               "--filter-platform", "x86_64-unknown-linux-gnu", "--manifest-path", str(out/"source/fuzz/Cargo.toml")]
    metadata = json.loads(subprocess.check_output(command, env=env, cwd=out/"source"))
    records = diagnostic_records(metadata, scalar_lock((out/"source/fuzz/Cargo.lock").read_text()))
    normalized = lambda values: [{k: v for k, v in row.items() if k != "metadata_id"} for row in values]
    require(normalized(records) == normalized(notice["groups"]["fuzz"]["resolved_packages"]), "resolved fuzz dependency/features graph differs")
    require(inventory(old/"licenses") == notice["license_sha256"], "historical license texts changed")
    shutil.copytree(old/"licenses", out/"licenses")
    shutil.copyfile(old/"notices.json", out/"M08-license-text-origin.json")
    save(out/"metadata-fuzz.json", metadata)
    save(out/"notices.json", dict(mode="M08 license texts only; no historical images or acquisition credit",
        source_notices_sha256=sha(old/"notices.json"), license_sha256=inventory(out/"licenses"),
        compiler_binary_sha256=compiler_sha, fuzz_lock_identical=True, resolved_fuzz_graph_identical=True,
        resolved_packages=records, metadata_command=command, metadata_sha256=sha(out/"metadata-fuzz.json"),
        licensed_text_bundle_contains_superset_including_M08_replay=True,
        scope="resolved fuzz graph/features; not attribution of every linked symbol"))


def run(candidate, out, target):
    require(sys.platform == "linux", "Linux/WSL coordinator required")
    candidate, out, target = Path(candidate).resolve(), Path(out).resolve(), Path(target).resolve()
    require(candidate.parent == ROOT/"artifacts/generated" and candidate.name.startswith("m09-final")
            and out.parent == ROOT/"artifacts/generated" and out.name.startswith("m09")
            and target.parent == ROOT/"target" and target.name.startswith("m09"), "new owned M09 paths required")
    require(not out.exists() and not target.exists(), "new smoke output and compiler target required")
    require(set(CPUS.values()) <= os.sched_getaffinity(0), "requested smoke CPU unavailable")
    manifest = read(candidate/"source.json")
    require(inventory(candidate/"source") == manifest["source_sha256"], "candidate capture changed")
    out.mkdir()
    try:
        shutil.copytree(candidate/"source", out/"source")
        shutil.copyfile(candidate/"source.json", out/"candidate-source.json")
        for parent, dirs, files in os.walk(ROOT/"fuzz"):
            dirs[:] = [name for name in dirs if name not in {"target", "corpus", "artifacts", "coverage"}]
            for name in files:
                source = Path(parent)/name
                relative = source.relative_to(ROOT)
                dest = out/"source"/relative
                if dest.exists():
                    require(sha(dest) == sha(source), "fuzz attachment conflicts with candidate capture")
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, dest)
        sources = inventory(out/"source")
        for name in CONTROLS:
            dest = out/"controls"/name
            dest.parent.mkdir(exist_ok=True)
            shutil.copyfile(ROOT/"research"/name, dest)
        for name in TARGETS:
            source = ROOT/"artifacts/generated/m03-seeds-final"/name
            require(source.is_dir(), "synthetic compact corpus missing")
            dest = out/"initial-corpus"/name
            dest.mkdir(parents=True)
            for item in source.iterdir():
                require(item.is_file(), "flat synthetic corpus expected")
                copied = dest/sha(item)
                if not copied.exists():
                    shutil.copyfile(item, copied)
        env = environment(target)
        cargo, rustc = (str(ROOT/".tools/linux-cargo/bin"/name) for name in ("cargo", "rustc"))
        rust = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
        fuzz = subprocess.check_output([cargo, "fuzz", "--version"], env=env, text=True)
        require("release: 1.91.1" in rust and fuzz.strip() == "cargo-fuzz 0.13.1", "pinned fuzz tools required")
        sysroot = Path(subprocess.check_output([rustc, "--print", "sysroot"], env=env, text=True).strip())
        compiler_sha = sha(sysroot/"bin/rustc")
        collect_notices(out, env, compiler_sha)
        build = ["taskset", "-c", ",".join(map(str, CPUS.values())), cargo, "fuzz", "build", "--fuzz-dir", str(out/"source/fuzz"),
                 "--target-dir", str(target), "--build-std"]
        lock = sha(out/"source/fuzz/Cargo.lock")
        save(out/"config.json", dict(profile=manifest["profile"], candidate_source_manifest_sha256=sha(candidate/"source.json"),
            source_sha256=sources, controller_sha256=inventory(out/"controls"), initial_corpus_sha256=inventory(out/"initial-corpus"),
            post_INITED_CPU_budget_seconds=30, affinity_CPU_by_harness=CPUS, started_utc=utc(),
            initially_requested_CPUs=[8, 12, 14, 16], unavailable_requested_CPU=16,
            CPU_adjustment_before_any_build="WSL exposes CPU0..15; replace unavailable CPU16 with CPU6",
            build_command=build, rustc=rust, cargo_fuzz=fuzz, compiler_binary_sha256=compiler_sha,
            cargo_fuzz_binary_sha256=sha(ROOT/".tools/linux-cargo/bin/cargo-fuzz"), ASAN_OPTIONS=env["ASAN_OPTIONS"],
            std_rebuild_requested=True, LLVM_source_coverage_measured=False, historical_CPU_credited=0,
            post_INITED_scope="CPU after observing INITED, including subsequent teardown; not pure mutation-instruction CPU"))
        started = utc()
        with (out/"build.log").open("xb") as log:
            process = subprocess.run(build, cwd=out/"source", env=env, stdout=log, stderr=subprocess.STDOUT)
        save(out/"build-result.json", dict(exit_code=process.returncode, started_utc=started, finished_utc=utc(),
                                           build_log_sha256=sha(out/"build.log")))
        require(process.returncode == 0 and sha(out/"source/fuzz/Cargo.lock") == lock
                and inventory(out/"source") == sources, "ASan build failed or changed captured source/lock")
        rebuilt = sorted((target/"x86_64-unknown-linux-gnu/release/deps").glob("libstd-*.rlib"))
        require(rebuilt, "rebuilt std absent")
        (out/"bin").mkdir()
        for name in TARGETS:
            dest = out/"bin"/name
            shutil.copyfile(target/"x86_64-unknown-linux-gnu/release"/name, dest)
            dest.chmod(0o700)
        save(out/"built.json", dict(binary_sha256=inventory(out/"bin"), fuzz_lock_sha256=lock,
                                    rebuilt_std_rlib_sha256={path.name: sha(path) for path in rebuilt}))
        results, failures = {}, {}
        with ThreadPoolExecutor(max_workers=4) as workers:
            futures = {workers.submit(run_worker, index, out, env): name for index, name in enumerate(TARGETS)}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except BaseException as error:
                    failures[name] = dict(type=type(error).__name__, message=str(error))
        results = {name: results[name] for name in TARGETS if name in results}
        save(out/"summary.json", dict(results=results, failures=failures, finished_utc=utc(),
            total_CPU_seconds=sum(row["CPU_seconds"] for row in results.values()),
            total_post_INITED_CPU_lower_seconds=sum(row["post_INITED_CPU_lower_seconds"] for row in results.values()),
            all_four_budgets_reached=set(results) == set(TARGETS) and all(row["post_INITED_CPU_lower_seconds"] >= 30 for row in results.values()),
            historical_CPU_credited=0, LLVM_source_coverage_measured=False, independent_oracle_replayed=False))
        require(not failures and set(results) == set(TARGETS), "smoke worker failed; all evidence retained")
        require(inventory(out/"source") == sources and inventory(out/"controls") == read(out/"config.json")["controller_sha256"],
                "frozen smoke inputs changed")
        # The notice binds these NEW images only after the fresh build exists.
        save(out/"diagnostic-images.json", dict(binary_sha256=inventory(out/"bin"), notices_sha256=sha(out/"notices.json"),
                                                historical_images_reused=False))
        result = verify(out)
        save(out/"verification.json", result)
        return result
    except BaseException as error:
        if not (out/"failure.json").exists():
            save(out/"failure.json", dict(type=type(error).__name__, message=str(error), at_utc=utc(), evidence_retained=True))
        raise


def verify_raws(raws):
    """Pure replay from archive member bytes; absent failure prefixes mean empty."""
    require(sum(map(len, raws.values())) <= 512*1024*1024, "smoke expansion exceeds 512 MiB")
    for name, raw in raws.items():
        path = PurePosixPath(name)
        require(type(name) is str and str(path) == name and not path.is_absolute() and "\\" not in name
                and all(part not in ("", ".", "..") and ":" not in part for part in name.split("/"))
                and isinstance(raw, bytes) and len(raw) <= 64*1024*1024, "unsafe/oversized smoke member")
    def read(path):
        return json.loads(raws[str(path)])
    def sha(path):
        return hashlib.sha256(raws[str(path)]).hexdigest()
    def inventory(folder):
        prefix = str(folder)+"/"
        return {name[len(prefix):]: hashlib.sha256(raw).hexdigest()
                for name, raw in raws.items() if name.startswith(prefix)}
    out = PurePosixPath(".")
    config, built, summary = (read(out/name) for name in ("config.json", "built.json", "summary.json"))
    require(inventory(out/"source") == config["source_sha256"] and inventory(out/"controls") == config["controller_sha256"]
            and inventory(out/"initial-corpus") == config["initial_corpus_sha256"], "smoke source/control/corpus differs")
    require(sha(out/"candidate-source.json") == config["candidate_source_manifest_sha256"]
            and all(config["source_sha256"][name] == checksum for name, checksum in read(out/"candidate-source.json")["source_sha256"].items()),
            "smoke candidate source binding differs")
    require(inventory(out/"bin") == built["binary_sha256"] and read(out/"build-result.json")["exit_code"] == 0
            and sha(out/"build.log") == read(out/"build-result.json")["build_log_sha256"]
            and sha(out/"source/fuzz/Cargo.lock") == built["fuzz_lock_sha256"] and built["rebuilt_std_rlib_sha256"], "smoke compiled images differ")
    require(config["historical_CPU_credited"] == summary["historical_CPU_credited"] == 0
            and summary["all_four_budgets_reached"] is True and not summary["failures"], "smoke budget/credit differs")
    total, total_lower, executions = 0.0, 0.0, 0
    for harness_index, name in enumerate(TARGETS):
        item = summary["results"][name]
        require(read(out/name/"summary.json") == item and item["affinity_CPU"] == CPUS[name], "worker summary differs")
        lower, cpu, work = 0.0, 0.0, 0
        for index, segment in enumerate(item["segments"]):
            folder = out/name
            log, usage = folder/f"segment-{index:03d}.log", folder/f"segment-{index:03d}-usage.json"
            require(read(folder/f"segment-{index:03d}-result.json") == segment and segment["segment"] == index
                    and sha(log) == segment["log_sha256"] and sha(usage) == segment["usage_sha256"]
                    and read(usage) == segment["resource_usage"] and segment["exit_code"] == 0
                    and segment["binary_sha256"] == built["binary_sha256"][name], "smoke segment bytes/image differ")
            argv = segment["command"]
            basename = lambda value: value.replace("\\", "/").rsplit("/", 1)[-1]
            require(len(argv) == 18 and argv[0:2] == ["/usr/bin/time", "-f"] and argv[3] == "-o"
                    and basename(argv[4]) == usage.name and argv[5:8] == ["taskset", "-c", str(CPUS[name])]
                    and basename(argv[8]) == name and argv[9].endswith("/"+name+"/corpus")
                    and argv[10].endswith("/"+name+"/failures/") and argv[10].startswith("-artifact_prefix=")
                    and argv[11] == f"-seed={5090201+harness_index*100+index}"
                    and type(segment["wall_limit_requested_seconds"]) is int and 5 <= segment["wall_limit_requested_seconds"] <= 30
                    and argv[12] == f"-max_total_time={segment['wall_limit_requested_seconds']}"
                    and argv[13:] == ["-max_len=16384", "-rss_limit_mb=2048", "-timeout=60", "-print_final_stats=1", "-use_value_profile=1"],
                    "smoke native command/CPU/seed differs")
            counts = parse_init(raws[str(log)])
            require(all(segment[key] == value for key, value in counts.items()) and counts["executions_after_INITED"] > 0,
                    "smoke post-INIT work differs")
            require(segment["INITED_observations"] == 1 and segment["resource_usage"]["exit_code"] == 0,
                    "smoke initialization/exit differs")
            snapshot = segment["observed_INITED_proc_snapshot"]
            if snapshot is not None:
                fields = snapshot["proc_stat"].rsplit(") ", 1)[1].split()
                require(type(snapshot["ticks_per_second"]) is int and snapshot["ticks_per_second"] > 0
                        and (int(fields[11])+int(fields[12])+2)/snapshot["ticks_per_second"]
                        == snapshot["upper_seconds"] == segment["observed_INITED_CPU_upper_seconds"],
                        "sampled INIT CPU bound differs")
            else:
                require(segment["observed_INITED_CPU_upper_seconds"] is None, "unobserved INIT CPU was credited")
            expected = cpu_lower(segment["resource_usage"], segment["observed_INITED_CPU_upper_seconds"])
            require(expected == segment["post_INITED_CPU_lower_seconds"], "post-INIT CPU accounting differs")
            lower += expected
            cpu += segment["resource_usage"]["user_seconds"]+segment["resource_usage"]["system_seconds"]
            work += counts["executions_after_INITED"]
        require(lower == item["post_INITED_CPU_lower_seconds"] and lower >= 30 and cpu == item["CPU_seconds"]
                and work == item["executions_after_INITED_including_repetitions"]
                and inventory(out/name/"corpus") == item["final_corpus_sha256"] and not inventory(out/name/"failures"), "worker CPU/corpus differs")
        total += cpu
        total_lower += lower
        executions += work
    # Workers finish asynchronously, so the writer and reader can add the
    # same floats in different orders. This tolerance is only for aggregate
    # consistency (<1 nanosecond); per-worker CPU budgets remain exact gates.
    require(math.isclose(total, summary["total_CPU_seconds"], rel_tol=0, abs_tol=1e-9)
            and math.isclose(total_lower, summary["total_post_INITED_CPU_lower_seconds"], rel_tol=0, abs_tol=1e-9),
            "total CPU differs")
    notices = read(out/"notices.json")
    old_notices = read(out/"M08-license-text-origin.json")
    require(inventory(out/"licenses") == notices["license_sha256"] == old_notices["license_sha256"]
            and sha(out/"M08-license-text-origin.json") == notices["source_notices_sha256"]
            and notices["compiler_binary_sha256"] == config["compiler_binary_sha256"] == old_notices["compiler_binary_sha256"]
            and sha(out/"metadata-fuzz.json") == notices["metadata_sha256"]
            and sha(out/"source/fuzz/Cargo.lock") == old_notices["groups"]["fuzz"]["lock_sha256"], "smoke license inputs/texts differ")
    from package_m08 import diagnostic_records
    graph = diagnostic_records(read(out/"metadata-fuzz.json"), scalar_lock(raws["source/fuzz/Cargo.lock"].decode()))
    normalize = lambda values: [{key: value for key, value in row.items() if key != "metadata_id"} for row in values]
    require(graph == notices["resolved_packages"] and normalize(graph) == normalize(old_notices["groups"]["fuzz"]["resolved_packages"]),
            "smoke license graph/features differ")
    images = read(out/"diagnostic-images.json")
    require(images["binary_sha256"] == built["binary_sha256"] and images["notices_sha256"] == sha(out/"notices.json")
            and images["historical_images_reused"] is False, "new smoke image/notice binding differs")
    return dict(status="PASS", total_CPU_seconds=total, total_post_INITED_CPU_lower_seconds=total_lower,
                executions_after_INITED_including_repetitions=executions, workers=4,
                LLVM_source_coverage_measured=False, independent_oracle_replayed=False, historical_CPU_credited=0)


def verify(out):
    out = Path(out)
    return verify_raws({name: (out/name).read_bytes() for name in inventory(out)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify"))
    parser.add_argument("--candidate-root", type=Path, default=ROOT/"artifacts/generated/m09-final-002")
    parser.add_argument("--output", type=Path, default=ROOT/"artifacts/generated/m09-fuzz-002")
    parser.add_argument("--target-dir", type=Path, default=ROOT/"target/m09-fuzz-002")
    args = parser.parse_args()
    result = run(args.candidate_root, args.output, args.target_dir) if args.action == "run" else verify(args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
