"""M08 matched source capture/builds, memory and paired API-return latency.

The native probe and core latency method extend M07. All sources and outputs
are new; historical controls/results are read only. Windows/WSL coordinator.
"""
import argparse
from collections import defaultdict
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess

from build_m06_validation import source_files
from capture_m07_timing import affinity
from run_m07 import MEMORY_NUMBERS, execute, linux, linux_prefix, read, require, save, sha, utc, windows_environment

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
PROBE = Path("research/m08-memory-probe")
CONSUMER = Path("research/m08-import-consumer")
CORE = {"crates/kem1536/src/dev_kem.rs": "3b7594bf96b6dcf3a52001582f8ab832da774ed059db66999e0e5091c8c8d48b",
        "crates/kem1536/src/engine_poly.rs": "ffe7b50dfebfe8d9998296672bd1973a8376a02cb06f2338418e27f23a392ac2"}
MEMORY_OPERATIONS = ("noop", "calibration_8192", "calibration_32768", "calibration_65536", "keygen", "encaps",
    "decaps_valid", "decaps_reject", "import_public_valid", "import_private_valid", "import_public_noncanonical",
    "import_private_hash", "import_private_secret_first", "import_private_secret_last", "import_private_public",
    "import_private_combined", "import_public_short", "import_private_short")
CORE_OPERATIONS = ("keygen", "encaps", "decaps_valid", "decaps_rejected")
IMPORT_OPERATIONS = ("public_valid", "public_noncanonical_first", "public_noncanonical_last", "private_valid",
    "private_secret_noncanonical_first", "private_secret_noncanonical_last", "private_public_noncanonical",
    "private_hash_invalid", "private_secret_and_hash_invalid", "private_public_and_hash_invalid",
    "private_secret_and_public_invalid")


def inventory(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def capture(out, label):
    if label == "baseline":
        require(not out.exists() and {n: sha(ROOT / n) for n in CORE} == CORE, "new run and exact M07 baseline required")
        out.mkdir(parents=True)
        for name in ("m08-fuzz-plan.json", "m08-acceptance.json"):
            shutil.copyfile(ROOT / "research" / name, out / name)
    else:
        decision = read(out / "decision-commit.json")
        require(sha(out / "m08-acceptance.json") == decision["acceptance_sha256"], "preregistered acceptance changed")
        require(subprocess.run(["git", "merge-base", "--is-ancestor", decision["commit"], "HEAD"], cwd=ROOT).returncode == 0,
                "acceptance must be committed before candidate")
    paths = source_files()
    for folder in (PROBE, CONSUMER):
        require((ROOT / folder / "Cargo.lock").is_file(), "standalone lock must precede capture")
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.is_file() and "target" not in p.relative_to(ROOT / folder).parts)
    paths.extend(ROOT / n for n in ("research/run_m08.py", "research/run_m07.py", "research/m08-fuzz-plan.json",
        "research/m08-acceptance.json", "docs/PROTOCOLE_M08_IMPORTS.md"))
    hashes = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(paths))}
    if label == "candidate":
        baseline = read(out / "baseline-source.json")["source_sha256"]
        require(set(hashes) == set(baseline), "candidate compilation closure changed")
        require(all(hashes[n] == h for n, h in baseline.items() if n not in
                    {"crates/kem1536/src/dev_kem.rs", "research/run_m08.py"}),
                "unexpected candidate input change")
    destination = out / (label + "-source")
    destination.mkdir(exist_ok=False)
    for name in hashes:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, path)
    require(inventory(destination) == hashes, "capture changed bytes")
    save(out / (label + "-source.json"), {"profile": PROFILE, "captured_utc": utc(), "source_sha256": hashes,
         "head_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
         "working_diff": subprocess.check_output(["git", "diff", "HEAD", "--", "crates/kem1536/src"], cwd=ROOT, text=True),
         "preregistered_acceptance_sha256": sha(out / "m08-acceptance.json"), "fuzz_plan_sha256": sha(out / "m08-fuzz-plan.json"),
         "measurement_control_change": "Before paired acquisitions: save each attempt's command/exit/times, validate consumer scope/status. Compiled inputs except dev_kem.rs and preregistered criteria remain identical." if label == "candidate" else None})
    print(json.dumps({"captured": label, "files": len(hashes)}), flush=True)


def checked_source(out, label):
    expected = read(out / (label + "-source.json"))["source_sha256"]
    require(inventory(out / (label + "-source")) == expected, "frozen source changed")
    return expected


def build(out, label, host):
    source = out / (label + "-source")
    hashes = checked_source(out, label)
    destination = out / label / host
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "bin").mkdir()
    target = ROOT / "target/m08-001" / label / host
    require(not target.exists(), "new isolated target required")
    configurations = (
        ("probe", ["--manifest-path", str(source / PROBE / "Cargo.toml")], "m08-memory-probe", host == "linux"),
        ("consumer", ["--manifest-path", str(source / CONSUMER / "Cargo.toml")], "m08-import-consumer", False),
        ("latency", ["-p", "kem1536-bench", "--bin", "m07-measure"], "m07-measure", False),
        ("research", ["-p", "kem1536-cli", "--bin", "kem1536", "--features", "research-vectors"], "kem1536", False),
        ("delivered", ["-p", "kem1536-cli", "--bin", "kem1536"], "kem1536", False),
        ("timing", ["-p", "kem1536-bench", "--bin", "kem1536-bench"], "kem1536-bench", False))
    receipts = {}
    for kind, selection, executable, metadata in configurations:
        args = ["build", "--release", "--locked", "--offline", *selection]
        if host == "windows":
            env, cargo, rustc, _ = windows_environment(target, metadata)
            command = [cargo, *args]
            versions = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
        else:
            env = None
            args = [linux(Path(p)) if p.startswith(str(ROOT)) else p for p in args]
            prefix = linux_prefix(target, metadata)
            command = [*prefix, linux(ROOT / ".tools/linux-cargo/bin/cargo"), *args]
            versions = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "-Vv"], text=True)
        require("release: 1.91.1" in versions, "wrong compiler")
        print(f"building {label}/{host}/{kind}", flush=True)
        with (destination / (kind + "-build.log")).open("xb") as log:
            subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        suffix = ".exe" if host == "windows" else ""
        binary = destination / "bin" / (kind + suffix)
        shutil.copyfile(target / "release" / (executable + suffix), binary)
        receipts[kind] = {"path": binary.relative_to(out).as_posix(), "sha256": sha(binary), "command": command,
                          "rustc": versions, "emit_stack_metadata": metadata}
    require(checked_source(out, label) == hashes, "build changed sources")
    save(destination / "build.json", {"profile": PROFILE, "host": host, "built_utc": utc(),
         "source_manifest_sha256": sha(out / (label + "-source.json")), "controller_sha256": sha(Path(__file__)),
         "shared_dependency_target_within_label_and_host": True, "binaries": receipts})


def binary(out, label, host, kind):
    row = read(out / label / host / "build.json")["binaries"][kind]
    path = out / row["path"]
    require(sha(path) == row["sha256"], "executable changed")
    return path


def validate_memory(rows, repetitions):
    keys = set(MEMORY_NUMBERS) | {"profile", "operation", "saturated", "functional_validation", "secrets_printed"}
    grid = {(op, p, i) for op in MEMORY_OPERATIONS for p in (0xa5, 0x5a) for i in range(repetitions)}
    seen, groups = set(), defaultdict(list)
    for row in rows:
        require(set(row) == keys and all(type(row[n]) is int and row[n] >= 0 for n in MEMORY_NUMBERS), "invalid memory fields/counters")
        identity = (row["operation"], row["paint_pattern"], row["sample"])
        require(identity in grid and identity not in seen, "unknown or duplicate memory observation")
        seen.add(identity)
        require(row["schema"] == 1 and row["profile"] == PROFILE and row["saturated"] is False
                and row["functional_validation"] is True and row["secrets_printed"] is False, "invalid scope/validation")
        require(row["native_stack_size_requested"] == 1048576 and row["paint_top_margin_bytes"] == 512
                and 0 < row["paint_search_bytes"] <= 262144
                and row["touched_stack_high_water_bytes"] < row["paint_search_bytes"] + 512, "invalid stack bounds")
        require(row["allocation_failures"] == row["foreign_deallocations"] == row["tracker_overflows"] == 0
                and row["retained_requested_bytes_at_api_return"] <= row["peak_live_requested_bytes"] <= row["total_requested_bytes"], "invalid heap accounting")
        if row["operation"].startswith("calibration_"):
            size = int(row["operation"].split("_")[1])
            require(row["calibration_written_array_bytes"] == size and row["touched_stack_high_water_bytes"] >= row["known_written_calibration_depth_bytes"] >= size,
                    "calibration underestimated")
        else:
            require(row["known_written_calibration_depth_bytes"] == row["calibration_written_array_bytes"] == 0, "unexpected calibration")
        groups[row["operation"]].append(row)
    require(seen == grid, "incomplete memory grid")
    return {op: {"count": len(items), "touched_stack_bytes": {"minimum": min(r["touched_stack_high_water_bytes"] for r in items),
            "median": statistics.median(r["touched_stack_high_water_bytes"] for r in items), "maximum": max(r["touched_stack_high_water_bytes"] for r in items)},
            "requested_allocation_ranges": {n: [min(r[n] for r in items), max(r[n] for r in items)] for n in
                ("alloc_calls", "alloc_zeroed_calls", "realloc_calls", "dealloc_calls", "total_requested_bytes", "retained_requested_bytes_at_api_return", "peak_live_requested_bytes")}}
            for op, items in sorted(groups.items())}


def probe(out, label, host, repetitions):
    exe = binary(out, label, host, "probe")
    require(not (out / label / host / "memory.jsonl").exists(), "new memory acquisition required")
    raw, command, errors, code = execute(exe, host, [repetitions])
    folder = out / label / host
    (folder / "memory.jsonl").write_bytes(raw)
    (folder / "memory.stderr").write_bytes(errors)
    require(code == 0, "probe failed; raw streams preserved")
    summary = validate_memory([json.loads(line) for line in raw.splitlines()], repetitions)
    save(folder / "memory-summary.json", summary)
    save(folder / "memory-run.json", {"command": command, "exit_code": code, "binary_sha256": sha(exe),
         "raw_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(errors).hexdigest(), "executed_utc": utc()})


def summarize(rows, operations, labels, samples, series):
    seen, groups = set(), defaultdict(list)
    for row in rows:
        identity = (row["version"], row["operation"], row["series"], row["iteration"])
        require(identity not in seen and row["version"] in labels and row["operation"] in operations
                and type(row["series"]) is int and 0 <= row["series"] < series and type(row["iteration"]) is int
                and 0 <= row["iteration"] < samples and type(row["nanoseconds"]) is int and row["nanoseconds"] > 0,
                "invalid/duplicate latency observation")
        seen.add(identity)
        if tuple(operations) == IMPORT_OPERATIONS:
            expected = 0 if row["operation"] in ("public_valid", "private_valid") else (3 if row["operation"] == "private_hash_invalid" else 2)
            require(row.get("schema") == 1 and row.get("profile") == PROFILE and row.get("status") == row.get("expected_status") == expected
                    and row.get("validation_and_drop_outside_timer") is True and row.get("secrets_printed") is False,
                    "import latency scope/status differs")
        groups[row["version"] + "/" + row["operation"]].append(row)
    require(len(rows) == len(labels) * len(operations) * samples * series, "incomplete latency grid")
    result = {}
    for key, items in sorted(groups.items()):
        values = sorted(r["nanoseconds"] for r in items)
        require(len(values) == samples * series, "incomplete operation panel")
        result[key] = {"count": len(values), "minimum_ns": values[0], "maximum_ns": values[-1],
            "median_ns": statistics.median(values), "p95_ns": values[math.ceil(.95 * len(values)) - 1],
            "series_median_ns": {str(i): statistics.median(r["nanoseconds"] for r in items if r["series"] == i) for i in range(series)},
            "observations_excluded": 0}
    require(len(result) == len(labels) * len(operations), "missing operation panel")
    return result


def latency(out, host, kind, samples, warmup, series, cpu):
    operations = CORE_OPERATIONS if kind == "latency" else IMPORT_OPERATIONS
    labels = ("baseline", "candidate")
    folder = out / ("paired-latency" if kind == "latency" else "paired-imports") / host
    folder.mkdir(parents=True, exist_ok=False)
    rows, schedule = [], []
    for number in range(series):
        for label in (labels if number % 2 == 0 else labels[::-1]):
            args = [number, samples, warmup] if kind == "latency" else ["latency", number, samples, warmup]
            started = utc()
            with affinity(cpu):
                raw, command, errors, code = execute(binary(out, label, host, kind), host, args, cpu if host == "linux" else None)
            with (folder / f"{label}-{number}.stdout.gz").open("xb") as sink:
                with gzip.GzipFile(fileobj=sink, mode="wb", filename="", mtime=0) as stream:
                    stream.write(raw)
            (folder / f"{label}-{number}.stderr").write_bytes(errors)
            save(folder / f"{label}-{number}.attempt.json", {"version": label, "series": number,
                 "command": command, "binary_sha256": sha(binary(out, label, host, kind)),
                 "started_utc": started, "finished_utc": utc(), "exit_code": code,
                 "stdout_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(errors).hexdigest(),
                 "controller_sha256": sha(Path(__file__))})
            require(code == 0, "latency process failed; raw streams retained")
            rows.extend(dict(version=label, **json.loads(line)) for line in raw.splitlines())
            schedule.append({"version": label, "series": number, "command": command, "started_utc": started,
                "finished_utc": utc(), "stdout_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(errors).hexdigest(), "exit_code": code})
            print(f"latency {host}/{kind}/{label}/{number}", flush=True)
    stats = summarize(rows, operations, labels, samples, series)
    with (folder / "observations.jsonl.gz").open("xb") as sink:
        with gzip.GzipFile(fileobj=sink, mode="wb", filename="", mtime=0) as stream:
            stream.write(b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode() for row in rows))
    save(folder / "statistics.json", stats)
    save(folder / "schedule.json", {"samples": samples, "warmup": warmup, "series": series, "CPU": cpu,
        "operations": list(operations), "frequency_fixed": False, "host_wide_isolation_proved": False,
        "drop_and_validation_outside_timing": True, "schedule": schedule})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "build", "probe", "latency", "imports"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m08-001")
    parser.add_argument("--label", choices=("baseline", "candidate"), default="baseline")
    parser.add_argument("--host", choices=("windows", "linux"), default="windows")
    args = parser.parse_args()
    out = args.output.resolve()
    require(out.parent == (ROOT / "artifacts/generated").resolve(), "new direct generated output required")
    if args.action == "capture": capture(out, args.label)
    elif args.action == "build": build(out, args.label, args.host)
    elif args.action == "probe": probe(out, args.label, args.host, 20)
    else: latency(out, args.host, "latency" if args.action == "latency" else "consumer", 1000, 100, 5, 10)


if __name__ == "__main__":
    main()
