"""M07 source capture, matched Windows/WSL builds and native observations.

All outputs are new children of artifacts/generated; compiler targets stay in
target/. No old result is overwritten and no production source is modified.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys

from build_m06_validation import source_files

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path("research/m07-memory-probe")
OPERATIONS = ("keygen", "encaps", "decaps_valid", "decaps_rejected")
MEMORY_OPERATIONS = ("noop", "calibration_8192", "calibration_32768", "calibration_65536",
                     "keygen", "encaps", "decaps_valid", "decaps_reject", "import_public_valid",
                     "import_private_valid", "import_public_noncanonical", "import_private_hash",
                     "import_public_short", "import_private_short")
MEMORY_NUMBERS = ("schema", "sample", "paint_pattern", "native_stack_size_requested",
                  "paint_top_margin_bytes", "paint_search_bytes", "touched_stack_high_water_bytes",
                  "known_written_calibration_depth_bytes", "alloc_calls", "alloc_zeroed_calls",
                  "calibration_written_array_bytes",
                  "realloc_calls", "dealloc_calls", "allocation_failures", "foreign_deallocations",
                  "tracker_overflows", "total_requested_bytes", "retained_requested_bytes_at_api_return",
                  "peak_live_requested_bytes")
BASELINE_CORE = {
    "crates/kem1536/src/dev_kem.rs": "eb7635eedc73c3db93d7baa81a86817157969a82890f797acfb3694a767e0262",
    "crates/kem1536/src/engine_poly.rs": "ffe7b50dfebfe8d9998296672bd1973a8376a02cb06f2338418e27f23a392ac2",
}

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def linux(path):
    path = path.resolve()
    return "/mnt/" + path.drive[0].lower() + str(path)[2:].replace("\\", "/")

def owned(path, parent):
    path = path.resolve()
    require(path != parent and path.is_relative_to(parent), "new owned child path required")
    return path

def inventory(folder):
    return {path.relative_to(folder).as_posix(): sha(path)
            for path in sorted(folder.rglob("*")) if path.is_file()}

def validate_memory(rows, repetitions):
    expected_keys = set(MEMORY_NUMBERS) | {"profile", "operation", "saturated", "functional_validation", "secrets_printed"}
    expected_grid = {(operation, pattern, sample) for operation in MEMORY_OPERATIONS
                     for pattern in (0xa5, 0x5a) for sample in range(repetitions)}
    identities, groups = set(), defaultdict(list)
    for row in rows:
        require(set(row) == expected_keys, "memory fields differ")
        require(all(type(row[name]) is int and row[name] >= 0 for name in MEMORY_NUMBERS), "invalid memory counter")
        identity = (row["operation"], row["paint_pattern"], row["sample"])
        require(identity in expected_grid and identity not in identities, "duplicate or unknown memory observation")
        identities.add(identity)
        require(row["schema"] == 1 and row["profile"] == "KEM1536-DEV-Q7681-R1"
                and row["saturated"] is False and row["functional_validation"] is True
                and row["secrets_printed"] is False, "memory validation or scope failed")
        require(row["native_stack_size_requested"] == 1024 * 1024 and row["paint_top_margin_bytes"] == 512
                and 0 < row["paint_search_bytes"] <= 256 * 1024
                and row["touched_stack_high_water_bytes"] < row["paint_search_bytes"] + 512,
                "invalid or saturated stack range")
        require(row["allocation_failures"] == row["foreign_deallocations"] == row["tracker_overflows"] == 0
                and row["retained_requested_bytes_at_api_return"] <= row["peak_live_requested_bytes"] <= row["total_requested_bytes"],
                "allocation window accounting differs")
        if row["operation"].startswith("calibration_"):
            size = int(row["operation"].split("_")[1])
            require(row["calibration_written_array_bytes"] == size
                    and row["touched_stack_high_water_bytes"] >= row["known_written_calibration_depth_bytes"] >= size,
                    "written-stack calibration underestimated")
        else:
            require(row["known_written_calibration_depth_bytes"] == row["calibration_written_array_bytes"] == 0,
                    "unexpected calibration depth")
        groups[row["operation"]].append(row)
    require(identities == expected_grid, "memory panel incomplete")
    result = {}
    for operation, observations in sorted(groups.items()):
        values = [row["touched_stack_high_water_bytes"] for row in observations]
        result[operation] = {"count": len(observations), "touched_stack_bytes": {
            "minimum": min(values), "median": statistics.median(values), "maximum": max(values)},
            "requested_allocation_ranges": {name: [min(row[name] for row in observations), max(row[name] for row in observations)]
                for name in ("alloc_calls", "alloc_zeroed_calls", "realloc_calls", "dealloc_calls", "total_requested_bytes",
                             "retained_requested_bytes_at_api_return", "peak_live_requested_bytes")}}
    return result

def capture(out, label):
    if label == "baseline":
        require({name: sha(ROOT / name) for name in BASELINE_CORE} == BASELINE_CORE,
                "M06 production baseline changed before capture")
    require((ROOT / PROBE / "Cargo.lock").is_file(), "freeze the standalone probe lock first")
    paths = source_files()
    decision_hash = None
    if label == "candidate":
        decision = read(out / "decision-commit.json")
        decision_hash = sha(out / "acceptance.json")
        require(decision_hash == decision["acceptance_sha256"], "acceptance decision changed")
        require(subprocess.run(["git", "merge-base", "--is-ancestor", decision["commit"], "HEAD"], cwd=ROOT).returncode == 0,
                "record the acceptance decision before the candidate")
        baseline = read(out / "baseline-source.json")["source_sha256"]
        for path in paths:
            name = path.relative_to(ROOT).as_posix()
            if name != "crates/kem1536/src/dev_kem.rs":
                require(sha(path) == baseline[name], f"unexpected other compiled input change: {name}")
        for name, checksum in baseline.items():
            if name.startswith(PROBE.as_posix() + "/"):
                require(sha(ROOT / name) == checksum, "measurement harness changed")
        paths.append(ROOT / "docs/DECISION_M07_BUDGETS.md")
    paths.extend(path for path in (ROOT / PROBE).rglob("*") if path.is_file()
                 and "target" not in path.relative_to(ROOT / PROBE).parts)
    paths.extend(ROOT / name for name in ("research/run_m07.py", "docs/PROTOCOLE_M07_MEMOIRE.md"))
    hashes = {path.relative_to(ROOT).as_posix(): sha(path) for path in sorted(set(paths))}
    destination = out / (label + "-source")
    destination.mkdir(parents=True, exist_ok=False)
    for name in hashes:
        dest = destination / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    require(inventory(destination) == hashes, "source capture changed bytes")
    save(out / (label + "-source.json"), {
        "captured_utc": utc(), "profile": "KEM1536-DEV-Q7681-R1",
        "head_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_sha256": hashes,
        "production_baseline_core": BASELINE_CORE if label == "baseline" else None,
        "acceptance_sha256": decision_hash,
        "working_diff": subprocess.check_output(["git", "diff", "HEAD", "--", "crates/kem1536/src"], cwd=ROOT, text=True),
    })
    print(json.dumps({"captured": label, "files": len(hashes)}), flush=True)

def checked_source(out, label):
    expected = read(out / (label + "-source.json"))["source_sha256"]
    require(inventory(out / (label + "-source")) == expected, "frozen source changed")
    return expected

def windows_environment(target, stack_metadata=False):
    env = dict(os.environ, CARGO_HOME=str(ROOT / ".tools/cargo"),
               RUSTUP_HOME=str(ROOT / ".tools/rustup"), RUSTUP_TOOLCHAIN="1.91.1-x86_64-pc-windows-gnu",
               RUSTUP_AUTO_INSTALL="0", CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2")
    cargo = ROOT / ".tools/cargo/bin/cargo.exe"
    rustc = ROOT / ".tools/cargo/bin/rustc.exe"
    sysroot = Path(subprocess.check_output([str(rustc), "--print", "sysroot"], env=env, text=True).strip())
    tool = sysroot / "lib/rustlib/x86_64-pc-windows-gnu/bin"
    env["PATH"] = os.pathsep.join(map(str, [ROOT / ".tools/native-tools", tool, tool / "self-contained", cargo.parent])) + os.pathsep + env["PATH"]
    env.pop("RUSTFLAGS", None)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    for name in list(env):
        if name.startswith("CARGO_PROFILE_RELEASE_") or name in ("CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
            env.pop(name)
    if stack_metadata:
        env.update(RUSTC_BOOTSTRAP="1", RUSTFLAGS="-Zemit-stack-sizes")
    return env, str(cargo), str(rustc), tool

def linux_prefix(target, stack_metadata=False):
    values = ["wsl", "-d", "Ubuntu-22.04", "--", "env", "-i",
              "CARGO_HOME=" + linux(ROOT / ".tools/linux-cargo"),
              "RUSTUP_HOME=" + linux(ROOT / ".tools/linux-rustup"),
              "RUSTUP_TOOLCHAIN=1.91.1-x86_64-unknown-linux-gnu", "RUSTUP_AUTO_INSTALL=0",
              "CARGO_BUILD_JOBS=2", "CARGO_TARGET_DIR=" + linux(target),
              "PATH=" + linux(ROOT / ".tools/linux-cargo/bin") + ":/usr/local/bin:/usr/bin:/bin"]
    if stack_metadata:
        values.extend(["RUSTC_BOOTSTRAP=1", "RUSTFLAGS=-Zemit-stack-sizes"])
    return values

def build(out, label, host):
    source = out / (label + "-source")
    hashes = checked_source(out, label)
    destination = out / label / host
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "bin").mkdir()
    target = ROOT / "target/m07-001" / label / host
    require(not target.exists(), "isolated M07 target already exists")
    configurations = [
        ("probe", ["--manifest-path", str(source / PROBE / "Cargo.toml")], "m07-memory-probe", host == "linux"),
        ("latency", ["-p", "kem1536-bench", "--bin", "m07-measure"], "m07-measure", False),
        ("research", ["-p", "kem1536-cli", "--bin", "kem1536", "--features", "research-vectors"], "kem1536", False),
        ("delivered", ["-p", "kem1536-cli", "--bin", "kem1536"], "kem1536", False),
    ]
    receipts = {}
    for name, selection, executable, metadata in configurations:
        this_target = target / name
        arguments = ["build", "--release", "--locked", "--offline", *selection]
        if host == "windows":
            env, cargo, rustc, llvm = windows_environment(this_target, metadata)
            command = [cargo, *arguments]
            versions = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
        else:
            env = None
            arguments = [linux(Path(part)) if part.startswith(str(ROOT)) else part for part in arguments]
            prefix = linux_prefix(this_target, metadata)
            command = [*prefix, linux(ROOT / ".tools/linux-cargo/bin/cargo"), *arguments]
            versions = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "-Vv"], text=True)
        require("release: 1.91.1" in versions, "wrong compiler")
        print(f"building {label}/{host}/{name}", flush=True)
        with (destination / (name + "-build.log")).open("xb") as log:
            subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        suffix = ".exe" if host == "windows" else ""
        binary = destination / "bin" / (name + suffix)
        shutil.copyfile(this_target / "release" / (executable + suffix), binary)
        receipts[name] = {"path": binary.relative_to(out).as_posix(), "sha256": sha(binary),
                          "command": command, "rustc": versions, "emit_stack_metadata": metadata}
        if metadata:
            if host == "windows":
                stack_command = [str(llvm / "llvm-readobj.exe"), "--stack-sizes", "--demangle", str(binary)]
            else:
                prefix = linux_prefix(this_target)
                sysroot = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "--print", "sysroot"], text=True).strip()
                stack_command = ["wsl", "-d", "Ubuntu-22.04", "--", sysroot + "/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-readobj", "--stack-sizes", "--demangle", linux(binary)]
            with (destination / "stack-sizes.txt").open("xb") as stream:
                subprocess.run(stack_command, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
    require(checked_source(out, label) == hashes, "build changed sources")
    save(destination / "build.json", {"profile": "KEM1536-DEV-Q7681-R1", "host": host,
         "built_utc": utc(), "source_manifest_sha256": sha(out / (label + "-source.json")),
         "controller_sha256": sha(Path(__file__)), "binaries": receipts})

def binary(out, label, host, kind):
    receipt = read(out / label / host / "build.json")["binaries"][kind]
    path = out / receipt["path"]
    require(sha(path) == receipt["sha256"], "built executable changed")
    return path

def execute(path, host, arguments, cpu=None):
    if host == "linux":
        command = ["wsl", "-d", "Ubuntu-22.04", "--"]
        if cpu is not None:
            command.extend(["taskset", "-c", str(cpu)])
        command.extend([linux(path), *map(str, arguments)])
    else:
        command = [str(path), *map(str, arguments)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout, command, result.stderr, result.returncode

def probe(out, label, host, repetitions):
    executable = binary(out, label, host, "probe")
    # The probe emits only counters/depths and public labels, never key material.
    raw, command, errors, exit_code = execute(executable, host, [str(repetitions)])
    folder = out / label / host
    with (folder / "memory.jsonl").open("xb") as stream:
        stream.write(raw)
    with (folder / "memory.stderr").open("xb") as stream:
        stream.write(errors)
    require(exit_code == 0, "native probe process failed; raw streams retained")
    rows = [json.loads(line) for line in raw.splitlines()]
    summary = validate_memory(rows, repetitions)
    save(folder / "memory-summary.json", summary)
    save(folder / "memory-run.json", {"executed_utc": utc(), "command": command,
         "binary_sha256": sha(executable), "raw_sha256": hashlib.sha256(raw).hexdigest(),
         "stderr_sha256": hashlib.sha256(errors).hexdigest(), "exit_code": exit_code,
         "controller_sha256": sha(Path(__file__))})
    print(json.dumps({"probe": label, "host": host}), flush=True)

def summarize(rows, labels, samples, series):
    groups, identities = defaultdict(list), set()
    for row in rows:
        identity = (row["version"], row["operation"], row["series"], row["iteration"])
        require(identity not in identities, "duplicate latency observation")
        identities.add(identity)
        require(row["version"] in labels and row["operation"] in OPERATIONS
                and type(row["series"]) is int and 0 <= row["series"] < series
                and type(row["iteration"]) is int and 0 <= row["iteration"] < samples
                and type(row["nanoseconds"]) is int and row["nanoseconds"] > 0, "invalid latency row")
        groups[(row["version"], row["operation"])].append(row)
    require(len(rows) == len(labels) * len(OPERATIONS) * samples * series, "latency panel incomplete")
    result = {}
    for (version, operation), items in sorted(groups.items()):
        values = sorted(row["nanoseconds"] for row in items)
        require(len(values) == samples * series, "operation panel incomplete")
        by_series = defaultdict(list)
        for row in items:
            by_series[row["series"]].append(row["nanoseconds"])
        result[version + "/" + operation] = {
            "count": len(values), "median_ns": statistics.median(values),
            "p95_ns": values[math.ceil(.95 * len(values)) - 1], "minimum_ns": values[0], "maximum_ns": values[-1],
            "series_median_ns": {str(number): statistics.median(v) for number, v in sorted(by_series.items())},
            "observations_excluded": 0,
        }
    require(len(result) == len(labels) * len(OPERATIONS), "missing operation")
    return result

def latency(out, host, paired, samples, warmup, series, cpu):
    labels = ("baseline", "candidate") if paired else ("baseline",)
    folder = out / ("paired-latency" if paired else "reference-latency") / host
    folder.mkdir(parents=True, exist_ok=False)
    rows, schedule = [], []
    # Windows child processes inherit this controller's temporary affinity.
    original_affinity = None
    if host == "windows":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.GetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
        kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        process_mask, system_mask = ctypes.c_size_t(), ctypes.c_size_t()
        handle = kernel.GetCurrentProcess()
        require(kernel.GetProcessAffinityMask(handle, ctypes.byref(process_mask), ctypes.byref(system_mask)), "cannot read affinity")
        original_affinity = process_mask.value
        require(original_affinity & (1 << cpu) and kernel.SetProcessAffinityMask(handle, ctypes.c_size_t(1 << cpu)), "invalid Windows affinity")
    try:
        for number in range(series):
            order = labels if number % 2 == 0 else labels[::-1]
            for label in order:
                started = utc()
                raw, command, errors, exit_code = execute(binary(out, label, host, "latency"), host,
                                       [number, samples, warmup], cpu if host == "linux" else None)
                with gzip.open(folder / f"{label}-{number}.stdout.gz", "xb") as stream:
                    stream.write(raw)
                with (folder / f"{label}-{number}.stderr").open("xb") as stream:
                    stream.write(errors)
                require(exit_code == 0, "latency process failed; raw streams retained")
                parsed = [dict(version=label, **json.loads(line)) for line in raw.splitlines()]
                rows.extend(parsed)
                schedule.append({"version": label, "series": number, "started_utc": started, "finished_utc": utc(),
                                 "command": command, "stdout_sha256": hashlib.sha256(raw).hexdigest(),
                                 "stderr_sha256": hashlib.sha256(errors).hexdigest(), "exit_code": exit_code})
                print(f"latency {host}/{label}/{number}: {len(parsed)}", flush=True)
    finally:
        if original_affinity is not None:
            require(kernel.SetProcessAffinityMask(handle, ctypes.c_size_t(original_affinity)), "cannot restore affinity")
    statistics_data = summarize(rows, labels, samples, series)
    with (folder / "observations.jsonl.gz").open("xb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            compressed.write(b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode() for row in rows))
    save(folder / "statistics.json", statistics_data)
    save(folder / "schedule.json", {"samples": samples, "warmup": warmup, "series": series,
         "CPU": cpu, "OS_randomness_included": True, "drop_and_validation_outside_timing": True,
         "frequency_fixed": False, "physical_core_exclusive": False, "host_activity_isolated": False,
         "controller_sha256": sha(Path(__file__)), "schedule": schedule})

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "build", "probe", "latency-reference", "latency-paired"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m07-001")
    parser.add_argument("--label", choices=("baseline", "candidate"), default="baseline")
    parser.add_argument("--host", choices=("windows", "linux"), default="windows")
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=25)
    parser.add_argument("--series", type=int, default=5)
    parser.add_argument("--cpu", type=int, default=10)
    arguments = parser.parse_args()
    require(1 <= arguments.repetitions <= 1000 and 1 <= arguments.samples <= 100_000
            and 0 <= arguments.warmup <= 10_000 and 1 <= arguments.series <= 20
            and 0 <= arguments.cpu < 64, "invalid finite measurement dimensions")
    out = owned(arguments.output, ROOT / "artifacts/generated")
    if arguments.action == "capture":
        capture(out, arguments.label)
    elif arguments.action == "build":
        build(out, arguments.label, arguments.host)
    elif arguments.action == "probe":
        probe(out, arguments.label, arguments.host, arguments.repetitions)
    else:
        latency(out, arguments.host, arguments.action == "latency-paired",
                arguments.samples, arguments.warmup, arguments.series, arguments.cpu)

if __name__ == "__main__":
    main()
