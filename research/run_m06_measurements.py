"""M06 immutable single-version builds, alternating measurements and receipts.

Linux/WSL actions use the local production compiler. RSS is measured in a
separate process per version; LLVM stack sizes are static frames, not a
dynamic stack high-water mark. No production source or old evidence is edited.
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
import platform
import shutil
import statistics
import subprocess
import sys
import tarfile
import io

ROOT = Path(__file__).resolve().parents[1]
LABELS = ("baseline", "candidate")
BASELINE = "693c6a305b5143b9b00b912353bbae153cad4e4f"
HARNESS = "crates/kem1536-bench/src/bin/m06-measure.rs"


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inventory(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def snapshot_baseline(out):
    out.mkdir(parents=True)
    names = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo", "crates", "profiles", "fuzz",
             "research/kem_r1_reference.py"]
    raw = subprocess.check_output(["git", "archive", BASELINE, *names])
    (out / "baseline-source.tar").write_bytes(raw)
    destination = out / "baseline-source"
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw)) as bundle:
        for member in bundle.getmembers():
            path = (destination / member.name).resolve()
            require(path.is_relative_to(destination.resolve()), "unsafe Git archive member")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bundle.extractfile(member).read())
            else:
                raise ValueError("only plain Git source files are accepted")
    save(out / "baseline-snapshot.json", {"baseline_commit": BASELINE,
         "git_archive_sha256": hashlib.sha256(raw).hexdigest(), "source_sha256": inventory(destination)})
    return {"baseline_files": len(inventory(destination)), "baseline_commit": BASELINE}


def snapshot_after(out):
    baseline = read(out / "baseline-snapshot.json")
    require(baseline["baseline_commit"] == BASELINE, "wrong baseline commit")
    before = out / "baseline-source"
    require(inventory(before) == baseline["source_sha256"], "Git baseline changed before harness attachment")
    after = out / "candidate-source"
    after.mkdir()
    names = list(baseline["source_sha256"])
    original = {name: sha(ROOT / name) for name in names}
    for name in names:
        destination = after / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    require(original == inventory(after) == {name: sha(ROOT / name) for name in names},
            "candidate changed during source capture")
    save(out / "candidate-snapshot.json", {
        "captured_utc": utc(), "head_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "source_sha256": original,
        "working_tree_diff": subprocess.check_output(["git", "diff", "--", "crates/kem1536/src"], text=True),
    })
    harness_sha = sha(ROOT / HARNESS)
    for folder in (before, after):
        destination = folder / HARNESS
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / HARNESS, destination)
    save(out / "harness.json", {"path": HARNESS, "sha256": harness_sha,
         "note": "same additional measurement harness, absent from baseline Git commit",
         "production_baseline_from_git_archive": True})
    shutil.copyfile(Path(__file__), out / "controller.py")


def check_source(out, label):
    receipt = read(out / f"{label}-snapshot.json")["source_sha256"]
    receipt = dict(receipt, **{HARNESS: read(out / "harness.json")["sha256"]})
    require(inventory(out / f"{label}-source") == receipt, f"{label} frozen source changed")
    return receipt


def environment(target):
    env = dict(os.environ, CARGO_HOME=str(ROOT / ".tools/linux-cargo"),
               RUSTUP_HOME=str(ROOT / ".tools/linux-rustup"),
               RUSTUP_TOOLCHAIN="1.91.1-x86_64-unknown-linux-gnu", RUSTUP_AUTO_INSTALL="0", CARGO_BUILD_JOBS="2",
               CARGO_TARGET_DIR=str(target), RUSTC_BOOTSTRAP="1", RUSTFLAGS="-Zemit-stack-sizes")
    env["PATH"] = str(ROOT / ".tools/linux-cargo/bin") + ":/usr/local/bin:/usr/bin:/bin"
    return env


def capture(command, env=None):
    return subprocess.check_output(command, env=env, stderr=subprocess.STDOUT, text=True)


def build(out, target):
    require(sys.platform == "linux", "Linux local toolchain required")
    (out / "bin").mkdir()
    env = environment(target)
    cargo = str(ROOT / ".tools/linux-cargo/bin/cargo")
    rustc = str(ROOT / ".tools/linux-cargo/bin/rustc")
    versions = {"rustc": capture([rustc, "-Vv"], env), "cargo": capture([cargo, "-V"], env),
                "gcc": capture(["gcc", "--version"]), "platform": platform.platform(),
                "lscpu": capture(["lscpu"])}
    require("release: 1.91.1" in versions["rustc"], "unexpected compiler")
    receipts = {}
    for label in LABELS:
        hashes = check_source(out, label)
        this_target = target / label
        require(not this_target.exists(), "new isolated target required")
        this_env = environment(this_target)
        command = [cargo, "build", "--locked", "--offline", "--release", "-p", "kem1536-bench", "--bin", "m06-measure"]
        with (out / f"{label}-build.log").open("xb") as log:
            subprocess.run(command, cwd=out / f"{label}-source", env=this_env, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
        require(check_source(out, label) == hashes, "build changed frozen source or lock")
        binary = out / "bin" / f"{label}-m06-measure"
        shutil.copyfile(this_target / "release/m06-measure", binary)
        binary.chmod(0o700)
        sysroot = Path(capture([rustc, "--print", "sysroot"], env).strip())
        llvm = sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-readobj"
        raw = capture([str(llvm), "--stack-sizes", "--demangle", str(binary)])
        with (out / f"{label}-stack-sizes.txt").open("x", encoding="utf-8") as stream:
            stream.write(raw)
        receipts[label] = {"binary_sha256": sha(binary), "source_sha256": hashes, "command": command,
                           "target_dir": str(this_target), "rustflags": this_env["RUSTFLAGS"],
                           "stack_metadata_only_unstable_flag": True}
    save(out / "build.json", {"versions": versions, "versions_built_separately": True, "builds": receipts})


def summarize(rows, samples=2000, series=5):
    grouped = defaultdict(list)
    identities = set()
    for row in rows:
        identity = (row["version"], row["operation"], row["series"], row["iteration"])
        require(identity not in identities, "duplicate observation")
        identities.add(identity)
        require(row["version"] in LABELS and row["operation"] in ("keygen", "encaps", "decaps")
                and 0 <= row["series"] < series and 0 <= row["iteration"] < samples
                and isinstance(row["nanoseconds"], int) and row["nanoseconds"] > 0,
                "invalid observation")
        grouped[(row["version"], row["operation"])].append(row["nanoseconds"])
    require(len(grouped) == 6 and len(rows) == 6 * samples * series, "observation panel incomplete")
    result = {}
    for (label, op), values in sorted(grouped.items()):
        require(len(values) == samples * series, "operation panel incomplete")
        values = sorted(values)
        result[f"{label}/{op}"] = {"count": len(values), "median_ns": statistics.median(values),
            "p95_ns": values[math.ceil(len(values) * .95) - 1], "mean_ns": statistics.mean(values),
            "minimum_ns": values[0], "maximum_ns": values[-1]}
    return result


def dispersion(rows):
    """Descriptive post-hoc Tukey counts; no observation is removed."""
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["version"], row["operation"])].append(row)
    result = {}
    for (label, op), observations in sorted(grouped.items()):
        by_series = defaultdict(list)
        for row in observations:
            by_series[row["series"]].append(row["nanoseconds"])
        values = sorted(row["nanoseconds"] for row in observations)
        q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive")
        iqr = q3 - q1
        result[f"{label}/{op}"] = {
            "series_median_ns": {str(s): statistics.median(v) for s, v in sorted(by_series.items())},
            "q1_ns": q1, "q3_ns": q3, "IQR_ns": iqr,
            "posthoc_Tukey_below_q1_minus_1_5_IQR": sum(v < q1 - 1.5 * iqr for v in values),
            "posthoc_Tukey_above_q3_plus_1_5_IQR": sum(v > q3 + 1.5 * iqr for v in values),
            "maximum_ns": max(values), "observations_excluded": 0,
        }
    return result


def measure(out, cpu, samples, warmup, series):
    require(sys.platform == "linux" and cpu in os.sched_getaffinity(0), "valid Linux CPU required")
    build_data = read(out / "build.json")
    rows, schedule = [], []
    shutil.copyfile(Path(__file__), out / "measurement-controller.py")
    save(out / "measurement-controller.json", {"sha256": sha(out / "measurement-controller.py"),
         "scope": "controller actually used for measurement; original controller.py was preserved before build"})
    save(out / "measurement-environment.json", {"started_utc": utc(), "CPU": cpu,
        "samples_per_operation_per_series": samples, "series": series, "warmup_per_operation": warmup,
        "proc_loadavg": Path("/proc/loadavg").read_text(), "processes": capture(["ps", "-eo", "pid,comm,pcpu", "--sort=-pcpu"]),
        "frequency_fixed": False, "host_activity_isolation_proven": False,
        "OS_randomness_included_keygen_and_encaps": True, "validation_and_drop_outside_timer": True})
    for number in range(series):
        order = LABELS if number % 2 == 0 else LABELS[::-1]
        for label in order:
            binary = out / "bin" / f"{label}-m06-measure"
            require(sha(binary) == build_data["builds"][label]["binary_sha256"], "measurement binary changed")
            command = ["taskset", "-c", str(cpu), str(binary), "measure", str(number), str(samples), str(warmup)]
            started = utc()
            raw = subprocess.check_output(command, stderr=subprocess.STDOUT)
            parsed = [dict(version=label, **json.loads(line)) for line in raw.splitlines()]
            require(len(parsed) == samples * 3, "series did not emit its full sample count")
            rows.extend(parsed)
            schedule.append({"version": label, "series": number, "started_utc": started, "finished_utc": utc(),
                             "command": command, "exit_code": 0})
            print(f"measured {label} series {number}: {len(parsed)} observations", flush=True)
    raw = b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode() for row in rows)
    with (out / "observations.jsonl.gz").open("xb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            compressed.write(raw)
    save(out / "statistics.json", summarize(rows, samples, series))
    save(out / "schedule.json", schedule)
    memory = []
    for label in LABELS:
        binary = out / "bin" / f"{label}-m06-measure"
        usage = out / f"{label}-rss.json"
        command = ["/usr/bin/time", "-f", '{"peak_RSS_KiB":%M,"user_seconds":%U,"system_seconds":%S}',
                   "-o", str(usage), "taskset", "-c", str(cpu), str(binary), "rss"]
        actual = json.loads(subprocess.check_output(command))
        require(actual == {"round_trips": 1000, "secrets_printed": False}, "RSS round trips failed")
        memory.append({"version": label, "command": command, "usage": read(usage), "round_trips": 1000})
    save(out / "memory.json", {"measurements": memory, "separate_process_for_each_version": True,
        "RSS_includes_runtime_allocator_executable_harness": True, "static_stack_frames_in_separate_files": True,
        "dynamic_stack_peak_measured": False})
    (out / "MEASUREMENTS_DONE").write_text(utc() + "\n")
    save(out / "provenance.json", {"finished_utc": utc(), "output_sha256": inventory(out),
                                  "no_constant_time_or_security_claim": True})
    return verify(out)


def verify(out):
    receipt = read(out / "provenance.json")
    for name, expected in receipt["output_sha256"].items():
        path = (out / name).resolve()
        require(path.is_relative_to(out.resolve()) and sha(path) == expected, f"measurement checksum: {name}")
    environment_data = read(out / "measurement-environment.json")
    with gzip.open(out / "observations.jsonl.gz", "rt") as stream:
        rows = [json.loads(line) for line in stream]
    expected = summarize(rows, environment_data["samples_per_operation_per_series"], environment_data["series"])
    require(expected == read(out / "statistics.json"), "measurement statistics differ")
    baseline = read(out / "baseline-snapshot.json")
    require(baseline["baseline_commit"] == BASELINE and sha(out / "baseline-source.tar") == baseline["git_archive_sha256"], "Git baseline receipt differs")
    with tarfile.open(out / "baseline-source.tar") as bundle:
        require(bundle.pax_headers.get("comment") == BASELINE, "Git archive commit identifier differs")
        archived = {m.name: hashlib.sha256(bundle.extractfile(m).read()).hexdigest()
                    for m in bundle.getmembers() if m.isfile()}
    require(archived == baseline["source_sha256"], "Git baseline archive content differs")
    for label in LABELS:
        check_source(out, label)
    require(read(out / "memory.json")["separate_process_for_each_version"], "mixed RSS process")
    return {"observations_verified": len(rows), "operations_per_version": 3, "sources_verified": True,
            "descriptive_dispersion": dispersion(rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("snapshot-baseline", "snapshot-after", "build", "measure", "verify", "freeze"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m06-measurements-001")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/m06-measurements-001")
    parser.add_argument("--cpu", type=int, default=10)
    parser.add_argument("--samples", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--series", type=int, default=5)
    args = parser.parse_args()
    out, target = args.output.resolve(), args.target_dir.resolve()
    require(out.is_relative_to(ROOT / "artifacts/generated") or out.is_relative_to(ROOT / "results/engine"), "NIST output required")
    require(target.is_relative_to(ROOT / "target") and target.name.startswith("m06"), "new M06 target required")
    if args.action == "snapshot-baseline":
        result = snapshot_baseline(out)
    elif args.action == "snapshot-after":
        result = snapshot_after(out)
    elif args.action == "build":
        result = build(out, target)
    elif args.action == "measure":
        result = measure(out, args.cpu, args.samples, args.warmup, args.series)
    elif args.action == "verify":
        result = verify(out)
    else:
        verify(out)
        archive = ROOT / "results/engine/m06-measurements-001"
        require(not archive.exists(), "never replace M06 frozen measurements")
        shutil.copytree(out, archive)
        result = verify(archive)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
