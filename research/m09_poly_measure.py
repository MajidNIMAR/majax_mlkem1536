"""Isolated M08/table-NTT acquisitions; historical evidence is read only."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import shutil
import statistics
import subprocess

from capture_m07_timing import affinity
from run_m07 import execute, linux, linux_prefix, windows_environment

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/generated/m09-poly-001"
POLY = "crates/kem1536/src/engine_poly.rs"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def manifest(folder):
    return {p.relative_to(folder).as_posix(): sha(p)
            for p in sorted(folder.rglob("*")) if p.is_file()}


def check_source(label):
    expected = json.loads((OUT / (label + "-source.json")).read_text())["source_sha256"]
    if manifest(OUT / (label + "-source")) != expected:
        raise ValueError("captured source changed")
    return expected


def prepare(label):
    if label == "candidate":
        check_source("baseline")
        if not (OUT / "preregistration.json").is_file():
            raise ValueError("preregister before candidate")
        shutil.copytree(OUT / "baseline-source", OUT / "candidate-source")
        shutil.copyfile(ROOT / POLY, OUT / "candidate-source" / POLY)
        hashes = manifest(OUT / "candidate-source")
        baseline = check_source("baseline")
        assert set(hashes) == set(baseline)
        assert all(hashes[n] == h for n, h in baseline.items() if n != POLY)
        save(OUT / "candidate-source.json", {"source_sha256": hashes,
             "baseline_manifest_sha256": sha(OUT / "baseline-source.json"),
             "preregistration_sha256": sha(OUT / "preregistration.json")})
    check_source(label)
    folder = OUT / label / "probe-source"
    (folder / "src").mkdir(parents=True, exist_ok=False)
    original = ROOT / "research/m09-poly-probe"
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(original / name, folder / name)
    main = (original / "src/main.rs").read_text().replace(
        "../../../crates/kem1536/src/engine_poly.rs",
        f"../../../{label}-source/crates/kem1536/src/engine_poly.rs")
    (folder / "src/main.rs").write_text(main, newline="\n")
    save(OUT / label / "probe-source.json", manifest(folder))


def build(label, host):
    check_source(label)
    destination = OUT / label / host
    destination.mkdir(exist_ok=False)
    receipts = {}
    for kind in ("micro", "kem"):
        target = ROOT / "target/m09-poly-001" / label / host / kind
        if kind == "micro":
            source = OUT / label / "probe-source"
            arguments = ["build", "--release", "--offline", "--locked"]
            name = "m09-poly-probe"
        else:
            source = OUT / (label + "-source")
            arguments = ["build", "--release", "--offline", "--locked", "-p", "kem1536-bench", "--bin", "m07-measure"]
            name = "m07-measure"
        if host == "windows":
            env, cargo, rustc, llvm = windows_environment(target, True)
            command = [cargo, *arguments]
            versions = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
            readobj = [str(llvm / "llvm-readobj.exe")]
        else:
            env = None
            prefix = linux_prefix(target, True)
            command = [*prefix, linux(ROOT / ".tools/linux-cargo/bin/cargo"), *arguments]
            versions = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "-Vv"], text=True)
            sysroot = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "--print", "sysroot"], text=True).strip()
            readobj = ["wsl", "-d", "Ubuntu-22.04", "--", sysroot + "/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-readobj"]
        assert "release: 1.91.1" in versions
        with (destination / (kind + "-build.log")).open("xb") as stream:
            subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        suffix = ".exe" if host == "windows" else ""
        binary = destination / (kind + suffix)
        shutil.copyfile(target / "release" / (name + suffix), binary)
        member = str(binary) if host == "windows" else linux(binary)
        for scope, args in (("sections", ["--sections"]), ("stack", ["--stack-sizes", "--demangle"])):
            with (destination / (kind + "-" + scope + ".txt")).open("xb") as stream:
                subprocess.run([*readobj, *args, member], env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        receipts[kind] = {"sha256": sha(binary), "command": command, "rustc": versions,
                           "binary": binary.relative_to(OUT).as_posix()}
    check_source(label)
    save(destination / "build.json", receipts)


def measure(host, prefix, series_count=5):
    records = []
    for series in range(series_count):
        for label in (("baseline", "candidate") if series % 2 == 0 else ("candidate", "baseline")):
            for kind, args in (("micro", [series, 500, 50, 32]), ("kem", [series, 250, 50])):
                receipt = json.loads((OUT / label / host / "build.json").read_text())[kind]
                binary = OUT / receipt["binary"]
                assert sha(binary) == receipt["sha256"]
                stem = f"{prefix}-{host}-{series}-{label}-{kind}"
                before = datetime.now(timezone.utc).isoformat()
                if host == "windows":
                    with affinity(10):
                        raw, command, err, code = execute(binary, host, args)
                else:
                    raw, command, err, code = execute(binary, host, args, cpu=10)
                (OUT / (stem + ".jsonl")).write_bytes(raw)
                (OUT / (stem + ".stderr")).write_bytes(err)
                record = {"label": label, "host": host, "kind": kind, "series": series,
                          "command": command, "binary_sha256": sha(binary), "started_utc": before,
                          "ended_utc": datetime.now(timezone.utc).isoformat(), "exit_code": code,
                          "raw": stem + ".jsonl", "raw_sha256": sha(OUT / (stem + ".jsonl"))}
                save(OUT / (stem + "-run.json"), record)
                assert code == 0 and not err
                records.append(record)
    save(OUT / f"{prefix}-{host}-runs.json", records)


def summarize(prefix):
    reports = {}
    for host in ("windows", "linux"):
        groups = defaultdict(list)
        records = json.loads((OUT / f"{prefix}-{host}-runs.json").read_text())
        assert len(records) == 20
        for record in records:
            path = OUT / record["raw"]
            assert sha(path) == record["raw_sha256"] and record["exit_code"] == 0
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            operations = ("forward", "inverse", "multiply_add") if record["kind"] == "micro" else ("keygen", "encaps", "decaps_valid", "decaps_rejected")
            count = 500 if record["kind"] == "micro" else 250
            assert len(rows) == count * len(operations)
            assert {(r["operation"], r["iteration"]) for r in rows} == {(op, i) for op in operations for i in range(count)}
            for row in rows:
                assert row["series"] == record["series"] and type(row["nanoseconds"]) is int and row["nanoseconds"] > 0
                batch = row.get("batch", 1)
                assert batch == (32 if record["kind"] == "micro" else 1)
                groups[(record["label"], row["operation"])].append(row["nanoseconds"] / batch)
        summaries = {}
        for (label, operation), values in groups.items():
            values.sort()
            summaries.setdefault(operation, {})[label] = {"count": len(values), "median_ns": statistics.median(values), "p95_ns": values[math.ceil(.95 * len(values)) - 1]}
        for operation, panel in summaries.items():
            ratio = {name: panel["candidate"][name] / panel["baseline"][name] for name in ("median_ns", "p95_ns")}
            limits = (.90, 1.20) if operation in ("forward", "inverse") else (1.10, 1.25) if operation == "multiply_add" else (1.05, 1.20)
            panel["ratios"] = ratio
            panel["budget_passed"] = ratio["median_ns"] <= limits[0] and ratio["p95_ns"] <= limits[1]
        reports[host] = summaries
    save(OUT / (prefix + "-summary.json"), reports)
    print(json.dumps(reports, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "build", "measure", "summarize"))
    parser.add_argument("--label", choices=("baseline", "candidate"))
    parser.add_argument("--host", choices=("windows", "linux"))
    parser.add_argument("--prefix", default="paired-001")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.label)
    elif args.action == "build":
        build(args.label, args.host)
    elif args.action == "measure":
        measure(args.host, args.prefix)
    else:
        summarize(args.prefix)


if __name__ == "__main__":
    main()
