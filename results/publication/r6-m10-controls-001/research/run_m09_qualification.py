"""New M09 PC source capture, six builds per OS, and finite validation.

Never replaces M08 evidence. Outputs must be new direct generated children.
The original instrument programs are reused as unchanged source, not as old
measurement credit. Compiler caches/tools are shared and explicitly recorded.
"""
import argparse
import gzip
import itertools
import json
from pathlib import Path
import shutil
import subprocess

from build_m06_validation import source_files
from run_m07 import linux, linux_prefix, read, require, save, sha, utc, windows_environment
import validate_hardening_m02 as validation
from analyze_delivery_timing import analyze
from capture_m07_timing import affinity
from run_m08 import validate_memory

ROOT = Path(__file__).resolve().parents[1]
KINDS = ("research", "delivered", "consumer", "latency", "timing", "probe")
PROBE = Path("research/m08-memory-probe")
CONSUMER = Path("research/m08-import-consumer")
CONTROLS = ("run_m09_qualification.py", "build_m06_validation.py", "run_m07.py", "run_m08.py",
            "capture_m07_timing.py", "validate_hardening_m02.py", "analyze_delivery_timing.py",
            "verify_r1_certificate_bridge.py", "m09_source_contract.py")


def inventory(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def checked(out):
    source = read(out / "source.json")
    require(inventory(out / "source") == source["source_sha256"], "M09 source capture changed")
    return source


def capture(out):
    require(not out.exists(), "new M09 output required")
    paths = source_files()
    for folder in (PROBE, CONSUMER):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.is_file()
                     and "target" not in p.relative_to(ROOT / folder).parts)
    paths.extend(ROOT / "research" / p for p in CONTROLS)
    paths.extend(ROOT / name for name in ("docs/PROTOCOLE_M09_MOTEUR.md", "docs/PROTOCOLE_M09_QUALIFICATION.md",
        "docs/ADDENDUM_M09_SCALAIRE.md", "LICENSE", "NOTICE",
        "THIRD_PARTY_NOTICES.md", "docs/SPECIFICATION_DEV_Q7681_R1.md"))
    out.mkdir(parents=True)
    for path in sorted(set(paths)):
        dest = out / "source" / path.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
    save(out / "source.json", {"profile": "KEM1536-DEV-Q7681-R1", "captured_utc": utc(),
        "source_sha256": inventory(out / "source"),
        "head_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "working_diff": subprocess.check_output(["git", "diff", "--", "crates"], text=True),
        "scope": "Full current compilable closure plus unchanged M08 instruments and M09 controls; not M09-poly isolated variant."})


def build(out, host):
    checked(out)
    folder = out / host
    folder.mkdir()
    (folder / "bin").mkdir()
    target = ROOT / "target" / out.name / host
    require(not target.exists(), "new isolated target required")
    source = out / "source"
    configs = (
        ("research", ["-p", "kem1536-cli", "--bin", "kem1536", "--features", "research-vectors"], "kem1536", False),
        ("delivered", ["-p", "kem1536-cli", "--bin", "kem1536"], "kem1536", False),
        ("consumer", ["--manifest-path", str(source / CONSUMER / "Cargo.toml")], "m08-import-consumer", False),
        ("latency", ["-p", "kem1536-bench", "--bin", "m07-measure"], "m07-measure", False),
        ("timing", ["-p", "kem1536-bench", "--bin", "kem1536-bench"], "kem1536-bench", False),
        ("probe", ["--manifest-path", str(source / PROBE / "Cargo.toml")], "m08-memory-probe", host == "linux"),
    )
    receipts = {}
    for kind, select, executable, metadata in configs:
        arguments = ["build", "--release", "--locked", "--offline", *select]
        if host == "windows":
            env, cargo, rustc, _ = windows_environment(target, metadata)
            command = [cargo, *arguments]
            version = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
        else:
            env = None
            arguments = [linux(Path(p)) if p.startswith(str(ROOT)) else p for p in arguments]
            prefix = linux_prefix(target, metadata)
            command = [*prefix, linux(ROOT / ".tools/linux-cargo/bin/cargo"), *arguments]
            version = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "-Vv"], text=True)
        require("release: 1.91.1" in version, "unexpected compiler")
        print(f"M09 build {host}/{kind}", flush=True)
        started = utc()
        with (folder / (kind + "-build.log")).open("xb") as log:
            completed = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
        require(completed.returncode == 0, "M09 build failed: " + kind)
        suffix = ".exe" if host == "windows" else ""
        dest = folder / "bin" / (kind + suffix)
        shutil.copyfile(target / "release" / (executable + suffix), dest)
        receipts[kind] = {"path": dest.relative_to(out).as_posix(), "sha256": sha(dest), "command": command,
            "rustc": version, "emit_stack_metadata": metadata, "exit_code": completed.returncode,
            "started_utc": started, "finished_utc": utc()}
    checked(out)
    save(folder / "build.json", {"profile": "KEM1536-DEV-Q7681-R1", "host": host,
        "source_manifest_sha256": sha(out / "source.json"), "binaries": receipts,
        "compiler_tools_and_dependency_caches_shared": True})


def image(out, host, kind):
    receipt = read(out / host / "build.json")
    require(receipt["source_manifest_sha256"] == sha(out / "source.json"), "source/image binding changed")
    row = receipt["binaries"][kind]
    path = out / row["path"]
    require(path.resolve().is_relative_to(out) and sha(path) == row["sha256"], "M09 image changed")
    return path


def run(out, host, kind, args, name, expected=0):
    folder = out / "validation" / host
    folder.mkdir(parents=True, exist_ok=True)
    command = validation.command(image(out, host, kind), args)
    started = utc()
    with (folder / (name + ".stdout")).open("xb") as log, (folder / (name + ".stderr")).open("xb") as errors:
        process = subprocess.run(command, cwd=ROOT, stdout=log, stderr=errors)
    save(folder / (name + ".receipt.json"), {"command": command, "started_utc": started,
        "finished_utc": utc(), "exit_code": process.returncode, "expected_exit_code": expected,
        "binary_sha256": sha(image(out, host, kind))})
    require(process.returncode == expected, "M09 command failed: " + name)
    return folder / (name + ".stdout")


def validate(out):
    checked(out)
    summary = {}
    ref = validation.oracle()
    for host in ("windows", "linux"):
        print("M09 full finite validation " + host, flush=True)
        binary = image(out, host, "research")
        # Capture every line generated during the existing full byte comparison.
        original_lines = validation.lines
        def captured_lines(binary, args):
            name = args[0]
            folder = out / "validation" / host
            folder.mkdir(parents=True, exist_ok=True)
            with (folder / (name + ".jsonl.gz")).open("xb") as raw:
                with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
                    for line in original_lines(binary, args):
                        zipped.write(line)
                        yield line
        validation.lines = captured_lines
        try:
            regression = validation.regression(binary)
            mutation = validation.mutations(captured_lines(binary, ["dev-mutations"]), ref)
        finally:
            validation.lines = original_lines
        require(mutation["cases"] == 10000, "full mutation panel required")
        formats = read(run(out, host, "research", ["dev-hardening"], "formats"))
        require(formats["inputs"] == 20000, "format panel incomplete")
        diagnostics = read(run(out, host, "delivered", ["dev-self-test"], "cli-self-test"))
        require(diagnostics["fresh_round_trips"] == 16 and diagnostics["implicit_rejections_checked"] == 16,
                "native CLI smoke missing")
        for index, args in enumerate((("dev-vectors", "1"), ("dev-rejection-vectors",),
                ("dev-hardening",), ("dev-mutations",), ("dev-timing",))):
            run(out, host, "delivered", list(args), "disabled-research-" + str(index), 1)
        run(out, host, "consumer", ["smoke"], "consumer-smoke")
        exhaustive = read(run(out, host, "consumer", ["exhaustive"], "consumer-exhaustive"))
        memory = run(out, host, "probe", ["3"], "memory")
        memory_summary = validate_memory([json.loads(line) for line in memory.read_bytes().splitlines()], 3)
        save(out / "validation" / host / "memory-summary.json", memory_summary)
        summary[host] = {"regression": regression, "mutation": mutation, "formats": formats,
            "CLI": diagnostics, "consumer": exhaustive, "memory": memory_summary}
    require(summary["windows"]["mutation"] == summary["linux"]["mutation"], "cross-OS mutations differ")
    require(summary["windows"]["formats"] == summary["linux"]["formats"], "cross-OS formats differ")
    checked(out)
    save(out / "validation.json", {"finished_utc": utc(), "source_manifest_sha256": sha(out / "source.json"),
        "hosts": summary, "fresh_fuzzing_credit_seconds": 0, "historical_campaign_credit": 0,
        "constant_time_or_global_erasure_proved": False})


def timing(out, cpu):
    for host in ("windows", "linux"):
        folder = out / "timing" / host
        folder.mkdir(parents=True)
        binary = image(out, host, "timing")
        command = validation.command(binary, ["delivery-timing"])
        if host == "linux":
            command = ["wsl", "-d", "Ubuntu-22.04", "--", "taskset", "-c", str(cpu), linux(binary), "delivery-timing"]
        started = utc()
        with affinity(cpu), (folder / "observations.jsonl").open("xb") as log, (folder / "stderr").open("xb") as errors:
            process = subprocess.run(command, stdout=log, stderr=errors)
        save(folder / "receipt.json", {"command": command, "binary_sha256": sha(binary), "started_utc": started,
            "finished_utc": utc(), "exit_code": process.returncode, "CPU": cpu, "frequency_fixed": False,
            "host_wide_isolation_proved": False, "constant_time_proved": False})
        require(process.returncode == 0, "timing executable failed")
        report = analyze(json.loads(line) for line in (folder / "observations.jsonl").read_bytes().splitlines())
        save(folder / "analysis.json", report)
        print(json.dumps({"host": host, "maximum_absolute_t": report["maximum_absolute_t"],
            "threshold_crossings": report["threshold_crossings"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "validate", "timing"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=10)
    args = parser.parse_args()
    out = args.output.resolve()
    require(out.parent == ROOT / "artifacts/generated", "direct generated child required")
    if args.action == "build":
        capture(out)
        for host in ("windows", "linux"):
            build(out, host)
    elif args.action == "validate":
        validate(out)
    else:
        timing(out, args.cpu)


if __name__ == "__main__":
    main()
