"""Single scalar-table prototype after the rejected vectorized M09 candidate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from capture_m07_timing import affinity
from m09_poly_measure import ROOT, save, sha
from run_m07 import execute, inventory, linux, linux_prefix, windows_environment

OUT = ROOT / "artifacts/generated/m09-poly-002"
BASE = ROOT / "artifacts/generated/m09-poly-001"


def require(value, message):
    if not value:
        raise ValueError(message)


def checked():
    record = json.loads((OUT / "candidate-source.json").read_text())
    require(inventory(OUT / "candidate-source") == record["source_sha256"], "scalar candidate source changed")


def build(host, kind):
    checked()
    folder = OUT / "candidate" / host
    folder.mkdir(exist_ok=True)
    target = ROOT / "target/m09-poly-002" / host / kind
    require(not target.exists(), "new scalar target required")
    if kind == "micro":
        source = OUT / "candidate/probe-source"
        args = ["build", "--release", "--offline", "--locked"]
        executable = "m09-poly-probe"
    else:
        source = OUT / "candidate-source"
        args = ["build", "--release", "--offline", "--locked", "-p", "kem1536-bench", "--bin", "m07-measure"]
        executable = "m07-measure"
    if host == "windows":
        env, cargo, rustc, llvm = windows_environment(target, True)
        command = [cargo, *args]
        version = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
        objdump = [str(llvm / "llvm-objdump.exe")]
        readobj = [str(llvm / "llvm-readobj.exe")]
    else:
        env = None
        prefix = linux_prefix(target, True)
        command = [*prefix, linux(ROOT / ".tools/linux-cargo/bin/cargo"), *args]
        rustc = linux(ROOT / ".tools/linux-cargo/bin/rustc")
        version = subprocess.check_output([*prefix, rustc, "-Vv"], text=True)
        sysroot = subprocess.check_output([*prefix, rustc, "--print", "sysroot"], text=True).strip()
        objdump = ["wsl", "-d", "Ubuntu-22.04", "--", sysroot + "/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump"]
        readobj = [*objdump[:-1], sysroot + "/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-readobj"]
    require("release: 1.91.1" in version, "wrong compiler")
    with (folder / (kind + "-build.log")).open("xb") as stream:
        process = subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT)
    require(process.returncode == 0, "scalar build failed")
    suffix = ".exe" if host == "windows" else ""
    binary = folder / (kind + suffix)
    shutil.copyfile(target / "release" / (executable + suffix), binary)
    member = str(binary) if host == "windows" else linux(binary)
    for name, tool, args in (("disassembly", objdump, ["--disassemble", "--demangle"]),
                             ("stack", readobj, ["--stack-sizes", "--demangle"]),
                             ("sections", readobj, ["--sections"])):
        with (folder / (kind + "-" + name + ".txt")).open("xb") as stream:
            subprocess.run([*tool, *args, member], env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
    if kind == "micro":
        text = (folder / "micro-disassembly.txt").read_text()
        blocks = [b for b in text.split("\n\n") if b.splitlines()
                  and "m09_poly_probe::engine_poly::transform::" in b.splitlines()[0]
                  and b.splitlines()[0].rstrip().endswith(">:")]
        (folder / "transform.txt").write_text("\n\n".join(blocks) + "\n")
    save(folder / (kind + "-build.json"), {"command": command, "exit_code": process.returncode,
         "binary_sha256": sha(binary), "rustc": version, "source_manifest_sha256": sha(OUT / "candidate-source.json")})
    checked()


def stderr_accepted(raw, host):
    return raw == b"" or (host == "linux" and raw.replace(b"\r\n", b"\n") ==
        b"wsl: Failed to start the systemd user session for 'majid'. See journalctl for more details.\n")


def measure(host, resume=False):
    records = []
    for series in range(4):
        for label in (("baseline", "candidate") if series % 2 == 0 else ("candidate", "baseline")):
            for kind, args in (("micro", [series, 500, 50, 32]), ("kem", [series, 250, 50])):
                if label == "baseline":
                    record = json.loads((BASE / "baseline" / host / "build.json").read_text())[kind]
                    binary = BASE / record["binary"]
                    expected = record["sha256"]
                else:
                    record = json.loads((OUT / "candidate" / host / (kind + "-build.json")).read_text())
                    binary = OUT / "candidate" / host / (kind + (".exe" if host == "windows" else ""))
                    expected = record["binary_sha256"]
                require(sha(binary) == expected, "measurement binary changed")
                stem = f"{host}-{series}-{label}-{kind}"
                receipt_path = OUT / (stem + "-run.json")
                if receipt_path.exists():
                    require(resume, "existing measurement requires explicit preserving resume")
                    receipt = json.loads(receipt_path.read_text())
                    require((receipt["host"], receipt["series"], receipt["label"], receipt["kind"], receipt["binary_sha256"], receipt["exit_code"]) ==
                            (host, series, label, kind, expected, 0), "preserved measurement identity differs")
                    require(sha(OUT / receipt["raw"]) == receipt["raw_sha256"], "preserved observation bytes changed")
                    require(stderr_accepted((OUT / (stem + ".stderr")).read_bytes(), host), "unclassified preserved stderr")
                    records.append(receipt)
                    continue
                require(not (OUT / (stem + ".jsonl")).exists() and not (OUT / (stem + ".stderr")).exists(), "unreceipted old streams must not be overwritten")
                if host == "windows":
                    with affinity(10):
                        raw, command, errors, code = execute(binary, host, args)
                else:
                    raw, command, errors, code = execute(binary, host, args, cpu=10)
                with (OUT / (stem + ".jsonl")).open("xb") as stream:
                    stream.write(raw)
                with (OUT / (stem + ".stderr")).open("xb") as stream:
                    stream.write(errors)
                receipt = {"host": host, "series": series, "label": label, "kind": kind, "command": command,
                           "binary_sha256": expected, "exit_code": code, "raw_sha256": hashlib.sha256(raw).hexdigest(),
                           "raw": stem + ".jsonl"}
                save(OUT / (stem + "-run.json"), receipt)
                require(code == 0 and stderr_accepted(errors, host), "scalar measurement failed; streams retained")
                records.append(receipt)
    save(OUT / (host + "-runs.json"), records)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "measure"))
    parser.add_argument("host", choices=("windows", "linux"))
    parser.add_argument("--kind", choices=("micro", "kem"), default="micro")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    build(args.host, args.kind) if args.action == "build" else measure(args.host, args.resume)
