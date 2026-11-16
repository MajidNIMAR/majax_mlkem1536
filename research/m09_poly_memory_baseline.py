"""Build two unchanged M08 memory probes against the pre-mutation M09 baseline."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from m09_poly_measure import OUT, ROOT, check_source, save, sha
from run_m07 import execute, linux, linux_prefix, utc, windows_environment
from run_m08 import validate_memory


def acquire(host):
    check_source("baseline")
    source = OUT / "baseline-source"
    destination = OUT / "baseline-memory" / host
    destination.mkdir(parents=True, exist_ok=False)
    target = ROOT / "target/m09-baseline-memory" / host
    if target.exists():
        raise ValueError("new target required")
    manifest = source / "research/m08-memory-probe/Cargo.toml"
    if host == "windows":
        env, cargo, rustc, _ = windows_environment(target)
        command = [cargo, "build", "--release", "--locked", "--offline", "--manifest-path", str(manifest)]
        versions = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
    else:
        env = None
        prefix = linux_prefix(target, True)
        command = [*prefix, linux(ROOT / ".tools/linux-cargo/bin/cargo"), "build", "--release", "--locked", "--offline", "--manifest-path", linux(manifest)]
        versions = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "-Vv"], text=True)
    if "release: 1.91.1" not in versions:
        raise ValueError("wrong compiler")
    with (destination / "build.log").open("xb") as stream:
        compiled = subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT)
    suffix = ".exe" if host == "windows" else ""
    binary = destination / ("probe" + suffix)
    if compiled.returncode != 0:
        raise ValueError("baseline memory build failed")
    shutil.copyfile(target / "release" / ("m08-memory-probe" + suffix), binary)
    save(destination / "build.json", {"command": command, "exit_code": compiled.returncode,
         "rustc": versions, "binary_sha256": sha(binary), "build_log_sha256": sha(destination / "build.log"),
         "source_manifest_sha256": sha(OUT / "baseline-source.json"), "emit_stack_metadata": host == "linux",
         "controller_sha256": sha(Path(__file__))})
    raw, run_command, errors, code = execute(binary, host, [3])
    (destination / "memory.jsonl").write_bytes(raw)
    (destination / "memory.stderr").write_bytes(errors)
    save(destination / "run.json", {"command": run_command, "exit_code": code,
         "binary_sha256": sha(binary), "raw_sha256": hashlib.sha256(raw).hexdigest(),
         "stderr_sha256": hashlib.sha256(errors).hexdigest(), "executed_utc": utc(), "repetitions": 3})
    if code != 0:
        raise ValueError("baseline memory probe failed; raw streams retained")
    summary = validate_memory([json.loads(line) for line in raw.splitlines()], 3)
    save(destination / "summary.json", summary)
    check_source("baseline")
    print(json.dumps({"host": host, "observations": len(raw.splitlines()), "validated": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", choices=("windows", "linux"))
    acquire(parser.parse_args().host)
