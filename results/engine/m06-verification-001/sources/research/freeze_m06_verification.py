"""Run final M06 evidence gates and preserve their integration receipts.

Windows coordinator for the project's configured WSL distribution. It does
not publish, install tools, restart the campaign or rerun benchmarks.
"""

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "artifacts/generated"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def freeze(output):
    if sys.platform != "win32" or output.exists() or output.parent != ROOT / "results/engine":
        raise ValueError("new project-local output on Windows required")
    if not (ROOT / "results/engine/m06-fuzz-001/provenance.json").is_file():
        raise ValueError("finish the finite campaign and its postprocessing first")
    compiled = json.loads((ROOT / "results/engine/m06-001/builds.json").read_text())
    for name in ("crates/kem1536/src/dev_kem.rs", "crates/kem1536/src/engine_poly.rs"):
        if sha(ROOT / name) != compiled["source_sha256"][name]:
            raise ValueError("the preserved engine no longer matches current production sources")
    output.mkdir()
    python = str(ROOT / ".tools/research-venv/Scripts/python.exe")
    commands = {
        "windows-engine": [python, "-B", "research/verify_m06.py"],
        "windows-measurements": [python, "-B", "research/run_m06_measurements.py", "verify", "--output", "results/engine/m06-measurements-001"],
        "windows-rejection": [python, "-B", "research/rejection_security_m06.py", "--verify", "results/security/m06-rejection-001"],
        "windows-fuzz": [python, "-B", "research/run_m06_fuzz.py", "verify-archive", "--output", "results/engine/m06-fuzz-001"],
        "windows-python-tests": [python, "-B", "-m", "unittest", "discover", "-s", "research", "-p", "test_*.py"],
        "linux-fuzz": ["wsl", "-d", "Ubuntu-22.04", "--", "python3", "-B", "research/run_m06_fuzz.py", "verify-archive", "--output", "results/engine/m06-fuzz-001"],
        "linux-new-tests": ["wsl", "-d", "Ubuntu-22.04", "--", "python3", "-B", "-m", "unittest", "discover", "-s", "research", "-p", "test_*m06*.py"],
    }
    receipts = {}
    (output / "checks").mkdir()
    for name, command in commands.items():
        path = output / "checks" / (name + ".log")
        print("checking " + name, flush=True)
        with path.open("xb") as stream:
            subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=True)
        receipts[name] = dict(command=command, exit_code=0, output_sha256=sha(path))
    final_tests = (output / "checks/windows-python-tests.log").read_text()
    count = int(re.search(r"Ran (\d+) tests", final_tests)[1])
    prior = ("m06-windows-check-initial-failed.log", "m06-windows-check.log", "m06-linux-tests.log",
             "m06-linux-research-tests.log", "m06-linux-engine-replay.log", "m06-final-python-tests.log",
             "m06-final-clippy.log", "m06-final-clippy-all-features.log", "m06-final-rust-tests.log",
             "m06-engine-self-test.log", "m06-canonical-binary.json")
    (output / "earlier-checks").mkdir()
    for name in prior:
        shutil.copyfile(GENERATED / name, output / "earlier-checks" / name)
    with (output / "canonical-windows-engine.exe.gz").open("xb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
            compressed.write((ROOT / "target/release/kem1536.exe").read_bytes())
    canonical = json.loads((GENERATED / "m06-canonical-binary.json").read_text())
    if sha(ROOT / "target/release/kem1536.exe") != canonical["sha256"]:
        raise ValueError("canonical release binary changed since its confirmation")
    sources = ["scripts/dev.ps1", "scripts/dev.sh", "research/freeze_m06_verification.py",
               "research/run_m06_fuzz.py", "research/replay_m06_fuzz_corpus.py", "research/test_m06_fuzz.py",
               "research/inspect_m06_coverage.py",
               "crates/kem1536-bench/src/bin/m06-replay.rs"]
    for name in sources:
        destination = output / "sources" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    summary = dict(created_utc=datetime.now(timezone.utc).isoformat(), checks=receipts,
                   final_Windows_Python_tests=count, full_Windows_check_earlier_exit_code=0,
                   full_Windows_check_earlier_Python_tests=144,
                   full_Windows_check_scope="after production change and initial M06 tools; later harness/tool additions covered by final gates and Rust/Clippy receipts",
                   first_Windows_check_failed=True, first_failure="obsolete M04 certificate source anchors; reviewed and fixed",
                   Linux_scope="Rust default/all-features, targeted M06 tests and preserved evidence replay; no new full Linux check",
                   current_production_source_sha256={n: sha(ROOT / n) for n in compiled["source_sha256"] if n.endswith(("dev_kem.rs", "engine_poly.rs"))},
                   constant_time_proved=False, full_concrete_CCA_proof=False, remote_publication_performed=False)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    manifest = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "provenance.json").write_text(json.dumps(dict(output_sha256=manifest), indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(dict(files_verified=len(manifest), Python_tests=count, all_final_gates_passed=True), indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/engine/m06-verification-001")
    freeze(parser.parse_args().output.resolve())
