"""Compare the current Windows/Linux research binaries with all frozen R1 outputs."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import time
from validate_hardening_m02 import ROOT, command, lines, regression


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "artifacts/generated"):
        raise ValueError("new output under artifacts/generated required")
    binaries = {"windows": args.windows.resolve(), "linux": args.linux.resolve()}
    hashes = {name: sha(path) for name, path in binaries.items()}
    output.mkdir(parents=True)
    start = time.monotonic()
    reports = {}
    for name, binary in binaries.items():
        print(f"{name}: complete vectors and rejection regression", flush=True)
        report = regression(binary)
        report["formats"] = json.loads(subprocess.check_output(command(binary, ["dev-hardening"])))
        if report["formats"]["inputs"] != 20000:
            raise ValueError("format panel incomplete")
        with gzip.open(ROOT / "results/engine/hardening-001/mutations.jsonl.gz", "rb") as frozen:
            count = 0
            for a, b in itertools.zip_longest(lines(binary, ["dev-mutations"]), frozen):
                if a is None or b is None or json.loads(a) != json.loads(b):
                    raise ValueError(f"mutation regression differs: {name}/{count}")
                count += 1
        if count != 10000:
            raise ValueError("mutation panel incomplete")
        report["frozen_M02_mutations_compared"] = count
        reports[name] = report
        print(f"{name}: all 1000 vectors, 10000 rejections, 20000 formats, 10000 mutations pass", flush=True)
    if reports["windows"]["formats"] != reports["linux"]["formats"]:
        raise ValueError("format decisions differ by platform")
    if hashes != {name: sha(path) for name, path in binaries.items()}:
        raise ValueError("a binary changed during verification")
    sources = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "research/validate_m04_engine.py"]
    sources += [p.relative_to(ROOT).as_posix() for p in (ROOT / "crates").rglob("*") if p.is_file()]
    for source in sources:
        destination = output / "sources" / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source, destination)
    result = {"created_utc": datetime.now(timezone.utc).isoformat(), "profile": "KEM1536-DEV-Q7681-R1",
              "platforms": reports, "binary_sha256": hashes, "elapsed_seconds": time.monotonic() - start,
              "oracle_scope": "complete equality to frozen M01/M02 outputs, previously independently checked; no new Python rare-event simulation",
              "constant_time_proved": False, "source_sha256": {s: sha(output / "sources" / s) for s in sources}}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
