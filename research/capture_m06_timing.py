"""Capture the finite M06 delivery timing panel before starting heavy validation.

Use only synthetic fresh keys. Raw stdout goes straight to files, never to the
console. Completion permits the separately coordinated fuzz build to start.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time

from analyze_delivery_timing import analyze
from validate_hardening_m02 import command

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "artifacts/generated"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture():
    builds = json.loads((GENERATED / "m06-validation-001/builds.json").read_text())
    marker = GENERATED / "m06-measurements-001/MEASUREMENTS_DONE"
    if not marker.exists():
        raise ValueError("before/after measurements must finish first")
    rows = {}
    for host in ("windows", "linux"):
        folder = GENERATED / "m06-validation-001" / host
        suffix = ".exe" if host == "windows" else ""
        timing = folder / ("timing" + suffix)
        delivery = folder / ("delivered" + suffix)
        if sha(timing) != builds["builds"][host]["timing"]["sha256"]:
            raise ValueError("timing executable changed")
        if sha(delivery) != builds["builds"][host]["delivered"]["sha256"]:
            raise ValueError("delivery executable changed")
        with (GENERATED / f"m06-{host}-self-test.json").open("xb") as stream:
            subprocess.run(command(delivery, ["dev-self-test"]), cwd=ROOT,
                           stdout=stream, check=True)
        path = GENERATED / f"m06-{host}-timing.jsonl"
        started = datetime.now(timezone.utc).isoformat()
        tick = time.monotonic()
        print(f"capturing {host}: 16000 delivery-timing observations", flush=True)
        with path.open("xb") as stream:
            subprocess.run(command(timing, ["delivery-timing"]), cwd=ROOT,
                           stdout=stream, check=True)
        elapsed = time.monotonic() - tick
        if sha(timing) != builds["builds"][host]["timing"]["sha256"]:
            raise ValueError("timing executable changed during capture")
        report = analyze(json.loads(line) for line in path.read_bytes().splitlines())
        report["input_sha256"] = sha(path)
        with (GENERATED / f"m06-{host}-timing.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        rows[host] = dict(started_utc=started, elapsed_seconds=elapsed,
                          binary_sha256=sha(timing), raw_sha256=sha(path),
                          self_test_sha256=sha(GENERATED / f"m06-{host}-self-test.json"),
                          threshold_crossings=report["threshold_crossings"],
                          maximum_absolute_t=report["maximum_absolute_t"])
        print(json.dumps({host: rows[host]}), flush=True)
    receipt = dict(created_utc=datetime.now(timezone.utc).isoformat(), hosts=rows,
                   controller_platform=platform.platform(), all_outliers_retained=True,
                   controller_policy="sequential hosts; benchmark finished; fuzz/build/regression held until completion",
                   cpu_frequency_fixed=False, host_wide_isolation_proved=False,
                   constant_time_proved=False)
    with (GENERATED / "m06-timing-capture.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    with (GENERATED / "m06-measurements-001/ROOT_TIMING_DONE").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(receipt["created_utc"] + "\n")


if __name__ == "__main__":
    capture()
