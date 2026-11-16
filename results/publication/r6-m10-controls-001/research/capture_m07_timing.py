"""Finite eight-key/five-class M07 diagnostic after paired latency, before fuzzing.

The diagnostic executable has its own hash and shares the measured source
closure. It is not a timing proof or a claim about every delivered call path.
"""
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess

from analyze_delivery_timing import analyze
from run_m07 import ROOT, checked_source, linux, linux_prefix, read, require, save, sha, utc, windows_environment


@contextmanager
def affinity(cpu):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.GetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
    kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    process = kernel.GetCurrentProcess()
    original, system = ctypes.c_size_t(), ctypes.c_size_t()
    require(kernel.GetProcessAffinityMask(process, ctypes.byref(original), ctypes.byref(system)), "affinity unavailable")
    require(original.value & (1 << cpu) and kernel.SetProcessAffinityMask(process, ctypes.c_size_t(1 << cpu)), "CPU unavailable")
    try:
        yield
    finally:
        require(kernel.SetProcessAffinityMask(process, original), "affinity restoration failed")


def capture(out, cpu=10):
    require(os.name == "nt", "Windows/WSL coordinator required")
    evaluation = read(out / "measurements-evaluation.json")
    require(evaluation["data_valid"] and evaluation["candidate_within_budgets"], "finish accepted paired comparison first")
    source = out / "candidate-source"
    hashes = checked_source(out, "candidate")
    destination = out / "timing"
    destination.mkdir(exist_ok=False)
    shutil.copyfile(Path(__file__), destination / "controller.py")
    results = {}
    for host in ("windows", "linux"):
        folder = destination / host
        folder.mkdir()
        target = ROOT / "target/m07-001/candidate" / host / "latency"
        selection = ["build", "--release", "--locked", "--offline", "-p", "kem1536-bench", "--bin", "kem1536-bench"]
        if host == "windows":
            env, cargo, _, _ = windows_environment(target)
            command = [cargo, *selection]
        else:
            env = None
            command = [*linux_prefix(target), linux(ROOT / ".tools/linux-cargo/bin/cargo"), *selection]
        with (folder / "build.log").open("xb") as stream:
            subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        suffix = ".exe" if host == "windows" else ""
        executable = folder / ("timing" + suffix)
        shutil.copyfile(target / "release" / ("kem1536-bench" + suffix), executable)
        require(checked_source(out, "candidate") == hashes, "diagnostic build changed sources")
        run = ([str(executable), "delivery-timing"] if host == "windows" else
               ["wsl", "-d", "Ubuntu-22.04", "--", "taskset", "-c", str(cpu), linux(executable), "delivery-timing"])
        print("diagnostic " + host + ": 16000 observations", flush=True)
        with (folder / "observations.jsonl").open("xb") as stream, (folder / "runtime.stderr").open("xb") as errors:
            with affinity(cpu):
                subprocess.run(run, cwd=ROOT, stdout=stream, stderr=errors, check=True)
        report = analyze(json.loads(line) for line in (folder / "observations.jsonl").read_bytes().splitlines())
        save(folder / "analysis.json", report)
        results[host] = {"binary_sha256": sha(executable), "binary": executable.relative_to(out).as_posix(),
                         "command": run, "build_command": command, "build_log_sha256": sha(folder / "build.log"),
                         "raw_sha256": sha(folder / "observations.jsonl"), "analysis_sha256": sha(folder / "analysis.json"),
                         "maximum_absolute_t": report["maximum_absolute_t"], "threshold_crossings": report["threshold_crossings"]}
        print(json.dumps({host: results[host]["maximum_absolute_t"], "crossings": report["threshold_crossings"]}), flush=True)
    save(destination / "capture.json", {"finished_utc": utc(), "hosts": results,
         "source_manifest_sha256": sha(out / "candidate-source.json"), "controller_sha256": sha(destination / "controller.py"),
         "observations": 32000, "CPU": cpu, "frequency_fixed": False, "host_wide_isolation_proved": False,
         "build_scope": "new diagnostic executables; preexisting matched latency dependency targets reused",
         "constant_time_proved": False})


if __name__ == "__main__":
    capture(ROOT / "artifacts/generated/m07-001")
