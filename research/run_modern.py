"""Run a bounded, explicit attack matrix and preserve every failure/timeout."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from modern_tools import ROOT, sources


def jobs():
    scenarios = [("baseline-1024", 4, 3329, 2), ("p0-1536", 6, 3329, 2),
                 ("q7681-eta2", 6, 7681, 2), ("q7681-eta3", 6, 7681, 3)]
    for scenario, k, q, eta in scenarios:
        for budget in ("key", "extended"):
            base = {"scenario": scenario, "parameters": {"n": 256, "k": k, "q": q, "eta": eta},
                    "sample_budget": budget, "samples": 256*(k+(budget == "extended")),
                    "targets": 1, "oracle": "none", "shape_model": "GSA",
                    "memory_cap": "none; exponential memory allowed"}
            for model in ("MATZOV-classical", "BCSS23-quantum-asymptotic"):
                algorithms = ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid")
                for algorithm in algorithms:
                    yield base | {"tool": "community", "cost_model": model, "algorithm": algorithm}
            for algorithm in ("bkw", "arora-gb"):
                yield base | {"tool": "community", "cost_model": "MATZOV-classical", "algorithm": algorithm}
            # Ring estimator is tested with its author's pinned dependency,
            # separate from the up-to-date community estimator panel.
            if budget == "key":
                for algorithm in ("rot_bdd_hybrid", "rot_bdd_mitm_hybrid"):
                    yield base | {"tool": "ring-2026", "cost_model": "MATZOV-classical",
                                  "algorithm": algorithm}


def execute(index, job, destination, timeout, repair_export=False):
    target = destination / f"job-{index:03d}.json"
    prior = None
    if target.exists():
        row = json.loads(target.read_text())
        if row["job"] != job:
            raise ValueError("existing job belongs to different parameters")
        if repair_export and row["status"] == "process_error" and "Out of range float values" in row.get("stderr", ""):
            prior = row
        else:
            return row
    command = [sys.executable, str(ROOT / "research/modern_worker_json.py"),
               "--job", json.dumps(job), "--output", str(target)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                   env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"})
        if not target.exists():
            row = {"job": job, "status": "process_error", "exit_code": completed.returncode,
                   "stderr": completed.stderr[-2000:]}
            target.write_text(json.dumps(row, indent=2)+"\n", encoding="utf-8")
    except subprocess.TimeoutExpired:
        row = {"job": job, "status": "timeout", "timeout_seconds": timeout}
        target.write_text(json.dumps(row, indent=2)+"\n", encoding="utf-8")
    row = json.loads(target.read_text())
    if prior is not None:
        row["prior_export_attempt"] = prior
        target.write_text(json.dumps(row, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/modern")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--repair-export", action="store_true", help="rerun only recorded JSON-overflow failures")
    args = parser.parse_args()
    destination = args.output.resolve()
    if not destination.is_relative_to(ROOT):
        raise ValueError("outputs must stay inside NIST")
    if destination.exists() and destination.is_relative_to(ROOT / "results"):
        raise FileExistsError("versioned research snapshots cannot be overwritten")
    sources()
    destination.mkdir(parents=True, exist_ok=True)
    priority = {name: i for i, name in enumerate(("usvp", "dual_hybrid", "dual", "bdd", "bkw",
                "arora-gb", "bdd_hybrid", "bdd_mitm_hybrid", "rot_bdd_hybrid", "rot_bdd_mitm_hybrid"))}
    selected = sorted(jobs(), key=lambda job: (priority[job["algorithm"]], job["cost_model"],
                                               job["sample_budget"], job["scenario"]))[:args.limit]
    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = {pool.submit(execute, i, job, destination, args.timeout, args.repair_export): i
                   for i, job in enumerate(selected)}
        for future in as_completed(pending):
            row = future.result()
            rows.append(row)
            print(f"{len(rows)}/{len(selected)} {row['job']['scenario']} "
                  f"{row['job']['algorithm']} {row['status']} "
                  f"{row.get('log2_cost', {}).get('rop', '')}", flush=True)
    rows.sort(key=lambda row: json.dumps(row["job"], sort_keys=True))
    output = destination / "modern-attacks.json"
    output.write_text(json.dumps({"schema": 1, "cutoff_date": "2026-10-24", "results": rows},
                                indent=2, allow_nan=False)+"\n", encoding="utf-8")
    from joint_noise_check import experiment
    (destination / "joint-noise-toy.json").write_text(json.dumps(experiment(), indent=2)+"\n", encoding="utf-8")
    from sage.version import version
    inputs = [ROOT / f"research/{name}" for name in
              ("modern_tools.py", "modern_worker.py", "modern_worker_json.py", "cost_serialization.py",
               "run_modern.py", "sieve_models.py",
               "modern-tools-manifest.json", "sage-bootstrap-manifest.json", "sage-linux-explicit.txt",
               "sage-linux-packages.json", "joint_noise_check.py", "prepare_sage_archives.py")]
    inputs.extend(ROOT / f"scripts/{name}" for name in
                  ("modern.sh", "bootstrap-modern.sh", "bootstrap-modern.ps1"))
    normalized = [p.relative_to(ROOT).as_posix() for p in inputs if p.suffix == ".ps1"]
    def input_digest(path):
        content = path.read_bytes()
        if path.suffix == ".ps1":
            content = content.replace(b"\r\n", b"\n")
        return hashlib.sha256(content).hexdigest()
    provenance = {"created_utc": datetime.now(timezone.utc).isoformat(), "sage": version,
                  "python": platform.python_version(), "platform": platform.platform(),
                  "workers": args.workers, "timeout_seconds": args.timeout,
                  "calculation_core": "modern_worker.estimate; unchanged across exporter correction",
                  "exporters": ["modern_worker.py", "modern_worker_json.py"],
                  "planned_jobs": len(selected), "normalized_lf_inputs": normalized, "input_sha256": {
                      p.relative_to(ROOT).as_posix(): input_digest(p) for p in inputs},
                  "output_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in sorted(destination.glob("*.json")) if p.name != "provenance.json"}}
    (destination / "provenance.json").write_text(json.dumps(provenance, indent=2)+"\n", encoding="utf-8")


if __name__ == "__main__":
    main()
