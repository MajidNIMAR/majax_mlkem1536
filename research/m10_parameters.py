"""Finite pre-registered R1/ML-KEM-1024 parameter comparison; no Rust changes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import queue
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ESTIMATOR_COMMIT = "7d59f866655362ea8eab803dbc833710c2bc362a"
KAIBURR_COMMIT = "08543c79ca61dc2d38c7530dd03756898895f759"
MODELS = ("MATZOV-classical", "BCSS23-quantum-reduction-sensitivity")
FAMILIES = ("usvp", "bdd", "primal_hybrid_mitm", "dual", "dual_hybrid_matzov")
PROFILES = {"R1": {"degree": 256, "rank": 6, "q": 7681, "eta": 3},
            "ML-KEM-1024": {"degree": 256, "rank": 4, "q": 3329, "eta": 2}}
CONTROL_FILES = ("m10_parameters.py", "m10_parameters_worker.py", "sieve_models.py", "cost_serialization.py")


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def jobs():
    result = []
    contracts = {"usvp": "GSA geometric predicate; not a certified global recovery probability",
                 "bdd": "BDD geometric predicate and estimator amplification; not global success certificate",
                 "primal_hybrid_mitm": "MITM=True, Babai=False, GSA, guessing amplification target0.99; heuristic geometry",
                 "dual": "dual solver success_probability0.99 under estimator distribution heuristics",
                 "dual_hybrid_matzov": "MATZOV internal mu0.5; not a certified recovery probability0.99"}
    for profile, params in sorted(PROFILES.items()):
        for extra in (0, 1):
            for model in MODELS:
                for family in FAMILIES:
                    result.append({"index": len(result), "profile": profile, **params,
                                   "dimension": params["degree"] * params["rank"],
                                   "sample_game": "key" if extra == 0 else "ideal_k_plus_1",
                                   "samples": params["degree"] * (params["rank"] + extra),
                                   "abstract_matrix_block_shape": [params["rank"] + extra, params["rank"]],
                                   "targets": 1, "leakage_oracle": "none", "memory_cap": None,
                                   "shape_model": "GSA where applicable", "cost_model": model, "family": family,
                                   "success_contract": contracts[family], "estimator_commit": ESTIMATOR_COMMIT,
                                   "real_ciphertext_rows_claimed_independent": False,
                                   "real_MLWE_claimed_IID_LWE": False})
    require(len(result) == 40, "finite plan must contain exactly 40 jobs")
    return result


def linux(path):
    path = Path(path).resolve()
    return "/mnt/" + path.drive[0].lower() + str(path)[2:].replace("\\", "/")


def prepare(output):
    require(not output.exists() and output.resolve().is_relative_to(ROOT / "artifacts/generated"), "new project-local run required")
    output.mkdir(parents=True)
    (output / "sources/research").mkdir(parents=True)
    (output / "jobs").mkdir()
    for name in CONTROL_FILES:
        shutil.copyfile(ROOT / "research" / name, output / "sources/research" / name)
    shutil.copyfile(ROOT / "docs/DECISION_PARAMETRES_M10.md", output / "protocol.md")
    shutil.copyfile(ROOT / "docs/PROTOCOLE_M10.md", output / "root-protocol.md")
    plan = {"schema": "m10-parameters-plan-v1", "created_utc": datetime.now(timezone.utc).isoformat(),
            "estimator_commit": ESTIMATOR_COMMIT, "jobs": jobs(), "timeout_seconds": 300,
            "workers": 4, "logical_CPUs": [0, 1, 2, 3, 4, 5], "memory_caps_log2_bytes_for_diagnostic": [40, 60, 80],
            "no_constrained_RAM_optimization_claimed": True, "old_M05_jobs_credited_as_new": 0,
            "protocol_sha256": sha(output / "protocol.md"), "root_protocol_sha256": sha(output / "root-protocol.md"),
            "controls_sha256": {name: sha(output / "sources/research" / name) for name in CONTROL_FILES},
            "root_commit_at_prepare": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()}
    save(output / "plan.json", plan)
    for job in plan["jobs"]:
        save(output / "jobs" / f"input-{job['index']:03d}.json", job)


def fetch_sources(output):
    plan = read(output / "plan.json")
    cache = ROOT / ".tools/upstream" / ("lattice-estimator-" + ESTIMATOR_COMMIT)
    archive = ROOT / ".tools/downloads" / ("lattice-estimator-" + ESTIMATOR_COMMIT + ".zip")
    require(not cache.exists() and not archive.exists(), "new pinned estimator cache required")
    url = "https://codeload.github.com/malb/lattice-estimator/zip/" + ESTIMATOR_COMMIT
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read(10_000_001)
    require(len(raw) <= 10_000_000, "unexpected estimator download size")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("xb") as stream:
        stream.write(raw)
    hashes = {}
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = "/".join(member.filename.split("/")[1:])
            if not name or member.is_dir():
                continue
            path = (cache / name).resolve()
            require(path.is_relative_to(cache.resolve()) and member.file_size <= 2_000_000, "unsafe estimator archive member")
            if "__pycache__" in path.parts or path.suffix in (".pyc", ".pkl", ".o", ".so"):
                continue
            raw = bundle.read(member)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
            hashes[name] = sha(path)
    save(output / "estimator-source.json", {"url": url, "commit": ESTIMATOR_COMMIT,
         "archive_sha256": sha(archive), "cache": cache.relative_to(ROOT).as_posix(), "files_sha256": hashes,
         "plan_sha256": sha(output / "plan.json")})


def run(output, preregistered_commit):
    plan = read(output / "plan.json")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", preregistered_commit, "HEAD"], cwd=ROOT).returncode == 0,
            "committed preregistration must precede acquisition")
    for name, digest in plan["controls_sha256"].items():
        require(sha(output / "sources/research" / name) == digest, "frozen worker/control changed")
        committed = subprocess.check_output(["git", "show", preregistered_commit + ":research/" + name], cwd=ROOT)
        require(hashlib.sha256(committed).hexdigest() == digest, "preregistered control bytes differ")
    committed_doc = subprocess.check_output(["git", "show", preregistered_commit + ":docs/DECISION_PARAMETRES_M10.md"], cwd=ROOT)
    require(hashlib.sha256(committed_doc).hexdigest() == plan["protocol_sha256"], "preregistered protocol differs")
    tool = read(output / "estimator-source.json")
    cache = ROOT / tool["cache"]
    require(all(sha(cache / name) == digest for name, digest in tool["files_sha256"].items()), "estimator source cache changed")
    require(not any((output / "jobs").glob("result-*.json")), "a new acquisition is required, no existing result replacement")
    env = ["wsl", "-d", "Ubuntu-22.04", "--", "env", "PYTHONDONTWRITEBYTECODE=1",
           "DOT_SAGE=" + linux(ROOT / ".tools/sage-ram/state"), "XDG_CACHE_HOME=" + linux(ROOT / ".tools/sage-ram/xdg-cache"),
           "TMPDIR=" + linux(ROOT / ".tools/sage-ram/tmp"), "CONDA_PKGS_DIRS=" + linux(ROOT / ".tools/sage-ram/mamba/pkgs")]
    runtime = [linux(ROOT / ".tools/micromamba-bootstrap/bin/micromamba"), "--no-rc", "-r", linux(ROOT / ".tools/sage-ram/mamba"),
               "run", "-p", linux(ROOT / ".tools/sage-ram/env"), "python"]
    save(output / "launch.json", {"preregistration_commit": preregistered_commit, "plan_sha256": sha(output / "plan.json"),
         "estimator_manifest_sha256": sha(output / "estimator-source.json"), "base_environment_command": env + runtime,
         "runtime_binary_sha256": sha(ROOT / ".tools/micromamba-bootstrap/bin/micromamba")})
    cpus = queue.SimpleQueue()
    for cpu in plan["logical_CPUs"][:plan["workers"]]:
        cpus.put(cpu)

    def one(job):
        index = job["index"]
        cpu = cpus.get()
        command = [*env, "taskset", "-c", str(cpu), "timeout", "--signal=TERM", "--kill-after=10s", str(plan["timeout_seconds"]) + "s", *runtime,
                   linux(output / "sources/research/m10_parameters_worker.py"), "--input", linux(output / "jobs" / f"input-{index:03d}.json"),
                   "--output", linux(output / "jobs" / f"result-{index:03d}.json"), "--estimator", linux(cache)]
        started = time.monotonic()
        try:
            process = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=plan["timeout_seconds"] + 30)
            stdout, stderr, code = process.stdout, process.stderr, process.returncode
            expired = code in (124, 137)
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, expired = error.stdout or b"", error.stderr or b"", None, True
        finally:
            cpus.put(cpu)
        (output / "jobs" / f"stdout-{index:03d}.log").write_bytes(stdout)
        (output / "jobs" / f"stderr-{index:03d}.log").write_bytes(stderr)
        result_path = output / "jobs" / f"result-{index:03d}.json"
        if not result_path.exists():
            save(result_path, {"job": job, "status": "timeout" if expired else "process_error", "exit_code": code})
        save(output / "jobs" / f"receipt-{index:03d}.json", {"command": command, "exit_code": code, "expired": expired,
             "wall_seconds": time.monotonic() - started, "stdout_sha256": sha(output / "jobs" / f"stdout-{index:03d}.log"),
             "stderr_sha256": sha(output / "jobs" / f"stderr-{index:03d}.log"), "result_sha256": sha(result_path)})
        print(json.dumps({"job": index, "status": read(result_path)["status"], "expired": expired}), flush=True)

    with ThreadPoolExecutor(max_workers=plan["workers"]) as pool:
        list(pool.map(one, plan["jobs"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "fetch", "run"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m10-parameters-001")
    parser.add_argument("--preregistered-commit")
    args = parser.parse_args()
    prepare(args.output.resolve()) if args.action == "prepare" else fetch_sources(args.output.resolve()) if args.action == "fetch" else run(args.output.resolve(), args.preregistered_commit)
