"""Resume only the interrupted M08 oracle; retain the partial first attempt.

The original campaign, coverage objects, replay image and frozen controllers
are never rebuilt or edited. This adapter records its own execution separately.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys

from run_m08_fuzz import PROFILE, TARGETS, inventory, ordinary, original_campaign_root, owned, read, require, save, sha

ROOT = Path(__file__).resolve().parents[1]
PARTIAL = ("oracle-replay.log", "oracle-replay-runtime.stderr", "oracle-transcript.jsonl.gz")


def utc():
    return datetime.now(timezone.utc).isoformat()


def bindings(out):
    names = ["config.json", "built.json", "fuzz-summary.json", "harvest.json", "post-init.json",
             "verification.json", "replay-build.json", "bin/m08-replay",
             "postprocessing/request.json", "postprocessing/coverage-summary.json",
             "postprocessing/coverage-worktree.json", "postprocessing/union.profdata",
             "postprocessing/union-full.json.gz"]
    names += ["controls/" + name for name in read(out / "config.json")["controller_sha256"]]
    names += ["postprocessing/" + name + suffix for name in TARGETS
              for suffix in ("-receipt.json", "-full.json.gz", ".profdata")]
    names += ["postprocessing/bin/" + name for name in TARGETS]
    for name in names:
        ordinary(out / name)
    return {name: sha(out / name) for name in sorted(names)}


def check_partial_members(members):
    require(set(members) == set(PARTIAL), "retain exactly the three interrupted oracle outputs")
    require(all(type(value) is str and len(value) == 64
                and all(c in "0123456789abcdef" for c in value) for value in members.values()),
            "invalid interrupted file hash")


def oracle_command(config):
    origin = original_campaign_root(config)
    require(origin.parts[:2] == ("/", "mnt") and len(origin.parts[2]) == 1,
            "historical Windows-mounted campaign required")
    windows = PureWindowsPath(origin.parts[2].upper() + ":/", *origin.parts[3:])
    project = windows.parents[2]
    return [str(project / ".tools/research-venv/Scripts/python.exe"), "-B",
            str(windows / "controls/replay_m08_fuzz_corpus.py"), "run", "--campaign", str(windows),
            "--linux-binary", str(origin / "bin/m08-replay")]


def check_resume_destination(out):
    ordinary(out, directory=True)
    folder = out / "postprocessing"
    ordinary(folder, directory=True)
    require(folder.resolve().parent == out.resolve(), "postprocessing must be a direct ordinary campaign child")
    names = ("postprocess.json", "failure.json", "recovery-request.json", "recovery.json",
             "recovery-adapter.py", "interrupted-oracle-001")
    require(not any(os.path.lexists(folder / name) for name in names)
            and not os.path.lexists(out / "oracle-replay.json"), "resume only a new interrupted oracle attempt")
    require((folder / "interrupted-oracle-001").resolve().parent == folder.resolve(),
            "interrupted attempt destination must stay inside postprocessing")
    return folder


def verify_recovery(out):
    folder = out / "postprocessing"
    request = read(folder / "recovery-request.json")
    result = read(folder / "recovery.json")
    partial = folder / "interrupted-oracle-001"
    check_partial_members(request["interrupted_outputs_sha256"])
    require(inventory(partial) == request["interrupted_outputs_sha256"], "interrupted evidence changed")
    require(request["schema"] == "m08-oracle-recovery-request-v1" and request["profile"] == PROFILE
            and request["original_postprocess_exit_code_known"] is False
            and request["campaign_or_coverage_rerun"] is False
            and request["oracle_command"] == oracle_command(read(out / "config.json"))
            and request["adapter_sha256"] == sha(folder / "recovery-adapter.py")
            and request["completed_inputs_sha256"] == bindings(out), "recovery inputs or scope changed")
    require(result["schema"] == "m08-oracle-recovery-result-v1"
            and result["request_sha256"] == sha(folder / "recovery-request.json")
            and type(result["exit_code"]) is int and result["exit_code"] == 0
            and result["oracle_receipt_sha256"] == sha(out / "oracle-replay.json")
            and result["oracle_log_sha256"] == sha(out / "oracle-replay.log")
            and result["adapter_sha256"] == request["adapter_sha256"], "recovery result changed")
    final = read(folder / "postprocess.json")
    require(final["recovery_receipt_sha256"] == sha(folder / "recovery.json")
            and final["oracle_command"] == request["oracle_command"]
            and final["oracle_receipt_sha256"] == result["oracle_receipt_sha256"], "recovery final binding changed")
    return {"interrupted_oracle_attempt_preserved": True, "original_campaign_or_coverage_rerun": False,
            "resumed_oracle_exit_code": 0}


def resume(out):
    require(os.name == "nt", "Windows coordinator with pinned NumPy required")
    out = owned(out, ROOT / "artifacts/generated")
    folder = check_resume_destination(out)
    config = read(out / "config.json")
    for name, checksum in config["controller_sha256"].items():
        require(sha(out / "controls" / name) == checksum, "frozen controller changed")
    completed = bindings(out)
    interrupted = {}
    for name in PARTIAL:
        ordinary(out / name)
        interrupted[name] = sha(out / name)
    check_partial_members(interrupted)
    command = oracle_command(config)
    require(Path(command[0]) == ROOT / ".tools/research-venv/Scripts/python.exe"
            and Path(command[2]) == out / "controls/replay_m08_fuzz_corpus.py", "historical paths differ")
    request = {"schema": "m08-oracle-recovery-request-v1", "profile": PROFILE, "started_utc": utc(),
               "observation": "Tool session disappeared, UTC advanced from approximately 04:30 to 10:18; WSL had a fresh boot and no original oracle/controller process. Partial transcript retained.",
               "original_postprocess_exit_code_known": False, "campaign_or_coverage_rerun": False,
               "completed_inputs_sha256": completed, "interrupted_outputs_sha256": interrupted,
               "adapter_sha256": sha(Path(__file__)), "oracle_command": command}
    save(folder / "recovery-request.json", request)
    shutil.copyfile(Path(__file__), folder / "recovery-adapter.py")
    partial = folder / "interrupted-oracle-001"
    partial.mkdir()
    for name in PARTIAL:
        source, destination = (out / name).resolve(), (partial / name).resolve()
        require(source.parent == out and destination.parent == partial.resolve() and not destination.exists(),
                "recovery move must remain inside the owned campaign")
        shutil.move(str(source), str(destination))
    require(inventory(partial) == interrupted, "partial attempt move changed bytes")
    with (out / "oracle-replay.log").open("xb") as log:
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    result = {"schema": "m08-oracle-recovery-result-v1", "finished_utc": utc(),
              "request_sha256": sha(folder / "recovery-request.json"), "exit_code": process.returncode,
              "adapter_sha256": request["adapter_sha256"], "oracle_log_sha256": sha(out / "oracle-replay.log"),
              "oracle_receipt_sha256": sha(out / "oracle-replay.json") if (out / "oracle-replay.json").exists() else None}
    save(folder / "recovery.json", result)
    require(process.returncode == 0, "resumed oracle failed; all evidence retained")
    require(bindings(out) == completed, "completed campaign/coverage/replay image changed")
    save(folder / "postprocess.json", {"finished_utc": utc(), "source_coverage_exported": True,
         "independent_python_replay_passed": True, "oracle_command": command,
         "oracle_receipt_sha256": sha(out / "oracle-replay.json"),
         "original_campaign_source_unchanged": inventory(out / "source") == config["source_sha256"],
         "new_security_constant_time_or_erasure_proof": False,
         "recovery_receipt_sha256": sha(folder / "recovery.json")})
    from postprocess_m08_fuzz import verify
    return {**verify(out), **verify_recovery(out)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("resume", "verify"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m08-fuzz-001")
    args = parser.parse_args()
    print(json.dumps(resume(args.output) if args.action == "resume" else verify_recovery(args.output), indent=2))


if __name__ == "__main__":
    main()
