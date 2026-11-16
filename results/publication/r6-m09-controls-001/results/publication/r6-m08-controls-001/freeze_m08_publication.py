"""Freeze/replay exact successful M08 hosted integration evidence, offline.

Future identities, test counts and image hashes must be supplied by a config.
The freeze action reads the public Git clone; verify uses frozen files only.
Neither action accesses credentials, the network, compilers or native images.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / "artifacts/generated/publication/m08-ci-001"
REPOSITORY = "MajidNIMAR/majax_mlkem1536"
PROFILE = "KEM1536-DEV-Q7681-R1"
RUNNERS = {"windows-latest": ("windows", "Windows"), "ubuntu-24.04": ("linux", "Ubuntu")}
RESEARCH_COMMANDS = [["dev-vectors", "1"], ["dev-rejection-vectors"], ["dev-hardening"], ["dev-mutations"], ["dev-timing"]]
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def hex_value(value, length):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def safe_name(name):
    require(type(name) is str and name and not PurePosixPath(name).is_absolute() and "\\" not in name
            and all(part not in {"", ".", ".."} and not any(ord(c) < 32 or c in ':<>"|?*' for c in part)
                    and part.rstrip(" .") == part for part in name.split("/")), "unsafe publication member name")
    return name


def moment(value):
    stamp = datetime.fromisoformat(value)
    require(stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0, "UTC timestamp required")
    return stamp


def config_check(config):
    require(config.get("schema") == "m08-publication-config-v1" and type(config.get("run_id")) is int
            and config["run_id"] > 0 and hex_value(config.get("public_commit"), 40)
            and hex_value(config.get("source_commit"), 40) and config.get("branch") == "main"
            and type(config.get("python_test_count")) is int and config["python_test_count"] > 0
            and hex_value(config.get("candidate_source_manifest_sha256"), 64), "explicit M08 publication config required")
    require(set(config.get("runners", {})) == set(RUNNERS), "exact Windows/Ubuntu runner config required")
    for runner, (host, _) in RUNNERS.items():
        item = config["runners"][runner]
        require(item.get("host") == host and hex_value(item.get("original_CLI_sha256"), 64)
                and hex_value(item.get("original_default_consumer_sha256"), 64), "explicit original CLI/consumer hashes required")
    return config


def check_run(run, jobs, run_id, public_commit, branch="main", successful=True):
    require(type(run_id) is int and run_id > 0 and hex_value(public_commit, 40), "explicit run and full commit required")
    require(run.get("id") == run_id and run.get("head_sha") == public_commit and run.get("head_branch") == branch
            and run.get("html_url") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
            and run.get("repository", {}).get("full_name") == REPOSITORY
            and type(run.get("run_attempt")) is int and run["run_attempt"] > 0, "exact API run/commit/repository/attempt differs")
    if successful:
        require(run.get("status") == "completed" and run.get("conclusion") == "success", "successful completed exact run required")
    require(jobs.get("total_count") == 2 and type(jobs.get("jobs")) is list and len(jobs["jobs"]) == 2,
            "two API jobs required; pagination or additional jobs are not accepted")
    observed, identities = {}, set()
    for job in jobs["jobs"]:
        match = re.fullmatch(r"check \(([^)]+)\)", job.get("name", ""))
        require(match is not None and match.group(1) in RUNNERS and match.group(1) not in observed, "expected distinct job runners required")
        runner = match.group(1)
        require(type(job.get("id")) is int and job["id"] > 0 and job["id"] not in identities
                and job.get("run_id") == run_id and job.get("head_sha") == public_commit
                and type(job.get("run_attempt")) is int and job["run_attempt"] == run["run_attempt"]
                and job.get("labels") == [runner], "API job ID/run/source/runner binding differs")
        identities.add(job["id"])
        if successful:
            require(job.get("status") == "completed" and job.get("conclusion") == "success", "two successful completed jobs required")
        observed[runner] = job
    require(set(observed) == set(RUNNERS), "one API job per expected runner required")
    return observed


def check_manifest(manifest, source_commit):
    require(manifest.get("schema") == 2 and manifest.get("local_source_commit") == source_commit
            and manifest.get("profile") == PROFILE and type(manifest.get("git_blob_sha256")) is dict
            and type(manifest.get("sha256")) is dict and manifest["sha256"]
            and set(manifest["git_blob_sha256"]) == set(manifest["sha256"]), "committed schema2 source provenance differs")
    for name in manifest["sha256"]:
        safe_name(name)
        require(hex_value(manifest["sha256"][name], 64) and hex_value(manifest["git_blob_sha256"][name], 64), "invalid source provenance hash")
    return len(manifest["sha256"])


def check_integrity(integrity, manifest, manifest_raw, config):
    count = check_manifest(manifest, config["source_commit"])
    require(integrity.get("schema") == "m08-source-integrity-v1" and integrity.get("public_commit") == config["public_commit"]
            and integrity.get("source_commit") == config["source_commit"] and integrity.get("all_equal") is True
            and integrity.get("canonical_git_blobs_verified") == integrity.get("exported_files_verified") == count
            and integrity.get("source_provenance_sha256") == hashlib.sha256(manifest_raw).hexdigest()
            and integrity.get("git_blob_map_sha256") == canonical_sha(manifest["git_blob_sha256"])
            and integrity.get("export_map_sha256") == canonical_sha(manifest["sha256"])
            and integrity.get("attribute_converted_paths") == sorted(name for name in manifest["sha256"]
                    if manifest["sha256"][name] != manifest["git_blob_sha256"][name]), "independent source-integrity receipt differs")


def check_smoke(value, runner, config):
    wanted = config["runners"][runner]
    require(value.get("schema") == "m08-native-smoke-v1" and value.get("profile") == PROFILE
            and value.get("host") == wanted["host"]
            and value.get("candidate_source_manifest_sha256") == config["candidate_source_manifest_sha256"]
            and value.get("original_CLI_sha256") == wanted["original_CLI_sha256"]
            and value.get("original_default_consumer_sha256") == wanted["original_default_consumer_sha256"],
            "native original CLI/consumer identity differs")
    for field, number in {"CLI_fresh_round_trips": 16, "CLI_implicit_rejections_checked": 16,
                          "consumer_import_cases": 13, "consumer_fresh_imported_key_round_trips": 1,
                          "consumer_fresh_rejections": 1, "consumer_single_coefficient_and_boundary_probes": 88576}.items():
        require(type(value.get(field)) is int and value[field] == number, "native M08 check count differs: " + field)
    for field in ("new_compilation_performed", "new_benchmark_performed", "new_disassembly_performed",
                  "constant_time_proved", "universal_erasure_proved", "secrets_printed"):
        require(value.get(field) is False, "native M08 finite-check scope differs: " + field)
    checks = value.get("checks")
    require(type(checks) is list and [item.get("operation") for item in checks] == ["dev-self-test", "smoke", "exhaustive"],
            "all three native JSON checks required")
    for item in checks:
        require(type(item.get("exit_code")) is int and item["exit_code"] == 0
                and hex_value(item.get("stdout_sha256"), 64) and item.get("stderr_sha256") == EMPTY_SHA,
                "native JSON check exit/output receipt differs")
    disabled = value.get("research_commands_rejected")
    require(type(disabled) is list and len(disabled) == len(RESEARCH_COMMANDS), "five normally refused research commands required")
    for row, arguments in zip(disabled, RESEARCH_COMMANDS, strict=True):
        require(row.get("arguments") == arguments and type(row.get("exit_code")) is int and row["exit_code"] == 1
                and row.get("stdout_sha256") == EMPTY_SHA and hex_value(row.get("stderr_sha256"), 64),
                "research command normal exit1 refusal differs")
    require(moment(value["started_utc"]) <= moment(value["finished_utc"]), "native check timestamps are reversed")


def log_summary(path, config, api_jobs):
    summary = {}
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(len(infos) <= 20000 and len({i.filename for i in infos}) == len(infos)
                and sum(i.file_size for i in infos) <= 1024**3
                and all(i.file_size <= 256 * 1024**2 for i in infos), "CI ZIP duplicate/member/size bounds differ")
        require(archive.testzip() is None, "CI logs ZIP corrupt")
        for info in infos:
            match = re.fullmatch(r"\d+_check \(([^)]+)\)\.txt", info.filename)
            if match is None:
                continue
            runner = match.group(1)
            require(runner in RUNNERS and runner not in summary, "unexpected/repeated full job log")
            log = archive.read(info).decode("utf-8-sig")
            require("##[error]" not in log, "job log contains a workflow error")
            clean = re.sub(r"^\d{4}-\d\d-\d\dT\S+\s?", "", log, flags=re.M)
            counts = list(re.finditer(r"(?m)^Ran (\d+) tests in [^\r\n]+\r?$", clean))
            require(len(counts) == 1 and int(counts[0].group(1)) == config["python_test_count"], "full job Python test count differs")
            following = clean[counts[0].end():].lstrip().splitlines()
            require(following and following[0].strip() == "OK", "full job Python tests did not report OK")
            smokes = []
            for found in re.finditer(r'\{\s*"schema"\s*:\s*"m08-native-smoke-v1"', clean):
                smokes.append(json.JSONDecoder().raw_decode(clean[found.start():])[0])
            require(len(smokes) == 1, "one complete M08 native smoke JSON required per full job log")
            check_smoke(smokes[0], runner, config)
            job, label = api_jobs[runner], RUNNERS[runner][1]
            steps = job.get("steps", [])
            require(len({s["name"] for s in steps}) == len(steps), "duplicate API step name")
            steps = {s["name"]: s for s in steps}
            required = ["Bootstrap " + label, "Prepare " + label + " research tools", "Check " + label,
                        "Run the original M08 package and import consumer on " + label]
            require(all(name in steps and steps[name]["status"] == "completed" and steps[name]["conclusion"] == "success"
                        for name in required), "required full check/M08 native API step did not pass")
            require(all(s["conclusion"] in {"success", "skipped"} for s in steps.values()), "failed/cancelled API step")
            summary[runner] = {"job_id": job["id"], "python_tests": config["python_test_count"],
                               "full_job_log": info.filename, "full_job_log_sha256": hashlib.sha256(archive.read(info)).hexdigest(),
                               "required_steps": required, "native_original_CLI_and_default_consumer": smokes[0]}
    require(set(summary) == set(RUNNERS), "both complete full job logs required")
    return summary


def evidence(source, config, integrity, manifest_raw):
    config_check(config)
    run, jobs, capture = (read(source / name) for name in ("run.json", "jobs.json", "receipt.json"))
    api_jobs = check_run(run, jobs, config["run_id"], config["public_commit"], config["branch"])
    require(capture.get("schema") == "m08-ci-capture-v1" and capture.get("run_id") == config["run_id"]
            and capture.get("public_commit") == config["public_commit"] and capture.get("run_url") == run["html_url"]
            and set(capture.get("sha256", {})) == {"run.json", "jobs.json", "ci-logs.zip"}
            and capture.get("credentials_retained") is False and capture.get("signed_log_storage_URL_retained") is False,
            "three captured CI members/identity/privacy scope differ")
    for name, expected in capture["sha256"].items():
        require(sha(source / name) == expected, "captured API/log member changed")
    manifest = json.loads(manifest_raw)
    check_integrity(integrity, manifest, manifest_raw, config)
    runners = log_summary(source / "ci-logs.zip", config, api_jobs)
    return {"schema": "m08-hosted-integration-v1", "profile": PROFILE, "public_tested_commit": config["public_commit"],
            "local_source_commit": config["source_commit"], "run_id": config["run_id"], "run_url": run["html_url"],
            "runners": runners, "source_integrity": integrity,
            "scope": "Fresh hosted full checks plus native execution of exact preserved CLI/default-feature consumer images. Historical measurements, binary review and fuzzing are data replays; native CLI16/16, five normal exit1 command refusals and consumer fresh1/1 plus88576 probes are new finite integration checks.",
            "global_security_constant_time_or_erasure_proved": False, "credentials_or_signed_log_URL_retained": False}


def freeze(config_path, output=None, public=None):
    config = config_check(read(config_path))
    output = ROOT / "results/publication/r6-m08-001" if output is None else Path(output)
    require(output.parent.resolve() == (ROOT / "results/publication").resolve() and not output.exists(), "new direct publication snapshot required")
    public = ROOT / "publication/majax_mlkem1536" if public is None else Path(public)
    command = ["git", "-C", str(public)]
    require(subprocess.check_output([*command, "rev-parse", "HEAD"]).decode().strip() == config["public_commit"], "public clone no longer at tested revision")
    require(subprocess.check_output([*command, "status", "--porcelain=v1", "--untracked-files=all"]) == b"", "clean public clone required")
    raw = subprocess.check_output([*command, "show", config["public_commit"] + ":PUBLICATION_PROVENANCE.json"])
    source = WORK / str(config["run_id"])
    integrity = read(WORK / "source-integrity.json")
    result = evidence(source, config, integrity, raw)  # All validation precedes any result-directory mutation.
    output.mkdir()
    (output / "main").mkdir()
    for name in ("run.json", "jobs.json", "ci-logs.zip", "receipt.json"):
        shutil.copyfile(source / name, output / "main" / name)
    save(output / "config.json", config)
    shutil.copyfile(WORK / "source-integrity.json", output / "source-integrity.json")
    (output / "tested-source-provenance.json").write_bytes(raw)
    save(output / "verification.json", result)
    (output / "README.md").write_text("# MAJAX R6 M08 hosted integration evidence\n\nExact API run/jobs and raw full logs bind two hosted Windows/Ubuntu checks to the committed schema2 source maps and the independently verified source-integrity receipt. Native checks execute the exact preserved original CLI and default-feature import consumer on each host. Counts, image hashes and tested identities are explicit in config.json and verification.json. Historical measurement, disassembly and fuzz archives are data replays. No credentials or signed log-storage URL is retained. These finite checks establish no global security, universal erasure or constant-time proof.\n", encoding="utf-8")
    files = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob("*")) if p.is_file()}
    save(output / "provenance.json", {"schema": "m08-publication-receipt-v1", "created_utc": datetime.now(timezone.utc).isoformat(),
                                     "public_tested_commit": config["public_commit"], "source_commit": config["source_commit"], "output_sha256": files})
    return verify(output)


def verify(output):
    provenance = read(output / "provenance.json")
    require(provenance.get("schema") == "m08-publication-receipt-v1", "publication receipt schema differs")
    moment(provenance["created_utc"])
    files = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob("*")) if p.is_file()}
    files.pop("provenance.json")
    require(files == provenance["output_sha256"], "frozen publication inventory/hash differs")
    for name in files:
        safe_name(name)
    config, integrity = read(output / "config.json"), read(output / "source-integrity.json")
    require(provenance["public_tested_commit"] == config["public_commit"] and provenance["source_commit"] == config["source_commit"], "frozen publication identity differs")
    result = evidence(output / "main", config, integrity, (output / "tested-source-provenance.json").read_bytes())
    require(result == read(output / "verification.json"), "hosted integration verification does not replay")
    return {"members_verified": len(files), "run_id": config["run_id"], "public_tested_commit": config["public_commit"],
            "expected_runner_jobs": 2, "new_network_or_native_execution_performed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze", "verify"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "results/publication/r6-m08-001")
    parser.add_argument("--public-clone", type=Path, default=ROOT / "publication/majax_mlkem1536")
    args = parser.parse_args()
    if args.action == "freeze":
        require(args.config is not None, "--config with future exact identities/counts/hashes required")
        result = freeze(args.config, args.output, args.public_clone)
    else:
        result = verify(args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
