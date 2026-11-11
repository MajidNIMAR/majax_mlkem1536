"""Capture one complete local Windows M08 check into a NEW ignored directory.

Preparation/import does not run the check. Use capture --output NEW_DIRECTORY
only after the root coordinator explicitly starts the final local check.
verify --output DIRECTORY replays receipt data without Git or executable calls.
All tracked and nonignored untracked maintained files are hashed before/after;
the two observations do not attest continuous filesystem or OS immutability.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
COMMAND = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/dev.ps1", "check"]
PROFILE = "KEM1536-DEV-Q7681-R1"


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def utc():
    return datetime.now(timezone.utc).isoformat()


def ordinary(path, directory=False):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
            "capture path contains a link/reparse point")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "capture path is not ordinary")
    return info


def safe_name(name):
    require(type(name) is str and name and not PurePosixPath(name).is_absolute() and "\\" not in name
            and all(part not in {"", ".", ".."} and not any(ord(c) < 32 or c in ':<>"|?*' for c in part)
                    and part.rstrip(" .") == part for part in name.split("/")), "unsafe maintained source name")


def output_path(value):
    output = Path(os.path.abspath(value))
    parent = ROOT / "artifacts/generated"
    require(output.is_relative_to(parent) and output != parent and not output.exists(),
            "capture requires a NEW output directory strictly under NIST/artifacts/generated")
    current = ROOT
    for part in output.relative_to(ROOT).parts:
        current /= part
        if current.exists() or current.is_symlink():
            ordinary(current, directory=True)
    require(output.resolve().is_relative_to(parent.resolve()), "capture output escaped generated workspace")
    return output


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT)


def names(raw):
    values = raw.decode("utf-8").split("\0")
    require(values[-1] == "", "Git source inventory is not NUL-terminated")
    result = sorted(set(values[:-1]))
    for name in result:
        safe_name(name)
    return result


def inventory():
    """Preserve all selected names; never silently omit a missing/nonfile entry."""
    tracked = names(git("ls-files", "--cached", "-z"))
    untracked = names(git("ls-files", "--others", "--exclude-standard", "-z"))
    files, unavailable = {}, {}
    for name in sorted(set(tracked) | set(untracked)):
        path = ROOT / name
        try:
            ordinary(path)
        except FileNotFoundError:
            unavailable[name] = "missing"
            continue
        require(path.resolve().is_relative_to(ROOT.resolve()), "maintained source escaped NIST")
        files[name] = sha(path)
    return {"schema": "m08-maintained-files-v1", "selection": "all Git tracked entries plus untracked --exclude-standard; ignored untracked outputs excluded",
            "git_head": git("rev-parse", "HEAD").decode().strip(),
            "git_status_porcelain_v1": git("status", "--porcelain=v1", "--untracked-files=all").decode("utf-8"),
            "tracked_names": tracked, "nonignored_untracked_names": untracked,
            "files_sha256": files, "unavailable_entries": unavailable}


def file_identity(path):
    path = Path(path).resolve()
    info = ordinary(path)
    return {"path": str(path), "sha256": sha(path), "bytes": info.st_size}


def check_inventory(value):
    require(value.get("schema") == "m08-maintained-files-v1" and type(value.get("files_sha256")) is dict
            and type(value.get("unavailable_entries")) is dict and type(value.get("git_status_porcelain_v1")) is str
            and re.fullmatch(r"[0-9a-f]{40}", value.get("git_head", "")), "maintained source inventory schema differs")
    selected = set()
    for key in ("tracked_names", "nonignored_untracked_names"):
        rows = value.get(key)
        require(type(rows) is list and rows == sorted(set(rows)), "maintained source names differ")
        for name in rows:
            safe_name(name)
        selected.update(rows)
    require(selected == set(value["files_sha256"]) | set(value["unavailable_entries"])
            and not set(value["files_sha256"]) & set(value["unavailable_entries"]), "maintained entry was omitted or duplicated")
    require(all(type(checksum) is str and re.fullmatch(r"[0-9a-f]{64}", checksum) for checksum in value["files_sha256"].values())
            and all(state == "missing" for state in value["unavailable_entries"].values()), "maintained source hash/state differs")


def query(command, environment=None):
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, timeout=40)
    return {"command": command, "exit_code": result.returncode,
            "stdout": result.stdout.decode("utf-8", errors="replace"),
            "stderr": result.stderr.decode("utf-8", errors="replace"),
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}


def tool_inventory():
    """Query versions and hash entry points/real Rust tools, never dump env/secrets."""
    environment = dict(os.environ)
    environment.update(CARGO_HOME=str(ROOT / ".tools/cargo"), RUSTUP_HOME=str(ROOT / ".tools/rustup"),
                       CARGO_TARGET_DIR=str(ROOT / "target"), RUSTUP_AUTO_INSTALL="0")
    cargo_bin = ROOT / ".tools/cargo/bin"
    environment["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")
    selected = {"powershell": shutil.which("powershell.exe"), "git": shutil.which("git"),
                "python_on_initial_PATH": shutil.which("python"), "capture_python": sys.executable,
                "research_python": str(ROOT / ".tools/research-venv/Scripts/python.exe"),
                "cargo_proxy": str(cargo_bin / "cargo.exe"), "rustc_proxy": str(cargo_bin / "rustc.exe")}
    require(all(selected.values()), "required local check tool is not on PATH")
    files = {name: file_identity(path) for name, path in selected.items()}
    # An ordered object avoids process-dependent Hashtable JSON property order
    # appearing as a tool change even when executable bytes/versions are equal.
    powershell_version = "[ordered]@{PSVersion=$PSVersionTable.PSVersion.ToString();PSEdition=[string]$PSVersionTable.PSEdition;CLRVersion=[string]$PSVersionTable.CLRVersion;BuildVersion=[string]$PSVersionTable.BuildVersion} | ConvertTo-Json -Compress"
    commands = {"powershell_version": [selected["powershell"], "-NoProfile", "-Command", powershell_version],
                "git_version": [selected["git"], "--version"], "python_version": [selected["python_on_initial_PATH"], "--version"],
                "research_python_version": [selected["research_python"], "--version"],
                "research_numpy_version": [selected["research_python"], "-c", "import numpy; print(numpy.__version__)"],
                "cargo_version": [selected["cargo_proxy"], "--version", "--verbose"],
                "rustc_version": [selected["rustc_proxy"], "-Vv"],
                "rustc_sysroot": [selected["rustc_proxy"], "--print", "sysroot"]}
    versions = {name: query(command, environment) for name, command in commands.items()}
    require(all(row["exit_code"] == 0 for row in versions.values()), "tool version query failed: "
            + ", ".join(name for name, row in versions.items() if row["exit_code"] != 0))
    sysroot = Path(versions["rustc_sysroot"]["stdout"].strip())
    require(sysroot.is_absolute(), "Rust sysroot is not absolute")
    for name in ("rustc.exe", "cargo.exe", "rustfmt.exe", "clippy-driver.exe"):
        path = sysroot / "bin" / name
        files["real_" + name] = file_identity(path)
    drivers = sorted((sysroot / "bin").glob("rustc_driver*.dll"))
    require(drivers, "real Rust compiler driver DLL is missing")
    for path in drivers:
        files["driver_" + path.name] = file_identity(path)
    native_folders = {"import_helpers": ROOT / ".tools/native-tools",
                      "host_native": sysroot / "lib/rustlib/x86_64-pc-windows-gnu/bin",
                      "self_contained": sysroot / "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained",
                      "gcc_ld": sysroot / "lib/rustlib/x86_64-pc-windows-gnu/bin/gcc-ld"}
    for label, folder in native_folders.items():
        if folder.exists():
            ordinary(folder, directory=True)
            for path in sorted(folder.glob("*.exe")):
                files[label + "/" + path.name] = file_identity(path)
    return {"schema": "m08-local-check-tools-v1", "platform": platform.platform(), "machine": platform.machine(),
            "capture_python_version": sys.version, "files": files, "version_queries": versions,
            "tool_query_environment": {key: environment[key] for key in ("CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "RUSTUP_AUTO_INSTALL")},
            "inherited_RUSTUP_TOOLCHAIN": os.environ.get("RUSTUP_TOOLCHAIN"),
            "native_tools_hash_scope": "available EXEs in dev.ps1 import-helper and pinned Rust native/self-contained linker directories; not an execution trace or complete OS/toolchain-library inventory",
            "check_environment": "ordinary inherited environment; scripts/dev.ps1 itself sets local Cargo/Rustup/target/PATH and PYTHONDONTWRITEBYTECODE",
            "system_environment_or_credentials_dumped": False}


def python_summary(text):
    matches = list(re.finditer(r"(?m)^Ran (\d+) tests in [^\r\n]+\r?$", text))
    counts, okay = [], []
    for match in matches:
        counts.append(int(match.group(1)))
        following = text[match.end():].lstrip().splitlines()
        okay.append(bool(following and following[0].strip() == "OK"))
    return {"test_counts": counts, "following_OK": okay}


def compare(before, after):
    left, right = before["files_sha256"], after["files_sha256"]
    return {"source_inventory_before_after_equal": before == after,
            "maintained_file_hashes_before_after_equal": left == right,
            "git_head_before_after_equal": before["git_head"] == after["git_head"],
            "git_status_before_after_equal": before["git_status_porcelain_v1"] == after["git_status_porcelain_v1"],
            "added_names": sorted(set(right) - set(left)), "removed_names": sorted(set(left) - set(right)),
            "changed_hashes": sorted(name for name in set(left) & set(right) if left[name] != right[name]),
            "endpoint_observations_only": True, "continuous_filesystem_or_OS_attestation": False}


def capture(output, expected_python_tests=None):
    require(sys.platform == "win32", "complete dev.ps1 capture requires native Windows")
    require(expected_python_tests is None or type(expected_python_tests) is int and expected_python_tests > 0,
            "expected Python test count must be a positive integer")
    output = output_path(output)
    output.mkdir(parents=True)
    started, source = utc(), Path(__file__).resolve()
    shutil.copyfile(source, output / "capture_full_check.py")
    receipt = {"schema": "m08-local-full-check-v1", "profile": PROFILE, "capture_started_utc": started,
               "command": COMMAND, "working_directory": str(ROOT), "capture_sha256": sha(source),
               "expected_python_test_count": expected_python_tests,
               "scope": "Complete local Windows working-tree dev.ps1 check, including historical data replays and finite self-tests. No renewed performance/disassembly/fuzz campaign; source/tool equality compares endpoints only.",
               "new_measurement_disassembly_or_fuzz_campaign": False}
    try:
        before = inventory()
        check_inventory(before)
        save(output / "source-before.json", before)
        require(not before["unavailable_entries"], "maintained source entries are missing; check not started")
        tools_before = tool_inventory()
        save(output / "tools-before.json", tools_before)
        receipt["started_utc"] = utc()
        tick = time.perf_counter()
        print("Running complete Windows scripts/dev.ps1 check; full output is retained in windows-check.log", flush=True)
        with (output / "windows-check.log").open("xb") as log:
            completed = subprocess.run(COMMAND, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        receipt.update(finished_utc=utc(), exit_code=completed.returncode, elapsed_wall_seconds=time.perf_counter() - tick)
        after = inventory()
        check_inventory(after)
        save(output / "source-after.json", after)
        tools_after = tool_inventory()
        save(output / "tools-after.json", tools_after)
        text = (output / "windows-check.log").read_text(encoding="utf-8-sig", errors="replace")
        summary, changes = python_summary(text), compare(before, after)
        tools_equal = tools_before == tools_after
        suites_passed = len(summary["test_counts"]) == 1 and summary["following_OK"] == [True]
        expected_count_matches = expected_python_tests is None or summary["test_counts"] == [expected_python_tests]
        accepted = completed.returncode == 0 and changes["source_inventory_before_after_equal"] and tools_equal and suites_passed and expected_count_matches
        receipt.update(source_comparison=changes, tools_before_after_equal=tools_equal, python_summary=summary,
                       expected_python_count_matches=expected_count_matches, complete_check_accepted=accepted,
                       effective_exit_code=completed.returncode if completed.returncode else 0 if accepted else 3,
                       capture_script_before_after_equal=sha(source) == receipt["capture_sha256"])
        if not receipt["capture_script_before_after_equal"]:
            receipt["complete_check_accepted"], receipt["effective_exit_code"] = False, 3
        receipt["files_sha256"] = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}
        save(output / "windows-check.json", receipt)
        verified = verify(output)
        print(json.dumps(verified, indent=2), flush=True)
        return receipt["effective_exit_code"]
    except BaseException as error:
        save(output / "failure.json", {"schema": "m08-local-check-failure-v1", "capture_started_utc": started,
             "finished_utc": utc(), "error_type": type(error).__name__, "error": str(error),
             "command": COMMAND, "evidence_preserved": True,
             "completed_check_exit_code": receipt.get("exit_code"), "check_started_utc": receipt.get("started_utc")})
        raise


def verify(output):
    """Data replay only: no original absolute source/tool path is dereferenced."""
    output = Path(output)
    ordinary(output, directory=True)
    for path in output.iterdir():
        ordinary(path)
    receipt = read(output / "windows-check.json")
    require(receipt["schema"] == "m08-local-full-check-v1" and receipt["profile"] == PROFILE
            and receipt["command"] == COMMAND and receipt["new_measurement_disassembly_or_fuzz_campaign"] is False,
            "complete local check receipt identity/scope differs")
    files = {p.name: sha(p) for p in output.iterdir() if p.is_file() and p.name != "windows-check.json"}
    require(files == receipt["files_sha256"]
            and set(files) == {"capture_full_check.py", "source-before.json", "source-after.json", "tools-before.json", "tools-after.json", "windows-check.log"},
            "complete local check file inventory/hash differs")
    require(sha(output / "capture_full_check.py") == receipt["capture_sha256"], "capture controller copy differs")
    before, after = read(output / "source-before.json"), read(output / "source-after.json")
    check_inventory(before)
    check_inventory(after)
    tools_before, tools_after = read(output / "tools-before.json"), read(output / "tools-after.json")
    text = (output / "windows-check.log").read_text(encoding="utf-8-sig", errors="replace")
    summary, comparison = python_summary(text), compare(before, after)
    require(summary == receipt["python_summary"] and comparison == receipt["source_comparison"]
            and (tools_before == tools_after) == receipt["tools_before_after_equal"], "local check observations do not replay")
    expected = receipt["expected_python_test_count"]
    expected_matches = expected is None or summary["test_counts"] == [expected]
    accepted = receipt["exit_code"] == 0 and comparison["source_inventory_before_after_equal"] and tools_before == tools_after
    accepted = accepted and len(summary["test_counts"]) == 1 and summary["following_OK"] == [True] and expected_matches and receipt["capture_script_before_after_equal"] is True
    require(accepted == receipt["complete_check_accepted"] and expected_matches == receipt["expected_python_count_matches"], "local check acceptance does not replay")
    code = receipt["exit_code"] if receipt["exit_code"] else 0 if accepted else 3
    require(code == receipt["effective_exit_code"], "local check effective exit differs")
    return {"profile": PROFILE, "command": COMMAND, "exit_code": receipt["exit_code"], "effective_exit_code": code,
            "complete_check_accepted": accepted, "maintained_files_hashed_before": len(before["files_sha256"]),
            "maintained_files_hashed_after": len(after["files_sha256"]), "python_summary": summary,
            "source_inventory_before_after_equal": comparison["source_inventory_before_after_equal"],
            "tools_before_after_equal": tools_before == tools_after, "members_verified": len(files),
            "new_executable_execution_performed_by_verifier": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-python-tests", type=int)
    args = parser.parse_args()
    if args.action == "capture":
        raise SystemExit(capture(args.output, args.expected_python_tests))
    print(json.dumps(verify(args.output), indent=2))


if __name__ == "__main__":
    main()
