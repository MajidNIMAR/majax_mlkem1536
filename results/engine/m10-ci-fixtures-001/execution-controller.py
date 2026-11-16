"""Preserve a cold-root regression and one complete Python-only M10 check.

The two production test methods run unchanged in separate empty temporary
roots. Only their ROOT globals are patched; owned/write_group stay intact.
No real artifacts directory is removed. No Rust build or fuzzing is invoked.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
TEST_COUNT = 514
TEST_SOURCES = ("research/test_archive_m10.py", "research/test_m10_campaign.py")


def require(value, message):
    if not value:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def ordinary_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and not (getattr(info, "st_file_attributes", 0) & 0x400), "ordinary owned directory required")


def root_from_script():
    for parent in Path(__file__).resolve().parents:
        if (parent / "Cargo.toml").is_file() and (parent / TEST_SOURCES[0]).is_file():
            return parent
    raise ValueError("NIST project root not found")


def inventory(folder):
    result = {}
    for path in sorted(folder.rglob("*")):
        require(not path.is_symlink(), "linked evidence member refused")
        if path.is_file():
            result[path.relative_to(folder).as_posix()] = sha(path)
    return result


def input_inventory(root):
    from build_m06_validation import source_files
    paths = sorted(set(source_files() + list((root / "research").glob("*.py"))
        + [root / "scripts/dev.ps1", root / "scripts/dev.sh", root / ".github/workflows/ci.yml"]))
    return {path.relative_to(root).as_posix(): sha(path) for path in paths}


def directory_identity(path):
    ordinary_directory(path)
    info = path.stat()
    return {"resolved": str(path.resolve()), "device": info.st_dev, "inode": info.st_ino}


def cold_case(root, name, fake):
    owned = (root / "target/m10-ci-fixtures-owned").resolve()
    ordinary_directory(owned)
    ordinary_directory(fake)
    require(fake.resolve().parent == owned and fake != root and not list(fake.iterdir()), "fresh empty fake ROOT required")
    require(not (fake / "artifacts").exists() and not (fake / "artifacts/generated").exists(),
            "cold regression must start without artifacts/generated")
    sys.path.insert(0, str(root / "research"))
    if name == "archive":
        import archive_m10
        import test_archive_m10
        function = archive_m10.write_group
        require(test_archive_m10.archive is archive_m10, "test archive alias differs")
        suite = unittest.TestSuite([test_archive_m10.PublicationPartsTests(
            "test_actual_streamed_tar_round_trip_keeps_exact_members")])
        with patch.object(archive_m10, "ROOT", fake):
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
        require(archive_m10.write_group is function, "archive writer was replaced")
        patched = ["archive_m10.ROOT"]
    else:
        import m10_campaign
        import test_m10_campaign
        function, code = m10_campaign.owned, m10_campaign.owned.__code__
        require(test_m10_campaign.owned is function, "ownership test function alias differs")
        suite = unittest.TestSuite([test_m10_campaign.M10CampaignTests(
            "test_ownership_is_restricted_to_direct_m10_children")])
        with patch.object(test_m10_campaign, "ROOT", fake), patch.object(m10_campaign, "ROOT", fake):
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
        require(m10_campaign.owned is function and function.__code__ is code, "strict ownership validation was replaced")
        patched = ["test_m10_campaign.ROOT", "m10_campaign.ROOT"]
    require(result.wasSuccessful() and result.testsRun == 1 and not result.skipped,
            "cold-root original test did not pass without skips")
    require((fake / "artifacts/generated").is_dir(), "test did not prepare its own missing parent")
    ordinary_directory(fake / "artifacts")
    ordinary_directory(fake / "artifacts/generated")
    return {"case": name, "tests": 1, "passed": True, "skipped": 0,
            "fake_ROOT": str(fake), "initial_artifacts_absent": True,
            "initial_artifacts_generated_absent": True, "test_created_parent": True,
            "patched_globals_only": patched, "validation_functions_replaced": False,
            "fake_files_after_test_sha256": inventory(fake)}


def captured_run(command, root, output, stem):
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    started = utc()
    with (output / (stem + ".stdout")).open("xb") as stdout, (output / (stem + ".stderr")).open("xb") as stderr:
        result = subprocess.run(command, cwd=root, env=environment, stdout=stdout, stderr=stderr)
    return {"command": command, "cwd": str(root), "started_utc": started, "finished_utc": utc(),
            "exit_code": result.returncode, "stdout_sha256": sha(output / (stem + ".stdout")),
            "stderr_sha256": sha(output / (stem + ".stderr"))}


def run(root):
    output = root / "results/engine/m10-ci-fixtures-001"
    require(not output.exists() and output.resolve().parent == (root / "results/engine").resolve(), "new fixture proof required")
    ordinary_directory(output.parent)
    parent = root / "target/m10-ci-fixtures-owned"
    require(parent.resolve().parent == (root / "target").resolve()
            and parent.resolve().is_relative_to(root.resolve()), "owned temporary parent escaped project")
    ordinary_directory(root / "target")
    parent.mkdir(exist_ok=True)
    ordinary_directory(parent)
    initial = root / "results/publication/r6-m10-initial-001"
    initial_before = inventory(initial)
    require(initial_before.get("provenance.json") == "367ed4a6df47cc224fb6da0127fefadb1d927a225b6e36c90cba37abb23fc6f3",
            "original failed CI evidence changed")
    artifacts_before = directory_identity(root / "artifacts")
    sys.path.insert(0, str(root / "research"))
    before = input_inventory(root)
    output.mkdir()
    controller = output / "execution-controller.py"
    shutil.copyfile(Path(__file__), controller)
    helper_sha = sha(controller)
    save(output / "inputs-before.json", before)
    for name in TEST_SOURCES:
        destination = output / "test-sources" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, destination)
    shutil.copyfile(initial / "provenance.json", output / "initial-CI-provenance.json")
    python = root / ".tools/research-venv/Scripts/python.exe"
    require(python.is_file(), "pinned local research Python required")
    steps, cold = [], {}
    failure = None
    try:
        for name in ("archive", "ownership"):
            with tempfile.TemporaryDirectory(prefix=name + "-root-", dir=parent) as temporary:
                fake = Path(temporary).resolve()
                require(fake.parent == parent.resolve() and fake.is_relative_to(root.resolve()), "fake ROOT outside owned parent")
                try:
                    command = [str(python), "-B", str(controller), "--root", str(root), "case", name,
                               "--fake-root", str(fake)]
                    receipt = captured_run(command, root, output, "cold-" + name)
                    steps.append(receipt)
                    save(output / ("cold-" + name + ".receipt.json"), receipt)
                    require(receipt["exit_code"] == 0, "cold regression failed: " + name)
                    proof = json.loads((output / ("cold-" + name + ".stdout")).read_text("utf-8"))
                    require(proof["passed"] is True and proof["initial_artifacts_generated_absent"] is True,
                            "missing-parent proof did not run cold")
                    cold[name] = proof
                finally:
                    # TemporaryDirectory will recursively clean only this new
                    # checked fake root. Never delete ROOT/artifacts itself.
                    require(fake.resolve().parent == parent.resolve()
                            and fake.resolve().is_relative_to(root.resolve()), "unsafe temporary cleanup refused")
                    ordinary_directory(fake)
            require(not fake.exists(), "owned fake ROOT was not cleaned")
        require(cold["archive"]["fake_ROOT"] != cold["ownership"]["fake_ROOT"], "separate cold roots required")
        command = [str(python), "-B", "-m", "unittest", "discover", "-s", "research", "-p", "test_*.py"]
        receipt = captured_run(command, root, output, "python")
        steps.append(receipt)
        save(output / "python.receipt.json", receipt)
        raw = (output / "python.stderr").read_bytes()
        summaries = list(re.finditer(rb"(?m)^Ran ([0-9]+) tests in [^\r\n]+\r?$", raw))
        require(receipt["exit_code"] == 0 and len(summaries) == 1
                and int(summaries[0][1]) == TEST_COUNT, "complete Python514 suite failed or count differs")
        tail = raw[summaries[0].end():].lstrip().splitlines()
        require(tail and tail[0].strip() == b"OK", "Python514 must end with exact OK, without skips")
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    after = input_inventory(root)
    save(output / "inputs-after.json", after)
    stable = before == after and inventory(initial) == initial_before and sha(Path(__file__)) == helper_sha
    stable = stable and directory_identity(root / "artifacts") == artifacts_before
    if not stable and failure is None:
        failure = {"type": "ValueError", "message": "source/controller/initial-CI/helper/artifacts identity changed"}
    report = {"schema": "m10-cold-CI-fixture-proof-v1", "finished_utc": utc(),
              "status": "PASS" if failure is None else "FAIL", "failure": failure,
              "Python_tests": TEST_COUNT if failure is None else None, "Python_status": "OK" if failure is None else None,
              "skipped": 0 if failure is None else None, "cold_cases": cold, "execution_receipts": steps,
              "source_and_control_input_count": len(before), "all_inputs_before_equal_after": before == after,
              "input_manifest_before_sha256": sha(output / "inputs-before.json"),
              "input_manifest_after_sha256": sha(output / "inputs-after.json"),
              "fixed_test_sources_sha256": {name: before[name] for name in TEST_SOURCES},
              "strict_owned_controller_sha256": before["research/m10_campaign.py"],
              "initial_failed_CI_receipt_sha256": initial_before["provenance.json"],
              "initial_failed_CI_members_unchanged": inventory(initial) == initial_before,
              "actual_ROOT_artifacts_identity_before": artifacts_before,
              "actual_ROOT_artifacts_identity_after": directory_identity(root / "artifacts"),
              "temporary_cleanup_scope": "Only separate new fake roots under target/m10-ci-fixtures-owned",
              "python_executable": str(python), "python_runtime": sys.version,
              "new_Rust_builds_invoked": 0, "new_fuzzing_credit_seconds": 0,
              "engine_or_frozen_controllers_modified": False, "external_audit": False}
    save(output / "verification.json", report)
    (output / "README.md").write_text(
        "# M10 missing-parent CI fixtures\n\nThe two previously failing test methods run unchanged in separate empty "
        "fake ROOTs, initially without artifacts/generated. Only ROOT globals are patched; ownership and archive "
        "validation functions remain intact. Each test must create its own parent. One full Python514 suite follows. "
        "Exact streams, both fixed test sources, the executing helper, before/after input hashes and the unchanged "
        "initial CI identity are preserved. No actual ROOT/artifacts directory is deleted; no Rust build or fuzzing "
        "is requested by this helper. verification.json declares the actual outcome.\n", encoding="utf-8")
    save(output / "provenance.json", {"schema": "m10-CI-fixture-evidence-v1", "status": report["status"],
         "output_sha256": inventory(output), "executing_helper_sha256": helper_sha,
         "initial_failed_CI_receipt_sha256": initial_before["provenance.json"],
         "new_Rust_builds_invoked": 0, "new_fuzzing_credit_seconds": 0})
    require(failure is None, "fixture proof failed; all traces retained: " + str(failure))
    return {"output": str(output), "status": "PASS", "cold_cases": 2, "Python_tests": TEST_COUNT,
            "source_and_control_input_count": len(before), "all_inputs_before_equal_after": before == after,
            "provenance_sha256": sha(output / "provenance.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("run")
    worker = actions.add_parser("case")
    worker.add_argument("name", choices=("archive", "ownership"))
    worker.add_argument("--fake-root", type=Path, required=True)
    args = parser.parse_args()
    root = (args.root or root_from_script()).resolve()
    result = run(root) if args.action == "run" else cold_case(root, args.name, args.fake_root.resolve())
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
