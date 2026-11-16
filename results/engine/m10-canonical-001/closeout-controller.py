"""Local M10 closeout: seal an existing check, or promote after verified CI.

Nothing runs at import. `seal-check` reads/copies already completed evidence.
`promote` copies the original qualified 003 Windows CLI and performs only
profile, 16 exchange/rejection and five disabled-command smoke checks. Neither
command compiles, benchmarks, fuzzes, contacts the network or claims C01.
Outputs use exclusive creation and preserve the executing helper on each run.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True

TESTS = 514
PROFILE = "KEM1536-DEV-Q7681-R1"
SOURCE_003 = "67084be5ab1cde058661104b16e738138db7993dec001ac39625feb830b2810d"
CLI_003 = "2d6aa2e5859ea1df7774e5dd1cbb35827c8e9e1feddbe9f1f72a80c1661d5468"
CANONICAL_M09 = "9eb95fb2cb9a8531a216012b4cff71d6b10d1a7951285d9d3c666f8186002255"
CHECK_COMMAND = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", "scripts/dev.ps1", "check"]
SMOKES = (("profile", ("dev-profile",), 0), ("self-test", ("dev-self-test",), 0),
          ("refuse-vectors", ("dev-vectors", "1"), 1),
          ("refuse-rejections", ("dev-rejection-vectors",), 1),
          ("refuse-hardening", ("dev-hardening",), 1),
          ("refuse-mutations", ("dev-mutations",), 1),
          ("refuse-timing", ("dev-timing",), 1))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def root_from_script():
    for folder in Path(__file__).resolve().parents:
        if (folder / "Cargo.toml").is_file() and (folder / "research/m10_publication.py").is_file():
            return folder
    raise ValueError("run this helper inside the NIST project or supply --root")


def ordinary(path, directory=False):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode)
            and not (getattr(info, "st_file_attributes", 0) & 0x400), "linked/reparse input refused: " + str(path))
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            "ordinary directory/file required: " + str(path))
    return path


def member(root, name):
    require(type(name) is str and name and "\\" not in name and ":" not in name,
            "portable relative member required")
    parts = name.split("/")
    require(not PurePosixPath(name).is_absolute() and all(p not in ("", ".", "..") for p in parts),
            "unsafe relative member")
    path = root.joinpath(*parts)
    require(path.resolve().is_relative_to(root.resolve()), "member escaped its root")
    return path


def exact(root, path, relative):
    path = Path(os.path.abspath(path))
    expected = root / relative
    require(path == expected and path.resolve() == expected.resolve(), "unexpected closeout path: " + str(path))
    current = root
    ordinary(current, directory=True)
    for part in Path(relative).parts[:-1]:
        current /= part
        ordinary(current, directory=True)
    if path.exists():
        ordinary(path, directory=path.is_dir())
    return path


def sha(path):
    ordinary(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    ordinary(path)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def inventory(folder):
    ordinary(folder, directory=True)
    result = {}
    for path in sorted(folder.rglob("*")):
        ordinary(path, directory=path.is_dir())
        if path.is_file():
            result[path.relative_to(folder).as_posix()] = sha(path)
    return result


def checked_inventory(folder, schema):
    provenance = read(folder / "provenance.json")
    actual = inventory(folder)
    actual.pop("provenance.json")
    require(provenance["schema"] == schema and provenance["output_sha256"] == actual,
            "sealed closeout inventory differs: " + str(folder))
    return provenance


def parse_full_check(raw):
    # Native PowerShell logs are normally byte/UTF-8 streams. Preserve their
    # original hash even if a UTF-16 BOM explicitly requests another decoder.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        parsed = raw.decode("utf-16").encode("utf-8")
    else:
        parsed = raw
    summaries = list(re.finditer(rb"(?m)^Ran ([0-9]+) tests in [^\r\n]+\r?$", parsed))
    require(len(summaries) == 1 and int(summaries[0][1]) == TESTS, "one full Ran 514 tests summary required")
    tail = parsed[summaries[0].end():].lstrip().splitlines()
    require(tail and tail[0].strip() == b"OK", "514 tests must finish with exact OK, without skips")
    return {"python_tests": TESTS, "python_status": "OK", "skipped": 0}


def qualified(root):
    folder = exact(root, root / "artifacts/generated/m10-final-003", "artifacts/generated/m10-final-003")
    engine_path = root / "results/engine/m10-001/provenance.json"
    engine = read(engine_path)
    require(engine["schema"] == "m10-engine-capsule-v1" and engine["profile"] == PROFILE
            and engine["C01_closed"] is False and engine["cryptographic_profile_finalized"] is False
            and engine["external_review_performed"] is False, "qualified engine scope differs")
    group = engine["groups"]["qualification"]
    source_path = folder / "source.json"
    source_raw = source_path.read_bytes()
    require(digest(source_raw) == SOURCE_003 == group["files"]["source.json"]["sha256"],
            "the final qualified source must be the frozen 003 capture")
    source = json.loads(source_raw)
    require(source["profile"] == PROFILE and source["label"] == "M10-borrowed-XOF-copied-output",
            "source003 profile/realization differs")
    builds = {}
    for host in ("windows", "linux"):
        path = folder / host / "build.json"
        require(sha(path) == group["files"][host + "/build.json"]["sha256"], "qualified build receipt differs")
        build = read(path)
        require(build["source_manifest_sha256"] == SOURCE_003 and build["host"] == host
                and build["profile"] == PROFILE, "build/source/host identity differs")
        item = build["binaries"]["delivered"]
        require(item["exit_code"] == 0 and item["emit_stack_metadata"] is False
                and "release: 1.91.1" in item["rustc"]
                and not any(a in ("--features", "--all-features") or a.startswith("--features=")
                            for a in item["command"]), "original default CLI build required")
        builds[host] = build
    require(builds["windows"]["binaries"]["delivered"]["sha256"] == CLI_003,
            "unexpected original Windows003 CLI")
    return folder, source, builds, engine_path


def copy_identity(output, folder, engine_path):
    for source, name in ((engine_path, "engine-provenance.json"), (folder / "source.json", "qualified-source.json"),
                         (folder / "windows/build.json", "windows-build.json"),
                         (folder / "linux/build.json", "linux-build.json")):
        shutil.copyfile(source, output / name)


def freeze_helper(output):
    raw = Path(__file__).read_bytes()
    (output / "closeout-controller.py").write_bytes(raw)
    return digest(raw)


def finish_inventory(output, schema, helper_sha, **bindings):
    require(sha(Path(__file__)) == helper_sha, "executing helper changed during closeout")
    save(output / "provenance.json", {"schema": schema, "output_sha256": inventory(output),
                                     "controller_sha256": helper_sha, **bindings})


def seal_check(root, check, output):
    root = Path(root).resolve()
    if str(root / "research") not in sys.path:
        sys.path.insert(0, str(root / "research"))
    check = exact(root, check, "artifacts/generated/m10-check-001")
    output = exact(root, output, "results/engine/m10-verification-001")
    require(not output.exists(), "new M10 local-check receipt required")
    folder, source, builds, engine_path = qualified(root)
    receipt, before = read(check / "receipt.json"), read(check / "inputs-before.json")
    require(type(before) is dict and before and receipt["command"] == CHECK_COMMAND
            and type(receipt["exit_code"]) is int and receipt["exit_code"] == 0
            and receipt["compiled_sources_and_check_scripts_unchanged"] is True
            and receipt["inputs_after_sha256"] == before
            and receipt["source_and_control_input_count"] == len(before)
            and receipt["historical_CPU_credit"] == 0, "local check failed or before/after inputs differ")
    require(sha(check / "full-check.log") == receipt["log_sha256"], "full check log differs")
    summary = parse_full_check((check / "full-check.log").read_bytes())
    require({name: sha(member(root, name)) for name in before} == before, "check inputs changed after completion")
    from m10_publication import qualified_input_names
    names = qualified_input_names(source["source_sha256"])
    require(names, "empty qualified compilation input map")
    for name in names:
        require(sha(member(root, name)) == source["source_sha256"][name], "current compilation input differs from003")
        if name in before:
            require(before[name] == source["source_sha256"][name], "checked compilation input differs from003")
    mandatory = {"Cargo.toml", "Cargo.lock", "crates/kem1536/src/dev_kem.rs",
                 "crates/kem1536/src/engine_poly.rs", "crates/kem1536/src/secret_box.rs"}
    require(mandatory <= set(before) & names, "core qualification absent from complete before/after check")
    captured = inventory(check)
    shutil.copytree(check, output)
    helper_sha = freeze_helper(output)
    copy_identity(output, folder, engine_path)
    require(inventory(check) == captured
            and all(sha(member(output, n)) == checksum for n, checksum in captured.items()),
            "complete local check changed while copied")
    require({name: sha(member(root, name)) for name in before} == before, "check inputs changed during seal")
    report = {"schema": "m10-local-full-check-v1", "sealed_utc": utc(), "exit_code": 0, **summary,
              "source_and_control_input_count": len(before), "source_and_controls_unchanged": True,
              "qualified_compilation_inputs_checked_at_seal": len(names),
              "qualified_inputs_in_before_after": len(names & set(before)),
              "qualified_inputs_outside_before_after": sorted(names - set(before)),
              "source_manifest_sha256": SOURCE_003, "engine_provenance_sha256": sha(engine_path),
              "original_check_members_sha256": captured, "fresh_long_fuzz_credit": 0, "new_builds": 0,
              "external_audit": False, "global_security_or_CT_or_erasure_proved": False}
    save(output / "verification.json", report)
    (output / "README.md").write_text(
        "# M10 local full check\n\nComplete captured check, 514 tests with exact OK and no skips, "
        "unchanged recorded inputs, and source003/engine-provenance bindings. "
        "This seal performs no new test, engine execution, compilation or fuzzing.\n", encoding="utf-8")
    finish_inventory(output, "m10-local-check-receipt-v1", helper_sha,
                     source_manifest_sha256=SOURCE_003, engine_provenance_sha256=sha(engine_path))
    return report


def check_local_seal(root, engine_sha):
    output = root / "results/engine/m10-verification-001"
    provenance = checked_inventory(output, "m10-local-check-receipt-v1")
    report = read(output / "verification.json")
    receipt, before = read(output / "receipt.json"), read(output / "inputs-before.json")
    require(report["source_manifest_sha256"] == provenance["source_manifest_sha256"] == SOURCE_003
            and report["engine_provenance_sha256"] == provenance["engine_provenance_sha256"] == engine_sha
            and sha(output / "qualified-source.json") == SOURCE_003
            and sha(output / "engine-provenance.json") == engine_sha,
            "sealed local check concerns another qualification")
    require(report["exit_code"] == receipt["exit_code"] == 0 and report["python_tests"] == TESTS
            and report["skipped"] == 0 and report["source_and_controls_unchanged"] is True
            and before == receipt["inputs_after_sha256"]
            and receipt["compiled_sources_and_check_scripts_unchanged"] is True
            and sha(output / "full-check.log") == receipt["log_sha256"], "sealed local check failed")
    parse_full_check((output / "full-check.log").read_bytes())
    return sha(output / "provenance.json")


def parse_profile(raw):
    text = raw.decode("utf-8-sig")
    values = []
    decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip()
        value, at = decoder.raw_decode(text)
        values.append(value)
        text = text[at:]
    require(len(values) == 2 and values[0] == {"configuration_check": "passed",
            "implementation_status": "experimental-r1-reference", "scope": "public parameters and object sizes only"},
            "canonical configuration/profile framing differs")
    expected = {"ciphertext_bytes": 2656, "dv": 5, "eta": 3, "expanded_private_key_bytes": 5088,
                "k": 6, "n": 256, "profile": PROFILE, "public_key_bytes": 2528, "q": 7681,
                "security_validation": "pending", "shared_secret_bytes": 32,
                "u_encoding": "exact-13-bit-canonical"}
    require(values[1] == expected, "canonical R1 parameters/object sizes differ")
    return values


def replace_image(target, raw, expected_current):
    require(sha(target) == expected_current, "canonical changed before atomic replacement")
    stage = target.with_name(".m10-closeout-001-stage.exe")
    require(not stage.exists() and stage.resolve().parent == target.resolve().parent, "new local staging file required")
    with stage.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(sha(stage) == digest(raw) and sha(target) == expected_current, "image changed during staging")
    os.replace(stage, target)
    require(sha(target) == digest(raw), "atomic canonical copy differs")


def promote(root, ci_path, output):
    root = Path(root).resolve()
    if str(root / "research") not in sys.path:
        sys.path.insert(0, str(root / "research"))
    require(os.name == "nt", "canonical promotion executes the native Windows CLI")
    ci_path = exact(root, ci_path, "results/publication/r6-m10-001")
    output = exact(root, output, "results/engine/m10-canonical-001")
    require(not output.exists(), "new M10 canonical receipt required")
    folder, source, builds, engine_path = qualified(root)
    from m10_publication import verify as verify_ci
    from smoke_m08_package import check_cli_test
    ci = verify_ci(ci_path)  # Offline reader; never calls capture/status or API.
    require(ci["schema"] == "m10-hosted-integration-v1"
            and set(ci["runners"]) == {"windows-latest", "ubuntu-24.04"}
            and all(type(row["python_tests"]) is int and row["python_tests"] == TESTS
                    for row in ci["runners"].values()), "two complete 514-test hosted jobs required")
    require(sha(ci_path / "engine-provenance.json") == sha(engine_path)
            and sha(ci_path / "qualified-source.json") == SOURCE_003, "CI concerns another qualified engine")
    for host in ("windows", "linux"):
        require(sha(ci_path / (host + "-build.json")) == sha(folder / host / "build.json"),
                "CI build/image binding differs from003")
    local_seal_sha = check_local_seal(root, sha(engine_path))
    previous_folder = root / "results/engine/m09-canonical-001"
    checked_inventory(previous_folder, "m09-canonical-evidence-v1")
    previous = read(previous_folder / "promotion.json")
    require(previous["schema"] == "m09-canonical-promotion-v1"
            and previous["target"] == "target/release/kem1536.exe"
            and previous["original_and_promoted_sha256"] == CANONICAL_M09, "known M09 promotion receipt required")
    target = exact(root, root / previous["target"], previous["target"])
    original = member(folder, builds["windows"]["binaries"]["delivered"]["path"])
    require(original == folder / "windows/bin/delivered.exe" and sha(original) == CLI_003
            and sha(target) == CANONICAL_M09, "known current M09 and original003 images required")
    previous_bytes, original_bytes = target.read_bytes(), original.read_bytes()
    require(digest(previous_bytes) == CANONICAL_M09 and digest(original_bytes) == CLI_003,
            "image changed while read")
    output.mkdir()
    helper_sha = freeze_helper(output)
    copy_identity(output, folder, engine_path)
    for source_path, name in ((previous_folder / "promotion.json", "previous-promotion.json"),
                              (previous_folder / "provenance.json", "previous-provenance.json"),
                              (ci_path / "provenance.json", "publication-provenance.json"),
                              (ci_path / "verification.json", "hosted-verification.json")):
        shutil.copyfile(source_path, output / name)
    with (output / "previous-canonical.exe.gz").open("xb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            compressed.write(previous_bytes)
    plan = {"schema": "m10-canonical-plan-v1", "started_utc": utc(), "target": previous["target"],
            "previous_sha256": CANONICAL_M09, "original_path": original.relative_to(root).as_posix(),
            "original_M10_sha256": CLI_003, "source_manifest_sha256": SOURCE_003,
            "engine_provenance_sha256": sha(engine_path), "local_check_provenance_sha256": local_seal_sha,
            "previous_promotion_sha256": sha(previous_folder / "promotion.json"),
            "publication_provenance_sha256": sha(ci_path / "provenance.json"),
            "final_CI_run": ci["run_id"], "public_tested_commit": ci["public_tested_commit"],
            "source_commit": ci["source_commit"], "python_tests_per_OS": TESTS,
            "controller_sha256": helper_sha, "new_builds": 0, "new_fuzzing_credit_seconds": 0}
    save(output / "plan-before.json", plan)
    checks, failure, copied, restored = [], None, False, False
    try:
        replace_image(target, original_bytes, CANONICAL_M09)
        copied = True
        for label, arguments, wanted_exit in SMOKES:
            require(sha(target) == CLI_003 and sha(original) == CLI_003, "image changed before canonical smoke")
            command = [str(target), *arguments]
            try:
                process = subprocess.run(command, capture_output=True, cwd=root, timeout=120)
                stdout, stderr, code = process.stdout, process.stderr, process.returncode
            except subprocess.TimeoutExpired as error:
                stdout, stderr, code = error.stdout or b"", error.stderr or b"", None
            (output / (label + ".stdout")).write_bytes(stdout)
            (output / (label + ".stderr")).write_bytes(stderr)
            item = {"operation": label, "arguments": list(arguments), "exit_code": code,
                    "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
            checks.append(item)
            require(code == wanted_exit, "canonical smoke failed/timed out: " + label)
            if wanted_exit == 1:
                require(stdout == b"", "default canonical exposed research output")
            else:
                require(stderr == b"", "successful canonical smoke wrote stderr")
                if label == "profile":
                    parse_profile(stdout)
                else:
                    value = json.loads(stdout)
                    check_cli_test(value)
                    require(value.get("security_validation") == "pending", "canonical overstated security validation")
        require(sha(target) == CLI_003 and sha(original) == CLI_003, "image changed during canonical smoke")
        require(sha(ci_path / "provenance.json") == plan["publication_provenance_sha256"]
                and sha(engine_path) == plan["engine_provenance_sha256"]
                and sha(previous_folder / "promotion.json") == plan["previous_promotion_sha256"],
                "bound evidence changed during promotion")
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error)}
        # Do not overwrite a concurrent external edit. Restore only our exact
        # copied candidate, keeping all outputs and the pre-copy bytes as proof.
        if target.is_file() and sha(target) == CLI_003:
            copied = True
            try:
                replace_image(target, previous_bytes, CLI_003)
                restored = True
            except BaseException as rollback_error:
                failure["rollback_failure"] = {"type": type(rollback_error).__name__, "message": str(rollback_error)}
    result = {**plan, "schema": "m10-canonical-promotion-v1", "finished_utc": utc(),
              "status": "PASS" if failure is None else "FAIL", "failure": failure,
              "original_and_promoted_sha256": CLI_003 if failure is None else None,
              "canonical_sha256_after": sha(target), "copied": copied,
              "previous_canonical_restored_after_failure": restored, "checks": checks,
              "fresh_round_trips": 16 if failure is None else 0,
              "implicit_rejections": 16 if failure is None else 0,
              "external_audit": False, "C01_closed": False,
              "global_security_or_CT_or_erasure_proved": False}
    save(output / "promotion.json", result)
    (output / "README.md").write_text(
        "# M10 canonical Windows CLI\n\nThe frozen original003 CLI is copied only after the "
        "verified two-OS 514-test hosted receipt and local full-check seal. Profile,16 exchanges,16 rejections "
        "and five disabled research commands are checked after copying. Old M09 bytes and identities are retained. "
        "Failure/rollback is explicit; no build, benchmark or fuzzing credit is created.\n", encoding="utf-8")
    finish_inventory(output, "m10-canonical-evidence-v1", helper_sha, source_manifest_sha256=SOURCE_003,
                     engine_provenance_sha256=plan["engine_provenance_sha256"],
                     publication_provenance_sha256=plan["publication_provenance_sha256"])
    require(failure is None, "canonical promotion failed; all traces retained: " + str(failure))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    commands = parser.add_subparsers(dest="action", required=True)
    seal = commands.add_parser("seal-check")
    seal.add_argument("--check-root", type=Path)
    seal.add_argument("--output", type=Path)
    promotion = commands.add_parser("promote")
    promotion.add_argument("--ci", type=Path)
    promotion.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = (args.root or root_from_script()).resolve()
    ordinary(root, directory=True)
    sys.path.insert(0, str(root / "research"))
    if args.action == "seal-check":
        result = seal_check(root, (args.check_root or root / "artifacts/generated/m10-check-001").absolute(),
                            (args.output or root / "results/engine/m10-verification-001").absolute())
    else:
        result = promote(root, (args.ci or root / "results/publication/r6-m10-001").absolute(),
                         (args.output or root / "results/engine/m10-canonical-001").absolute())
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
