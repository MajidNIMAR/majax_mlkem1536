"""Exercise exact preserved M08 CLI and default-feature consumer images natively.

This fresh finite CI integration check performs no rebuild, benchmark, fuzzing,
disassembly, constant-time proof or universal-erasure proof. Only the delivery
and import-review archive stages are reconstructed; no application keys are used.
"""
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile

import archive_m08 as archive
import package_m08 as delivery
import review_m08_imports as import_review

PROFILE = "KEM1536-DEV-Q7681-R1"
MAX_CONSUMER_BYTES = 256 * 1024 * 1024
CASES = (("public_valid", 0), ("public_noncanonical_first", 2), ("public_noncanonical_last", 2),
         ("private_valid", 0), ("private_secret_noncanonical_first", 2),
         ("private_secret_noncanonical_last", 2), ("private_public_noncanonical", 2),
         ("private_hash_invalid", 3), ("private_secret_and_hash_invalid", 2),
         ("private_public_and_hash_invalid", 2), ("private_secret_and_public_invalid", 2),
         ("public_short", 1), ("private_short", 1))
FIXTURE = {"kind": "deterministic synthetic structural encodings; not a generated KEM key pair",
           "public_sha3_256": "bd26b3e8db2f105b3881b9f1d6319f53b43ad4b98893e31a7e0a67680ee8ab16",
           "private_sha3_256": "d9fa8ca0a1ecf13ce7f168fdc9dc5dcbe4120f0de38eea9f1678527509fcf465",
           "encoding_bytes_printed": False}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def native_host():
    require(platform.machine().casefold() in {"amd64", "x86_64"}, "M08 native images require x86-64")
    require(os.name == "nt" or platform.system() == "Linux", "M08 native images support Windows/Linux")
    return "windows" if os.name == "nt" else "linux"


def check_architecture(path, host):
    with path.open("rb") as stream:
        header = stream.read(4096)
    if host == "windows":
        require(len(header) >= 64 and header[:2] == b"MZ", "native image is not a PE executable")
        offset = struct.unpack_from("<I", header, 60)[0]
        require(offset <= len(header) - 26 and header[offset:offset + 4] == b"PE\0\0"
                and struct.unpack_from("<H", header, offset + 4)[0] == 0x8664
                and struct.unpack_from("<H", header, offset + 24)[0] == 0x20B,
                "native image is not x86-64 PE32+")
    else:
        require(host == "linux" and len(header) >= 20 and header[:6] == b"\x7fELF\x02\x01"
                and struct.unpack_from("<H", header, 18)[0] == 62,
                "native image is not little-endian x86-64 ELF64")


def recover_consumer(compressed, destination, expected, limit=MAX_CONSUMER_BYTES):
    """Recover a hash-identified image with a finite decompression budget."""
    length = 0
    with gzip.open(compressed, "rb") as source, destination.open("xb") as sink:
        while chunk := source.read(min(1024 * 1024, limit - length + 1)):
            length += len(chunk)
            require(length <= limit, "consumer image exceeds decompression budget")
            sink.write(chunk)
    require(archive.sha(destination) == expected, "recovered consumer is not the sealed original")


@contextmanager
def executable_directory():
    parent = archive.ROOT / "target/m08-native-smoke"
    require(parent.resolve().is_relative_to(archive.ROOT.resolve()), "native temporary path escapes NIST")
    parent.mkdir(parents=True, exist_ok=True)
    current = archive.ROOT
    for part in parent.relative_to(archive.ROOT).parts:
        current /= part
        archive.ordinary(current, directory=True)
    with tempfile.TemporaryDirectory(prefix="native-", dir=parent) as raw:
        path = Path(raw)
        require(path.resolve().parent == parent.resolve(), "native temporary directory escapes owned parent")
        yield path


def run_process(binary, arguments, timeout):
    result = subprocess.run([str(binary), *arguments], capture_output=True, timeout=timeout)
    return result


def json_result(binary, argument, timeout):
    result = run_process(binary, [argument], timeout)
    require(result.returncode == 0 and result.stderr == b"", "native JSON check failed: " + argument)
    # Never include captured stdout/stderr in failures or the CI report.
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise ValueError("native JSON check returned invalid JSON: " + argument) from None
    return value, {"operation": argument, "exit_code": result.returncode,
                   "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                   "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}


def check_cli_test(value):
    require(value.get("profile") == PROFILE and type(value.get("fresh_round_trips")) is int
            and value["fresh_round_trips"] == 16 and type(value.get("implicit_rejections_checked")) is int
            and value["implicit_rejections_checked"] == 16 and value.get("secrets_printed") is False,
            "preserved CLI self-test scope differs")


def check_consumer_smoke(value, host):
    require(value.get("schema") == 1 and value.get("profile") == PROFILE
            and value.get("host") == host and value.get("architecture") == "x86_64"
            and value.get("research_vectors_feature_requested") is False
            and value.get("secrets_printed") is False and value.get("fixtures") == FIXTURE,
            "default consumer smoke identity/scope differs")
    require(value.get("cases") == [{"operation": name, "expected": status, "status": status} for name, status in CASES],
            "default consumer import cases differ")
    require(type(value.get("fresh_imported_key_round_trips")) is int and value["fresh_imported_key_round_trips"] == 1
            and type(value.get("fresh_rejections")) is int and value["fresh_rejections"] == 1
            and value.get("repeat_rejection_equal") is True
            and value.get("fresh_private_with_fixed_z_imported") is True
            and value.get("fixed_z_import_is_syntax_not_entropy_validation") is True,
            "default consumer fresh imported-key checks differ")


def check_consumer_exhaustive(value):
    expected = {"schema": 1, "profile": PROFILE, "mode": "exhaustive single-coefficient probes",
                "single_coefficient_value_alignment_cases": 65536, "boundary_position_cases": 23040,
                "total_cases": 88576, "all_expected_statuses_and_accepted_encodings_match": True,
                "complete_vector_space_exhausted": False, "formal_program_verification": False,
                "secrets_printed": False, "fixture": FIXTURE}
    require(value == expected, "default consumer 88576-probe checks differ")


def check_stage_binding(delivery_stage, import_stage, host):
    """Join separately sealed consumer and original CLI evidence before execution."""
    delivery.verify(delivery_stage)
    import_review.verify(import_stage)
    collection = archive.read(import_stage / "collection.json")
    marker = archive.read(delivery_stage / "validation/delivery-accepted.json")
    manifest = delivery_stage / "validation/candidate-source.json"
    require(archive.sha(import_stage / "provenance.json") == marker["import_review_receipt_sha256"]
            and collection["source_manifest_sha256"]["candidate"] == archive.sha(manifest)
            and collection["memory_acceptance_sha256"] == archive.sha(delivery_stage / "validation/memory-accepted.json")
            and archive.sha(import_stage / "collection.json") == archive.sha(delivery_stage / "validation/import-review-collection.json"),
            "native CLI/consumer stages are not the same accepted M08 candidate")
    original = archive.read(delivery_stage / "result.json")["platforms"][host]["original_binary_sha256"]
    consumer = collection["binaries"]["candidate-" + host]["sha256"]
    return original, consumer, collection["source_manifest_sha256"]["candidate"]


def smoke(snapshot=None):
    host, started = native_host(), datetime.now(timezone.utc).isoformat()
    snapshot = (archive.ROOT / "results/engine/m08-001") if snapshot is None else Path(snapshot).resolve()
    with ExitStack() as stack:
        delivery_stage = stack.enter_context(archive.extracted_stage(snapshot, "delivery"))
        import_stage = stack.enter_context(archive.extracted_stage(snapshot, "imports"))
        cli_hash, consumer_hash, source_hash = check_stage_binding(delivery_stage, import_stage, host)
        temporary = stack.enter_context(executable_directory())
        suffix = ".exe" if host == "windows" else ""
        cli, consumer = temporary / ("kem1536" + suffix), temporary / ("m08-import-consumer" + suffix)
        original = delivery_stage / host / "package/bin" / ("kem1536" + suffix)
        require(archive.sha(original) == cli_hash, "native CLI is not the shipped original")
        shutil.copyfile(original, cli)
        require(archive.sha(cli) == cli_hash, "native CLI copy differs")
        recover_consumer(import_stage / "audit" / ("candidate-" + host) / "binary.gz", consumer, consumer_hash)
        for binary in (cli, consumer):
            check_architecture(binary, host)
            if host == "linux":
                binary.chmod(0o700)
        checks = []
        value, receipt = json_result(cli, "dev-self-test", 120)
        check_cli_test(value)
        checks.append(receipt)
        disabled = []
        for arguments in delivery.RESEARCH_COMMANDS:
            result = run_process(cli, list(arguments), 30)
            require(result.returncode == 1 and result.stdout == b"", "CLI research command did not reject normally")
            disabled.append({"arguments": list(arguments), "exit_code": result.returncode,
                             "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                             "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        value, receipt = json_result(consumer, "smoke", 120)
        check_consumer_smoke(value, host)
        checks.append(receipt)
        value, receipt = json_result(consumer, "exhaustive", 180)
        check_consumer_exhaustive(value)
        checks.append(receipt)
        require(archive.sha(cli) == cli_hash and archive.sha(consumer) == consumer_hash,
                "native image changed during fresh checks")
        return {"schema": "m08-native-smoke-v1", "profile": PROFILE, "host": host,
                "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
                "candidate_source_manifest_sha256": source_hash, "original_CLI_sha256": cli_hash,
                "original_default_consumer_sha256": consumer_hash, "checks": checks,
                "CLI_fresh_round_trips": 16, "CLI_implicit_rejections_checked": 16,
                "research_commands_rejected": disabled, "consumer_import_cases": len(CASES),
                "consumer_fresh_imported_key_round_trips": 1, "consumer_fresh_rejections": 1,
                "consumer_single_coefficient_and_boundary_probes": 88576,
                "new_compilation_performed": False, "new_benchmark_performed": False,
                "new_disassembly_performed": False, "constant_time_proved": False,
                "universal_erasure_proved": False, "secrets_printed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=archive.ROOT / "results/engine/m08-001")
    args = parser.parse_args()
    print(json.dumps(smoke(args.snapshot), indent=2))


if __name__ == "__main__":
    main()
