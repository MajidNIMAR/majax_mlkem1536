"""Compare two local M06 builds and bind fresh self-tests to delivered bytes."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import struct

from validate_hardening_m02 import command

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "artifacts/generated"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def comparison_bytes(raw, host):
    """Mask only two PE header metadata fields in a temporary comparison copy."""
    if host != "windows":
        return raw, []
    if len(raw) < 256 or raw[:2] != b"MZ":
        raise ValueError("expected a PE executable")
    pe = struct.unpack_from("<I", raw, 60)[0]
    if pe + 92 > len(raw) or raw[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    if struct.unpack_from("<H", raw, pe + 4)[0] != 0x8664 or struct.unpack_from("<H", raw, pe + 24)[0] != 0x20B:
        raise ValueError("expected x86-64 PE32+")
    fields = [("COFF_TimeDateStamp", pe + 8), ("OptionalHeader_CheckSum", pe + 88)]
    normalized = bytearray(raw)
    for _, offset in fields:
        normalized[offset:offset + 4] = b"\0" * 4
    return bytes(normalized), [dict(name=name, offset=offset, size=4,
                                   value=struct.unpack_from("<I", raw, offset)[0]) for name, offset in fields]


def confirm():
    first = json.loads((GENERATED / "m06-validation-001/builds.json").read_text())
    second = json.loads((GENERATED / "m06-validation-002/builds.json").read_text())
    for name, checksum in first["source_sha256"].items():
        if second["source_sha256"].get(name) != checksum:
            raise ValueError("a common build source differs")
    rows = {}
    for host in ("windows", "linux"):
        comparisons = {}
        for kind in ("research", "delivered", "timing"):
            checksum = second["builds"][host][kind]["sha256"]
            raw = []
            for label, receipt in (("001", first), ("002", second)):
                path = ROOT / receipt["builds"][host][kind]["path"]
                if sha(path) != receipt["builds"][host][kind]["sha256"]:
                    raise ValueError(f"build {label} bytes changed")
                raw.append(path.read_bytes())
            normalized = [comparison_bytes(value, host) for value in raw]
            if normalized[0][0] != normalized[1][0]:
                raise ValueError(f"rebuilt program bytes differ outside allowed metadata: {host}/{kind}")
            comparisons[kind] = dict(byte_identical=raw[0] == raw[1],
                                     comparison_sha256=hashlib.sha256(normalized[0][0]).hexdigest(),
                                     first_metadata=normalized[0][1], second_metadata=normalized[1][1],
                                     binaries_modified=False)
        binary = ROOT / first["builds"][host]["delivered"]["path"]
        checksum = sha(binary)
        result = json.loads(subprocess.check_output(command(binary, ["dev-self-test"]), cwd=ROOT))
        if sha(binary) != checksum:
            raise ValueError("delivery binary changed during self-test")
        if (result["fresh_round_trips"], result["implicit_rejections_checked"], result["secrets_printed"]) != (16, 16, False):
            raise ValueError("fresh self-test failed")
        rows[host] = dict(build_comparisons=comparisons,
                          self_test_binary_sha256_before=checksum, self_test_binary_sha256_after=sha(binary),
                          fresh_self_test=result)
    result = dict(created_utc=datetime.now(timezone.utc).isoformat(), platforms=rows,
                  initial_source_capture_scope="project crates/profiles/configs; external Rust includes omitted",
                  second_source_capture_scope="same sources plus literal Rust include_str/include_bytes inputs, captured before rebuild",
                  all_common_source_bytes_identical=True,
                  raw_binaries_byte_identical=False,
                  Windows_comparison_scope="only COFF timestamp and PE optional-header checksum masked in temporary copies; original bytes retained",
                  first_builds_json_sha256=sha(GENERATED / "m06-validation-001/builds.json"),
                  second_builds_json_sha256=sha(GENERATED / "m06-validation-002/builds.json"),
                  independent_cross_host_reproduction_claimed=False)
    with (GENERATED / "m06-build-confirmation.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    confirm()
