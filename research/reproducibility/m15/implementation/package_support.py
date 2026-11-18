"""Standard-library checks shared by the bounded M15 Windows replay tools."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import stat
import struct
import sys
from pathlib import Path, PurePosixPath

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
MANIFEST_SCHEMA = "m15-public-implementation-lot1-v1"
LOCK_SCHEMA = "m15-windows-solver-lock-v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative_name(value: str) -> str:
    require(isinstance(value, str) and bool(value), "empty/non-string relative path")
    require("\\" not in value and ":" not in value and "\x00" not in value,
            "non-portable relative path")
    parts = PurePosixPath(value).parts
    require(not value.startswith("/") and all(p not in (".", "..", "") for p in parts),
            "path must remain relative and canonical")
    require("/".join(parts) == value, "noncanonical relative path")
    require(all(not p.endswith((".", " ")) for p in parts), "Windows path alias")
    require(all(p.split(".", 1)[0].upper() not in
                {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                 *(f"LPT{i}" for i in range(1, 10))} for p in parts), "Windows device path")
    return value


def no_links(path: Path) -> None:
    """Check existing ancestors, including Windows junctions/reparse points."""
    for node in (path, *path.parents):
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not
                (getattr(info, "st_file_attributes", 0) & 0x400),
                f"linked/reparse path refused: {node.name}")


def safe_path(relative: str, base: Path | None = None) -> Path:
    base = ROOT if base is None else base
    relative_name(relative)
    no_links(base)
    path = base.joinpath(*PurePosixPath(relative).parts)
    no_links(path)
    require(path.resolve().is_relative_to(base.resolve()), "path escaped its base")
    return path


def read_json(path: Path) -> dict:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    require(isinstance(value, dict), "JSON object required")
    return value


def check_platform() -> None:
    require(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 13),
            "full replay requires CPython 3.13")
    require(sys.platform == "win32" and struct.calcsize("P") == 8 and
            platform.machine().upper() in ("AMD64", "X86_64"),
            "full replay requires Windows x86-64")


def check_record(path: Path, record: dict) -> None:
    require(path.is_file(), f"missing input: {path.name}")
    require(type(record.get("bytes")) is int and record["bytes"] >= 0,
            "invalid recorded size")
    require(isinstance(record.get("sha256"), str) and
            re.fullmatch("[0-9a-f]{64}", record["sha256"]) is not None,
            "invalid recorded digest")
    require(path.stat().st_size == record["bytes"] and sha(path) == record["sha256"],
            f"input bytes differ: {path.name}")


def package_members() -> set[str]:
    members = set()
    for path in BASE.rglob("*"):
        no_links(path)
        relative = path.relative_to(BASE).as_posix()
        if "__pycache__" in path.relative_to(BASE).parts:
            # The isolated runner redirects reads away from any pre-existing cache.
            continue
        require(not path.is_file() or path.suffix not in (".pyc", ".pyo"),
                "unexpected legacy Python bytecode")
        if path.is_file() and relative != "MANIFEST.json":
            members.add(relative_name(relative))
    require(len({name.casefold() for name in members}) == len(members),
            "case-alias package members")
    return members


def load_lock() -> dict:
    lock = read_json(safe_path("solver.lock.json", BASE))
    source = read_json(safe_path("solver-source.json", BASE))
    toolchain = read_json(safe_path("toolchain.json", BASE))
    require(lock.get("schema") == LOCK_SCHEMA, "unsupported solver lock")
    for key in ("version", "wheel_url", "wheel_sha256", "wheel_bytes", "cache_relative", "target"):
        require(lock.get(key) == source.get(key), f"solver lock mismatch: {key}")
    require(lock["version"] == "4.15.4.0" and
            lock["wheel_sha256"] == "00e35b02632ed085ea8199fb230f6015e6fc40554a6680c097bd5f060e827431" and
            lock["wheel_bytes"] == 16259597, "unsupported solver artifact")
    require(lock["wheel_url"].startswith("https://files.pythonhosted.org/packages/") and
            lock["wheel_url"].endswith("/z3_solver-4.15.4.0-py3-none-win_amd64.whl"),
            "unexpected solver URL")
    require(lock["cache_relative"] == ".tools/m15-proof/z3_solver-4.15.4.0-py3-none-win_amd64.whl"
            and lock["target"] == ".tools/m15-proof/site-packages", "unexpected solver cache")
    require(lock.get("expected_members_sha256") == toolchain.get("members_sha256") and
            len(lock["expected_members_sha256"]) == 34, "solver member lock mismatch")
    for name, digest in lock["expected_members_sha256"].items():
        relative_name(name)
        require(name.startswith("z3/") and re.fullmatch("[0-9a-f]{64}", digest) is not None,
                "invalid solver member")
    require(lock.get("metadata_sha256") == toolchain.get("official_release_metadata_sha256") ==
            sha(safe_path("pypi-release.json", BASE)), "release metadata mismatch")
    return lock


def check_package() -> dict:
    manifest = read_json(safe_path("MANIFEST.json", BASE))
    require(manifest.get("schema") == MANIFEST_SCHEMA, "unsupported manifest")
    records = manifest.get("files")
    require(isinstance(records, dict) and records, "empty manifest")
    require(package_members() == set(records), "package membership differs from manifest")
    for relative, record in records.items():
        check_record(safe_path(relative, BASE), record)
    inputs = manifest.get("repository_inputs")
    require(isinstance(inputs, dict) and set(inputs) ==
            {"crates/kem1536/src/dev_kem.rs", "crates/kem1536/src/engine_poly.rs"},
            "unexpected repository input set")
    for relative, record in inputs.items():
        check_record(safe_path(relative), record)
    require(manifest.get("scope") == {"arithmetic_obligations": 31,
            "ntt_linear_coefficients": 131072, "component_tests": 21,
            "C01_closed": False}, "unexpected verification scope")
    load_lock()
    return manifest
