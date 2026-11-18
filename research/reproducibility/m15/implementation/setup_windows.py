"""Install the pinned, repository-local M15 solver without pip or a Z3 import.

Run with CPython 3.13 x64 on Windows: ``python -I -S -B setup_windows.py``.
Only the selected package is read; downloads, extracted solver files and setup
receipts live under .tools/m15-proof. Existing unverified files are never replaced.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

# -I deliberately omits the script directory from sys.path. Restore only this
# package directory; never add a solver directory or import the solver here.
_BASE = Path(__file__).resolve().parent
_BYTECODE_PREFIX = _BASE.parents[3] / ".tools" / "m15-proof" / f".pycache-{uuid.uuid4().hex}"
if os.path.lexists(_BYTECODE_PREFIX):
    raise RuntimeError("The fresh bytecode prefix unexpectedly exists.")
# -B alone suppresses writes but still reads old caches. Neither this unused
# prefix nor its directory is created; the setting also protects helper imports.
sys.pycache_prefix = str(_BYTECODE_PREFIX)
sys.dont_write_bytecode = True
sys.path.insert(0, str(_BASE))
import package_support as p  # noqa: E402


_CACHE_ROOT = ".tools/m15-proof"
_PASSIVE_PIP_METADATA = {"INSTALLER", "REQUESTED", "RECORD", "direct_url.json"}
_MAX_MEMBER_BYTES = 256 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


def _regular(path: Path, *, directory: bool = False) -> None:
    """Reject links/junctions as well as special files before using a node."""
    details = path.lstat()
    p.require(
        not stat.S_ISLNK(details.st_mode)
        and not (getattr(details, "st_file_attributes", 0) & 0x400),
        "Reparse points and symbolic links are not permitted in solver paths.",
    )
    predicate = stat.S_ISDIR if directory else stat.S_ISREG
    p.require(predicate(details.st_mode), "Unexpected solver path type.")


def _owned(relative: str) -> Path:
    path = p.safe_path(relative, base=p.ROOT)
    root = Path(p.ROOT).absolute()
    p.require(path.is_absolute() and path.is_relative_to(root), "Path leaves the repository.")
    _regular(root, directory=True)
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if os.path.lexists(current):
            details = current.lstat()
            p.require(
                not stat.S_ISLNK(details.st_mode)
                and not (getattr(details, "st_file_attributes", 0) & 0x400),
                "Reparse points and symbolic links are not permitted in solver paths.",
            )
    return path


def _locations(lock: dict) -> tuple[Path, Path, Path]:
    owner = _owned(_CACHE_ROOT)
    cache = _owned(lock["cache_relative"])
    target = _owned(lock["target"])
    p.require(
        cache.parent == owner and target.parent == owner and cache != target,
        "Solver cache and target must be distinct children of .tools/m15-proof.",
    )
    return owner, cache, target


def _mkdir_owned(path: Path) -> None:
    root = Path(p.ROOT).absolute()
    p.require(path.is_relative_to(root), "Directory leaves the repository.")
    current = root
    _regular(current, directory=True)
    for part in path.relative_to(root).parts:
        current = current / part
        if not os.path.lexists(current):
            current.mkdir()
        _regular(current, directory=True)


def _member_name(name: str) -> str:
    p.require(isinstance(name, str) and bool(name), "Invalid wheel member name.")
    p.require("\\" not in name and ":" not in name and "\x00" not in name, "Unsafe wheel member name.")
    p.require(not any(character in '<>"|?*' or ord(character) < 32 for character in name),
              "Invalid Windows wheel member name.")
    parsed = PurePosixPath(name)
    p.require(
        not parsed.is_absolute()
        and all(part not in {"", ".", ".."} for part in name.split("/"))
        and parsed.as_posix() == name,
        "Unsafe wheel member name.",
    )
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
                *(f"COM{number}" for number in range(1, 10)),
                *(f"LPT{number}" for number in range(1, 10))}
    p.require(all(not part.endswith((".", " ")) and part.split(".", 1)[0].upper() not in reserved
                  for part in parsed.parts), "Windows wheel member alias.")
    return name


def _expected(lock: dict) -> dict[str, str]:
    members = lock["expected_members_sha256"]
    p.require(isinstance(members, dict) and bool(members), "Missing pinned solver members.")
    normalized = {}
    folded = set()
    for name, digest in members.items():
        name = _member_name(name)
        p.require(name.startswith("z3/"), "Only pinned z3/ members may be extracted.")
        p.require(name.casefold() not in folded, "Case-colliding pinned solver members.")
        p.require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                  "Invalid pinned member hash.")
        folded.add(name.casefold())
        normalized[name] = digest
    return normalized


def _stream_hash(source) -> str:
    digest = hashlib.sha256()
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def _wheel_index(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    index = {}
    folded = set()
    total = 0
    for member in archive.infolist():
        raw_name = member.filename
        name = _member_name(raw_name[:-1] if raw_name.endswith("/") else raw_name)
        p.require(name.casefold() not in folded, "Duplicate or case-colliding wheel members.")
        folded.add(name.casefold())
        mode = member.external_attr >> 16
        kind = stat.S_IFMT(mode)
        permitted_kind = {0, stat.S_IFDIR} if member.is_dir() else {0, stat.S_IFREG}
        p.require(kind in permitted_kind and not (member.flag_bits & 1),
                  "Links, special or encrypted wheel members are not permitted.")
        p.require(0 <= member.file_size <= _MAX_MEMBER_BYTES, "Oversized wheel member.")
        total += member.file_size
        p.require(total <= _MAX_ARCHIVE_BYTES, "Oversized solver archive.")
        if not member.is_dir():
            index[name] = member
    return index


def _validate_wheel(lock: dict, cache: Path) -> dict[str, str]:
    _regular(cache)
    p.require(cache.stat().st_size == lock["wheel_bytes"], "Cached wheel has the wrong size; refusing replacement.")
    p.require(p.sha(cache) == lock["wheel_sha256"], "Cached wheel hash mismatch; refusing replacement.")
    expected = _expected(lock)
    with zipfile.ZipFile(cache) as archive:
        index = _wheel_index(archive)
        actual_z3 = {name for name in index if name.startswith("z3/")}
        p.require(actual_z3 == set(expected), "Wheel z3 members differ from the pinned set.")
        for name, digest in expected.items():
            with archive.open(index[name]) as member:
                p.require(_stream_hash(member) == digest, "Pinned wheel member hash mismatch.")
    return expected


def _walk_files(root: Path):
    """Walk without following a reparse directory, including empty directories."""
    _regular(root, directory=True)
    for child in sorted(root.iterdir(), key=lambda item: item.name):
        details = child.lstat()
        is_directory = stat.S_ISDIR(details.st_mode)
        _regular(child, directory=is_directory)
        yield child, is_directory
        if is_directory:
            yield from _walk_files(child)


def _verify_site(lock: dict, target: Path, cache: Path, expected: dict[str, str]) -> int:
    _regular(target, directory=True)
    metadata_dir = f"z3_solver-{lock['version']}.dist-info"
    allowed_roots = {"z3", "bin", metadata_dir}
    expected_dirs = set()
    for name in expected:
        expected_dirs.update(parent.as_posix() for parent in PurePosixPath(name).parents if parent.as_posix() != ".")
    observed = set()
    with zipfile.ZipFile(cache) as archive:
        index = _wheel_index(archive)
        for path, is_directory in _walk_files(target):
            name = path.relative_to(target).as_posix()
            parts = PurePosixPath(name).parts
            p.require(parts[0] in allowed_roots, "Unexpected module or file beside the solver package.")
            if parts[0] == "z3":
                if "__pycache__" in parts:
                    cache_position = parts.index("__pycache__")
                    parent = "/".join(parts[:cache_position])
                    p.require(parent in expected_dirs, "Unexpected solver cache directory.")
                    p.require(
                        (is_directory and cache_position == len(parts) - 1)
                        or (not is_directory and cache_position == len(parts) - 2 and path.suffix == ".pyc"),
                        "Unexpected file inside a solver bytecode cache.",
                    )
                    # The verifier runs children with a fresh pycache_prefix;
                    # old .pyc files are neither imported nor trusted here.
                    continue
                if is_directory:
                    p.require(name in expected_dirs, "Unexpected directory inside the solver package.")
                else:
                    p.require(name in expected, "Unexpected file inside the solver package.")
                    p.require(p.sha(path) == expected[name], "Installed solver member hash mismatch.")
                    observed.add(name)
            elif parts[0] == "bin":
                if name == "bin":
                    p.require(is_directory, "Unexpected solver bin path.")
                    continue
                wheel_name = f"z3_solver-{lock['version']}.data/data/{name}"
                p.require(not is_directory and name == "bin/z3.exe" and wheel_name in index,
                          "Unexpected executable beside the solver package.")
                with archive.open(index[wheel_name]) as member:
                    p.require(p.sha(path) == _stream_hash(member), "Existing solver executable differs from its wheel.")
            else:
                if name == metadata_dir:
                    p.require(is_directory, "Unexpected solver metadata path.")
                    continue
                p.require(not is_directory and len(parts) == 2, "Unexpected nested solver metadata.")
                p.require(path.stat().st_size <= 1024 * 1024, "Oversized solver metadata.")
                if parts[1] in _PASSIVE_PIP_METADATA:
                    # pip-generated metadata is passive under -I -S. It is
                    # never added to the package, executed or used as evidence.
                    continue
                p.require(name in index, "Unexpected file in solver metadata.")
                with archive.open(index[name]) as member:
                    p.require(p.sha(path) == _stream_hash(member), "Installed solver metadata differs from its wheel.")
    p.require(observed == set(expected), "Installed solver package is incomplete.")
    return len(observed)


def verify_installed(lock: dict) -> dict:
    """Read-only, offline validation of the cached wheel and installed runtime.

    This does not import Z3 and does not qualify solver correctness. Callers
    must isolate solver children and ignore pre-existing bytecode caches.
    """
    _, cache, target = _locations(lock)
    expected = _validate_wheel(lock, cache)
    count = _verify_site(lock, target, cache, expected)
    return {
        "status": "PASS",
        "solver_version": lock["version"],
        "wheel_sha256": lock["wheel_sha256"],
        "validated_package_files": count,
        "cache_relative": lock["cache_relative"],
        "target": lock["target"],
        "solver_imported": False,
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Pinned wheel redirects are refused.", headers, fp)


def _download(lock: dict, cache: Path) -> None:
    url = lock["wheel_url"]
    parsed = urllib.parse.urlsplit(url)
    p.require(
        parsed.scheme == "https" and parsed.netloc == "files.pythonhosted.org"
        and not parsed.query and not parsed.fragment and parsed.path.endswith(".whl"),
        "The solver download must use its pinned HTTPS Python-hosted wheel URL.",
    )
    p.require(not os.path.lexists(cache), "Existing wheel will not be replaced.")
    part = _owned(f"{_CACHE_ROOT}/.wheel-{uuid.uuid4().hex}.part")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "M15-reproducibility-bootstrap/1"})
        opener = urllib.request.build_opener(_NoRedirect())
        digest = hashlib.sha256()
        size = 0
        with opener.open(request, timeout=60) as response, part.open("xb") as output:
            p.require(response.status == 200 and response.geturl() == url, "Unexpected wheel download response.")
            for block in iter(lambda: response.read(1024 * 1024), b""):
                size += len(block)
                p.require(size <= lock["wheel_bytes"], "Downloaded wheel exceeds its pinned size.")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        p.require(size == lock["wheel_bytes"] and digest.hexdigest() == lock["wheel_sha256"],
                  "Downloaded wheel does not match its pinned size and SHA-256.")
        _regular(part)
        _owned(lock["cache_relative"])
        # A hard link fails if the cache appeared meanwhile; it never replaces
        # an existing file, including on a development host outside Windows.
        os.link(part, cache)
    finally:
        if os.path.lexists(part):
            _regular(part)
            part.unlink()


def _extract(lock: dict, target: Path, cache: Path, expected: dict[str, str]) -> None:
    p.require(not os.path.lexists(target), "Existing solver target will not be overwritten.")
    relative = f"{_CACHE_ROOT}/.staging-{uuid.uuid4().hex}"
    staging = _owned(relative)
    staging.mkdir()
    # A failed staging directory is retained for diagnosis. There is no
    # recursive removal, no replacement of an unknown installation and no pip.
    with zipfile.ZipFile(cache) as archive:
        index = _wheel_index(archive)
        for name in sorted(expected):
            destination = staging.joinpath(*PurePosixPath(name).parts)
            _mkdir_owned(destination.parent)
            with archive.open(index[name]) as member, destination.open("xb") as output:
                digest = hashlib.sha256()
                for block in iter(lambda: member.read(1024 * 1024), b""):
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            p.require(digest.hexdigest() == expected[name], "Extracted solver member hash mismatch.")
    _verify_site(lock, staging, cache, expected)
    _regular(staging, directory=True)
    _owned(lock["target"])
    p.require(not os.path.lexists(target), "Solver target appeared during setup; refusing replacement.")
    # On the required Windows platform rename refuses any existing target.
    os.rename(staging, target)


def _receipt(result: dict) -> str:
    stamp = uuid.uuid4().hex
    receipts = _owned(f"{_CACHE_ROOT}/setup-receipts")
    _mkdir_owned(receipts)
    relative = f"{_CACHE_ROOT}/setup-receipts/{stamp}.json"
    temporary = _owned(f"{_CACHE_ROOT}/setup-receipts/.{stamp}.tmp")
    destination = _owned(relative)
    payload = dict(result, schema="m15-local-solver-setup-v1",
                   created_utc=datetime.now(timezone.utc).isoformat(),
                   python_version=sys.version.split()[0], global_environment_modified=False)
    with temporary.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(payload, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    _regular(temporary)
    os.link(temporary, destination)
    temporary.unlink()
    return relative


def ensure_setup(*, allow_download: bool = True) -> dict:
    """Validate inputs first, then prepare only the private pinned tool cache."""
    p.check_platform()
    p.check_package()
    lock = p.load_lock()
    owner, cache, target = _locations(lock)
    cache_exists = os.path.lexists(cache)
    target_exists = os.path.lexists(target)
    p.require(not target_exists or cache_exists,
              "Existing solver target has no cached wheel; refusing to modify it.")
    if not cache_exists:
        p.require(allow_download, "Pinned wheel is absent; offline setup cannot download it.")
        _mkdir_owned(owner)
        _download(lock, cache)
    expected = _validate_wheel(lock, cache)
    if target_exists:
        _verify_site(lock, target, cache, expected)
    else:
        _mkdir_owned(owner)
        _extract(lock, target, cache, expected)
    result = verify_installed(lock)
    result.update(downloaded=not cache_exists, installed=not target_exists,
                  old_bytecode_trusted=False, scientific_payload_modified=False)
    result["receipt"] = _receipt(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Refuse network access; require the pinned cached wheel.")
    arguments = parser.parse_args()
    try:
        p.require(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
                  "Run setup with CPython's -I -S -B options.")
        result = ensure_setup(allow_download=not arguments.offline)
    except (OSError, ValueError, RuntimeError, KeyError, zipfile.BadZipFile) as error:
        print(f"M15 solver setup failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
