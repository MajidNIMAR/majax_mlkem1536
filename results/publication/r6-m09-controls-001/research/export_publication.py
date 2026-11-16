"""Export committed sources, or update a clean durable public Git checkout.

New trees belong below artifacts/generated/publication/. --sync accepts only an
existing direct child of publication/ and preserves its Git database and history.
Both source and public worktrees must be clean, except for ignored local caches.
Research-only external copies are restored separately by research setup.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = "PUBLICATION_PROVENANCE.json"
EXCLUDED = {
    "AGENTS.md",
    PROVENANCE,
    "docs/NETTOYAGE_ET_ORGANISATION.md",
    "docs/maintenance/cleanup-001.json",
    "references/coded-dual-audit/optimizer_naive.py.txt",
    "references/coded-dual-audit/rot_utilitaries.py.txt",
    "references/coded-dual-audit/utilitaries.py.txt",
}


def git(root, *arguments):
    return subprocess.check_output(["git", *arguments], cwd=root)


def safe_name(name):
    """Accept portable relative paths, with no aliases of Git's private data."""
    parts = name.split("/")
    if not name or PurePosixPath(name).is_absolute() or "\\" in name:
        raise ValueError(f"unsafe publication path: {name!r}")
    for part in parts:
        stem = part.split(".", 1)[0].casefold()
        reserved = {"con", "prn", "aux", "nul"}
        device = (stem.startswith(("com", "lpt")) and
                  stem[3:] in "123456789\u00b9\u00b2\u00b3" and len(stem[3:]) == 1)
        if (part in {"", ".", ".."} or part.rstrip(" .") != part or
                part.casefold() == ".git" or part.casefold().startswith("git~") or
                any(ord(c) < 32 or c in ':<>"|?*' for c in part) or
                stem in reserved or device):
            raise ValueError(f"unsafe publication path: {name!r}")
    return parts


def check_path(root, relative=""):
    """Reject existing symlinks/reparse points and directory/file collisions."""
    path = root
    parts = safe_name(relative) if relative else []
    for position in range(len(parts) + 1):
        if position:
            path = path / parts[position - 1]
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"publication paths must not traverse links: {path}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            raise ValueError(f"publication files must not be hard links: {path}")
        if position < len(parts) and not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"publication parent is not a directory: {path}")
        if position == len(parts) and not (stat.S_ISDIR(info.st_mode) or
                                           stat.S_ISREG(info.st_mode)):
            raise ValueError(f"publication path is not an ordinary file/directory: {path}")
    return path


def clean_head(root, label):
    actual = Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve()
    if actual != root.resolve():
        raise ValueError(f"{label} must be the root of its own Git checkout")
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError(f"{label} worktree must be clean (commit tracked/untracked changes first)")
    return git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()


def inventory(root, commit):
    files = {}
    spellings = {}
    for entry in git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, kind, _ = metadata.split()
        name = raw_name.decode("utf-8")
        parts = safe_name(name)
        if mode not in {b"100644", b"100755"} or kind != b"blob":
            raise ValueError(f"source/public Git links and special entries are forbidden: {name}")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            previous = spellings.setdefault(prefix.casefold(), prefix)
            if previous != prefix:
                raise ValueError(f"case-colliding publication paths: {previous}, {prefix}")
        files[name] = int(mode, 8)
    return files


def canonical_blob_hashes(commit, names):
    """Hash canonical Git blobs in bounded chunks, before attribute conversion."""
    objects = {}
    for entry in git(ROOT, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        name = raw_name.decode("utf-8")
        if name in names:
            _, kind, oid = metadata.split()
            if kind != b"blob":
                raise ValueError(f"expected a canonical Git blob: {name}")
            objects[name] = oid
    if set(objects) != set(names):
        raise ValueError("canonical blob inventory differs from publication files")
    hashes, by_object = {}, {}
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=ROOT,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        for name, oid in objects.items():
            if oid not in by_object:
                process.stdin.write(oid + b"\n")
                process.stdin.flush()
                header = process.stdout.readline().split()
                if (len(header) != 3 or header[:2] != [oid, b"blob"] or
                        not header[2].isdigit()):
                    raise ValueError(f"unexpected canonical blob header for {name}")
                remaining = int(header[2])
                digest = hashlib.sha256()
                while remaining:
                    chunk = process.stdout.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise ValueError(f"truncated canonical Git blob: {name}")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if process.stdout.read(1) != b"\n":
                    raise ValueError(f"missing canonical Git blob separator: {name}")
                by_object[oid] = digest.hexdigest()
            hashes[name] = by_object[oid]
        process.stdin.close()
        error = process.stderr.read()
        if process.wait() != 0:
            raise RuntimeError(f"git cat-file failed: {error.decode('utf-8', errors='replace')}")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
    return hashes


def prepare(destination, sync):
    destination = Path(destination)
    if ".." in destination.parts:
        raise ValueError("publication destination must not contain traversal components")
    destination = Path(os.path.abspath(destination))
    allowed = ROOT / ("publication" if sync else "artifacts/generated/publication")
    if sync:
        if destination.parent != allowed:
            raise ValueError("--sync requires a direct child of publication/")
    elif destination == allowed or not destination.is_relative_to(allowed):
        raise ValueError("export must be inside artifacts/generated/publication/")
    check_path(ROOT, destination.relative_to(ROOT).as_posix())
    if sync:
        if not destination.is_dir() or not (destination / ".git").is_dir():
            raise ValueError("--sync requires an existing standalone Git checkout")
        # .git is deliberately never passed to the public-file path validator.
        git_info = (destination / ".git").lstat()
        if stat.S_ISLNK(git_info.st_mode) or getattr(git_info, "st_file_attributes", 0) & 0x400:
            raise ValueError("public Git database must not be a link")
    elif destination.exists():
        raise FileExistsError("refusing to replace an existing publication tree")
    return destination


def stream_snapshot(destination, commit, files):
    """Stream Git's tar directly to owned files; no ZIP or complete staging copy."""
    hashes = {}
    process = subprocess.Popen(
        ["git", "archive", "--format=tar", commit], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as snapshot:
            for member in snapshot:
                name = member.name.rstrip("/") if member.isdir() else member.name
                safe_name(name)
                if member.isdir():
                    continue
                if not member.isfile() or member.name not in files or member.name in hashes:
                    raise ValueError(f"unexpected archive entry: {member.name}")
                if member.name in EXCLUDED:
                    continue
                path = check_path(destination, member.name)
                if path.is_dir():
                    raise ValueError(f"file would replace a publication directory: {path}")
                path.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with snapshot.extractfile(member) as source, path.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                        output.write(chunk)
                if os.name != "nt":
                    path.chmod(files[member.name] & 0o777)
                hashes[member.name] = digest.hexdigest()
        # tarfile stops at its end marker; drain Git's record padding before
        # closing the pipe so a successful producer cannot receive SIGPIPE.
        while process.stdout.read(64 * 1024):
            pass
        process.stdout.close()
        error = process.stderr.read()
        if process.wait() != 0:
            raise RuntimeError(f"git archive failed: {error.decode('utf-8', errors='replace')}")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    if set(hashes) != set(files) - EXCLUDED:
        raise ValueError("Git archive omitted committed publication files")
    return hashes


def export(destination, *, sync=False):
    """Write HEAD only. Preflight precedes writes; a runtime failure may be partial."""
    destination = prepare(destination, sync)
    commit = clean_head(ROOT, "source")
    files = inventory(ROOT, commit)
    public_commit = None
    if sync:
        public_commit = clean_head(destination, "public")
        tracked = inventory(destination, public_commit)
        stale = set(tracked) - (set(files) - EXCLUDED) - {PROVENANCE}
        if stale:
            raise ValueError("refusing stale tracked public files; review and remove explicitly "
                             "with git rm before committing: " + ", ".join(sorted(stale)))
        for name in (set(files) - EXCLUDED) | {PROVENANCE}:
            path = check_path(destination, name)
            if path.is_dir():
                raise ValueError(f"file would replace a publication directory: {path}")
            if path.exists() and name not in tracked:
                raise ValueError(f"refusing to replace an ignored/untracked public file: {name}")
    # Source links and all known target collisions have been checked before writes.
    blob_hashes = canonical_blob_hashes(commit, set(files) - EXCLUDED)
    destination.mkdir(parents=True, exist_ok=sync)
    hashes = stream_snapshot(destination, commit, files)
    if clean_head(ROOT, "source") != commit:
        raise ValueError("source HEAD changed during export; review the partial export")
    if sync and git(destination, "rev-parse", "HEAD").decode("ascii").strip() != public_commit:
        raise ValueError("public HEAD changed during sync; review the partial export")
    provenance = {
        "schema": 2,
        "local_source_commit": commit,
        "profile": "KEM1536-DEV-Q7681-R1",
        "excluded_paths": sorted(EXCLUDED),
        "scope": "Committed public source snapshot, not the local Git history. Historical "
                 "commit IDs in research notes refer to local research history.",
        "hash_scope": {
            "sha256": "SHA-256 of file bytes emitted by git archive, including attribute "
                      "conversion such as .ps1 CRLF. Checkout bytes can vary with Git attributes.",
            "git_blob_sha256": "SHA-256 of canonical source Git blob contents before archive "
                               "or checkout attribute conversion; these are not Git object IDs.",
        },
        "sha256": hashes,
        "git_blob_sha256": blob_hashes,
    }
    if sync:
        provenance["previous_public_commit"] = public_commit
    check_path(destination, PROVENANCE).write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    result = {"destination": str(destination), "commit": commit,
              "files": len(hashes), "sync": sync}
    print(json.dumps(result))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--sync", action="store_true",
                        help="update an existing clean direct child of publication/")
    args = parser.parse_args()
    export(args.destination, sync=args.sync)
