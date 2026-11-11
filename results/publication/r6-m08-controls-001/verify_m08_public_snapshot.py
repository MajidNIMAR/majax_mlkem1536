"""Independently verify every public M08 Git blob and exported working file.

Future exact public/source identities are required. No credential or network
access occurs. The resulting source-integrity receipt is separate from CI.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from freeze_m08_publication import ROOT, WORK, canonical_sha, check_manifest, hex_value, require, safe_name, save, sha


def verify(public_commit, source_commit, public=None, output=None):
    require(hex_value(public_commit, 40) and hex_value(source_commit, 40), "explicit full public/source commits required")
    public = ROOT / "publication/majax_mlkem1536" if public is None else Path(public)
    output = WORK / "source-integrity.json" if output is None else Path(output)
    require(output.resolve().parent == WORK.resolve() and not output.exists(), "new M08 independent integrity receipt required")

    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(public), *arguments])

    require(git("status", "--porcelain=v1", "--untracked-files=all") == b"", "clean public clone required")
    require(git("rev-parse", "HEAD").decode().strip() == public_commit, "public clone is not the requested commit")
    raw_manifest = git("show", public_commit + ":PUBLICATION_PROVENANCE.json")
    manifest = json.loads(raw_manifest)
    count = check_manifest(manifest, source_commit)
    expected = manifest["git_blob_sha256"]
    names = git("ls-tree", "-r", "-z", "--name-only", public_commit).decode("utf-8").split("\0")
    require(names[-1] == "" and set(names[:-1]) == set(expected) | {"PUBLICATION_PROVENANCE.json"}, "committed public file inventory differs")
    process = subprocess.Popen(["git", "-C", str(public), "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for name, checksum in expected.items():
            safe_name(name)
            process.stdin.write((public_commit + ":" + name + "\n").encode())
            process.stdin.flush()
            header = process.stdout.readline().decode().split()
            require(len(header) == 3 and header[1] == "blob", "committed Git member is not a blob")
            remaining, digest = int(header[2]), hashlib.sha256()
            require(remaining >= 0, "invalid Git blob size")
            while remaining:
                chunk = process.stdout.read(min(remaining, 1024 * 1024))
                require(chunk, "Git blob stream ended early")
                digest.update(chunk)
                remaining -= len(chunk)
            require(process.stdout.read(1) == b"\n" and digest.hexdigest() == checksum, "committed public blob differs from source map")
        process.stdin.close()
        require(process.wait(timeout=30) == 0, "Git batch process failed")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()
    for name, checksum in manifest["sha256"].items():
        path = public / name
        require(path.resolve().is_relative_to(public.resolve()) and not path.is_symlink(), "exported file escaped public clone")
        require(sha(path) == checksum, "exported working file differs from source export map")
    require(git("status", "--porcelain=v1", "--untracked-files=all") == b""
            and git("rev-parse", "HEAD").decode().strip() == public_commit, "public clone changed during verification")
    result = {"schema": "m08-source-integrity-v1", "public_commit": public_commit, "source_commit": source_commit,
              "canonical_git_blobs_verified": count, "exported_files_verified": count, "all_equal": True,
              "source_provenance_sha256": hashlib.sha256(raw_manifest).hexdigest(),
              "git_blob_map_sha256": canonical_sha(expected), "export_map_sha256": canonical_sha(manifest["sha256"]),
              "attribute_converted_paths": sorted(name for name in expected if expected[name] != manifest["sha256"][name]),
              "method": "Independent streamed git cat-file --batch SHA-256 of every committed public blob and every exported working file, compared with both committed schema2 source maps"}
    output.parent.mkdir(parents=True, exist_ok=True)
    save(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-commit", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--public-clone", type=Path, default=ROOT / "publication/majax_mlkem1536")
    parser.add_argument("--output", type=Path, default=WORK / "source-integrity.json")
    args = parser.parse_args()
    print(json.dumps(verify(args.public_commit, args.source_commit, args.public_clone, args.output), indent=2))


if __name__ == "__main__":
    main()
