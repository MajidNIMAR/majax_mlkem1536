"""Export committed project sources into a new standalone public repository tree.

Never exports ignored caches, live campaigns or the local Git database.
Research-only external copies are restored separately by research setup.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {
    "AGENTS.md",
    "PUBLICATION_PROVENANCE.json",
    "references/coded-dual-audit/optimizer_naive.py.txt",
    "references/coded-dual-audit/rot_utilitaries.py.txt",
    "references/coded-dual-audit/utilitaries.py.txt",
}


def export(destination):
    destination = destination.resolve()
    allowed = (ROOT / "artifacts/generated/publication").resolve()
    if not destination.is_relative_to(allowed) or destination == allowed:
        raise ValueError("export must be inside artifacts/generated/publication/")
    if destination.exists():
        raise FileExistsError("refusing to replace an existing publication tree")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    allowed.mkdir(parents=True, exist_ok=True)
    archive = allowed / f"source-{commit}.zip"
    if not archive.exists():
        subprocess.run(
            ["git", "archive", "--format=zip", f"--output={archive}", commit],
            cwd=ROOT, check=True,
        )
    hashes = {}
    destination.mkdir()
    with zipfile.ZipFile(archive) as snapshot:
        for member in snapshot.infolist():
            if member.is_dir() or member.filename in EXCLUDED:
                continue
            path = destination / member.filename
            if not path.resolve().is_relative_to(destination):
                raise ValueError("invalid archive path")
            content = snapshot.read(member)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            hashes[member.filename] = hashlib.sha256(content).hexdigest()
    provenance = {
        "schema": 1,
        "local_source_commit": commit,
        "profile": "KEM1536-DEV-Q7681-R1",
        "excluded_paths": sorted(EXCLUDED),
        "scope": "Initial public source snapshot, not the local Git history. Historical commit IDs in research notes refer to local research history.",
        "sha256": hashes,
    }
    (destination / "PUBLICATION_PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({"destination": str(destination), "commit": commit, "files": len(hashes)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    export(parser.parse_args().destination)
