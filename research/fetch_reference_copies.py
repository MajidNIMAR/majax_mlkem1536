"""Restore hash-pinned third-party reference copies excluded from distribution.

These files are read as reference data, never imported or executed here.
Their upstream license has not been established; no project license is
applied to them. Existing local research snapshots remain unchanged.
"""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "references/coded-dual-audit"


def ensure_references(fetch=False):
    manifest = json.loads((DIRECTORY / "sources.json").read_text(encoding="utf-8"))
    for entry in manifest["sources"]:
        destination = DIRECTORY / entry["file"]
        if destination.parent != DIRECTORY or not destination.name.endswith(".py.txt"):
            raise ValueError("invalid reference destination")
        if not destination.exists():
            if not fetch:
                raise FileNotFoundError("Run research/fetch_reference_copies.py --fetch first")
            # The historical manifest contains both raw and HTML GitHub URLs.
            url = entry["url"].replace("https://github.com/", "https://raw.githubusercontent.com/")
            url = url.replace("/blob/", "/")
            if not url.startswith("https://raw.githubusercontent.com/TabOg/CodedDualAttack/"):
                raise ValueError("unexpected upstream reference host or repository")
            with urlopen(url, timeout=60) as response:
                content = response.read()
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                raise ValueError(f"download checksum mismatch: {entry['file']}")
            destination.write_bytes(content)
        if hashlib.sha256(destination.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError(f"reference checksum mismatch: {entry['file']}")
    return len(manifest["sources"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    arguments = parser.parse_args()
    print(f"Verified external reference copies: {ensure_references(arguments.fetch)}")
