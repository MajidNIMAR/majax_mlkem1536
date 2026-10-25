"""Fetch and verify immutable research tools into the ignored local cache."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "research/tools-manifest.json"


def ensure_tools(fetch: bool = False) -> Path:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cache = ROOT / ".tools/upstream/security-estimates"
    for entry in manifest["files"]:
        destination = cache / entry["name"]
        if not destination.exists() and fetch:
            with urlopen(entry["url"], timeout=60) as response:
                content = response.read()
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                raise ValueError(f"download checksum mismatch: {entry['name']}")
            cache.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        if not destination.exists():
            raise FileNotFoundError("Run python research/upstream_tools.py --fetch first")
        content = destination.read_bytes()
        if len(content) != entry["bytes"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise ValueError(f"cached source checksum mismatch: {entry['name']}")
    return cache


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    print(ensure_tools(args.fetch).relative_to(ROOT))
