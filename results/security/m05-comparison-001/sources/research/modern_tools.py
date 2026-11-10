"""Immutable archives for the current estimator and the 2026 ring study."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "research/modern-tools-manifest.json"


def sources(fetch=False):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    result = {}
    for entry in manifest["archives"]:
        archive = ROOT / entry["cache_archive"]
        if not archive.exists() and fetch:
            archive.parent.mkdir(parents=True, exist_ok=True)
            with urlopen(entry["url"], timeout=60) as response:
                archive.write_bytes(response.read())
        if not archive.exists():
            raise FileNotFoundError("Run python research/modern_tools.py --fetch")
        if hashlib.sha256(archive.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError(f"archive checksum mismatch: {entry['id']}")
        destination = ROOT / entry["cache_directory"]
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                relative = "/".join(info.filename.split("/")[1:])
                if not relative or info.is_dir():
                    continue
                # Never hydrate upstream bytecode or prebuilt native binaries.
                if "__pycache__" in Path(relative).parts or Path(relative).suffix in (".pyc", ".pkl", ".o"):
                    continue
                path = (destination / relative).resolve()
                if not path.is_relative_to(destination.resolve()):
                    raise ValueError("unsafe archive member")
                content = bundle.read(info)
                if not path.exists() and fetch:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
                if not path.exists() or path.read_bytes() != content:
                    raise ValueError(f"cached research source mismatch: {entry['id']}/{relative}")
        result[entry["id"]] = destination
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    print(json.dumps({key: str(path.relative_to(ROOT)) for key, path in sources(args.fetch).items()}, indent=2))
