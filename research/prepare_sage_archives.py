"""Verify and retain package archives; optionally stage the temporary runtime."""

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def prepare(fetch=False, stage=False):
    packages = json.loads((ROOT / "research/sage-linux-packages.json").read_text())["packages"]
    cache = ROOT / ".tools/downloads/sage-packages"
    cache.mkdir(parents=True, exist_ok=True)
    for package in packages:
        url = urlparse(package["url"])
        decoded_path = unquote(url.path).lstrip("/")
        path = cache / Path(decoded_path).name
        old = ROOT / ".tools/mamba-linux/pkgs/https" / url.netloc / decoded_path
        if not path.exists() and old.is_file():
            try:
                os.link(old, path)
            except OSError:
                path.write_bytes(old.read_bytes())
        if not path.exists() and fetch:
            with urlopen(package["url"], timeout=60) as response:
                path.write_bytes(response.read())
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != package["sha256"]:
            raise ValueError(f"missing or altered Sage archive: {package['name']}")
        if stage:
            target = ROOT / ".tools/sage-ram/mamba/pkgs/https" / url.netloc / decoded_path
            if not target.resolve().is_relative_to(ROOT):
                raise ValueError("package path outside NIST")
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(path)
    return {"package_archives_sha256_verified": len(packages), "staged": stage}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--stage", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.fetch, args.stage), indent=2))
