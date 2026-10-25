#!/usr/bin/env bash
set -euo pipefail
task_sage_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_sage_root"
export XDG_CACHE_HOME="$task_sage_root/.tools/sage-ram/xdg-cache"
export TMPDIR="$task_sage_root/.tools/sage-ram/tmp"
export CONDA_PKGS_DIRS="$task_sage_root/.tools/sage-ram/mamba/pkgs"
mkdir -p .tools/downloads .tools/micromamba-bootstrap "$XDG_CACHE_HOME" "$TMPDIR"
mkdir -p .tools/sage-ram
python3 - <<'PY'
import hashlib, json, pathlib, urllib.request
root = pathlib.Path.cwd()
# The Windows entry point mounts temporary Linux storage inside NIST/.tools.
probe = root/'.tools/sage-ram/.case-check'
probe.mkdir(exist_ok=True)
(probe/'a').write_bytes(b'a')
(probe/'A').write_bytes(b'A')
if (probe/'a').read_bytes() != b'a':
    raise ValueError('Enable NTFS case sensitivity first with scripts/bootstrap-modern.ps1')
manifest = json.loads((root/'research/sage-bootstrap-manifest.json').read_text())
archive = root/'.tools/downloads/micromamba-linux-64.tar.bz2'
entry = manifest['micromamba']
if not archive.exists():
    with urllib.request.urlopen(entry['url'], timeout=60) as response:
        archive.write_bytes(response.read())
if hashlib.sha256(archive.read_bytes()).hexdigest() != entry['sha256']:
    raise ValueError('micromamba archive checksum mismatch')
explicit = root/manifest['environment']['explicit_file']
if hashlib.sha256(explicit.read_bytes()).hexdigest() != manifest['environment']['sha256']:
    raise ValueError('explicit environment checksum mismatch')
package_manifest = root/manifest['environment']['package_manifest']
if hashlib.sha256(package_manifest.read_bytes()).hexdigest() != manifest['environment']['package_manifest_sha256']:
    raise ValueError('package provenance checksum mismatch')
PY
tar -xjf .tools/downloads/micromamba-linux-64.tar.bz2 -C .tools/micromamba-bootstrap bin/micromamba
python3 research/prepare_sage_archives.py --fetch --stage
.tools/micromamba-bootstrap/bin/micromamba --no-rc -r "$task_sage_root/.tools/sage-ram/mamba" \
  create -p "$task_sage_root/.tools/sage-ram/env" --file research/sage-linux-explicit.txt -y
python3 research/modern_tools.py --fetch
