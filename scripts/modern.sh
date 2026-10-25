#!/usr/bin/env bash
set -euo pipefail
task_modern_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_modern_root"
export DOT_SAGE="$task_modern_root/.tools/sage-ram/state"
export XDG_CACHE_HOME="$task_modern_root/.tools/sage-ram/xdg-cache"
export TMPDIR="$task_modern_root/.tools/sage-ram/tmp"
export CONDA_PKGS_DIRS="$task_modern_root/.tools/sage-ram/mamba/pkgs"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$DOT_SAGE" "$XDG_CACHE_HOME" "$TMPDIR"
exec .tools/micromamba-bootstrap/bin/micromamba --no-rc -r "$task_modern_root/.tools/sage-ram/mamba" \
  run -p "$task_modern_root/.tools/sage-ram/env" python research/run_modern.py "$@"
