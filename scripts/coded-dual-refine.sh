#!/usr/bin/env bash
set -euo pipefail
task_refine_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_refine_root"
export DOT_SAGE="$task_refine_root/.tools/sage-ram/state"
export XDG_CACHE_HOME="$task_refine_root/.tools/sage-ram/xdg-cache"
export TMPDIR="$task_refine_root/.tools/sage-ram/tmp"
export CONDA_PKGS_DIRS="$task_refine_root/.tools/sage-ram/mamba/pkgs"
export PYTHONDONTWRITEBYTECODE=1
exec .tools/micromamba-bootstrap/bin/micromamba --no-rc -r "$task_refine_root/.tools/sage-ram/mamba" \
  run -p "$task_refine_root/.tools/sage-ram/env" python research/refine_coded_dual.py "$@"
