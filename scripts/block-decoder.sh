#!/usr/bin/env bash
set -euo pipefail
task_decoder_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_decoder_root"
export DOT_SAGE="$task_decoder_root/.tools/sage-ram/state"
export XDG_CACHE_HOME="$task_decoder_root/.tools/sage-ram/xdg-cache"
export TMPDIR="$task_decoder_root/.tools/sage-ram/tmp"
export CONDA_PKGS_DIRS="$task_decoder_root/.tools/sage-ram/mamba/pkgs"
export PYTHONDONTWRITEBYTECODE=1
exec .tools/micromamba-bootstrap/bin/micromamba --no-rc -r "$task_decoder_root/.tools/sage-ram/mamba" \
  run -p "$task_decoder_root/.tools/sage-ram/env" python research/run_block_decoder.py "$@"
