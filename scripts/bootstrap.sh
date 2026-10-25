#!/usr/bin/env bash
set -euo pipefail
task_project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="$task_project_root/.tools/cargo"
export RUSTUP_HOME="$task_project_root/.tools/rustup"
export RUSTUP_INIT_SKIP_PATH_CHECK=yes
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
    mkdir -p "$task_project_root/.tools/downloads"
    curl --proto '=https' --tlsv1.2 --fail --location \
        https://sh.rustup.rs -o "$task_project_root/.tools/downloads/rustup-init.sh"
    sh "$task_project_root/.tools/downloads/rustup-init.sh" -y \
        --no-modify-path --profile minimal --default-toolchain none
fi
"$CARGO_HOME/bin/rustup" toolchain install 1.91.1 --profile minimal --component rustfmt --component clippy
printf '%s\n' 'Local toolchain ready. Run bash scripts/dev.sh check'

