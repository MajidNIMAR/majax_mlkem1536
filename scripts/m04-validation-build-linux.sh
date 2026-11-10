#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="$task_root/.tools/linux-cargo"
export RUSTUP_HOME="$task_root/.tools/linux-rustup"
export CARGO_TARGET_DIR="$task_root/target/m04-linux-research"
export RUSTUP_AUTO_INSTALL=0
export PATH="$CARGO_HOME/bin:/usr/local/bin:/usr/bin:/bin"
cd "$task_root"
rustc -Vv
cargo test --locked --workspace --all-features
cargo build --locked --release -p kem1536-cli -p kem1536-bench --features research-vectors
