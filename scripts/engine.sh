#!/usr/bin/env bash
set -euo pipefail
task_engine_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="$task_engine_root/.tools/cargo"
export RUSTUP_HOME="$task_engine_root/.tools/rustup"
export CARGO_TARGET_DIR="$task_engine_root/target"
export PATH="$CARGO_HOME/bin:$PATH"
cd "$task_engine_root"
case "${1:-self-test}" in
    build) cargo build --locked --release -p kem1536-cli ;;
    self-test) cargo run --locked --release -p kem1536-cli -- dev-self-test ;;
    stress) cargo run --locked --release -p kem1536-cli -- dev-stress "${2:-10000}" ;;
    vectors) cargo run --locked --release -p kem1536-cli --features research-vectors -- dev-vectors "${2:-1000}" ;;
    check)
        cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
        cargo test --locked --workspace --all-features
        ;;
    *) printf '%s\n' 'Use build, self-test, stress, vectors or check.' >&2; exit 1 ;;
esac
