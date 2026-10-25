#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="$task_root/.tools/linux-cargo"
export RUSTUP_HOME="$task_root/.tools/linux-rustup"
export CARGO_TARGET_DIR="$task_root/target/m03-linux"
export PATH="$CARGO_HOME/bin:/usr/local/bin:/usr/bin:/bin"
cd "$task_root"
case "${1:-version}" in
  setup)
    cargo install cargo-fuzz --version 0.13.1 --locked --root "$CARGO_HOME"
    rustup component add llvm-tools-preview rust-src --toolchain 1.91.1
    ;;
  version) rustc -Vv; cargo fuzz --version ;;
  build)
    cargo build --locked --release -p kem1536-bench -p kem1536-cli
    ;;
  fuzz-build)
    export RUSTC_BOOTSTRAP=1
    export CARGO_TARGET_DIR="$task_root/target/m03-fuzz"
    task_fuzz_lock_sum="$(sha256sum fuzz/Cargo.lock)"
    cargo fuzz build --fuzz-dir fuzz --build-std
    printf '%s\n' "$task_fuzz_lock_sum" | sha256sum --check
    ;;
  fuzz-lock)
    cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null
    ;;
  fmt)
    cargo fmt --all
    cargo fmt --manifest-path fuzz/Cargo.toml
    ;;
  campaign)
    python3 research/run_m03_fuzz.py "${@:2}"
    ;;
  coverage)
    export RUSTC_BOOTSTRAP=1
    cargo fuzz coverage --fuzz-dir fuzz --target-dir "$task_root/target/m03-coverage" "${2:?target required}" "${3:?corpus required}" -- -timeout=60 -rss_limit_mb=2048
    ;;
  *) printf '%s\n' 'Unsupported M03 action.' >&2; exit 1 ;;
esac
