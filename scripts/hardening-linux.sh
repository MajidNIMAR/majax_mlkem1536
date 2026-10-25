#!/usr/bin/env bash
set -euo pipefail
task_linux_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="$task_linux_root/.tools/linux-cargo"
export RUSTUP_HOME="$task_linux_root/.tools/linux-rustup"
export CARGO_TARGET_DIR="$task_linux_root/target/linux"
export PATH="$CARGO_HOME/bin:/usr/local/bin:/usr/bin:/bin"
cd "$task_linux_root"
rustc -Vv
case "${1:-test}" in
    test) cargo test --locked --workspace --all-features ;;
    test-default) cargo test --locked --workspace ;;
    build) cargo build --locked --release -p kem1536-cli --features research-vectors ;;
    asan|asan-build)
        export CARGO_TARGET_DIR="$task_linux_root/target/linux-asan"
        export RUSTC_BOOTSTRAP=1
        export RUSTFLAGS='-Zsanitizer=address -Cdebuginfo=1'
        export ASAN_OPTIONS='detect_leaks=1:strict_string_checks=1'
        if [[ "${1:-asan}" == asan-build ]]; then
            cargo build --locked --release --target x86_64-unknown-linux-gnu -p kem1536-cli --features research-vectors
        else
            cargo test --locked --target x86_64-unknown-linux-gnu --workspace --all-features
        fi
        ;;
    asm) cargo rustc --locked --release -p kem1536 --features research-vectors --lib -- --emit=asm ;;
    *) printf '%s\n' 'Use test, test-default, build, asan, asan-build or asm.' >&2; exit 1 ;;
esac
