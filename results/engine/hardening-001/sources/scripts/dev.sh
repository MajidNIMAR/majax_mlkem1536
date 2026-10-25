#!/usr/bin/env bash
set -euo pipefail
task_project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="$task_project_root/.tools/cargo"
export RUSTUP_HOME="$task_project_root/.tools/rustup"
export CARGO_TARGET_DIR="$task_project_root/target"
export PYTHONDONTWRITEBYTECODE=1
export PATH="$CARGO_HOME/bin:$PATH"
cd "$task_project_root"
if [[ ! -x "$CARGO_HOME/bin/cargo" ]]; then
    printf '%s\n' 'Run bash scripts/bootstrap.sh first.' >&2
    exit 1
fi
case "${1:-check}" in
    doctor) cargo --version; rustc --version --verbose; python3 --version ;;
    check)
        python3 research/verify_sources.py
        cargo fmt --all -- --check
        cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
        cargo test --locked --workspace
        cargo test --locked --workspace --all-features
        python3 research/check_profile.py
        task_check_research_python="$task_project_root/.tools/research-venv/bin/python"
        if [[ ! -x "$task_check_research_python" ]]; then
            printf '%s\n' 'Run bash scripts/research-setup.sh first.' >&2
            exit 1
        fi
        "$task_check_research_python" -m unittest discover -s research -p 'test_*.py'
        python3 research/verify_results.py
        python3 research/verify_modern_results.py
        python3 research/verify_decapsulation_results.py
        python3 research/verify_u_dependency_results.py
        python3 research/verify_witness_certificate.py
        python3 research/verify_mixed_precision_results.py
        python3 research/verify_mixed_certificate_bits.py
        python3 research/verify_group_quantization_results.py
        python3 research/verify_group_certificate_bits.py
        python3 research/compare_compression.py --verify
        python3 research/verify_coded_dual_results.py
        python3 research/verify_coded_dual_refinement.py
        python3 research/verify_block_decoder_results.py
        python3 research/verify_block_decoder_independent.py
        python3 research/verify_decoder_score_results.py
        python3 research/verify_decoder_score_independent.py
        python3 research/verify_cbd_decoder_results.py
        python3 research/verify_cbd_decoder_independent.py
        python3 research/verify_full_dual_toy_results.py
        python3 research/verify_full_dual_toy_independent.py
        python3 research/verify_dual_expansion_results.py
        python3 research/verify_dual_expansion_independent.py
        "$task_check_research_python" research/verify_higher_cbd_results.py
        "$task_check_research_python" research/verify_higher_cbd_independent.py
        python3 research/verify_score_transfer.py
        python3 research/verify_score_transfer_independent.py
        "$task_check_research_python" research/verify_real_dual.py
        "$task_check_research_python" research/verify_real_dual_independent.py
        "$task_check_research_python" research/verify_additive_score.py
        "$task_check_research_python" research/verify_additive_score_independent.py
        "$task_check_research_python" research/verify_cbd_fourth.py
        "$task_check_research_python" research/verify_cbd_fourth_independent.py
        "$task_check_research_python" research/verify_bounded_moments.py
        "$task_check_research_python" research/verify_bounded_moments_independent.py
        "$task_check_research_python" research/validate_engine_r1.py --limit 16
        "$task_check_research_python" research/validate_rejections_r1.py --limit 16
        "$task_check_research_python" research/validate_hardening_m02.py --limit 16
        cargo run --locked --quiet -p kem1536-cli -- dev-self-test
        cargo run --locked --quiet -p kem1536-cli -- self-check
        ;;
    build) cargo build --locked --workspace ;;
    test) cargo test --locked --workspace ;;
    profile|status) cargo run --locked --quiet -p kem1536-cli -- "$1" ;;
    fmt) cargo fmt --all ;;
    clippy) cargo clippy --locked --workspace --all-targets -- -D warnings ;;
    sources) python3 research/verify_sources.py ;;
    analysis) .tools/research-venv/bin/python research/run_j2.py ;;
    modern) bash scripts/modern.sh --repair-export ;;
    reference)
        python3 research/verify_sources.py
        mkdir -p artifacts/generated
        cargo run --locked --quiet -p kem1536-cli -- reference-1024 | tee artifacts/generated/reference-1024.json
        ;;
    *) printf '%s\n' 'Usage: bash scripts/dev.sh doctor|check|build|test|profile|status|fmt|clippy|sources|reference|analysis|modern' >&2; exit 1 ;;
esac

