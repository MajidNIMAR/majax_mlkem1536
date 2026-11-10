#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
task_snapshot="${1:?usage: reproduce-release-linux.sh SNAPSHOT_DIRECTORY}"
task_snapshot="$(realpath "$task_snapshot")"
case "$task_snapshot/" in
  "$task_root/artifacts/generated/m04-distribution/"*) ;;
  *) printf '%s\n' 'Snapshot must stay below artifacts/generated/m04-distribution.' >&2; exit 1 ;;
esac
export CARGO_HOME="$task_root/.tools/linux-cargo"
export RUSTUP_HOME="$task_root/.tools/linux-rustup"
export RUSTUP_TOOLCHAIN=1.91.1-x86_64-unknown-linux-gnu
export RUSTUP_AUTO_INSTALL=0
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_RELEASE_STRIP=debuginfo
export PATH="$CARGO_HOME/bin:/usr/local/bin:/usr/bin:/bin"
unset RUSTFLAGS
task_python=python3
task_helper="$task_root/research/verify_m04_distribution.py"
task_target=x86_64-unknown-linux-gnu
task_build="$task_snapshot/linux"
if [[ -e "$task_build" ]]; then
  printf '%s\n' 'Linux build output already exists; use a new run ID.' >&2
  exit 1
fi
task_sysroot="$(rustc --print sysroot)"
task_rustc="$(rustc -Vv)"
[[ "$task_rustc" == *'release: 1.91.1'* ]] || { printf '%s\n' 'Rust 1.91.1 is required.' >&2; exit 1; }
export SOURCE_DATE_EPOCH="$("$task_python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_date_epoch"])' "$task_snapshot/source-manifest.json")"
mkdir -p "$task_build"
"$task_python" - "$task_build/environment.json" "$task_rustc" "$(cargo -V)" "$(uname -srmo)" <<'PY'
import json,os,sys
data=dict(target="x86_64-unknown-linux-gnu",rustc=sys.argv[2],cargo=sys.argv[3],host=sys.argv[4],
          source_date_epoch=os.environ["SOURCE_DATE_EPOCH"],jobs=2,
          strip="debuginfo; symbol names retained for binary review",
          features="default CLI; research-vectors disabled",build_id="disabled with --build-id=none",
          path_remaps=["source=/source","target=/target","cargo=/cargo","rustup=/rustup"],
          dependency_cache="shared preexisting local Cargo cache; --frozen --offline")
with open(sys.argv[1],"w",encoding="utf-8") as f:json.dump(data,f,indent=2,sort_keys=True);f.write("\n")
PY
for task_letter in a b; do
  task_one="$task_build/build-$task_letter"
  task_source="$task_one/source"
  export CARGO_TARGET_DIR="$task_one/target"
  "$task_python" "$task_helper" copy-source --snapshot "$task_snapshot" --destination "$task_source"
  task_flags=(-C link-arg=-Wl,--build-id=none
    "--remap-path-prefix=$task_source=/source"
    "--remap-path-prefix=$CARGO_TARGET_DIR=/target"
    "--remap-path-prefix=$CARGO_HOME=/cargo"
    "--remap-path-prefix=$RUSTUP_HOME=/rustup")
  printf -v CARGO_ENCODED_RUSTFLAGS '%s\x1f' "${task_flags[@]}"
  export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS%$'\x1f'}"
  (
    cd "$task_source"
    cargo build --frozen --offline --release --target "$task_target" -p kem1536-cli --bin kem1536 \
      --no-default-features --message-format=json-render-diagnostics > "$task_one/cargo.jsonl" 2> "$task_one/cargo.stderr.log"
    cargo metadata --frozen --offline --format-version 1 --filter-platform "$task_target" > "$task_build/metadata-$task_letter.json"
  )
  task_binary="$CARGO_TARGET_DIR/$task_target/release/kem1536"
  "$task_binary" dev-self-test > "$task_one/self-test.json"
  if "$task_binary" dev-vectors > "$task_one/research-disabled.stdout.log" 2> "$task_one/research-disabled.stderr.log"; then
    printf '%s\n' 'Research vectors are unexpectedly enabled.' >&2
    exit 1
  fi
done
task_binary="$task_build/build-a/target/$task_target/release/kem1536"
readelf -d -V "$task_binary" > "$task_build/native-dependencies.txt"
"$task_python" "$task_helper" seal --snapshot "$task_snapshot" --platform linux --rust-root "$task_sysroot"
"$task_python" "$task_helper" verify --snapshot "$task_snapshot"
