# M07 native memory probe

This is a separate measurement executable. The production KEM crate retains
its `unsafe_code = "forbid"` policy. The probe's platform-specific unsafe code
is restricted to x86-64 Windows and Linux, native thread creation/join, stack
bounds, volatile watermark access, and the standard allocator interface.

## Measurements and their scope

- `touched_stack_high_water_bytes` is the deepest changed byte in a painted
  region below a fixed native caller's stack pointer. It is **not a maximum
  stack-pointer trace, a stack bound, or a production CLI stack measurement**.
  Untouched reserved frame space and coincidentally equal pattern bytes can
  be missed. The upper 512 bytes below the reference pointer are not painted.
- Each native worker requests a 1 MiB stack. At most 256 KiB below its measured
  reference pointer is painted; a further 8 KiB above the reported lower stack
  bound is excluded. Windows additionally checks every painted virtual-memory
  region for committed, writable, non-guard status. Linux uses the usable
  bounds returned by the native pthread API. Painting and scanning are inline
  volatile loops, with no logging, allocator activity or helper call.
- No-op and 8/32/64 KiB written-array calibrations use the same native caller.
  Observations retain only the relative depth of the lowest written array
  address, never the address or a byte dump. An underestimated calibration, exhausted
  search region or failed bound check aborts the run. No-op values describe
  harness overhead; they must not be subtracted as an exact engine cost.
- Each operation uses its own non-inlined callback. A match over all operations
  inside one callback would reserve the largest branch's frame for every case.
- Global allocator hooks record **requested Rust allocations** visible in this
  compiled harness, not OS allocations, C/runtime allocations, allocator
  metadata, process RSS or source-level allocation guarantees. Optimization may
  elide or combine requests. The callback's allocator instrumentation also adds
  stack work, so these observations belong to this exact executable.
- `alloc_calls`, `alloc_zeroed_calls` and `realloc_calls` count attempts;
  `total_requested_bytes` sums their requested sizes. Failed requests are
  reported and invalidate the run. `peak_live_requested_bytes` counts successful
  requests currently owned inside the window, using a fixed 128-entry pointer
  registry. `retained_requested_bytes_at_api_return` identifies requested bytes
  still owned by returned objects. Foreign frees/reallocations or tracker
  exhaustion invalidate the run. There is no allocation or formatted logging
  in the allocator hooks.

## Operation window

Inputs and expected outputs are prepared before measurement. A new native
thread first warms the selected API/provider path once and drops its warm-up
outputs. The region is then painted and allocation counters are reset. The
selected API is called once and its returned owners are stored in the job.
Allocation recording stops at API return; the region is scanned before any
validation or output destruction. The parent validates returned objects after
joining the worker, and drops them after the observation is emitted. This is
the API-return boundary used by the M06 latency comparison, **excluding
validation and result destruction**. Destruction of internal temporaries
inside an API remains inside its window.

The process has only a parent blocked in native join and one worker. An OS
signal/APC, provider or runtime path can affect the stack watermark. KeyGen and
Encaps include warmed OS-randomness calls. Values apply to the public APIs in
this harness, on the identified host/build, not to every client or cold start.

One fresh synthetic input pair is generated per executable invocation. The
valid/rejected Decaps and import samples reuse that input pair; they are not
distinct-input campaign counts. The altered ciphertext starts with a
noncanonical coefficient. Its expected rejection secret is independently
recomputed from the specified J domain and the synthetic private key outside
the measurement window. No key, secret, stack byte, memory address, or user
material is emitted.

## Build and smoke checks

Use Rust 1.91.1 and the committed probe lockfile. The nested workspace is
intentional; do not add the executable or unsafe code to the production
workspace. Release profile defaults match the root's release defaults.

Windows, from the project root, using the existing local tool installation:

```powershell
$taskProbeRoot = (Get-Location).Path
$env:CARGO_HOME = Join-Path $taskProbeRoot '.tools/cargo'
$env:RUSTUP_HOME = Join-Path $taskProbeRoot '.tools/rustup'
$env:CARGO_TARGET_DIR = Join-Path $taskProbeRoot 'target/m07-probe-dev/windows'
$env:PATH = (Join-Path $taskProbeRoot '.tools/native-tools') + [IO.Path]::PathSeparator + $env:PATH
.\.tools\cargo\bin\cargo.exe build --locked --offline --release --manifest-path research/m07-memory-probe/Cargo.toml
.\target\m07-probe-dev\windows\release\m07-memory-probe.exe 1
```

Linux uses the existing `.tools/linux-cargo` / `.tools/linux-rustup` pair:

```bash
export CARGO_HOME="$PWD/.tools/linux-cargo"
export RUSTUP_HOME="$PWD/.tools/linux-rustup"
export CARGO_TARGET_DIR="$PWD/target/m07-probe-dev/linux"
export PATH="$CARGO_HOME/bin:/usr/bin:/bin"
cargo build --locked --offline --release --manifest-path research/m07-memory-probe/Cargo.toml
"$CARGO_TARGET_DIR/release/m07-memory-probe" 1
```

The single argument is samples per operation **and per pattern**, from 1 to
1000. Every invocation emits 14 operations × 2 patterns × that argument in
JSONL. Use a controller to bind raw output to source/compiler/binary hashes;
do not treat an unbound smoke invocation as the frozen M07 baseline.
