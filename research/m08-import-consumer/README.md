# M08 default-feature import consumer

This separate workspace depends on `kem1536` without requesting
`research-vectors`. It retains `import_public_probe` and
`import_private_probe` as non-inlined consumers of the actual public import
API. Their helpers can still be inlined by the compiler; binary review must
follow the complete emitted path, not assume one function name.

No private encoding or shared secret is printed. Deterministic fixtures
are **structural encodings**, with canonical synthetic coefficients and a
correct embedded-public hash. They are not claimed to form a generated KEM
key pair. Accepted private inputs are checked for byte preservation, not
algebraic consistency of the public/secret pair. All owned private fixtures
and copied private outputs use zeroizing owners.

Modes:

- `smoke`: thirteen valid/invalid import cases, then one fresh system-random
  KEM key pair, imports, successful exchange and changed-ciphertext rejection.
  A fresh private encoding with only its final 32-byte rejection key replaced
  by a fixed value also imports, illustrating that syntax/hash checks do not
  certify key entropy. This is expected format behavior, not a key blacklist.
- `exhaustive`: 65,536 single-coefficient probes (8,192 values at each of
  eight serialized bit alignments), plus 23,040 boundary/position/error-order
  probes. Every vector position is checked at q−1/q/8191 in public, secret
  and embedded-public encodings, with valid/invalid hash combinations. This
  is not an exhaustive test of the full vector input space.
- `fixture-digests`: SHA3-256 fingerprints of the identical structural inputs.
- `latency SERIES SAMPLES WARMUPS`: eleven import cases, measured until API
  return. Status validation, accepted-encoding comparison, logging and output
  destruction occur afterward. Short-length returns are tested by smoke but
  excluded from this per-call timing panel because they can be below clock
  resolution. Raw zero times, if any, are emitted unchanged, not floored.

Build with the pinned Rust 1.91.1 toolchain and the same target-specific flags
as the engine, for example:

```sh
cargo build --locked --offline --release --manifest-path research/m08-import-consumer/Cargo.toml
```

Use a separate compiler target for each baseline/candidate/host and bind all
source, toolchain, flags, executable and output hashes. Results are finite
checks, not complete constant-time or erasure proofs. Borrowed caller input
is not owned or erased by the import API.
