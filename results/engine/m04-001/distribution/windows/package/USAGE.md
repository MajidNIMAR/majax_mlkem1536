# Experimental R1 release

This package is a research distribution, without production-security or certification claims.

Run `bin/kem1536 dev-profile` and `bin/kem1536 dev-self-test` (add `.exe` on Windows).
The self-test uses fresh OS randomness and prints no secret keys. `research-vectors` is disabled.

Extract source.tar.gz to use the Rust library through `crates/kem1536`, with Rust 1.91.1.
Cargo.lock pins crate versions; dependencies are not vendored. A fresh computer needs Cargo
registry access and the native target/toolchain described in provenance.json. Read README.md
and docs/DISTRIBUTION_M04.md in the sources. The CLI is a diagnostics interface; library
consumers call keygen, encapsulate and decapsulate through the Rust API.

The system libraries listed in dependencies.json remain prerequisites and are not included.
Normal Rust dependency graph membership does not prove every dependency symbol survives
linker garbage collection. Compile-time-only crates and toolchain notices are listed separately.

This package reuses the two-build evidence from release-003; no new build was run.
All production compilation inputs are byte-identical; see validation/compiled-input-equality.json.
Sources include subsequent integration-test, report and review-tool corrections.
