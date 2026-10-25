# Majax MLKEM1536 — experimental KEM engine

A working Rust implementation of **KEM1536-DEV-Q7681-R1**, an experimental
module-lattice KEM with **six polynomials of 256 coefficients**. This
repository publishes the engine, its specification, independent Python
reference and preserved research evidence while development continues.

**1536 means 6 × 256 coefficients.** It is neither a security-bit claim nor
a standardized ML-KEM parameter-set name. The R1 profile has its own modulus,
formats and hash domains. It is not interoperable with FIPS 203 ML-KEM.

This is a separate research project by the author of
[majax-mlkem1024-demo](https://github.com/MajidNIMAR/majax-mlkem1024-demo).
That companion repository demonstrates the standardized ML-KEM parameter
sets through PQClean-backed dependencies. Here, the R1 arithmetic and KEM
operations are implemented in the project's Rust source. Neither repository
publishes the operational architecture of Majax Messenger.

## Implemented today

- Key generation, encapsulation and decapsulation, with operating-system
  randomness and implicit ciphertext rejection.
- Typed public keys, private keys, ciphertexts and shared secrets.
- Specialized arithmetic in `Z_7681[X]/(X^256 + 1)` with rank six and CBD(3)
  noise; exact canonical 13-bit `u` and 5-bit compressed `v`.
- An independent Python implementation for synthetic reference checks.
- Windows and Linux/WSL2 execution, frozen vectors, negative tests,
  sanitizer checks, timing diagnostics, binary inspection and benchmarks.

| R1 object | Bytes |
| --- | ---: |
| Encapsulation/public key | 2528 |
| Expanded decapsulation/private key | 5088 |
| Ciphertext | 2656 |
| Shared secret | 32 |

The [specification](docs/SPECIFICATION_DEV_Q7681_R1.md) defines the actual
construction. The [engine guide](docs/MOTEUR_KEM_R1.md) explains the API and
its validation boundary. Research notes are currently maintained in French.

## Run the engine

On Windows, from PowerShell at the repository root:

```powershell
.\scripts\bootstrap.ps1
.\scripts\engine.ps1 self-test
```

On Linux, with `curl` and a C compiler/linker available:

```bash
bash scripts/bootstrap.sh
bash scripts/engine.sh self-test
```

The scripts install Rust **1.91.1** under this checkout's `.tools/` directory.
The self-test builds the release executable and checks 16 fresh exchanges
and 16 implicit rejections. Its JSON summary contains no private key or
shared secret. Build only with `engine.ps1 build` or `engine.sh build`;
the executable is `target/release/kem1536[.exe]`.

For 10,000 additional fresh exchanges and rejection checks:

```powershell
.\scripts\engine.ps1 stress -Count 10000
```

```bash
bash scripts/engine.sh stress 10000
```

## Verify the research evidence

The full checks also require **Python 3.11 or newer** (`python` on Windows,
`python3` on Linux). On Debian/Ubuntu, install the Python venv support
package if it is not already available. Setup installs **NumPy 2.3.5** in
a local virtual environment and downloads hash-pinned external research
references. It does not install Python packages globally.

```powershell
.\scripts\research-setup.ps1
.\scripts\dev.ps1 check
```

```bash
bash scripts/research-setup.sh
bash scripts/dev.sh check
```

`check` runs formatting, Clippy, Rust and Python tests, the standardized
ML-KEM-1024 comparison and integrity checks over the research snapshots.
It replays **16** cases from each of the large R1 regression corpora.
Commands for full replay are documented in the engine and hardening guides.
The workflow in `.github/workflows/ci.yml` runs the full check command on
Windows and Ubuntu; its actual status is visible in this repository's
Actions tab.

The complete checks passed on fresh GitHub-hosted **Windows and Ubuntu**
runners for [code revision 75c26f6](https://github.com/MajidNIMAR/majax_mlkem1536/commit/75c26f668a99cf0676a01494bc33a7c99a193803),
including **95 Python tests** per platform. The
[CI run](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/40210986511)
and [preserved logs and provenance](results/publication/portability-001/)
record the result and the two portability fixes found during publication.

## Preserved evidence and current limits

| Evidence | Preserved scope |
| --- | --- |
| [M01 vectors](results/engine/r1-001/) | 1,000 complete vectors matched between Rust and Python; 10,000 fresh exchanges |
| [M01 rejection corpus](results/engine/r1-rejections-001/) | 10,000 paired rejection secrets matched exactly |
| [M02 hardening](docs/DURCISSEMENT_MOTEUR_M02.md) | Full Windows/Linux regression, 20,000 format cases and 10,000 mutations per platform, sanitizer and timing diagnostics |
| [M03 measurements](docs/M03_FUZZ_BINAIRES_BENCHMARKS.md) | 60,000 raw benchmark observations and compiled-code review on Windows/Linux |
| [M03 short fuzzing](results/engine/m03-smoke-001/) | 85.01 CPU seconds; 511 retained deterministic requests checked against the independent Python reference |

The separate long fuzzing campaign has a target of **24 cumulative CPU
hours** across four workers. At the initial public snapshot it is still
running locally. Its live ignored output is not a completed public result.
Publication of its final archive requires completion and review.

Parameter selection and cryptanalysis remain open. The existing checks do
not establish a security level, a formal constant-time guarantee, complete
secret-copy erasure or external certification. M03-A01 documents a 512-byte
temporary without an explicit wipe in the reviewed Windows multiplication
binary. See [SECURITY.md](SECURITY.md) and the detailed review.

Functional agreement across implementations and tested platforms is
documented. Byte-for-byte reproducible **builds** have not yet been established
for R1. The companion 1024 project's build procedure is a separate result.

## Follow development

- [Research report](docs/RAPPORT_RECHERCHE.md) and [research journal](docs/JOURNAL_RECHERCHE.md)
- [Engine roadmap](docs/FEUILLE_DE_ROUTE_MOTEUR.md)
- [Initial requirements](CAHIER_DES_CHARGES_KEM_1536.md) and [profile specification](docs/SPECIFICATION_DEV_Q7681_R1.md)
- [Detailed research context](docs/CONTEXTE_RECHERCHE.md) and [development guide](docs/DEVELOPPEMENT.md)
- [Public snapshot and reproduction notes](docs/PUBLICATION_GITHUB.md)

Historical P0 and twenty J2 snapshots are preserved with negative results
and model assumptions. P0 is not the executable R1 profile. Development
continues with reproducibility, hardening and independent cryptanalysis.

## License and attribution

Original project contributions are licensed under **Apache-2.0**, consistent
with the companion 1024 repository. Third-party sources and datasets retain
their own terms; see [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The local research workspace
is named `NIST`; that name does not indicate institutional affiliation.
