# MAJAX R6

**Post-quantum KEM research and cryptographic engineering**

MAJAX R6 is an open research and engineering project built around a working
Rust key encapsulation mechanism. It brings together a specified cryptographic
construction, polynomial arithmetic, key and secret management, independent
reference implementations, cryptanalysis and reproducible experiments.

The implemented construction is **`KEM1536-DEV-Q7681-R1`**: a module-lattice
KEM with **six polynomials of 256 coefficients**. The project develops the
engine itself and preserves the reasoning, measurements and implementation
evidence needed to examine its evolution.

[Specification](docs/SPECIFICATION_DEV_Q7681_R1.md) ·
[Engine and API guide](docs/MOTEUR_KEM_R1.md) ·
[Research report](docs/RAPPORT_RECHERCHE.md) ·
[M07 memory and delivery study](docs/M07_MEMOIRE_ET_VALIDATION.md)

[![Main-branch checks](https://github.com/MajidNIMAR/majax_mlkem1536/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MajidNIMAR/majax_mlkem1536/actions/workflows/ci.yml)

## Research program and engine architecture

The work connects three areas:

- **Cryptographic research:** construction and parameter analysis, exact
  correctness certificates, conditional security arguments and comparisons
  under declared attack models.
- **Engine development:** KeyGen, Encaps and Decaps in Rust, operating-system
  randomness, typed objects, validated encodings and implicit rejection.
- **Implementation evaluation:** independent Python checks, malformed inputs,
  instrumented diagnostics, compiled-code review and preserved raw benchmarks.

| Component | Current realization | Source or reference |
|---|---|---|
| KEM construction | R1 key generation, encapsulation, decapsulation and implicit rejection | [KEM implementation](crates/kem1536/src/dev_kem.rs) |
| Polynomial arithmetic | Scalar negacyclic NTT in `Z_7681[X]/(X^256 + 1)`, reused transforms and accumulated products | [Arithmetic implementation](crates/kem1536/src/engine_poly.rs) |
| Secret ownership | Typed keys and shared secrets, bounded buffers and explicit zeroizing owners | [Secret storage](crates/kem1536/src/secret_box.rs), [implementation review](docs/M06_REVUE_INDEPENDANTE.md) |
| Independent reference | Separate Python implementation and generic convolution checks | [Python reference](research/kem_r1_reference.py), [certificate/program bridge](docs/LIEN_CERTIFICAT_PROGRAMME_R1.md) |
| Integration | Rust library API, command-line diagnostics and a KEM/HKDF/AEAD consumer example | [Engine guide](docs/MOTEUR_KEM_R1.md), [channel example](examples/r1-channel-demo/README.md) |

R1 uses rank six, modulus **7681**, **CBD(3)** noise, exact canonical
13-bit `u` coefficients and 5-bit compressed `v`. Its serialized objects are:

| R1 object | Bytes |
|---|---:|
| Encapsulation/public key | 2528 |
| Expanded decapsulation/private key | 5088 |
| Ciphertext | 2656 |
| Shared secret | 32 |

**R6 denotes the module rank; 1536 denotes the coefficient count, 6 × 256.**
The implemented R1 identifier, formats and hash domains are defined by its
own specification. R1 is distinct from the standardized FIPS 203 ML-KEM
parameter sets and does not interoperate with them. These names do not
represent a security-bit rating.

This is a separate research project by the author of
[MAJAX ML-KEM](https://github.com/MajidNIMAR/majax-mlkem),
the companion repository for standardized ML-KEM parameter sets. R6's
arithmetic and KEM operations are implemented in this repository. The
project is developed independently from Majax Messenger's operational
architecture.

## Current engineering milestone: M07

M07 streams coefficient rows through reused operation-owned buffers while
retaining the transformed operands and the **48/55/68** transform counts.
R1 parameters, formats, domains and complete regression outputs remain the same.
The [M07 study](docs/M07_MEMOIRE_ET_VALIDATION.md) compares both versions on
Windows and Linux, using 2,240 memory observations and 80,000 paired latency
observations under criteria fixed before the candidate.

| Operation | Windows touched-stack maximum, M06 → M07, bytes | Linux touched-stack maximum, M06 → M07, bytes |
|---|---:|---:|
| Key generation | 13,392 → 8,144 | 12,824 → 7,208 |
| Encapsulation | 14,808 → 7,672 | 14,536 → 7,400 |
| Valid or rejected decapsulation | 23,688 → 13,064 | 23,336 → 12,696 |

These are **instrumented touched-stack observations**, not universal stack
bounds or the delivered CLI's peak. Private-key import also uses one allocation
instead of two. All predefined budgets pass; Windows key generation is 1.8%
slower at the median in this panel, a result retained alongside the gains.

The [compact M07 evidence](results/engine/m07-001/) preserves new binary reviews,
the full regression receipts, a finite 248.73 CPU-second ASan/std-rebuilt
campaign and Windows/Linux packages with compact compilable source and licenses.
Linux's repeat build is byte-identical; Windows differs only in the COFF
timestamp and PE checksum. Both use the same source path, toolchain and shared
dependency caches; this is not an independent third-party reproduction.
The packages ship the original reviewed binaries. A preexisting invalid-private-key
import spill limitation remains documented in [SECURITY](SECURITY.md).

## Previous engineering milestone: M06

M06 reuses transformed operands and accumulates rank-six products before
a single inverse transform. Coefficient and NTT representations have
distinct types, and results are written into storage owned by the caller.
The number of transforms per KeyGen/Encaps/Decaps operation changes from
**108/126/144 to 48/55/68**, while preserving R1 formats and outputs on the
complete regression corpora.

The [recorded comparison](docs/M06_MESURES_ET_DURCISSEMENT.md) contains
**60,000 raw observations** in five alternating series on an AMD Ryzen 7
2700 under WSL2 Ubuntu 22.04, with Rust 1.91.1:

| Operation | Median before M06, µs | Median M06, µs | Ratio before/M06 |
|---|---:|---:|---:|
| Key generation | 912.009 | 508.664 | 1.79× |
| Encapsulation | 1045.195 | 560.313 | 1.87× |
| Valid decapsulation | 1207.790 | 686.917 | 1.76× |

These are measurements from the documented machine and harness. All
outliers are retained. The speedup has a storage tradeoff: several static
LLVM stack frames increase. Whole-process RSS is measured separately and
does not establish the engine's dynamic stack peak. The measurement note
preserves the distributions, build inputs, compiler details and limitations.

## Preserved implementation and research evidence

| Evidence | Recorded scope |
|---|---|
| [M07 memory, binary, fuzz and delivery evidence](results/engine/m07-001/) | 116/116 budgets pass, complete Windows/Linux output regression, four bounded binary reviews, 32,000 finite timing observations and new finite ASan/std-rebuilt campaign; no global erasure or constant-time proof |
| [R1 reference vectors](results/engine/r1-001/) and [rejection corpus](results/engine/r1-rejections-001/) | 1,000 complete Rust/Python vectors, 10,000 fresh exchanges and 10,000 paired rejection outputs |
| [M06 engine regression and binary review](results/engine/m06-001/) | Complete Windows/Linux equality to the frozen outputs: 1,000 vectors, 10,000 rejections, 10,000 mutations and 20,000 format cases per system; four preserved binary inventories and targeted owner review |
| [M06 instrumented campaign](results/engine/m06-fuzz-001/) | 850.99 CPU seconds with ASan and rebuilt standard library, a separate API supplement, four source-coverage exports and their LLVM union |
| [M06 independent corpus replay](docs/M06_MESURES_ET_DURCISSEMENT.md) | 8,638 deterministic Rust/Python requests match, including 1,545 decapsulation probes with accepted imported private keys; fresh-randomness operations remain a separate harness check |
| [M06 integration receipts](results/engine/m06-verification-001/) | 154 Python tests on Windows, 25 targeted M06 tests on Linux, preserved Rust/Clippy/format checks and evidence replay; the Linux scope is not a new complete project check |
| [Correctness certificate and program bridge](docs/LIEN_CERTIFICAT_PROGRAMME_R1.md) | Exact finite reconstruction and explicit ideal-sampler assumptions linked to the implemented operations |
| [M05 security analysis](docs/SECURITE_CONCRETE_R1_M05.md) and [M06 ideal rejection](docs/REJET_IMPLICITE_R1_M06.md) | Conditional ROM/QROM bounds, query budgets, exact rational panels and explicit remaining obligations |
| [Experimental KEM comparison](docs/COMPARAISON_EXPERIMENTALE_M05.md) | 108 finite estimator outputs across six profiles/problems, with declared rounding proxies and 36 historical cross-checks |

The [M04 review](docs/M04_MOTEUR_NTT_ET_CONTROLES.md) records the earlier
memory correction, NTT introduction and delivery checks. Its
[distribution](docs/DISTRIBUTION_M04.md) and
[direct repository comparison](docs/COMPARAISON_DEPOTS_EXECUTION_M04.md)
retain their original version and measurement scope.

The historical long M03 campaign reached **86,941.20 cumulative CPU
seconds** on its own frozen implementation. Its
[automatic archive](results/engine/m03-fuzz-001/) still requires final
review. That duration is kept separate from the later M06 campaign.

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

The scripts install Rust **1.91.1** inside this checkout's `.tools/`
directory. The self-test builds the release executable and checks
**16 fresh exchanges and 16 implicit rejections**. Its JSON summary
contains no private key or shared secret.

Build only with `engine.ps1 build` or `engine.sh build`; the executable
is `target/release/kem1536[.exe]`. For 10,000 additional fresh exchanges
and rejection checks:

```powershell
.\scripts\engine.ps1 stress -Count 10000
```

```bash
bash scripts/engine.sh stress 10000
```

The [engine guide](docs/MOTEUR_KEM_R1.md) documents the Rust API. The
[consumer example](examples/r1-channel-demo/README.md) shows how to combine
the KEM's shared secret with HKDF and AEAD for a channel experiment.

## Reproduce the checks

The complete checks require **Python 3.11 or newer** (`python` on Windows,
`python3` on Linux). Setup creates a local virtual environment with
**NumPy 2.3.5** and retrieves hash-pinned external research references.
On Debian/Ubuntu, Python venv support must be available.

```powershell
.\scripts\research-setup.ps1
.\scripts\dev.ps1 check
```

```bash
bash scripts/research-setup.sh
bash scripts/dev.sh check
```

`check` runs formatting, Clippy, Rust and Python tests, the standardized
ML-KEM-1024 comparison and integrity checks over the preserved snapshots.
Its ordinary reference replay uses **16 cases** from each of the large
R1 corpora. Full-corpus commands and their retained results are documented
in the engine and hardening guides. Evidence verifiers recompute retained
data; they do not rerun long campaigns or benchmarks as part of every check.

The published CI baseline passed on fresh GitHub-hosted **Windows and
Ubuntu** runners for [revision 75c26f6](https://github.com/MajidNIMAR/majax_mlkem1536/commit/75c26f668a99cf0676a01494bc33a7c99a193803),
with **95 Python tests** per platform. Its
[CI run](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/40210986511)
and [logs](results/publication/portability-001/)
preserve that historical result. The M04–M06 evidence above records
subsequent development and validation; each snapshot retains its own scope.
Current public workflow results for the revision under test are available
in the [repository's Actions tab](https://github.com/MajidNIMAR/majax_mlkem1536/actions).

The **M07** source passed the complete checks on fresh Windows and Ubuntu
runners at commit `97d776c`, with **227 Python tests per platform**, Rust
default/all-feature tests, strict Clippy, formatting, evidence replay and
fresh engine self-tests. Each runner then executed its **original preserved
M07 package**, checking 16 exchanges, 16 rejections and five normally rejected
research commands. The [successful run](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/42936652940)
and [retained records](results/publication/r6-m07-001/) bind this to the exact
revision and original binary hashes. Historical campaigns/measurements are
data replays; the native package self-tests are fresh. The documentation
closure preserves the tested executable source, controls and evidence.

The earlier **MAJAX R6 / M06** source passed the full checks on fresh
Windows and Ubuntu runners at [revision feaeef2](https://github.com/MajidNIMAR/majax_mlkem1536/commit/feaeef2d027b9f769c3623d92408fa2cb09e28b2),
with **166 Python tests per platform**, Rust tests, formatting, strict
Clippy, evidence replay and engine self-tests. The
[successful main-branch run](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/42906288492)
and [retained receipts](results/publication/r6-m06-001/)
bind those results to the exact public source. The snapshot also verifies
1,882 exported files and their canonical public Git blobs against the
source provenance. These checks replay the archived campaigns and
measurements; they do not start new fuzzing or benchmark campaigns.
The subsequent publication of these receipts changes documentation and
evidence only.

## Security and research status

R6 is an **experimental research implementation** intended for analysis,
reproducibility and independent review. Parameter selection and cryptanalysis
continue. The correctness certificates and conditional ROM/QROM arguments
retain their stated assumptions; the seeded-PKE obligations, concrete
SHAKE-based security argument and final reduction margins remain open.
The loose quantum rejection bound does not certify the earlier illustrative
allocation. Formal constant-time execution, complete erasure of secret
copies, an external security audit and standardization remain future work.
The available evidence does not establish a global security-bit rating or
production-security guarantee. See [SECURITY.md](SECURITY.md).

## Research record and next work

- [Research report](docs/RAPPORT_RECHERCHE.md) and [research journal](docs/JOURNAL_RECHERCHE.md)
- [Engine roadmap](docs/FEUILLE_DE_ROUTE_MOTEUR.md)
- [Initial requirements](CAHIER_DES_CHARGES_KEM_1536.md) and [R1 specification](docs/SPECIFICATION_DEV_Q7681_R1.md)
- [Detailed context](docs/CONTEXTE_RECHERCHE.md) and [development guide](docs/DEVELOPPEMENT.md)
- [Publication provenance](docs/PUBLICATION_GITHUB.md)

Research notes are currently maintained in French. The historical P0
candidate and twenty J2 snapshots preserve the original hypotheses,
negative results and decisions. Current work continues on memory usage,
implementation guarantees, portable delivery and the remaining security
arguments.

## License and attribution

Original project contributions are licensed under **Apache-2.0**.
Third-party material retains its own terms; see [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The local workspace name
`NIST` does not indicate institutional affiliation.
