# MLKEM-1536 Core

**Post-quantum KEM research and cryptographic engineering**

MLKEM-1536 Core is an open research and engineering project built around a working
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
[Research progress through M15](docs/ETAT_RECHERCHE_M15.md) ·
[M15 Windows replay lot](research/reproducibility/m15/implementation/README.md) ·
[M10 engine and qualification](docs/M10_MOTEUR_ET_QUALIFICATION.md) ·
[M09 engine and qualification](docs/M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md) ·
[M08 import study and delivery](docs/M08_IMPORTS_ET_VALIDATION.md) ·
[M07 memory and delivery study](docs/M07_MEMOIRE_ET_VALIDATION.md)

[![Main-branch checks](https://github.com/MajidNIMAR/mlkem-1536-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MajidNIMAR/mlkem-1536-core/actions/workflows/ci.yml)

## Current engine and reproducible research — 18 November 2026

**M10 remains the delivered Rust engine.** It implements KeyGen, Encaps,
Decaps and implicit rejection for the specified R1 construction. Subsequent
M11–M15 work develops the security argument without changing the engine's
sources, parameters, formats or canonical binary.

The first [public M15 replay lot](research/reproducibility/m15/implementation/README.md)
now supplies **31 source-linked arithmetic SMT obligations**, an algebraic
NTT certificate with **131,072 checked linear coefficients** and **21
component tests**. Its **18 packaging-tool tests** are a separate suite.
The remaining M11–M15 workstreams are described in the
[progress note](docs/ETAT_RECHERCHE_M15.md); their detailed acquisitions and
reviews remain private.

**C01, the complete concrete R1 security argument, remains open.** This
replay lot makes a bounded part of the research independently examinable;
it does not establish whole-KEM or compiler verification, constant time,
universal erasure, an external audit or production suitability.

### Replaying the public M15 lot

From a checkout containing the lot, on Windows x64 with CPython 3.13 x64:

```powershell
python -I -S -B research/reproducibility/m15/implementation/setup_windows.py
python -I -S -B research/reproducibility/m15/implementation/verify.py
python -I -S -B research/reproducibility/m15/implementation/test_tools.py
```

The installer downloads the pinned official Z3 wheel into a local cache;
the verifier does not download or install dependencies. The
[lot guide](research/reproducibility/m15/implementation/README.md) documents
the offline mode, integrity-only mode, receipts and trust dependencies.
No Rust compiler, engine binary or private research archive is needed for
these checks.

These commands have been exercised from an independent fresh local clone,
including a new solver download and a second offline replay. That is a
recorded same-host Windows/CPython check, not a new-machine experiment.
A dedicated Windows job in the [CI workflow](.github/workflows/ci.yml)
runs the lot and preserves its receipts and logs. Hosted success must be
checked on the workflow run for the revision being examined.

## Broader research progress — M11–M15

The research program has advanced through M11–M15 while **M10 remains the
delivered engine reference**. The latest cycle adds targeted cryptanalysis,
constructive accounting for fixed SHA3/SHAKE computations, conditional
per-key correctness certificates, matched comparisons with ML-KEM-1024 and
source-linked arithmetic verification.

M15 records **16 new analysis jobs, 28,484 cost evaluations and 32 matched
profile comparisons**. Its scoped verification includes **31 universal
arithmetic obligations checked with SMT** and an algebraic NTT certificate.
The final local integration passes **27 checks and 82 targeted tests**,
with cross-reviews by other internal reviewers. These counts describe
specific instruments and models, not a global security level.

A sufficient margin is available at the declared working checkpoint under
explicit ideal-model and quantitative assumptions. **The full concrete R1
security argument, C01, remains open.** The required hardness assumptions,
fixed-primitive transfers and final CCA comparison are not established by
these results. The scoped proofs do not formally verify the whole KEM or
its compiler, and the internal reviews are not an external audit.

The [public progress note](docs/ETAT_RECHERCHE_M15.md) explains these boundaries.
The arithmetic/NTT lot above publishes one delimited subset of these results.
The other research programs, raw artifacts and detailed reviews remain
private; this is not a replay bundle for all M11–M15 studies. The **82
internal research tests** are distinct from the 21 public component tests,
the 18 packaging-tool tests and the public engine CI suite.
The engine source, R1 parameters, wire formats and canonical binary are
unchanged by these studies.

## Delivered engine and public evidence — M10

**M10 is the delivered engine reference, qualified internally on the recorded
PC targets.** It preserves the R1 construction, wire formats and deterministic outputs. SHA3/SHAKE material
is written into existing secret owners; borrowed SHAKE finalization keeps
the absorbed state subject to wiping, and the local decapsulation output
owner remains alive until after copying. The [four-image PC review](docs/REVUE_CYCLE_SECRET_M10.md)
qualifies removal of two observed normal-return stack residues. The first
two M10 iterations and their negative evidence are retained. Sensitive mask,
ABI/register/dependency/caller copies and global constant time remain open.

The fresh M09 → M10 comparison contains **40,000 latencies and 432 memory
observations**, with all preregistered budgets passed. Median changes range
from **4.31% lower to 2.20% higher**, depending on operation and OS. Observed
decapsulation touched-stack maxima fall by **224 bytes on each OS**;
Windows encapsulation rises by **16 bytes**. Requested allocation counters
do not increase. A separate 32,000-observation timing diagnostic has no
threshold crossing; it does not prove constant time. See the [M10 study](docs/M10_MOTEUR_ET_QUALIFICATION.md)
for complete distributions, costs, source/image identities and limitations.

The [M10 security composition](docs/SECURITE_M10.md) supplies explicit matrix,
noise and classical FO reductions, with conditional quantum analyses and
resource maps. The [parameter decision](docs/DECISION_PARAMETRES_M10.md)
records **40 fresh finite-sample estimates and 20 strict pairs favourable
to the R1 proxy**. These are declared attack-cost models, including
extrapolations; they give no certified global bit rating or constrained-RAM
optimum. R1 is retained for development; **C01 and final cryptographic
parameter selection remain open**. External review is deferred.

The new four-harness ASan/std-rebuilt campaign has completed with no observed
defect: **8,041.14 total CPU seconds**, including **7,408.48 conservative
post-INIT CPU seconds**, with each harness exceeding its own 1,800-second
budget. It records **33,197,231 post-INIT executions including repetitions**
and 3,968 harvested entries deduplicated within each harness. Historical
runs, compilation and initialization receive no post-INIT budget credit.
Separate LLVM coverage objects record **492/669 mapped core lines and
18/38 branches**, with zero-count mappings retained. Independent replay
matches **4,263 deterministic Rust/Python requests**, including 641 accepted
private-key decapsulation probes. The 1,887 fresh-randomness operations
encoded in the corpus are counted separately and are not recreated by the
oracle. These results do not establish complete path coverage, constant
time or global erasure; the [M10 study](docs/M10_MOTEUR_ET_QUALIFICATION.md)
classifies the uncovered code.

The [evidence capsule](results/engine/m10-001/) is sealed and its 10,908
members replay successfully, with the file-only mirror adaptation preserved.
The [complete local Windows check](results/engine/m10-verification-001/)
passes with **514 Python tests, none skipped**, Rust tests, formatting,
strict Clippy and the required evidence replays. Its 313 recorded source
and control inputs are identical before and after the check. Same-host
repeat CLI builds match Linux raw bytes and Windows outside the two declared
PE metadata fields; the distribution is qualified internally.

[Fresh hosted CI 43893183494 passes on Windows and Ubuntu](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43893183494)
at tested public commit [`82c63441`](https://github.com/MajidNIMAR/majax_mlkem1536/commit/82c63441d1885c1e348884a2d9442ee48b6eaf03),
with **514 Python tests per OS, none skipped**, Rust/fmt/strict Clippy,
evidence replays and native checks of the original M10 CLI/API consumer.
The [publication receipt](results/publication/r6-m10-001/) links the tested
source to all 37 qualified compilation inputs. The [frozen publication reader](results/publication/r6-m10-controls-001/)
retains 50 exact tested Python Git blobs, passes its four pure tests and
replays that receipt offline. The original M10 Windows CLI
is [promoted locally and checked after copying](results/engine/m10-canonical-002/):
profile, 16 fresh exchanges, 16 rejections and five disabled research-command
refusals pass. The initial hosted fixture failure, its test-only correction
and the first rolled-back promotion attempt are retained in the [M10 study](docs/M10_MOTEUR_ET_QUALIFICATION.md).
These integrations add no fuzzing credit, external audit or global security rating.

<a id="latest-verified-results--m09"></a>

## Historical delivered results — M09

**M09 is an immutable historical delivered milestone, qualified internally.** It introduced fixed-size
borrowed noise roles, operation-level partial-entropy failure checks, direct
message ownership and a scalar NTT with public precomputed twiddles. R1
formats, domains and outputs are unchanged. The final M08 → M09 comparison
contains **40,000 latency observations** across five alternating series:

| Operation | Windows median µs | Linux/WSL median µs |
|---|---:|---:|
| KeyGen | 488.800 → **419.500** (14.18% lower) | 501.062 → **435.257** (13.13% lower) |
| Encaps | 537.750 → **458.900** (14.66% lower) | 553.481 → **475.742** (14.05% lower) |
| Valid Decaps | 663.700 → **564.800** (14.90% lower) | 678.690 → **581.109** (14.38% lower) |
| Rejected Decaps | 662.100 → **564.400** (14.76% lower) | 697.092 → **579.844** (16.82% lower) |

All predefined final KEM latency and observed-memory budgets pass. The
memory panel retains 216 reference observations and adds 216 candidate
observations; KEM touched-stack maxima and requested allocation counters
do not increase. Tables cost 1,020 public bytes and the reviewed transform
frame grows by 16 bytes; these are different memory metrics.

The first vectorized candidate was **rejected for delivery** after a
confirmed Windows ABI secret-copy finding. The corrected scalar candidate
has its own four-image review; removal of that mechanism is bounded to
those images and functions. `black_box` supplies no cryptographic guarantee.

Each host replays 1,000 full vectors, 10,000 rejections, 10,000 independently
checked mutations and 20,000 format inputs; its default-feature consumer
checks 88,576 finite import probes. The new ASan/std-rebuilt-image smoke
records **194.64 CPU seconds**, four post-INIT budgets and no observed defect.
It does not supply new LLVM source coverage or independent replay of its
harvested fuzz corpus. A separate 32,000-observation timing diagnostic has
zero threshold crossings, without proving constant time.

The [M09 study](docs/M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md) preserves the
negative result, corrected images, raw measurements and acquisition/replay
incidents. The [classical ROM seeded-noise sub-lemma](docs/SECURITE_M09.md)
advances a specific security obligation; **C01, QROM and concrete-primitive
security remain open**. [Independent review is prepared](docs/REVUE_EXTERNE_M09.md),
with no external audit claimed. The [complete local check](results/engine/m09-verification-001/)
passes with 438 Python tests, Rust tests, formatting, strict Clippy and the
required evidence replays. The [storage-reader follow-up](results/engine/m09-reader-review-001/)
then passes the 439-test Python suite while preserving all 37 qualified
compilation inputs. These receipts remain separate from the acquisitions.

[Fresh hosted CI passes on Windows and Ubuntu](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43806407492)
at public commit [`fdd323dc`](https://github.com/MajidNIMAR/majax_mlkem1536/commit/fdd323dcf840b0d12fd43a446acffbd0cce83d7b),
with **439 Python tests executed per OS, none skipped**, Rust/fmt/strict
Clippy, the required archive replays and native checks of the original
M09 CLI/default consumer. The [publication receipt](results/publication/r6-m09-001/)
binds 2,138 exported files and canonical Git blobs, the 37 qualified
compilation inputs and the original image hashes. The [frozen offline reader](results/publication/r6-m09-controls-001/)
replays that receipt. The [initial green run](results/publication/r6-m09-initial-001/)
retains one omitted test and the reason a second run was required; its
test-only correction changed no compiled input or scientific evidence.
The [historical qualified packages](docs/DISTRIBUTION_M09.md) remain available.
The original M09 Windows image was copied and
[checked natively after its promotion](results/engine/m09-canonical-001/), with
16 fresh exchanges/rejections and five normal research-command refusals.
These integrations are separate from the frozen measurements and campaigns.

<a id="latest-verified-results--m08"></a>

## Historical delivered results — M08

**M08 remains the immutable previous delivered milestone.** The Rust engine
implements KeyGen, Encaps, Decaps and implicit rejection for the specified
R1 profile. M08 strengthens key import while preserving R1 formats and
outputs. Its measured import medians are:

| Valid key import | Windows, M07 → M08 | Linux/WSL2, M07 → M08 |
|---|---:|---:|
| Public key | 18.900 → **1.400 µs** (**13.50×**) | 19.119 → **1.240 µs** (**15.42×**) |
| Private key | 46.200 → **11.200 µs** (**4.12×**) | 47.122 → **10.936 µs** (**4.31×**) |

These are operation-specific observations on the recorded environments.
The four core KEM operations remain close to M07. The [M08 study](docs/M08_IMPORTS_ET_VALIDATION.md)
retains the full distributions, source and executable identities, and limits:
300,000 latency observations, 2,880 memory observations and 210 passed budgets.

Earlier engine improvements are documented separately: [M06](docs/M06_MESURES_ET_DURCISSEMENT.md)
measured **1.79× / 1.87× / 1.76×** gains for KeyGen / Encaps / valid Decaps
on its Linux panel. [M07](docs/M07_MEMOIRE_ET_VALIDATION.md) reduced observed
decapsulation touched-stack maxima from **23,688 to 13,064 bytes** on Windows
and **23,336 to 12,696 bytes** on Linux; M08 retains those maxima. These
stage-specific results are not combined into a cumulative speedup or a
universal memory bound.

The M08 validation included **352 Python tests per OS**, Rust tests and
fresh Windows/Ubuntu CI; complete regression replay on both measured hosts;
**7,256.67 new CPU seconds of ASan/std-rebuilt fuzzing** without an observed
defect; and **3,156 deterministic requests** matched to the independent Python
reference, including 433 accepted-private-key decapsulation probes.
The LLVM union records **438/604 mapped core lines and 17/36 branches**, with
zero-count mappings retained. The [M08 evidence](results/engine/m08-001/)
and [hosted execution receipts](results/publication/r6-m08-001/) preserve the
scope and raw results.

| Assurance area | Current published status |
|---|---|
| Functional engine and compatibility | Implemented and exercised on Windows/Linux; complete reference corpora match and R1 formats remain compatible |
| Implementation hardening | M10 qualifies removal of two observed stack residues in its four reviewed PC images and completes its new long sanitizer campaign; earlier M08/M09 findings retain their own image scope. Register/ABI/all-PKE erasure and formal constant time remain open |
| Cryptographic security argument | Exact correctness certificates and conditional ROM/QROM analyses under stated assumptions; the full concrete R1 argument **C01 remains open** |
| Research progress through M15 | A public Windows arithmetic/NTT lot supplies 31 SMT obligations, 131,072 checked coefficients and 21 component tests; the broader conditional-margin and per-key research, detailed acquisitions and full 82-test internal suite are not supplied by that lot |
| External assurance and security rating | A certified global bit rating, NIST category or external cryptographic audit is not established by these artifacts; **1536 denotes the coefficient count** |
| Target qualification | M10 CLI/default-consumer reviews and hosted native checks concern the recorded GNU x86-64 Windows/Linux PC images; M08/M09 retain their own historical scope. Android/ARM requires its own qualification |

The [security status](SECURITY.md) separates the M10 corrections, earlier
M08/M09 findings and the remaining cryptographic obligations.
The [five-point technical review](docs/REVUE_CRITIQUE_M08_CIBLES_ET_CONTRATS.md)
records the Android boundary, noise-domain framing and existing error-order tests.

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
| Secret ownership | Typed keys and shared secrets, bounded buffers and explicit zeroizing owners | [Secret storage](crates/kem1536/src/secret_box.rs), [M10 secret-lifecycle review](docs/REVUE_CYCLE_SECRET_M10.md) |
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
[ML-KEM-1024 Forge](https://github.com/MajidNIMAR/mlkem-1024-forge),
the companion repository for standardized ML-KEM parameter sets. R6's
arithmetic and KEM operations are implemented in this repository. The
project is developed independently from Majax Messenger's operational
architecture.

<a id="current-engineering-milestone-m08"></a>

## Previous engineering milestone: M08

M08 replaces polynomial reconstruction during key import with a direct scan
of the canonical 13-bit encoding. It checks all **1,536 coefficients** before
the final decision, preserving R1 formats, domains and error order. The
[M08 study](docs/M08_IMPORTS_ET_VALIDATION.md) records the measured candidate,
the preregistered criteria and the remaining work.

The Windows/Linux comparison retains **300,000 paired latency observations**
and **2,880 memory observations**; all **210 predefined budget checks pass**.
Each of the four reference/candidate API consumers passes **88,576 finite
import probes**, and complete engine regression outputs match. These checks
do not enumerate the full space of keys or ciphertexts.

The sealed review of the four default-feature API consumers contains **124
addressed instruction witnesses**. The candidate images no longer produce
the targeted decoded-coefficient stack copies on the examined invalid-secret
paths. Caller-owned data, ABI save areas, registers and other PKE paths remain
outside that conclusion. Separate inventories identify the candidate CLI
images; the consumer review is not a proof of CLI erasure.

The four long-campaign harnesses have reached their new CPU budgets:
**7,256.67 CPU seconds** in 30 segments, with no observed defect and no
historical time credited. The separate LLVM union covers **438/604 mapped
core lines** and **17/36 branches**, retaining zero-count mappings. The
independent replay matches **3,156 distinct deterministic requests**, including
433 accepted-private-key decapsulation probes. Fresh-randomness operations are
counted separately. An environment interruption preserved the first partial
oracle transcript; only the oracle was resumed with the frozen controller and
replay image. Two qualified delivery packages ship the original inventoried
CLI images. One new repeat build per host matches Linux bytes exactly and
Windows bytes apart from the COFF timestamp/PE checksum. Source, notices and
finite execution receipts are retained. The [complete M08 snapshot](results/engine/m08-001/)
preserves 7,520 files and 428 directories, and its extracted data replay passes;
the full Windows check passes with **352 Python tests**, Rust tests, fmt,
strict Clippy and required data replays. Original-image native checks also
pass locally. [Fresh Windows/Ubuntu CI](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43008567843)
passes on public commit `b0491eb`, with 352 Python tests on each OS and native
execution of the original M07/M08 images. The M08 CLI passes 16 exchanges,
16 rejections and five normal command refusals; its original API consumer
passes a fresh imported-key exchange/rejection and 88,576 probes per OS.
The [hosted integration receipt](results/publication/r6-m08-001/) binds both
source maps (2,024 exported files and Git blobs) to the tested commit. Hosted
native execution and historical measurements retain separate receipts.
The [frozen offline readers](results/publication/r6-m08-controls-001/) make
the hosted receipt replayable from the public repository.
The
[bounded side-information result](docs/REJET_ET_INFORMATION_LATERALE_M08.md)
is already preserved separately: it generalizes the ideal rejection-key
assumption to classical side information, without establishing the entropy
of imported keys or closing the complete KEM security argument.

## Previous engineering milestone: M07

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
The packages ship the original reviewed binaries. The frozen M07 binaries
retain the import-spill finding documented in [SECURITY](SECURITY.md).
M08's separate consumer review qualifies the targeted correction described
above, with its remaining register/ABI/PKE limits.

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
| [M08 ideal rejection with classical side information](results/security/m08-rejection-001/) | Ten exact rational panels under explicit conditional independence and guessing-probability assumptions; no quantum side information or concrete SHAKE guarantee |
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
in the [repository's Actions tab](https://github.com/MajidNIMAR/mlkem-1536-core/actions).

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

MLKEM-1536 Core is an **experimental research implementation** intended for analysis,
reproducibility and independent review. Parameter selection and cryptanalysis
continue. The correctness certificates and conditional ROM/QROM arguments
retain their stated assumptions. Research through M15 provides a sufficient
conditional margin for its declared working checkpoint, while the exact
fixed-primitive argument, quantitative assumption qualification and final
comparison remain open. Formal constant-time execution, complete erasure of secret
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
negative results and decisions. Current work focuses on the quantitative
security assumptions, concrete-primitive and correctness populations,
matched security comparisons and stronger implementation guarantees.
See the [M15 progress and evidence boundary](docs/ETAT_RECHERCHE_M15.md).

## License and attribution

Original project contributions are licensed under **Apache-2.0**.
Third-party material retains its own terms; see [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The local workspace name
`NIST` does not indicate institutional affiliation.
