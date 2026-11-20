# Selected verification and test record

Documentation updated 20 November 2026 for `KEM1536-DEV-Q7681-R1`.
The construction and Rust engine are experimental. Concrete security
qualification C01 remains open. This page reports what was checked and how
the evidence can be examined; it does not assign a security level.

The post-M28 C01 Blocks 1–4 are the latest local research program. M24–M28
are the latest numbered scoped C01 research blocks. M20–M23 are the
latest numbered scoped engine qualification cycles, each with
an internally reviewed result. M18 and M19 retain their historical outcomes.
M10 remains the delivered engine reference. The C01 and block-3 studies remain
separate cryptographic research.

The latest private classical ideal-game reduction passed its source-anchor,
exact CBD(3) atom, rational residual and negative-scope controls. A separate
internal counter-reading required a correction to the treatment of hidden
game computations; the amended proof was saved as a new sealed capsule, with
the original retained. A second counter-reading checked the seeded-PKE
hybrids, conditional matrix-stream programming and query accounting. These
are checks of a **conditional mathematical argument**, not measurements of
Module-LWE hardness or a fixed-function IND-CCA advantage. The detailed
proofs, readers, reviews and seals remain in locally ignored capsules.
The separate composition reader checked the substitution of both reductions,
the full `q_post_G` multiplier and an exact rational residual below `2^-189`
under the declared illustrative caps. Its independent review found no
blocking objection in the same classical ideal model. This bound excludes
the two unbounded Module-LWE advantages; it is not a whole-KEM security bound.

For the actual fixed SHA3/SHAKE roles, eight synthetic vectors passed 96
functional checks and seven negative mutations were detected. A separate
replayable harness executed 464 synthetic R1 game trials with a restricted
adversary process and checked 16 archived Rust vectors. Its reader, self-test,
replay and seal passed. The observed outcomes apply only to the strategies
and budgets tested; they give no statistical security level. No source,
parameter, wire-format, canonical-binary or hosted-CI change is credited.
**Concrete C01 stays open.**

The M15 Windows replay job uses the frozen publication commit
`53d501de898ec6ba024cc05a3f7373563c6a2ef4`, because its manifest
pins the exact Rust input bytes from that lot. The current `main` source
is checked by the two engine CI jobs. This preserves the historical M15
integrity check after a later test-only addition to `dev_kem.rs`; an M15
success does not retest that later source. The first hosted run of the
20 November publication failed at the M15 input gate before solver setup;
the correction is the explicit historical checkout, not a change to the
frozen manifest or scientific inputs. The [replacement workflow #18](https://github.com/MajidNIMAR/mlkem-1536-core/actions/runs/44652862478)
on public commit `5740d322e655f40c5cb6cfac35d7a59f6c1fb686` completed
successfully: Windows engine, Ubuntu engine and frozen M15 replay all passed.

A classical multi-rate follow-up compared the new ideal lemmas with the
previous sponge theorem. A source-level review confirmed the total-query
accounting and identified a simulator-contact event that remains unbounded
for the full direct-permutation interface. A restricted, monitored game
without direct permutation access has an exact arithmetic composition:
the ideal correction upper bound and one indifferentiability penalty sum
to less than `2^-192` under a deterministic `N≤2^32` cap. Local readers,
negative scope controls and an independent review apply only to these
declared games; they are not fixed-function security tests or hosted CI.
The private `c01-head-ip-transfer-001` verifier passed its model check,
nine negative scope controls and seal verification. The restricted
correction capsule passed its exact arithmetic reader and seal; its
primary-theorem transfer was separately reviewed. These are proof checks,
not experiments that measured a 192-bit security level.
The sealed `c01-ip-integration-001` reader replayed both new capsules,
the ideal correction seal and the historical multi-rate receipt; it passed.

The preceding local cycle checked a selected challenge-key extraction route
with two finite readers and four overclaim controls. A separate ideal-oracle
correctness lemma passed its rational-bound verifier, independent reader,
nine comparisons with the Python reference and an internal mathematical
counter-reading. A new Rust regression test exercises the corresponding
noise-coincidence case in the actual engine. The all-message result is a
bound in the stated ideal game; none of these checks proves an IND-CCA
advantage for fixed SHA3/SHAKE, a quantum transfer or an external audit.
An independently reviewed ideal challenge-head note passed 384 finite
post-challenge comparisons and a control demonstrating why pre-challenge
Decaps must be counted. Its remaining target-query probability is open.

The detailed records remain in locally ignored capsules. A fresh strict
Clippy and all-features workspace run passed 47 Rust tests in nonempty
groups; formatting and `git diff --check` passed. No hosted CI is credited
for this local source change.

The separate adaptive-seed certificate passed a rational calculation and
an independent integer reader for a bounded classical ideal game. Its
`2^-195` statement assumes at most `2^32` distinct non-key noise seeds
across all relevant direct, engine and simulator calls. It is a proof
check within that model, not an experimental attack measurement or a
fixed-function security bound.

An integration reader then replayed the selected local seals and bound
checks and confirmed that the remaining C01 gates are still marked open.
Its capsule is retained locally outside Git; the public README and this
summary alone cannot reproduce those private checks.

An earlier local C01 proof-route cycle ran two independent readers for
the challenge-key branch (all 7,681 compression inputs and 256 finite
classifiers), two decapsulation-model readers (seven directed scenarios,
77,760 finite cases and 46,656 two-query adaptive sequences), and a
six-role classical ideal-permutation bound reader with an overclaim
mutation rejected. A separate integration reader and five overclaim
mutations passed; the earlier Block 1, collision and M27 readers were
replayed. These are local algebra, source-link and scope checks. They do
not measure R1 attack advantage, verify quantum security, or add a fresh
engine test or hosted CI run. The exact programs and receipts remain in
ignored local capsules outside the public repository. Concrete C01 is open.

The further C01 closure attempt checks scoped local capsules:
collision/correction lemma, decoding radius, fixed-primitive audit and
honest-correction bridge, quantitative upper-bound check, alternative
recipe screen, conditional adaptive-simulation route, and primary-source
transfer screen. A separate joint-decoupling diagnostic and a narrow R2
inequality amendment have also been checked. Their seals and available
readers pass locally; the finite
checks verify identities and acquisition integrity, not resistance of R1.
The unchanged Rust workspace was also rechecked on this PC with
`scripts/engine.ps1 -Task check`: strict Clippy passed and 46 tests passed
across nonempty groups, with no failure or skip. The first direct `cargo`
invocation was unavailable on the shell PATH; the pinned project script
located its local toolchain and completed successfully. No fresh binary
qualification, hosted CI, external review or fixed-function IND-CCA proof
is credited to this cycle.

The subsequent Blocks 2–4 are locally retained, scoped decisions. Block 2
passes its calculation reader and negative controls; Block 3 passes its
independent matrix-size reader and negative controls. Block 4 passes the
Rust workspace with all features and strict Clippy (46 Rust tests in the
selected nonempty groups), compares 64 synthetic vectors byte by byte to
the independent Python reference, and executes 256 fresh exchanges plus
256 rejection checks on a retained release image. These are local
functional and research checks, not a fixed-function IND-CCA proof, a
qualified R2 engine or an external audit. Their exact receipts are under
`artifacts/retained/r1-c01-block2-001/`, `r2-block3-001/` and
`r1-c01-block4-001/`, ignored by Git and unavailable in this public tree.

## Evidence available in this repository

| Scope | Recorded checks | Availability and limit |
|---|---|---|
| Engine CI | The [workflow](../.github/workflows/ci.yml) runs the Rust workspace, Python research suite, formatting, strict Clippy and historical package checks on Windows and Ubuntu. | Check the Actions run for the commit under examination. A green run verifies those commands on its runners; it is not a cryptographic audit. |
| M10 engine qualification | The retained [M10 study](M10_MOTEUR_ET_QUALIFICATION.md) records 514 Python tests with no skips in the selected full check, Rust checks, four sanitizer harnesses, independent-reference comparisons, coverage and a bounded binary review. | The counts and limits belong to the recorded M10 images and campaigns. They do not establish complete path coverage or a universal timing or memory property. |
| M15 public replay | The [replay lot](../research/reproducibility/m15/implementation/README.md) checks 31 arithmetic obligations, an NTT certificate over 131,072 linear coefficients and 21 component tests. Its 18 packaging-tool tests are separate. | The commands and inputs are public. This is a scoped arithmetic and tooling check, not a proof of the whole KEM. |

The [README](../README.md) and the linked milestone documents retain earlier
M07–M09 engine checks and their historical qualifications. Re-running a prior
suite does not create a new independent test population.

## Later local research checks

These results are documented as bounded research summaries. Their detailed
instruments, acquisitions and internal review records are not part of the
public replay package. The rows are separate selections; their counts must
not be added into a single total.

| Research cycle | Selected record | Public reproducibility boundary |
|---|---|---|
| M11–M15 | 27 integration checks and 82 targeted tests. | The public M15 lot above releases one delimited subset; the other detailed records remain local. See the [M15 progress note](ETAT_RECHERCHE_M15.md). |
| M16 | Nine validation jobs and 113 targeted tests, with no skips in the selection. | Public [scope note](ETAT_RECHERCHE_M16.md); detailed instruments remain local. |
| M17 | 18 validation jobs and 217 targeted tests, with no skips in the selection. | Public [C01 scope note](ETAT_RECHERCHE_C01.md); detailed instruments remain local. |
| Conditional C01 consolidation | Nine validation jobs and 42 targeted tests, with no skips in the selection. | Internally reviewed conditional result only; concrete C01 remains open. |
| Subsequent scoped studies | 66 distinct targeted tests in five suites. | Local research checks and independent record replay; no new public CI suite. |
| Pre-M18 qualification | 90 distinct targeted tests across three selected suites: 11 conditional calculation checks, 27 construction-to-program checks and 52 implementation checks, with internal cross-review. | The tests examine stated research and implementation scopes. Their resistance findings are bounded by fixed budgets and do not give a general hardness claim. |
| Later reader and integrity checks | 34 reader checks, seven adapter checks, 12 comparison checks and ten integrity fixtures. | These check interpretation and preservation of prior evidence; they are not new engine or resistance experiments. |
| Pre-M18 construction and program study | One aggregate diagnostic completed 16 fresh exchanges and 16 rejection checks on the canonical binary; selected calculations and source links were independently checked. | Prior records were replayed separately and are not credited as fresh acquisitions. This is a functional and conditional research result, not a concrete security proof. |
| M18 scoped PC qualification | New Windows API/reference check: 16 comparisons and 32 regression decisions. Windows and Ubuntu release diagnostics: 16 fresh exchanges and 16 rejection checks each. Rust workspace tests, formatting and strict Clippy passed on both systems. Each OS produced 30,000 benchmark observations; four fresh ASan campaigns met 120 seconds CPU each. | Local retained package and internal cross-review. Ubuntu repeat builds matched byte for byte; Windows repeat builds failed raw equality; observed differences were confined to examined PE header fields. LLVM line coverage is per harness, with branch coverage not acquired. No global timing, erasure, security, or external audit claim. |
| M19 scoped follow-up | After one Windows GNU configuration-line change, two fresh CLI and bench builds match as raw files on the same host. Both CLI images pass 16 fresh exchanges and 16 rejection checks; one bench image emits 30,000 structurally checked rows. Rust workspace tests, formatting and strict Clippy pass. Four Linux LLVM-instrumented harnesses have authentic, nonzero branch denominators linked to retained images and corpus. | Local retained evidence and internal cross-review. Branch coverage is partial and applies to the instrumented images only. Same-host reproducibility is not a cross-host result. No new hosted CI, public replay package, external audit, global timing, erasure or concrete-security claim. |
| M20 source-path check | Two fresh Windows GNU builds from separately extracted, identical source archives yield byte-identical CLI and bench images on the same PC. Both CLI images pass 16 fresh exchanges and 16 rejection checks. | `M20_COMPLETE_SCOPED_DEFAULT` is same-host source-path invariance, not cross-host reproducibility. Images, commands and review are retained locally. |
| M21 unified branch measurement | One Linux LLVM-instrumented image runs 176 synthetic inputs across four API families. In the active R1 files, 18 of 24 LLVM-mapped branch outcomes are exercised; historical P0 is separate. | `M21_COMPLETE_SCOPED` applies only to this image, toolchain and corpus. These counts are not added to M19's separate-image counts and do not describe all semantic paths or release images. |
| M22 exact PC-image link | The retained Windows PE and Linux x86-64 ELF have matching R1 profiles and each passes 16 fresh exchanges and 16 rejection checks. Bounded binary witnesses and their source links are checked on those exact images. | `M22_COMPLETE_SCOPED` is not whole-program source-to-binary equivalence, global constant time or erasure. No new image was built. |
| M23 emulated Linux AArch64 port | A release AArch64 ELF is built with the pinned cross-build chain. Under QEMU user emulation, its R1 profile matches the PC witness and it passes 16 fresh exchanges and 16 rejection checks. | `M23_COMPLETE_SCOPED` applies to the retained Linux image under emulation. It does not qualify Android, a real SoC, physical timing or erasure. |
| M24 fixed-game proof cut | A bounded proof-route certificate, finite controls, an independent reader and internal second reading identify two missing fixed-function transitions. | Local sealed capsule. It is neither a break nor a complete R1 proof. |
| M25 seeded PKE and common-model estimates | Four budgeted native-dimension estimates completed after a retained failed tool attempt, with separate candidate recomposition and a seeded-distribution certificate. | Local sealed capsule. The costs use a scalar IID surrogate and extrapolate for R1; they are not actual seeded-KEM advantage bounds. |
| M26 primitive-role hop | A conditional rejection-role game hop, six-role source map, independent readers and mutation checks passed. | Local sealed capsule. No numerical fixed-primitive bound, challenge bridge or public adaptive simulator is established. |
| M27 fixed-game composition | The selected M24–M26 seals, source commit and symbolic terms were checked; an independent reader verified 4,913 rational cases and rejected five overclaim mutations. | Local sealed capsule. All numerical terms remain open; no fixed-function IND-CCA bound is obtained. |
| M28 construction decision | The published primary source and a distinct classical PKE-to-KEM wrapper were internally reviewed; a separate R2 construction card has finite controls and 11 open obligations. | Local sealed construction card and decision. No R2 engine, quantum theorem, R1 proof or external audit is credited. |
| Post-M28 C01 Block 1 | Independent readers, finite algebra controls, primary-source transfer review and internal mathematical cross-reviews checked selected proof-route obstacles. | Local retained capsule. The checks validate scoped identities, not R1 resistance, a fixed-function IND-CCA bound or an external audit. |
| Post-M28 Block 2 | R1 format sizes, a model-bound correction calculation and selected common-convention estimator outputs were recomputed; an independent reader and seven negative controls passed. | Local sealed capsule; parameter freeze held. These numbers do not bound the concrete fixed-function KEM or establish superiority over ML-KEM-1024. |
| Post-M28 Block 3 | Primary-source ledger, dimension-only matrix cost screen, independent reader, six negative controls and two internal cross-reviews passed. | Local sealed capsule; no selected R2 parameters or R2 code. The cost scenarios are not theorem-admissible parameter sets. |
| Post-M28 Block 4 | Strict Rust workspace check (46 tests), 64 synthetic byte comparisons to the independent Python reference, 256 fresh exchanges and 256 rejection checks on exact locally retained release images. | Local retained capsule and preparatory external-review mandate. Functional results only; no completed R2 engine, external review or complete binary qualification. |

The earlier decision and review steps checked consistency of their selected
argument and resource accounting. M18–M23 add local engine checks and
instrumented measurements, but no new hosted CI run or external audit. M19
changed only the Windows GNU build configuration; M20–M23 made no further
tracked implementation change. The cryptographic engine, parameters and wire
formats remain unchanged. The M20–M28 capsules and the post-M28 Blocks 1–4
capsules are ignored by Git and are not
replayable from this public repository alone. R1 remains experimental and
concrete C01 remains open.

## Reading the results

- **Publicly replayable** means the repository contains the programs and
  inputs needed for the stated check, such as the M15 lot and the hosted
  workflow. Confirm success at the exact commit being cited.
- **Local and internally reviewed** means a result has a retained local
  record but its full acquisition and verification package is not published.
  It should not be described as independently reproduced by a GitHub reader.
- A test count measures the selected checks, not the range of all possible
  inputs or adversaries. Replays, cross-reviews and repeated suites are not
  added again as new tests.
- Resistance evaluations are reported here only by their scope, budgeted
  status and inference limits. They do not establish a general hardness
  bound. R1 is experimental and concrete C01 remains open.
