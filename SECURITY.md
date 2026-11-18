# Security and research status

MLKEM-1536 Core develops the experimental profile `KEM1536-DEV-Q7681-R1`.
R1 is a specified and implemented profile intended for research,
reproducibility and independent review. Its suitability for production and
standardization remains to be established through further cryptanalysis
and review. No NIST certification,
formal constant-time guarantee or production-security claim is made.

## Current assurance boundary

Research has advanced through M15. It adds internally reviewed quantitative
and correctness arguments, constructive fixed-primitive resource accounting
and source-linked arithmetic/NTT certificates. A sufficient margin is
available for a declared working checkpoint under explicit assumptions.
Those results do not establish the concrete fixed-primitive transfers,
the required quantitative hardness bounds, full-KEM formal verification
or a global security rating. **C01 remains open and R1 is not authorized
for production in MAJAX Messenger.** External review remains deferred.

The [M15 progress note](docs/ETAT_RECHERCHE_M15.md) distinguishes the scoped
internal results from published, independently replayable evidence. The
[public Windows arithmetic/NTT lot](research/reproducibility/m15/implementation/README.md)
supplies 31 source-linked SMT obligations, a certificate checking 131,072
linear coefficients and 21 component tests. Its 18 packaging-tool tests
check the surrounding installation and replay tools. A dedicated Windows
CI job runs this lot; its result must be checked at the revision under review.
The full 82-test internal M11–M15 suite and detailed artifacts from the other
workstreams remain private and are not made public by this subset.

The pinned solver, restricted source translator and checked NTT template
mapping remain trust dependencies. The stored Z3 proof objects are not
checked by an independent proof kernel. These results do not formally
verify the whole PKE/KEM, Rust/LLVM or a final compiled image, and add no
constant-time or universal-erasure guarantee. The lot was exercised in a
fresh local clone on the same recorded Windows/CPython host; this does not
qualify every platform or a clean system installation.

The delivered engine remains M10; the following M10 measurements and image
qualifications keep their original scope and are not new M15 campaigns.

M10 is the delivered engine reference, qualified internally on the recorded
GNU x86-64 Windows/Linux PC images. It writes derived material into existing owners,
uses borrowed SHAKE finalization and keeps the local decapsulation output
owner alive through copying. The [M10 lifecycle review](docs/REVUE_CYCLE_SECRET_M10.md)
qualifies removal of the two observed normal-return stack residues. Sensitive
mask copies, ABI/register/dependency/caller copies and whole-program constant
time remain outside that bounded result. Its new four-harness sanitizer
campaign has completed with no observed defect: 8,041.14 total CPU seconds,
of which 7,408.48 are conservative post-INIT CPU seconds. Each harness
exceeds its own 1,800-second budget, without historical, compilation or
initialization credit. Separate LLVM objects cover 492/669 mapped core
lines and 18/38 branches, retaining zero-count mappings. All 4,263 distinct
deterministic corpus-derived requests match the independent Python reference,
including 641 accepted-private-key decapsulation probes. The 1,887 fresh
operations encoded in the corpus are not recreated by the oracle. OS-entropy
failure paths, the diagnostic wrapper and other unmapped or unvisited paths
remain outside this coverage result; its [classification](docs/M10_MOTEUR_ET_QUALIFICATION.md)
also distinguishes source functions from generic instantiations. These
results do not establish a global security rating, constant time or complete
secret erasure. The sealed [evidence capsule](results/engine/m10-001/) passes
its data-only replay; the file-only mirror correction is retained separately.
The [complete local Windows check](results/engine/m10-verification-001/)
passes with all 514 Python tests executed, none skipped, plus Rust tests,
formatting, strict Clippy and the required evidence replays. The 313 recorded
source/control inputs are unchanged before and after. This check and its
seal add no fuzzing, cryptographic, constant-time or erasure guarantee.
[Fresh hosted CI 43893183494](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43893183494)
passes on Windows and Ubuntu at public commit `82c63441d1885c1e348884a2d9442ee48b6eaf03`,
with 514 Python tests executed per OS, none skipped, and native checks of
the original M10 CLI/default consumer. The [publication receipt](results/publication/r6-m10-001/)
links all 37 qualified compilation inputs to that tested source. Its [frozen
reader](results/publication/r6-m10-controls-001/) preserves 50 byte-identical
tested Git blobs, passes four pure tests and replays the receipt offline;
this is a receipt check, not a new engine or campaign execution. The original
M10 Windows CLI is [promoted locally](results/engine/m10-canonical-002/), with
profile, 16 exchanges, 16 rejections and five research-command refusals
checked after copying. The first failed hosted attempt and test-only fix,
and the failed initial promotion with M09 rollback, remain documented in
the [M10 study](docs/M10_MOTEUR_ET_QUALIFICATION.md).

The [M10 security argument](docs/SECURITE_M10.md) supplies conditional matrix,
noise and classical FO compositions with explicit resources. The [parameter
decision](docs/DECISION_PARAMETRES_M10.md) retains R1 for development after
forty new finite-sample estimates. C01, concrete advantage/resource calibration,
the complete quantum resource map and fixed SHA3/SHAKE assumptions remain open.
External cryptographic review remains deferred by the project owner. M09
and earlier milestones remain immutable historical evidence.

M09 is the previous delivered milestone, qualified internally. It preserves R1 bytes,
uses fixed-size borrowed noise roles and tests operation-level failures
after every partial entropy prefix. Decapsulation writes its recovered
message into its final zeroizing owner. A scalar public-twiddle NTT improves
the recorded PC KEM medians with no increase in observed KEM stack maxima
or requested allocation counts. The [M09 study](docs/M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md)
gives the finite scope and costs. The [complete local check](results/engine/m09-verification-001/)
is closed with 438 Python tests plus Rust/formatting/Clippy and evidence
replays. The [storage-reader follow-up](results/engine/m09-reader-review-001/)
passes the 439-test Python suite without changing the 37 qualified
compilation inputs. [Fresh hosted run 43806407492](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43806407492)
passes on Windows and Ubuntu at `fdd323dcf840b0d12fd43a446acffbd0cce83d7b`,
with all 439 Python tests executed per OS and none skipped. The
[publication receipt](results/publication/r6-m09-001/) binds the exact
source maps, compiled inputs and original CLI/consumer images. The original
Windows CLI was [promoted locally and checked after copying](results/engine/m09-canonical-001/).
This closure grants no new cryptographic, constant-time or global-erasure assurance.

The first M09 vectorized candidate was rejected: a Windows ABI save copied
16 bytes derived from e2+Encode(m) outside its wiping owner. The four final
scalar images have a separate [targeted review](docs/REVUE_CYCLE_SECRET_M09.md)
showing removal of this mechanism and normal-return message-owner wipes.
Neither this review nor the public-data black_box hint proves whole-program
constant time or erasure of every ABI/register/PKE/caller copy.

M08 is the immutable previous delivered engineering milestone. Functional agreement,
format compatibility, finite malformed-input tests, sanitizer fuzzing and
fresh Windows/Ubuntu integration are documented. Its [import review](docs/M08_IMPORTS_ET_VALIDATION.md)
qualifies removal of the targeted decoded-coefficient stack copies on the
examined invalid-secret paths of the default-feature API consumers.
This finding is specific to the preserved images and paths.

The M10 four-image review and the historical M08/M09 reviews concern their
recorded GNU x86-64 Windows and Linux/WSL images. Android/ARM is not qualified by those results. Arithmetic instruction timing
and secret-copy behavior require the actual target ABI, compiler/link flags
and CPU to be examined. The [target and contract review](docs/REVUE_CRITIQUE_M08_CIBLES_ET_CONTRATS.md)
records this boundary, the already specified noise domains and the combined
invalid-secret/invalid-hash test that is already covered.

The [M09 classical ROM hybrid](docs/SECURITE_M09.md) bounds one seeded-noise
replacement term while retaining a public seeded matrix. It is not a full
PKE proof, a QROM transfer or a guarantee for concrete SHAKE. The
[external review dossier](docs/REVUE_EXTERNE_M09.md) is prepared; no third
party has been contacted or credited as an auditor.

The mathematical support includes exact correctness certificates linked to
source and conditional ROM/QROM security arguments. **C01, the complete
concrete security argument for R1, remains open.** The published tests and
lattice-attack estimates do not assign a certified global security-bit
rating. The number 1536 is the coefficient count. Whole-program constant
time, universal erasure and independent external cryptographic audit or
certification are not established by this evidence.

## Historical findings and their qualified corrections

Known findings are recorded in
[the historical M03 review](docs/M03_FUZZ_BINAIRES_BENCHMARKS.md).
M03-A01 concerns a 512-byte temporary in the older multiplication binary.
The [M04 review](docs/M04_MOTEUR_NTT_ET_CONTROLES.md) records its correction
in the two delivered M04 binaries and the limits of that check. This does
not establish universal erasure of secret copies or constant-time execution.
Long fuzzing runs and their validation are reported separately from short tests.

The [M05 security analysis](docs/SECURITE_CONCRETE_R1_M05.md) provides
conditional ROM/QROM bounds with explicit query budgets and unknown
seeded-PKE and rejection-PRF advantages. The concrete Keccak-based KEM's
complete security argument remains open. The
[experimental comparison](docs/COMPARAISON_EXPERIMENTALE_M05.md) reports
declared lattice-estimator proxies, not global KEM security ratings.

The [M06 rejection analysis](docs/REJET_IMPLICITE_R1_M06.md) bounds the
ideal secret-prefix rejection function in the ROM and QROM, for a uniform
independent 256-bit rejection key and classical indexed-function access.
The quantum bound is conservative and does not certify the illustrative
M05 rejection allocation. This is a limitation of the bound, not a demonstrated
attack. It does not establish concrete SHAKE security. The M06 NTT
accumulation refactor has its [own review](docs/M06_REVUE_INDEPENDANTE.md);
historical binary-wipe checks and fuzz durations do not transfer automatically.

The [M07 implementation study](docs/M07_MEMOIRE_ET_VALIDATION.md) preserves
R1 formats while streaming coefficient rows through reused owners. Its
memory metric is instrumented touched-stack depth, not a universal stack
bound. A bounded review of the Windows/Linux research binaries identified
coefficient-bit spills outside zeroizing owners in private-key validation.
The delivered Linux CLI does not retain those import functions; their machine
form is outside this check's scope. On the examined
invalid-secret import paths, some spilled bits are not explicitly erased
before return. The corresponding M06 reference binaries already have this
limitation; M07 does not establish complete erasure. This observation does
not demonstrate a remote or practical leak. Callers requiring erasure of
every compiler temporary, register and error path do not have that guarantee.

The [M08 import study](docs/M08_IMPORTS_ET_VALIDATION.md) replaces the
coefficient reconstruction used for key validation with a direct encoding
scan. Its paired default-feature API consumers reproduce the targeted M07
coefficient-bit stack copies in the reference images and no longer produce
those copies on the examined invalid-secret return paths in the candidate
images. This bounded result does not establish erasure of caller-owned input,
preexisting ABI save areas or registers, and does not extend to all PKE paths or compiler
configurations. CLI inventories are separate from this consumer import review.
Extended campaign and delivery status are recorded in the study.

An accepted private-key encoding does not certify honest key generation,
the embedded key relation or the rejection key's entropy. The
[M08 side-information analysis](docs/REJET_ET_INFORMATION_LATERALE_M08.md)
bounds ideal rejection using a supplied classical conditional guessing
probability and explicit ideal-view independence assumptions. It recovers
the M06 uniform-key bound, whose quantum loss remains conservative. It
does not cover quantum side information, establish concrete SHAKE security
or supply a complete IND-CCA proof for R1.

For a suspected vulnerability, use this repository's **Security → Report a
vulnerability** private reporting facility. Include the commit, platform,
toolchain and a minimal reproduction with synthetic data. Do not include
real keys, credentials or application data. General build problems and
research questions can be raised as public issues.

This research repository has no access to Majax Messenger production
systems. Reports about that service belong to its own disclosure process.
