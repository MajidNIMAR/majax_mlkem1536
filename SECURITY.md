# Security and research status

MAJAX R6 develops the experimental profile `KEM1536-DEV-Q7681-R1`.
It is intended for research, reproducibility and independent review.
Parameter selection and cryptanalysis remain open. No NIST certification,
formal constant-time guarantee or production-security claim is made.

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
