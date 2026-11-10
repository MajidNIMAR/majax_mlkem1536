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

For a suspected vulnerability, use this repository's **Security → Report a
vulnerability** private reporting facility. Include the commit, platform,
toolchain and a minimal reproduction with synthetic data. Do not include
real keys, credentials or application data. General build problems and
research questions can be raised as public issues.

This research repository has no access to Majax Messenger production
systems. Reports about that service belong to its own disclosure process.
