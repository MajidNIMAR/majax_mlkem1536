# Security and research status

This repository develops the experimental profile `KEM1536-DEV-Q7681-R1`.
It is intended for research, reproducibility and independent review.
Parameter selection and cryptanalysis remain open. No NIST certification,
formal constant-time guarantee or production-security claim is made.

Known findings are recorded in
[the M03 review](docs/M03_FUZZ_BINAIRES_BENCHMARKS.md), including M03-A01:
a 512-byte stack temporary without an explicit wipe in the reviewed Windows
multiplication binary. This observation has not demonstrated a protocol leak.
Long fuzzing runs and their validation are reported separately from short tests.

For a suspected vulnerability, use this repository's **Security → Report a
vulnerability** private reporting facility. Include the commit, platform,
toolchain and a minimal reproduction with synthetic data. Do not include
real keys, credentials or application data. General build problems and
research questions can be raised as public issues.

This research repository has no access to Majax Messenger production
systems. Reports about that service belong to its own disclosure process.
