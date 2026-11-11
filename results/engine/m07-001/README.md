# MAJAX R6 — M07 evidence

Four byte-preserving stage archives retain all raw files, binaries, sources, logs and empty directories.
The provenance records every file's SHA-256 and size. No build cache is included.

Run `python research/archive_m07.py verify --output results/engine/m07-001` from the checkout.
This unpacks into a temporary directory and replays data checks only: no compiler, executable,
objdump, benchmark or fuzz campaign is run. The controls archive preserves the Python import closure.

`delivery.tar.gz` contains the Windows ZIP and Linux tar.gz packages plus compact compilable
source and licenses; its `result.json` lists the exact archive names and SHA-256 values.
The packages carry the original reviewed delivered binaries, not the comparison rebuilds.
`binary.tar.gz` includes OBSERVATIONS.md and the preexisting Windows invalid-key spill limit.
`measurements.tar.gz` contains baseline, preregistered budgets, candidate, raw memory/latency,
full regression receipt and finite timing diagnostic. `fuzz.tar.gz` is a new finite M07
ASan/std-rebuilt campaign, with no LLVM source coverage or independent oracle replay claimed.

See docs/M07_MEMOIRE_ET_VALIDATION.md for results and limits. These archives do not establish
global cryptographic security, complete erasure or constant time. Historical absolute paths
are provenance strings and are not dereferenced during verification.
