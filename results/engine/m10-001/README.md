# M10 — scoped engine qualification evidence

This capsule preserves new acquisitions for source capture
`67084be5ab1cde058661104b16e738138db7993dec001ac39625feb830b2810d`
and the unchanged experimental profile `KEM1536-DEV-Q7681-R1`.
It links the separate M10 security and parameter-study capsules. It does not
declare C01 closed, a final cryptographic parameter selection, a global
constant-time/erasure proof or an external audit.

Nine logical groups retain the fresh M09-source baseline builds, selected
003 qualification, original CLI/API binary inventories, bounded secret
review, prolonged fuzzing plus separate coverage/oracle replay, distribution,
reader/controller snapshots, and the two rejected M10 iterations. Baseline
builds and measurements are new; historical campaign time receives no credit.

`provenance.json` records every member and logical archive digest.
`archive-parts.json` describes byte-preserving parts of the rejected archive.
The reused `m09-byte-identical-parts-v1` name is a storage format; the bytes
and acquisitions are M10. No physical part exceeds 90 MiB. The reader checks
the parts even if a complete archive is also present.

```powershell
.tools/research-venv/Scripts/python.exe -B research/archive_m10.py verify
```

This command reads evidence, recomputes summaries and performs Python oracle
checks; it does not execute an engine, compiler or new fuzz/coverage campaign.
Native package checks use `research/smoke_m10_package.py` separately.

The first global replay exposed an adapter error: a file-only archive does
not recreate the four empty `failures` directories required by the campaign
reader. The [reader adaptation](../m10-reader-adapter-001/) preserves the
original failure, before/after sources and new data-only replay. It restores
those directories in the temporary mirror without removing archived files.
Original controller snapshots, campaign data and logical archives are unchanged.

The `distribution.tar.gz` group contains the original Windows ZIP, Linux
tarball and source tarball, licenses, dependency inventories, repeat-build
comparisons and internal acceptance receipt. The `qualification.tar.gz`
group contains source/build captures and raw regression/measurement streams.
Documents inside captures retain their acquisition-time bytes; the maintained
[M10 study](../../../docs/M10_MOTEUR_ET_QUALIFICATION.md) and
[research report](../../../docs/RAPPORT_RECHERCHE.md) describe later closure.

The long campaign records 33,197,231 post-INIT executions with repetitions,
7,408.48 conservative post-INIT CPU seconds and four separate reached budgets.
Separate LLVM objects retain 492/669 mapped core lines and 18/38 branches;
all zero-count mappings remain present. The independent oracle replay matches
4,263 deterministic requests. These finite results have their stated scope.
