# Current research scope and the conditional C01 argument

Public scope statement, updated 19 November 2026. **MLKEM-1536 Core** develops the
working experimental profile `KEM1536-DEV-Q7681-R1`, with six polynomials
of 256 coefficients. The number 1536 counts coefficients; it is not a
security-bit rating or a standardized ML-KEM parameter set.

**A conditional IND-CCA argument for the R1 construction has been
consolidated and internally reviewed in the declared QROM/RC1 model.
The complete concrete qualification of R1 remains open. R1 is experimental,
its final cryptographic freeze is deferred, and it is not production-qualified.**

## Current bounded research and verification

Four further work packages examine the unchanged R1 construction. The
construction decision, conditional whole-KEM argument, corresponding resource
calculation and source-to-program link have internally cross-checked deliverables
within their stated scopes. The conditional argument and functional checks do
not establish the security of the concrete fixed-function KEM. **Concrete C01
remains open.**

The latest qualification selected 90 distinct local targeted tests in three
suites. A later diagnostic on the canonical binary completed 16 fresh exchanges
and 16 rejection checks. Other recent checks replayed retained records or
validated research tools; these are not additional new engine tests. The
[verification and test record](TESTS_AND_EVIDENCE.md) separates these local
results from the public CI and M15 replay lot. Resistance studies retain their
budget and inference limits without disclosing methods in this overview.

No engine, parameter, format or canonical-binary change, new hosted CI result,
external audit, certification or production qualification is credited here.
Detailed recent records remain private.

## Earlier bounded studies and interface work

The recent private cycle strengthens the examination process around the
central computational premise. It executes a complete public-input decision
pipeline, keeps its acquisition and resource records, and reconstructs the
retained data with separately implemented local readers. Calibration cases,
native-parameter observations and their budget limits are reported within
their own populations and models. A finite experiment, an observed cost or
an absence of success is not a universal advantage bound.

The ideal-model work adds two resource-parametric results: a coherent
transport for a bounded ideal primitive interface, and a corollary covering
pre-key processing whose entire preparation and retained state are charged.
They have explicit interface, independence, circuit and resource premises.
The earlier C01 consolidation below retains its originally declared scope;
these extensions do not silently enlarge its recorded numerical budgets.
They also do not identify fixed SHA3/SHAKE functions with ideal random
oracles, qualify arbitrary advice or change the concrete C01 status.

The selected local component suites passed **66 distinct targeted tests across
five suites**. Internal replays are not counted again as new tests or statistical
acquisitions. The detailed instruments, raw records and review files remain
private; this page publishes a scope summary rather than their reproduction
package. The separate public M15 arithmetic/NTT lot remains available.

R1 stays experimental and is not production-qualified. M10's Rust sources,
parameters, wire formats and canonical binary are unchanged by this cycle.
No new performance gain, hosted CI result, external audit, certification or
global superiority over ML-KEM-1024 is claimed.

## Earlier consolidation — what advanced after M16

M17 extends the earlier research through ten scoped workstreams, followed
by a targeted consolidation of the central C01 argument. Their results
address different questions and are kept within their declared models.

| Area | Scoped progress | Assurance boundary |
|---|---|---|
| Resistance and quantitative premises | Decisions using the public matrix, matrix-dependent probe selection and explicit quantitative hypothesis filters | Restricted decision families and reduced-model checks do not establish a full-adversary hardness bound for the concrete KEM |
| Primitive family, populations and reduction resources | Joint primitive-role modeling, conditional population arguments and expanded resource accounting | A construction cost or a conditional transport statement does not establish a small concrete primitive gap |
| Functional conformity | Execution of selected actual Rust function bodies through a restricted source interpreter, with import, error and rejection controls | The interpreter and PKE/primitive contracts remain trust dependencies; the entire Rust/LLVM program is not formally verified |
| Recorded PC images | Dependency checks for selected branches and memory addresses, plus stronger bounded frame-effect analysis | The results retain their function, path, image and model limits; they do not establish physical constant time or global erasure |
| C01 consolidation | One statement connects the exact construction, reduction, correctness, implicit rejection and resource accounting | The completed conditional implication does not prove the numerical hardness premise or the fixed SHA3/SHAKE instantiation |

The M17 selection passed **18 local validation jobs and 217 targeted tests**.
The targeted C01 selection passed **nine jobs and 42 targeted tests**. No
tests were skipped in either selection. Repeated suites during internal
cross-review are not added again to these counts. These are records of
scoped local research, not a global security level or an external audit.

## The conditional C01 result

The targeted work brings the existing reduction arguments and their
conditions together in one dossier. Internal mathematical review identified
no additional missing bridge lemma within the stated model. The two native
MLWE premises can be covered by a single resource-indexed hypothesis when
the enlarged budget includes the adapter's complete cost. A retained
quantitative working checkpoint is satisfied under that hypothesis.

The earlier consolidated theorem has the following originally declared scope:

- a single honestly generated key and a single-user IND-CCA game;
- classical adaptive decapsulation requests excluding the exact challenge;
- quantum access to the declared typed, framed-role oracle interface,
  preserving complete responses and consistent XOF prefixes;
- the stated RC1 circuit and resource conventions, without oracle-correlated
  preprocessing before matrix setup;
- no free equivalence with unrestricted raw Keccak or permutation-oracle
  access across roles.

The hardness hypothesis is an explicit computational premise about an
underlying MLWE problem, rather than an assumption that the KEM is already
secure. The conditional theorem does not require an unconditional proof of
MLWE hardness. Its validity also does not demonstrate the numerical truth
of that premise. Available attack estimates and finite filters retain their
declared limitations and do not become universal advantage upper bounds.

## Why the concrete C01 qualification remains open

The original C01 criterion sought an IND-CCA dossier explaining its
hypotheses and transformation conditions, including the relevant quantum
models. That explanatory conditional dossier is now constituted and
internally reviewed for the announced scope.

Earlier reports also used C01 for the stronger ambition of qualifying the
fully concrete R1 KEM. That ambition remains open. In particular, the
quantitative confidence in the native MLWE premise and the interpretation
with fixed SHA3/SHAKE functions are not established by the conditional
QROM theorem. No small whole-KEM event gap is assumed merely to declare
this transfer complete. The retained working checkpoint is not a claim of
a global security-bit rating or a matched global advantage over ML-KEM-1024.

This distinction does not rewrite historical results or remove their
unresolved questions. Constant time, erasure, compiler conformity,
external review and deployment are separate assurance subjects; they
are not substitutes for a mathematical argument and are not established
by the conditional theorem.

## Delivered engine, public evidence and CI

M10 remains the delivered executable reference. M17, the targeted C01 work
and the latest scoped studies preserve the engine's Rust sources, parameters, wire formats and
canonical binary. No new performance, fuzzing, platform qualification or
production result is credited to this research summary.

The detailed M17 and C01 statements, programs, acquisitions and internal
review records remain private. This page publishes their scope and status;
it is not a public replay package for those studies.

The separate [M15 Windows arithmetic/NTT replay lot](../research/reproducibility/m15/implementation/README.md)
remains public. It supplies 31 source-linked arithmetic SMT obligations,
an NTT certificate checking 131,072 linear coefficients and 21 component
tests, plus 18 distinct packaging-tool tests. It does not reproduce the
entire later security argument.

The recorded [public CI run 44223949348](https://github.com/MajidNIMAR/mlkem-1536-core/actions/runs/44223949348)
passed its three jobs at commit
[`53d501de`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/53d501de898ec6ba024cc05a3f7373563c6a2ef4):
the Windows/Ubuntu engine checks and the dedicated M15 Windows replay job.
The local M17 and C01 test counts are separate from that hosted execution.
A documentation publication does not acquire a new CI result; consult
the workflow status and tested inputs of the revision being examined.

See [SECURITY.md](../SECURITY.md), the [research report](RAPPORT_RECHERCHE.md),
the [roadmap](FEUILLE_DE_ROUTE_MOTEUR.md), the [M16 scope note](ETAT_RECHERCHE_M16.md)
and the [M15 progress note](ETAT_RECHERCHE_M15.md).
