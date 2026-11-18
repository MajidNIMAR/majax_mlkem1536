# Research progress through M16

Public scope statement, 18 November 2026. **MLKEM-1536 Core** develops
`KEM1536-DEV-Q7681-R1`, an experimental module-lattice KEM with six
polynomials of 256 coefficients. The number 1536 counts coefficients;
it is not a security-bit rating or a standardized ML-KEM parameter set.

**R1 remains experimental and C01, its complete concrete security argument,
remains open. The final cryptographic profile freeze is deferred.**

## Engine reference and scope of this update

M10 remains the delivered executable reference. M16 changes neither the
engine's Rust sources, parameters and wire formats nor its canonical binary.
The [M10 engineering study](M10_MOTEUR_ET_QUALIFICATION.md) retains its
recorded targets, measurements and image qualification. No new benchmark,
fuzzing campaign, deployment or external audit is credited to this update.

This page publishes a summary of the local M16 research cycle. Its detailed
instruments, acquisitions, raw results and internal review records remain
private. This summary is not a public replay bundle for those studies.

## Five workstreams and their assurance boundaries

| Workstream | New scoped result | Boundary that remains |
|---|---|---|
| PKE resistance | An exact marginal-law calibration and decision tests for a restricted family, applied to R1 and the reference profile | The declared decision class does not cover all adversaries observing the complete public transcript or choosing matrix-dependent tests; it supplies no universal MLWE advantage bound |
| Seeds, fixed primitives and correctness | Constructive resource maps, source-linked correction constructions and explicit population conditions | Statistical confidence is not a cryptographically rare failure bound or adversarial advantage; information access and preparation require their own justification |
| Program conformity | Additional contracts for encoding, canonicality, sampling, messages and conditional PKE/FO behavior, with distinct control implementations | The restricted interpreter, source templates and dependency contracts remain trusted; the entire Rust/LLVM program and KEM are not formally verified |
| Compiled PC images | 40 direct-frame wipe-path obligations on four recorded CLI/consumer Windows/Linux images | The checks concern selected normal intraprocedural paths and modeled writes; callee/alias memory effects, exceptional paths, registers, ABI saves and caller copies remain outside that guarantee |
| Composition and decision | Context-aware admission checks and a combined candidate decision | A result cannot be promoted across populations, statistics, conditions, adversary classes or resources without a justified adapter; unresolved premises keep C01 open |

The selected results were replayed in **nine local validation jobs**, with
**113 targeted tests passed and none skipped**. Internal cross-reviews
examined the selected versions, their controls and their conditions of use.
Those reviews are distinct from an external cryptographic evaluation.

The decision is to **retain R1 for research and defer its final freeze**.
The acquired results do not establish a need to change the construction or
engine. That decision is not a certificate of security.

## Public reproducibility and CI

The [M15 Windows replay lot](../research/reproducibility/m15/implementation/README.md)
is already public. It supplies 31 source-linked arithmetic SMT obligations,
an algebraic NTT certificate checking 131,072 linear coefficients, 21 component
tests and 18 separate packaging-tool tests. Its manifest, pinned solver
installation, verifier and instructions remain available.

The recorded [CI run 44223949348](https://github.com/MajidNIMAR/mlkem-1536-core/actions/runs/44223949348)
examines public commit
[`53d501de`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/53d501de898ec6ba024cc05a3f7373563c6a2ef4).
Its three jobs passed: 514 public Python tests per OS without skips and
original M10 native checks under Windows/Ubuntu, plus the dedicated M15
Windows replay job. That job performed a new solver installation and a second
offline replay, preserving its receipts and logs.

The **113 local M16 tests are separate** from that public CI, the M15 replay
tests and the broader private M11–M15 studies. Publishing this summary does
not imply that the detailed M16 programs or their tests are publicly supplied.
For the exact revision being examined, consult its workflow status and the
scope of the recorded validation; a documentation update does not acquire a
new execution result by changing the presentation.

## Remaining security obligations

The full concrete R1 argument still requires qualification of the two native
MLWE-game assumptions for their declared adversary/resource classes, transfer
to the fixed primitive family, the relevant correctness and adaptive
populations, the complete quantum-reduction resource map and the final
IND-CCA composition.

No global superiority over ML-KEM-1024, certified security-bit rating,
whole-program constant time or universal erasure is claimed. R1 remains
unauthorized for production in MAJAX Messenger. See [SECURITY.md](../SECURITY.md),
the [research report](RAPPORT_RECHERCHE.md), the [roadmap](FEUILLE_DE_ROUTE_MOTEUR.md)
and the [M15 scope note](ETAT_RECHERCHE_M15.md).
