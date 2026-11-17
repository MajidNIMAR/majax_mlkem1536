# Research progress through M15

Public scope statement, 17 November 2026. **MLKEM-1536 Core** develops
`KEM1536-DEV-Q7681-R1`, an experimental module-lattice KEM with six
polynomials of 256 coefficients. The number 1536 is a coefficient count,
not a security-bit rating or a standardized ML-KEM parameter set.

## Delivered engine and subsequent research

M10 remains the delivered executable reference. Its source, parameters,
formats and canonical binary are unchanged by the subsequent research.
The [M10 engineering study](M10_MOTEUR_ET_QUALIFICATION.md) and its public
evidence retain their recorded Windows/Linux targets, measurements and
qualified images. No new benchmark, sanitizer campaign or target
qualification is credited to M11–M15.

The later cycles develop security composition, resource accounting,
quantitative assumptions, correctness populations and implementation
conformity. M14 produces a sufficient conditional margin at a declared
working checkpoint. M15 adds the following scoped results.

| Workstream | New internal result | Assurance boundary |
|---|---|---|
| Cryptanalysis | 16 new analysis jobs and 28,484 cost evaluations across the candidate and reference profiles; additional arguments for structured distributions | Heuristic cost models and partial resource filters do not establish a universal advantage upper bound |
| Fixed primitives | Executable constructions and explicit accounting for SHA3/SHAKE computations in the examined games | Concrete transfer gaps and the required populations remain unestablished |
| Correctness | Conditional per-key certificates and stronger treatment of message selection and key populations | The assumptions on the actual encryption randomness must still be justified |
| Reference comparison | 32 matched profile contexts, with distributions, cost models and success conventions retained | Some success/bias comparisons and the full concrete CCA comparison remain unqualified |
| Program conformity | 31 universal arithmetic obligations checked by SMT and an algebraic NTT certificate | The restricted translator, checked source templates and solver are declared trust dependencies; the whole KEM and compiler are not formally verified |

The final local integration passes 27 checks and 82 targeted tests. Cross-reviews
by other internal reviewers examine the selected versions and their scope.
These are internal research checks, distinct from the public engine CI.
They are not an external cryptographic audit or an institutional validation.

## Public and private evidence

The public repository supplies the engine, specification, reference
implementation and the published historical evidence linked from the
[README](../README.md). Its CI checks those public sources and artifacts.

The detailed M11–M15 research programs, acquisitions and reviews are retained
privately. This update publishes their scope and research status, **not a
public replay bundle for those studies**. Readers cannot independently
reproduce those new internal studies solely from this public snapshot.
Internal test counts must not be presented as hosted-CI test counts.

## Remaining security boundary

**C01, the complete concrete security argument for R1, remains open.** The
quantitative hardness assumptions, fixed-primitive transfers, concrete
correctness populations and final CCA comparison are not all established.
The conditional working margin does not resolve those obligations by itself.

No global superiority over ML-KEM-1024, certified security-bit rating,
whole-program constant time, universal secret erasure or external audit is
claimed. R1 is retained for research and is not authorized for production
in MAJAX Messenger. See [SECURITY.md](../SECURITY.md), the
[research report](RAPPORT_RECHERCHE.md) and the [roadmap](FEUILLE_DE_ROUTE_MOTEUR.md).
