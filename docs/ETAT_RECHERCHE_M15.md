# Historical M15 research and public evidence

Public scope statement, 18 November 2026. **MLKEM-1536 Core** develops
`KEM1536-DEV-Q7681-R1`, an experimental module-lattice KEM with six
polynomials of 256 coefficients. The number 1536 is a coefficient count,
not a security-bit rating or a standardized ML-KEM parameter set.
This note records the M15 stage and its frozen public replay lot. Later
numbered work reached M23 for engine qualification and M28 for C01 research;
the latest C01 studies are unnumbered. See the [current status](ETAT_RECHERCHE_C01.md).

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

The first [M15 Windows replay lot](../research/reproducibility/m15/implementation/README.md)
adds a bounded, source-linked arithmetic/NTT subset:

| Public check | Supplied inputs and expected result |
|---|---|
| Arithmetic | 31 SMT-LIB queries, stored Z3 proof objects, acquisition receipt and restricted translator; reconstruct the source-derived obligations, compare the captured assertions and re-establish 31 UNSAT results |
| NTT algebra | Selected certificate and reconstruction instrument; check 131,072 linear coefficients and the declared schedule identities |
| Component tests | 21 tests of the scoped scientific instruments, including domain and synthetic-mutation controls |
| Packaging tools | 18 separate tests of input-integrity refusals, local extraction and Python isolation |

The lot includes its file manifest, solver lock, installer, verifier and
notices. It reads the two existing Rust source files and fetches the exact
official Windows Z3 wheel separately. It needs neither a Rust compiler nor
the engine binary or private M11–M14 archives. The guide gives the commands,
offline and integrity-only modes, receipt locations and trust assumptions.
A dedicated Windows job in the [CI workflow](../.github/workflows/ci.yml)
runs these checks and preserves their logs; its hosted result is the result
of the specific commit's workflow run, not a consequence of this scope note.

Local preparation exercised a complete independent fresh clone, a real
download into an absent solver cache, the first scientific replay and a
second offline replay. The recorded host is Windows x86-64 with CPython
3.13.7; this is a fresh clone and local solver installation on that host,
not a new-machine or clean-system experiment.

The 78 selected scientific inputs retain their original bytes. The context
of README/PROOF is adapted for public use. Revision notes preserve the
lineage; superseded acquisitions are outside this selected lot. The
restricted translator, reviewed NTT schedule mapping and pinned Z3 solver
remain part of its trust base. Stored proof objects do not constitute a
second independent proof-kernel check.

The detailed programs, acquisitions and reviews for the other M11–M15
workstreams remain private. This first lot does not make the entire internal
study reproducible. The 82 internal research tests are not interchangeable
with the 21 public component tests, the 18 packaging-tool tests or the
existing public engine CI suite.

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
