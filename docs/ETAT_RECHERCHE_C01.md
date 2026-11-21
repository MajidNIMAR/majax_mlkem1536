# Current research scope and the conditional C01 argument

Scope statement updated 21 November 2026. **MLKEM-1536 Core** develops the
working experimental profile `KEM1536-DEV-Q7681-R1`, with six polynomials
of 256 coefficients. The number 1536 counts coefficients; it is not a
security-bit rating or a standardized ML-KEM parameter set.

**A conditional IND-CCA argument for the R1 construction has been
consolidated and internally reviewed in the declared QROM/RC1 model.
The complete concrete qualification of R1 remains open. R1 is experimental,
its final cryptographic freeze is deferred, and it is not production-qualified.**

M24–M28 are the latest numbered, scoped **C01 research** blocks. M23 remains
the latest numbered engine qualification cycle, following M20–M22. Neither
kind of result closes concrete C01.
Later post-M28 blocks and the 20–21 November C01 studies are unnumbered; they
are the newest research. M10 remains the delivered engine reference. M15 is
the frozen public replay lot, not the project's current milestone. These
numbers label work packages rather than engine versions or security levels.
The M16 note below is historical.

## Numerical audit of all nine fixed-R1 terms — 21 November

The latest study examined every term of the exact classical `R1-CHAIN`
with the completed honest-KeyGen law and the induced resource budgets.
For each of the five passive terms it proves a universal ceiling of
`1−2^-256`, almost one. The two adaptive-correction terms retain only
the trivial ceiling `1`. The two knowledge terms have no small upper
bound for the selected efficient public-view simulation; exhaustive
extraction makes them zero only after up to `q_D·2^256` complete public
encapsulation evaluations. The resulting nine-term CCA ceiling remains
the vacuous `1`, not a security level.

A separate conditional lower constraint on those knowledge terms, using
an auxiliary passive adversary **different from** the one in `R1-CHAIN`,
shows why nine individually small bounds cannot certify the selected
public-view simulation if passive secrecy and correction are strong at
the matched budgets. This is a limit of that proof route, not a claim
that R1 is insecure or unprovable by another argument. A deterministic
fixed-source witness proves only `p_complete≥2^-256` and
`tau_512≤1−2^-256`; an ideal-stream cap calculation does not transfer
to fixed SHAKE. The three detailed proof capsules and their independent
review remain local and excluded from Git. **The current additive
public-view nine-term route is held; concrete C01 remains open and R1
experimental.** See the [research report](RAPPORT_RECHERCHE.md) and
[verification record](TESTS_AND_EVIDENCE.md).

## Exact R1 source-level composition — 21 November

Four further local studies link the passive challenge, adaptive Decaps and
correction on the **executed fixed-function R1 source**, conditional on an
honestly completed KeyGen. The classical CCA advantage has a nine-term
upper expression: two encryption-coin switches, two uniform-coin PKE
games, a head-output game, and two each of adaptive decoding and witness
knowledge events. This is an exact composition of conditional game
inequalities, **not a numerical security bound**. None of its nine terms
has an adopted, security-useful resource-matched upper bound for fixed R1.

The challenge study shows that the selected *statistical* replacement is
unsuited to a well-correcting profile; any useful argument must justify
a computational property of the actual fixed G/PKE coupling. A simulator
seeing only public information cannot obtain a small universal Decaps
response gap from the examined route, either before or after the challenge.
Forwarding prechallenge Decaps to a real oracle removes that part of the
simulation error but requires security of a stronger `CCA1-F` game; the
earlier passive five-term argument does not automatically cover it.
These results rule on proof routes, not on R1's practical resistance.

An independent `CorrList` game states the adaptive-correction premise
needed for verified witnesses. A generic lift from honest mean correction
loses a factor `2^256`; the upper expression obtained from the earlier
ideal-model certificate lies between `2^-55` and `2^-54`, above an
illustrative `2^-130` allocation. This is a gap in that **proof route**,
not a measured fixed-R1 failure probability. Fixed-function primitive
assumptions, postreduction resources, the quantum case and external review
remain open. Detailed readers and proofs are retained locally outside Git
and cannot be replayed from GitHub alone. The engine, parameters, formats
and API did not change. **Concrete C01 remains open; R1 is experimental.**

## Earlier unnumbered five-block C01 follow-up — 20 November

Four locally retained research acquisitions and one integration gate refine
the obligations of the **unchanged** R1 construction. The passive
challenge-key game has a scoped decomposition, but its construction-specific
terms and component advantages have no adopted security-useful numerical
bounds. The selected public-view extraction route cannot certify a small
error for
adaptive Decaps under its stated premises; this does not exclude a
different simulation. A global statistical transfer
from independent CBD(3) samples to the fixed seeded noise law is inapplicable;
the actual fixed-function correction probability remains unbounded here.
The quantitative reader recalculates sufficient assumptions for the two
native Module-LWE games under illustrative ideal-game caps and checks the
archived attack-cost panels. Those panels do not supply native-game
advantage bounds or complete post-reduction resources. The integration gate
therefore returns **`C01_CONCRETE_OPEN`**. The conclusion concerns only the
routes and models examined; it neither establishes a weakness in R1 nor
a concrete security level. Quantum fixed-function security and external
cryptographic review remain open.

The detailed proofs, readers, results and internal checks are in ignored
local capsules, absent from GitHub. They cannot be independently replayed
from this repository alone. No engine source, parameters, formats or API
changed in this cycle; R1 remains experimental and not production-qualified.

## Fixed-function structural step and CCA accounting — 20 November

Two locally sealed and independently read capsules now attach an exact
decapsulation invariant to the frozen Rust source and compose the earlier
conditional trace-aware coupling with a passive `CPA-F` challenge game.
For a completed honest KeyGen and a fresh uniform challenge message drawn
after prechallenge queries, an accepted postchallenge Decaps query on a
different ciphertext cannot decode to that challenge message. With at most
`q_pre` earlier Decaps queries, the probability of a decoded-message match
is at most `q_pre/2^256`; a prior ciphertext matching the later challenge
has probability at most `q_pre/2^256 + epsilon_corr_fixed`. The latter
term is the **actual fixed-function average correctness error** and has
no adopted numerical bound. Completed honest KeyGen traverses all 36
matrix streams reused by later encryption; its own termination remains
a separate condition.

For an executable online extractor `E`, the classical single-key game
satisfies the conditional decomposition

```
Adv_CCA(A) <= Adv_CPA-F(B_E) + delta_0 + delta_1.
```

Each `delta_b` is an error measured on the simulated bit-`b` transcript:
an adaptively produced verified witness may decode differently, or a
ciphertext may be accepted without a verified witness. The simulator's
public-function evaluations, extractor, time and memory are accounted
for symbolically; no concrete resource caps are established here.
This refines and composes the earlier trace-aware conditional lemma; it
does **not** prove any of the three needed small terms. `CPA-F` is the
passive challenge-key obligation of the exact fixed R1 construction,
not an independent SHA3 theorem. The finite verifiers check source
anchors and small logical models, not a security level. **Concrete C01,
quantum treatment and binary qualification remain open.**

## Classical full-game reduction and fixed-function boundary — 20 November

A locally retained, internally counter-read proof now covers the **classical,
single-key, typed random-oracle** IND-CCA game with adaptive Decaps before
and after the challenge. A public G-query trace supports an explicit
Decaps simulator; its error is bounded using the earlier adaptive
correctness certificate and the exact uncompressed `u` encoding. A second
conditional reduction connects the remaining seeded-PKE inversion term
to decision Module-LWE distributions `(6,6)` and `(7,6)`, with oracle
preprocessing and simulator costs charged. The numerical hardness of
those distributions at the enlarged resource budgets is **not proved**.
The small residual terms therefore do not constitute a security-bit claim.
An independent composition reader checks a residual below `2^-189` only
after removing the two unbounded Module-LWE advantage terms and imposing
the stated illustrative `2^32` caps. This work gives no nontrivial
numerical upper bound on the total IND-CCA advantage.
The proof does not apply to quantum oracle queries or directly to the
executed SHA3/SHAKE functions.

The six fixed-function roles and G-derived encryption coins passed bounded
cross-implementation checks. A separate, replayable fixed-function game
harness ran 464 synthetic trials and checked 16 archived Rust vectors.
Those finite controls validate the experiment's interface and positive
controls, not an adversarial advantage bound. A generic small-gap
replacement of public fixed SHA3/SHAKE or Keccak-f by random functions or
a random permutation is unavailable; a construction-specific fixed-function
argument remains necessary. The exact locally ignored proof and test
capsules are listed in the research report. **Concrete C01 remains open;
R1 remains experimental and is not production-qualified.**

## Classical shared-permutation follow-up

The previously established multi-rate indifferentiability envelope can
cover an internally executed KeyGen/challenge/Decaps game under a
**deterministic total permutation-call cap**. In the ideal world, direct
permutation access is answered by a simulator that may itself consult a
challenge-relevant random-oracle entry. A conditional challenge-head hop
therefore needs a broader target-contact event than adversarial typed G
queries alone. Its post-challenge probability is not bounded here; simply
adding the earlier hop and the indifferentiability term would overclaim.

For a separate classical game **without direct permutation/inverse access**,
one honest key, monitored honest-key encryptions, and a pathwise total
budget `N≤2^32`, the adaptive correction certificate transfers to a
shared random permutation with upper bound below `2^-192`. The total
budget includes the engine, oracle responses and monitored checks; the
key's 36 matrix streams are capped and their abort event counted. The
statement concerns only this monitored event and stopped game. It does
not cover arbitrary private adversarial calculations, the unrestricted
permutation interface, fixed Keccak-f, or the QROM. **C01 remains open.**

## Earlier local correction and challenge-route checks

A selected standard-model extraction route was tested against the exact
256-bit message and challenge-key dimensions. Its sufficient entropy
condition is unavailable for unchanged R1; this is a decision about that
route, not a proof of insecurity or a general impossibility theorem.
An independent primary-source screen likewise found no theorem that directly
closes the fixed-function R1 challenge-key and adaptive-Decaps transitions.
An independent narrow hop for the **classical typed ideal-oracle game**
shows that changing the challenge key is bounded by an adversarial query
to the target G input and, when pre-challenge Decaps is allowed, by an
additional term at most `q_pre_dec/2^256`. A finite control and internal
counter-reading checked the pre/post-challenge distinction. The target
query probability remains unbounded; this hop is not an IND-CCA reduction
or a fixed-function claim.

For a separately declared **classical typed ideal-oracle game**, a new lemma
uses the actual R1 nonce schedule and the existing J2 correction certificate
to bound the event that any of the `2^256` messages for one honest key
decrypts incorrectly. The capped-matrix version has an upper bound below
`2^-54`; this is a deliberately loose all-message union bound, not the C05
correction target or an estimate for fixed SHA3/SHAKE. It removes the
decoding-error event from the earlier conditional adaptive trace coupling
in that game, while leaving witness extraction and challenge-key security
unproved. The calculation is averaged over honest keys and ideal tables;
it does not certify each particular key. An added Rust test checks the
source-level seed-coincidence case without changing production code.

A second proof bounds the correction event for **at most `2^32` distinct
non-key noise seeds actually touched**, even when those seeds are chosen
adaptively. Its integer and rational readers certify a bound below
`2^-195` in the same classical typed ideal-oracle setting. The budget
must count direct calls, genuine engine work and every simulated
re-encryption in both compared worlds. It is a correction bound for
honestly constructed ciphertexts, not a Decaps extractor or an IND-CCA
bound. No direct composition with the earlier shared-permutation theorem
has been justified.

The local proof readers, independent finite controls and internal
counter-reading passed within their stated scopes. Detailed capsules are
retained outside Git. **Concrete C01, the fixed-function transfer and the
quantum case remain open. R1 remains experimental.**

## Earlier local A/B and primitive-bound cycle

This earlier local cycle kept the exact R1 engine and fixed SHA3/SHAKE
construction unchanged. An exact public-key distribution switch was
proved, but its advantage and the remaining correlated challenge-key
term have no adopted bound. A conditional classical coupling for adaptive
Decaps identifies the extraction and adaptive-correction events that must
be bounded; it can compute the fixed rejection role with one independent
seed only if those conditions hold. At that stage, no efficient extractor
for the full game or adaptive-correction event bound had been established.

For the six primitive roles, a separate theorem gives an explicit **classical
random-permutation** envelope with minimum capacity 256 bits and a total
query cost that includes all relevant calls. A small, capped matrix-sampling
event has a bounded marginal in that model. This does not establish a bound
for fixed Keccak-f, a shared multi-rate quantum theorem, or the complete
IND-CCA game. The local proof readers, independent finite models and
overclaim checks passed within their stated scopes; they are not new engine
tests or a security audit. Detailed capsules remain outside Git. **A, B and
concrete C01 remain open; R1 is experimental.**

## Earlier post-M28 C01 closure attempt: verified scope

That work proved a correctness-to-collision lemma for R1 without
assuming global injectivity and certifies a uniform arithmetic decoding
radius of 1799. A separate game argument now connects **honest** KEM
correction to the actual seeded construction, but its matrix-tail term and
four fixed-function advantages remain symbolic. A source-bound audit checks
the six SHA3/SHAKE roles; a quantitative study proves a generic public-search
**upper** cost bound, not a resistance lower bound. Selected alternative
parameter recipes have also been screened without selecting an R2 engine.
A further conditional Decaps simulation is exact only for a capped KeyGen
game and has exhaustive cost; it is not an efficient reduction for R1.
The latest primary-source transfer screen finds no theorem directly
covering unchanged R1, without implying an attack or general impossibility.
A tested joint-decoupling premise does not weaken the remaining challenge
gate. A separate R2 parameter check rejects direct reuse of R1's q in one
corrected matrix construction, without ruling out other designs.

Each local result has an executable reader or certificate and internal
cross-reading. Their detailed capsules are retained outside Git. The
unchanged Rust workspace was rechecked locally with strict Clippy and all
features: 46 tests passed in nonempty groups. These checks confirm the
declared functional and mathematical scopes, not the fixed-function
IND-CCA property.

**The decisive C01 gates remain open:** an independent argument for the
challenge key correlated with its ciphertext, an efficient adaptive Decaps
simulation or other reduction, bounded assumptions for the exact fixed
primitives and seeded PKE, and numerical composition under one adversary
budget. No security level or production status is assigned. The
[research report](RAPPORT_RECHERCHE.md) and [test record](TESTS_AND_EVIDENCE.md)
give the current scope; earlier conditional QROM/RC1 work is preserved below
with its original model.

## Post-M28 Blocks 2–4: parameter, construction and engine gates

Block 2 recomputes actual R1 sizes, a correction bound in its stated model,
and selected attack-cost estimates under their respective conventions. Its
`BLOCK2_PARAMETER_FREEZE_HELD` verdict leaves the security parameter freeze
pending: none of these numbers is a fixed-function IND-CCA bound. Block 3
screens selected distinct R2 constructions and reproducible matrix-size
scenarios. Its `R2_SELECTED_CANDIDATES_NOT_VIABLE_YET` verdict applies only
to those candidates; the illustrative numbers are not admissible R2
parameters or a theorem for a rank-six module. No R2 profile is selected.

Block 4 checks the unchanged R1 engine with fresh local Rust and
independent-reference runs, retains exact executable images and prepares
an external review package. `BLOCK4_PREPARED_PARTIAL` does not credit a
new R2 engine, complete image qualification or an external review actually
received. The detailed records remain local in `artifacts/retained/`,
outside the public Git repository. **R1 remains experimental; concrete
C01 remains open.** See the [research report](RAPPORT_RECHERCHE.md) and
[test record](TESTS_AND_EVIDENCE.md) for the scoped outcomes.

## Post-M28 Block 1: decision on selected fixed-function proof routes

The Block 1 local study tests three route families against the exact,
unchanged R1 KEM with public fixed SHA3/SHAKE functions. Checked generic
separations show why the selected component assumptions alone do not
justify the challenge key; a bounded result constrains one class of
adaptive-decapsulation simulations. Selected primary theorems do not
supply the missing transitions for this exact program. Independent
internal reviews accepted the stated mathematical scope. Detailed proof
records remain in the local retained capsule, outside the public repo.

The verdict `R1_SELECTED_ROUTES_NO_GO` applies **only to these examined
routes**. It does not establish an R1 attack or rule out a future
construction-specific proof. Neither missing fixed-function transition
is closed, and no numerical IND-CCA bound follows. **Concrete C01 remains
open; R1 is experimental.** Source, parameters, API, formats and canonical
binary are unchanged. See the [research report](RAPPORT_RECHERCHE.md) for
the decision and [test record](TESTS_AND_EVIDENCE.md) for verification scope.

## M24–M28: fixed-function security route and architecture decision

M24 fixes the honest-key, public-function R1 game and gives a checked cut of
the selected proof route: the fixed challenge head and adaptive Decaps
transitions need independent arguments. M25 adds four native-dimension
cost estimates in one scalar IID surrogate, plus a seeded-distribution
certificate. These are bounded observations, with model extrapolation for
R1, not advantages for the actual seeded PKE or KEM. M26 establishes a
conditional hop for the rejection role and maps all six fixed primitive
roles to the frozen source, but adopts no numerical PRF bound. M27 composes
the selected receipts under one source commit and retains the missing
transitions and all numerical unknowns explicitly. M28 keeps R1 experimental
and records a **separate, unimplemented R2 research candidate** with an
abstract classical PKE-to-KEM reduction; its concrete and quantum obligations
remain open. The full M24–M28 packages, including internal reviews and
negative records, are retained locally and are not part of this public repo.

**Concrete C01 is still open for R1.** This cycle changed no cryptographic
core, parameter, wire format, API or canonical binary. It did not deliver a
new hosted CI run, external audit, security rating, NIST certification or
production qualification. The [research report](RAPPORT_RECHERCHE.md) records
the bounded conclusions and the next scientific decision.

## Earlier bounded research and verification

Four earlier block-3 work packages examine the unchanged R1 construction. The
construction decision, conditional whole-KEM argument, corresponding resource
calculation and source-to-program link have internally cross-checked deliverables
within their stated scopes. The conditional argument and functional checks do
not establish the security of the concrete fixed-function KEM. **Concrete C01
remains open.**

Before M18, the selected research qualification had 90 distinct local targeted tests in three
suites. A later diagnostic on the canonical binary completed 16 fresh exchanges
and 16 rejection checks. Other recent checks replayed retained records or
validated research tools; these are not additional new engine tests. The
[verification and test record](TESTS_AND_EVIDENCE.md) separates these local
results from the public CI and M15 replay lot. Resistance studies retain their
budget and inference limits without disclosing methods in this overview.

M18 separately acquired fresh API/reference checks, Windows and Ubuntu
binary diagnostics, Rust regressions, paired benchmarks, bounded ASan runs
and line coverage. Its Windows repeat builds did not match byte for byte;
LLVM branch coverage was not acquired. The internal cross-review accepted
the measured scopes and recommended `M18_PARTIAL`. See the
[research report](RAPPORT_RECHERCHE.md) for the current summary. These
engineering checks do not close the fixed-function security argument.

M19 then resolved two selected build and branch-measurement gaps within its
declared PC scope. M20 repeated the Windows build from two verified source
locations on the same PC. M21 measured branch outcomes from four synthetic
input families in one Linux instrumented image. M22 tied bounded witnesses
and diagnostics to exact retained Windows and Linux PC images. M23 built a
Linux AArch64 image and ran its profile and functional diagnostics under QEMU
user emulation. The detailed M20–M23 capsules remain local, outside this
public repository. Same-host builds, instrumented coverage, bounded binary
links and emulation do not prove resistance of the concrete R1 KEM, physical
constant time, global erasure or Android readiness. **Concrete C01 remains
open.**

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
