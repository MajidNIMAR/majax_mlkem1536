# Selected verification and test record

Public status updated 19 November 2026 for `KEM1536-DEV-Q7681-R1`.
The construction and Rust engine are experimental. Concrete security
qualification C01 remains open. This page reports what was checked and how
the evidence can be examined; it does not assign a security level.

M17 is the latest numbered research milestone; the subsequent C01 and block-3
work has no M18 designation. M10 remains the delivered engine reference.

## Evidence available in this repository

| Scope | Recorded checks | Availability and limit |
|---|---|---|
| Engine CI | The [workflow](../.github/workflows/ci.yml) runs the Rust workspace, Python research suite, formatting, strict Clippy and historical package checks on Windows and Ubuntu. | Check the Actions run for the commit under examination. A green run verifies those commands on its runners; it is not a cryptographic audit. |
| M10 engine qualification | The retained [M10 study](M10_MOTEUR_ET_QUALIFICATION.md) records 514 Python tests with no skips in the selected full check, Rust checks, four sanitizer harnesses, independent-reference comparisons, coverage and a bounded binary review. | The counts and limits belong to the recorded M10 images and campaigns. They do not establish complete path coverage or a universal timing or memory property. |
| M15 public replay | The [replay lot](../research/reproducibility/m15/implementation/README.md) checks 31 arithmetic obligations, an NTT certificate over 131,072 linear coefficients and 21 component tests. Its 18 packaging-tool tests are separate. | The commands and inputs are public. This is a scoped arithmetic and tooling check, not a proof of the whole KEM. |

The [README](../README.md) and the linked milestone documents retain earlier
M07–M09 engine checks and their historical qualifications. Re-running a prior
suite does not create a new independent test population.

## Later local research checks

These results are documented as bounded research summaries. Their detailed
instruments, acquisitions and internal review records are not part of the
public replay package. The rows are separate selections; their counts must
not be added into a single total.

| Research cycle | Selected record | Public reproducibility boundary |
|---|---|---|
| M11–M15 | 27 integration checks and 82 targeted tests. | The public M15 lot above releases one delimited subset; the other detailed records remain local. See the [M15 progress note](ETAT_RECHERCHE_M15.md). |
| M16 | Nine validation jobs and 113 targeted tests, with no skips in the selection. | Public [scope note](ETAT_RECHERCHE_M16.md); detailed instruments remain local. |
| M17 | 18 validation jobs and 217 targeted tests, with no skips in the selection. | Public [C01 scope note](ETAT_RECHERCHE_C01.md); detailed instruments remain local. |
| Conditional C01 consolidation | Nine validation jobs and 42 targeted tests, with no skips in the selection. | Internally reviewed conditional result only; concrete C01 remains open. |
| Subsequent scoped studies | 66 distinct targeted tests in five suites. | Local research checks and independent record replay; no new public CI suite. |
| Latest qualification | 90 distinct targeted tests across three selected suites: 11 conditional calculation checks, 27 construction-to-program checks and 52 implementation checks, with internal cross-review. | The tests examine stated research and implementation scopes. Their resistance findings are bounded by fixed budgets and do not give a general hardness claim. |
| Later reader and integrity checks | 34 reader checks, seven adapter checks, 12 comparison checks and ten integrity fixtures. | These check interpretation and preservation of prior evidence; they are not new engine or resistance experiments. |
| Latest construction and program study | One aggregate diagnostic completed 16 fresh exchanges and 16 rejection checks on the canonical binary; selected calculations and source links were independently checked. | Prior records were replayed separately and are not credited as fresh acquisitions. This is a functional and conditional research result, not a concrete security proof. |

The latest decision and review steps also checked consistency of the selected
argument and its resource accounting. They added no new engine test suite,
hosted CI run, performance claim or external audit. The engine sources,
parameters, wire formats and canonical binary remained unchanged throughout
these later research cycles.

## Reading the results

- **Publicly replayable** means the repository contains the programs and
  inputs needed for the stated check, such as the M15 lot and the hosted
  workflow. Confirm success at the exact commit being cited.
- **Local and internally reviewed** means a result has a retained local
  record but its full acquisition and verification package is not published.
  It should not be described as independently reproduced by a GitHub reader.
- A test count measures the selected checks, not the range of all possible
  inputs or adversaries. Replays, cross-reviews and repeated suites are not
  added again as new tests.
- Resistance evaluations are reported here only by their scope, budgeted
  status and inference limits. They do not establish a general hardness
  bound. R1 is experimental and concrete C01 remains open.
