# Mīzān Phase V.2.2 — Unresolved Ownership Coverage & Strict Variant Validation

## 1. Executive summary

Phase V.2.2 closes two narrow correctness gaps in Phase V:

1. **Relevant unresolved ownership is now counted.** Resources discovered
   through ownership-sensitive reads/writes that lack a confirmed owner are no
   longer dropped by the `resource.owner` guards. They are represented once per
   stable `(law, action, resource, principal)` check identity in L2/L3 coverage
   as eligible, attempted and `INCONCLUSIVE` — never as a finding and never as
   a resolved check.
2. **Strict variant validation is complete.** A strict relationship contract
   now rejects every invalid non-object variant entry, empty/non-string variant
   names, and invalid declarations inside an otherwise valid variant object at
   load time. Lenient mode keeps dropping invalid entries without ever creating
   an effective grant.

Irrelevant resources (health/login/static metadata, resources absent from the
tested API surface) still create no ownership checks. L2 and L3 remain
separate. `FINDINGS` retains precedence; a `CLEAN` verdict still requires every
relevant eligible check to be attempted and resolved.

## 2. Exact pre-fix defect

`Mizan._eligible_probe_targets()`, `_probe_read_authorization()` and
`_probe_write_authorization()` all skipped a resource when `resource.owner`
was empty. `build_ownership_graph()` deliberately leaves `owner_of()` empty for
`CANDIDATE`, `AMBIGUOUS`, `CONTRADICTED` and `UNKNOWN` ownership; those are
precisely the cases that need to stay visible. The checks disappeared before
they could be counted, so `LawCoverage.eligible` and `inconclusive` both stayed
at zero and the aggregate verdict could still be `CLEAN`.

Separately, `RelationshipContract.from_dict()` filtered `variants` with
`isinstance(value, dict)`, silently discarding string, list, numeric, boolean
and null variant values in strict mode.

## 3. Why relevant unresolved resources were skipped

An ownership fact is not stored on the `Resource` when the graph cannot
confirm it; `learn()` clears a response-level owner on contradiction and leaves
it empty when only structural evidence exists. The probes used that same
`owner` field as a relevance filter, conflating "no owner was proven" with
"this resource is outside the ownership model". A CANDIDATE owner, an
ambiguous row mapping, an unresolved identity anchor or contradictory evidence
all produced an empty `owner` and therefore no L2/L3 eligibility entry.

## 4. The new relevance rule

An unresolved resource contributes to L2/L3 coverage only when **all** hold:

1. it was discovered through a successful (`2xx`/`3xx`) traffic record;
2. the operation is in the L2 read vocabulary (`GET`/`HEAD`) or the L3 write
   vocabulary (`POST`/`PUT`/`PATCH`), never a health/login/metadata call;
3. a non-privileged, testable identity exists to serve as the check principal;
4. the resource belongs to the ownership model: it has a unique database row
   mapping, any ownership relationship evidence (even CANDIDATE), an
   ownership/sharing declaration for its type, or a recorded mapping ambiguity.

The rule is implemented in `engine.py` (`_ownership_unresolved`,
`_ownership_relevant`, `_representative_principal`, `_unresolved_checks`) and
documented in `PHASE_V_DESIGN.md`. Ledger-only scans (no graph) keep their
historical behavior rather than inventing uncertainty for every resource.

## 5. Revised L2/L3 coverage model

The V.2.1 `LawCoverage` fields are extended in meaning, not replaced:
`eligible` now includes relevant unresolved checks; `attempted` includes them
once they are recorded; `decided`, `allowed_by_grant`, `findings` and
`inconclusive` partition the attempted checks; `pending = eligible - attempted`
(bounded at zero). Check identity is `(law, action, resource, principal)`, so
repeated traffic observations cannot inflate the denominator and a single
write seen by the direct probe and the ledger analyzer remains one check.

## 6. Verdict invariants

- `ERROR` for setup/execution failure.
- `FINDINGS` whenever a violation is proven, regardless of other unresolved
  checks, which remain visible.
- `CLEAN` only with meaningful coverage, no pending or unresolved relevant
  L2/L3 check, grants counted as resolved, and no budget truncation.
- `INCONCLUSIVE` for any relevant unresolved/pending check or insufficient
  meaningful coverage. The verdict consults per-law outcomes, not a broad
  `ownership_semantics_missing > 0` rule.

Three distinct claims are kept separate throughout: proving a vulnerability
(`VIOLATION`), proving that a tested operation was resolved (`DECIDED` or
`ALLOWED_BY_GRANT`), and failing to establish enough evidence to decide
(`INCONCLUSIVE`).

## 7. Mixed-resource adversarial results

The independent `mixed_ownership` fixture exposes confirmed resource A,
candidate-ownership resource B and unknown-ownership resource C with two
non-privileged principals.

| Scenario | Expected | Actual |
|---|---|---|
| `clean` | no finding, unresolved L2 (B) and L3 (B/C) visible, INCONCLUSIVE | L2 eligible 4 / attempted 4 / decided 1 / inconclusive 3; L3 eligible 4 / attempted 4 / decided 1 / inconclusive 3; 0 findings; **INCONCLUSIVE** |
| `finding` | proven L3 violation on A, unresolved B still visible, FINDINGS | L3 eligible 4 / findings 1 / inconclusive 3; L2 inconclusive 3 retained; **FINDINGS** |

The fixture proves that completed checks on A cannot hide unresolved checks on
B/C, and that CANDIDATE/UNKNOWN ownership never produces a violation.

## 8. Unrelated-resource exclusions

Tests prove that health/login traffic creates zero L2/L3 eligible checks, a
resource absent from the tested API surface creates no pending check, duplicate
traffic observations do not inflate `eligible`, and a privileged or
non-testable identity is not an eligible attacker.

## 9. Strict variants validation behavior

Strict parsing rejects non-object variant values (string, list, number,
boolean, null), mixed valid/invalid sets, empty variant names and invalid
action/sharing declarations inside a variant object. Valid overrides keep their
merge semantics; lenient parsing never turns an invalid sharing declaration
into an effective grant.

## 10. Full regression results

- **Full `pytest` suite:** `579 passed, 1 warning in 387.40s` (556 from
  Phase V.2.1 + 23 new V.2.2 tests). No test was deleted, skipped, relaxed or
  excluded. The warning is an unrelated Starlette/httpx deprecation notice.
- **New failing-first suite:** `tests/test_phase_v2_2_coverage.py` — 23 tests.
  First run before the production fix: 12 failures for the intended reasons
  (invalid strict variants accepted, unresolved L3 eligibility missing,
  duplicate observations inflating L2 eligibility, and mixed-pipeline
  `KeyError: 'L2'`) with 10 passing; the additional candidate-read relevance
  test was written in the same RED set. All 23 now pass.
- **Targeted gate run:** 239 passed across the V.2.2/V.2.1 soundness suites,
  ownership semantics, adversarial and linked applications, cross-framework
  test module, PostgreSQL audits, Mīzān-scans-Mīzān, evidence integrity, SARIF
  and replay regression.
- **Cross-framework benchmark:** `--repetitions 1` — **8/8 scenarios as
  expected**, 8 true positives, 0 false positives, 0 false negatives, 8/8
  reproductions, 14 requests per scenario.
- **Ownership benchmark:** 23 cases with explicit denominators (section 11).
- **Static gates:** `ruff check` all checks passed; `ruff format --check` 84
  files already formatted; `git diff --check` clean.

## 11. Benchmark results with denominators

`python -m benchmarks.ownership.run` — 23 cases, budget 90 per scan, fresh
workspace per case. Full data: `benchmarks/ownership/results.json`.

| Metric | Result | Denominator |
|---|---|---|
| Case count | 23 | — |
| Ownership evidence: confirmed / candidate / unknown checks | 46 / 4 / 10 | 23 cases |
| L2 coverage | 58 eligible / 58 attempted / 28 decided / 4 allowed-by-grant / 14 findings / 12 inconclusive | 58 eligible L2 checks |
| L3 coverage | 61 eligible / 61 attempted / 35 decided / 1 allowed-by-grant / 10 findings / 15 inconclusive | 61 eligible L3 checks |
| Pending checks | 0 | 23 cases |
| Duplicate outcomes / findings | 0 / 0 (L2 and L3) | 23 cases |
| CLEAN verdict false positives | 0 with findings, 0 with unresolved checks | 10 clean controls |
| Mixed fixture | 2 cases, 6 L2 inconclusive, 6 L3 inconclusive, 1 L3 finding | 2 mixed cases |
| Law detection (all expected) | 13 detected | 13 eligible cases |
| L2 / L3 detection | 8 / 6 detected | 8 / 6 eligible cases |
| INCONCLUSIVE classification | 4 correct | 4 expected cases |
| Read-only grant behavior | 1 L3 finding, 0 L2 findings | 2 cases; 2 L2 resolved by grant |
| Read+write grant | 0 false-positive findings | 1 case |
| Incorrect grant suppression | 0 suppressed | 4 action-scope cases |
| Resource↔row mapping | 46 resolved | 56 discovered resources |
| Requests consumed | 496 | 23 scans × budget 90 (2,070 available) |
| Invalid contracts rejected | 9 | 9 invalid contracts |
| CLI contract propagation | 1 propagated, 0 invented ownership without contract | 1 case / 1 control |

## 12. Remaining limitations

- The contract remains trusted operator metadata: it declares intent, not
  application enforcement. Behavioral enforcement is still tested through
  observed traffic and attributed writes.
- An unresolved check is not a finding. Where ownership cannot be established,
  the scan reports `INCONCLUSIVE` rather than guessing an owner.
- Relevant resources are derived from observed ownership-sensitive operations;
  a private endpoint never exercised during learning cannot be classified.
- Ownership-graph evidence remains SQLite-specific; PostgreSQL deployments keep
  their existing policy-level behavior.
- No new law, backend or LLM component was added; JWT subjects remain extracted,
  not verified.

## 13. Exact final SHA

Implementation commit: `25d0debe4e205d5814f5bcb6a2fd6f7b04fa7c86`
(`fix(coverage): account for unresolved ownership and validate variants
strictly`). It is the commit whose code, tests, fixtures, benchmark and CI
results are measured here. A documentation-only follow-up commit adds this
report; its SHA is recorded in the final delivery message. Both commits are on
`feat/ownership-graph-v1`, and local/remote heads match after the final push.

## 14. CI run ID and results on that SHA

GitHub Actions run **`44112332599`** (run number **227**) on the exact
implementation SHA `25d0debe4e205d5814f5bcb6a2fd6f7b04fa7c86`:
**`completed` / `success`**.

| Job | Result |
|---|---|
| A — static & unit | success |
| B — PostgreSQL | success |
| C — security regression | success |
| D — benchmark | success |
| E — Mīzān scans Mīzān | success |
| F — independent application | success |
| G — cross-framework gate | success |
| G — external target (opt-in) | **SKIPPED by design — not PASSED** |

The optional external-target job is opt-in and was skipped; it is reported as
`SKIPPED`, not as a passed gate. All seven mandatory jobs succeeded on the
exact SHA above.

PR #9 remains open and unmerged; `main` is untouched. Local and remote
`feat/ownership-graph-v1` heads match after the final push.
