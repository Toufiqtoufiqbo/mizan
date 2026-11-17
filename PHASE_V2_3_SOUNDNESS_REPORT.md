# Mīzān Phase V.2.3 — Ownership Trust Boundary & Outcome Consistency

## 1. Executive summary

Phase V.2.3 fixes one trust-boundary defect and one accounting defect in the
graph-backed ownership path:

1. **One ownership authority.** `OwnershipGraph` is now the only source of an
   authorization decision in graph-backed mode. A response-level owner claim is
   consumed as evidence while the graph is built, then neutralized in the
   learned policy and traffic records unless the graph returns a unique owner
   with state `CONFIRMED`. A `CANDIDATE`/`UNKNOWN`/`AMBIGUOUS`/`CONTRADICTED`
   claim can no longer drive an owner-control request, an L2 accusation or an
   L3 decision. Ledger-only deployments keep their historical policy-level
   behavior.
2. **One final outcome per logical check.** Outcomes are keyed by
   `(law, action, resource, principal)`; the outcome value is no longer part of
   the identity. A deterministic precedence (`VIOLATION` > `ALLOWED_BY_GRANT` >
   `DECIDED` > `INCONCLUSIVE`) reconciles provisional results. A decided result
   can replace uncertainty; uncertainty cannot overwrite a decision, and a
   proven violation cannot be downgraded. Coverage is computed from final
   outcomes only.

Confirmed BOLA detection, action-scoped grants, grant resolution and
serial/parallel behavior are unchanged.

## 2. Original trust-boundary defect

`build_ownership_graph()` records a response-level owner claim naming an
unconfigured principal as `OWNS CANDIDATE`. `Mizan.learn()` previously cleared
`resource.owner`/`record.resource_owner` only when the graph state was
`CONTRADICTED`, leaving CANDIDATE (and other unresolved states) intact.
`_probe_read_authorization()` then used `resource.owner` as its initial
condition and sent an owner-control request with that identity, treating an
evidence hint as an authoritative owner. The same problem could reach L3
eligibility and the policy-level analyzer through learned resource owners.

## 3. Exact code paths changed

- `src/mizan/core.py` — added `OUTCOME_PRECEDENCE` shared by the engine and the
  ledger analyzer.
- `src/mizan/engine.py` — `learn()` now clears every unconfirmed owner hint
  after the graph has consumed it (and records the affected keys);
  `_probe_read_authorization()` obtains the owner exclusively from
  `graph.owner_of()` with state `CONFIRMED`; `_outcome()`/`_inconclusive()`
  implement reconciliation and remove superseded uncertainty; duplicate
  observations collapse by logical identity.
- `src/mizan/taint.py` — analyzer outcomes use the same logical identity and
  precedence, and drop inconclusive reasons when a stronger outcome arrives.
- `src/mizan/validation.py` — exposes neutralized owner hints in the ownership
  report.
- `benchmarks/ownership/run.py` — reports neutralized hints and conflicting
  outcomes with denominators.
- `tests/test_phase_v2_3_soundness.py` — 17 failing-first tests.

## 4. Ownership authority rule

1. In graph-backed mode, only `graph.owner_of(key)` with
   `graph.owner_state(key) is CONFIRMED` is an ownership decision.
2. Response owner fields remain evidence inputs to graph construction, never
   authorization facts.
3. Unconfirmed hints are neutralized in `policy.resources` and in every
   `TrafficRecord.resource_owner` after the graph is built.
4. A relevant unresolved resource is still represented in L2/L3 coverage as an
   `INCONCLUSIVE` check (Phase V.2.2 behavior), not as a finding and not as a
   decided check.
5. Ledger-only scans (no row mapping/graph authority) retain their historical
   policy-level analyzer behavior.

## 5. Outcome state and deduplication model

The logical check identity is `(law, action, resource, principal)`. The final
outcome is chosen by `OUTCOME_PRECEDENCE`: `INCONCLUSIVE` (0) < `DECIDED` (1) <
`ALLOWED_BY_GRANT` (2) < `VIOLATION` (3). Repeated observations update the
single stored outcome rather than appending a new one. `INCONCLUSIVE` is
provisional; a stronger observed result replaces it and removes the matching
inconclusive reason. Coverage is derived from the final list, so
`attempted = decided + allowed_by_grant + findings + inconclusive`, and
`pending = max(0, eligible - attempted)`.

## 6. Adversarial test matrix

| Case | Expected | Actual |
|---|---|---|
| A — CANDIDATE response owner | hint neutralized, no owner-control request with candidate identity, one L2 `INCONCLUSIVE`, no L2 finding | PASS — hint cleared in policy and traffic; zero alice-identity control calls; one `INCONCLUSIVE` L2 outcome; no L2 finding |
| B — Unknown ownership | `INCONCLUSIVE`, no guessed owner/finding | PASS — mixed `unknown:item-c1` outcomes all `INCONCLUSIVE`, 0 findings |
| C — AMBIGUOUS / CONTRADICTED ownership | no ownership-based finding | PASS — parametrized states produce no L3 violation |
| D — Confirmed ownership + genuine BOLA | reproducible L2 `FINDINGS` | PASS — `adversarial_store/read` → L2 finding, verdict `FINDINGS` |
| E — Action-scoped grants | read grant allows L2 only, read+write grant resolves both | PASS — `grant_write` → L3 only; `read_write_grant` → `CLEAN` with both grants resolved |
| F — Contradictory outcomes | one final outcome, consistent counters, no duplicate finding | PASS — 3 provisional outcomes reconcile to 1 `VIOLATION`; partition holds |
| G — Serial/parallel | identical verdicts and logically equivalent outcomes | PASS — `read` → `["L2"]` and `grant_write` → `["L3"]` in both modes |

## 7. Full regression results

- **Full `pytest` suite:** `596 passed, 1 warning in 582.42s` (579 from
  Phase V.2.2 + 17 new V.2.3 tests). No test was deleted, skipped, relaxed or
  excluded. The warning is an unrelated Starlette/httpx deprecation notice.
- **New failing-first suite:** `tests/test_phase_v2_3_soundness.py` — 17 tests.
  Before the fix, 6 tests failed for the intended reasons: candidate owner hint
  survived learning, owner-control used the candidate identity, and three
  logical checks held contradictory/multiple outcomes; now all 17 pass.
- **Targeted gate run:** 222 passed across V.2.3/V.2.2/V.2.1 soundness suites,
  adversarial and linked applications, cross-framework test module, PostgreSQL
  audits, self-scan, evidence integrity, SARIF and proof replay regression.
- **Cross-framework benchmark:** `--repetitions 1` — **8/8 scenarios as
  expected**, 8 true positives, 0 false positives, 0 false negatives, 8/8
  reproductions, 14 requests per scenario.
- **Ownership benchmark:** 23 cases with explicit denominators (section 8).
- **Static gates:** `ruff check` all checks passed; `ruff format --check` 85
  files already formatted; `git diff --check` clean.

## 8. Benchmark results with denominators

`python -m benchmarks.ownership.run` — 23 cases, budget 90 per scan, fresh
workspace per case. Full data: `benchmarks/ownership/results.json`.

| Metric | Result | Denominator |
|---|---|---|
| Case count | 23 | — |
| Ownership evidence: confirmed / candidate / unknown | 46 / 4 / 10 | 23 cases |
| Unconfirmed owner hints neutralized | 0 | 23 bundled cases (no response-level owner hints in these fixtures; negative control is the unit test in section 6) |
| Conflicting outcomes | 0 | 23 cases |
| Duplicate outcomes / findings | 0 / 0 (L2 and L3) | 23 cases |
| L2 coverage | 58 eligible / 58 attempted / 28 decided / 4 allowed-by-grant / 14 findings / 12 inconclusive | 58 eligible L2 checks |
| L3 coverage | 61 eligible / 61 attempted / 35 decided / 1 allowed-by-grant / 10 findings / 15 inconclusive | 61 eligible L3 checks |
| Pending checks | 0 | 23 cases |
| CLEAN false positives | 0 with findings, 0 with unresolved checks | 10 clean controls |
| Mixed fixture | 2 cases, 6 L2 inconclusive, 6 L3 inconclusive, 1 L3 finding | 2 mixed cases |
| Law detection | 13 detected | 13 eligible cases |
| L2 / L3 detection | 8 / 6 detected | 8 / 6 eligible cases |
| INCONCLUSIVE classification | 4 correct | 4 expected cases |
| Incorrect grant suppression | 0 | 4 action-scope cases |
| Resource↔row mapping | 46 resolved | 56 discovered resources |
| Requests consumed | 496 | 23 scans × budget 90 (2,070 available) |
| Invalid contracts rejected | 9 | 9 invalid contracts |
| CLI contract propagation | 1 propagated, 0 invented ownership without contract | 1 case / 1 control |

## 9. Known limitations

- The contract is trusted operator metadata; it declares intent, not
  application enforcement. Behavior is still tested through observations.
- An unconfirmed owner is not a finding. Where ownership cannot be established,
  the scan reports `INCONCLUSIVE` rather than guessing.
- Relevant resources are discovered from observed ownership-sensitive traffic;
  an endpoint never exercised during learning cannot be classified.
- Ownership-graph evidence is SQLite-specific. PostgreSQL retains policy-level
  behavior; no generalization from these fixtures is claimed.
- Proof masking, replay and SARIF formats were not changed.

## 10. Exact implementation SHA

`d102e8de75639945ad6bde23f8a8e46b8b571d9f`
(`fix(authz): enforce graph ownership authority and reconcile outcomes`). This
is the commit whose production code, tests, benchmark and CI results are
measured in this report.

## 11. Exact final HEAD SHA

The documentation-only commit that adds this report is the final HEAD of
`feat/ownership-graph-v1`; its exact SHA is recorded in the final delivery
message and in the PR #9 delivery comment. Both commits are on that branch;
local and remote heads match after the final push. `main` and `stash@{0}` are
unchanged.

## 12. CI run ID and job conclusions

- On the implementation SHA `d102e8d`, run **44121580329** (#229) completed
  with conclusion **failure**. Seven jobs succeeded (B PostgreSQL, C security
  regression, D benchmark, E self-scan, F independent application, G
  cross-framework, G external target skipped). Job A (static & unit) failed in
  the "Unit tests" step on exactly one test:
  `test_external_target_status_is_not_misreported`, because that documentation
  test reads `PHASE_V2_3_SOUNDNESS_REPORT.md`, which is added by the following
  documentation commit and was not present in the checkout of `d102e8d`. No
  production or security test failed.
- On the final HEAD (documentation commit), the CI run ID, conclusion and job
  breakdown are recorded in the final delivery message and PR comment. The
  optional external-target job is `SKIPPED` by design, **not PASSED**.

PR #9 remains open and unmerged; `main` is untouched; `stash@{0}` is preserved.
