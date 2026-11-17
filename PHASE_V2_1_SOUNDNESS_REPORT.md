# Mīzān Phase V.2.1 — Action-Scoped Authorization & Verdict Soundness

## 1. Executive summary

Phase V.2.1 closes two soundness gaps in Phase V without adding a new law,
backend or feature:

1. **Action-scoped grants.** A sharing declaration must now declare which
   operations it authorizes. A confirmed `read` grant explains an L2 read and
   can never suppress an L3 write. A `write` grant explains the corresponding
   write and never explains a read. The same vocabulary (`read`, `write`) is
   used by the HTTP-method mapping, the contract, the graph, the direct engine
   probes and the ledger analyzer.
2. **Verdict soundness.** Authorization checks now have four explicit outcomes
   (`DECIDED`, `ALLOWED_BY_GRANT`, `VIOLATION`, `INCONCLUSIVE`) and L2/L3 have
   separate coverage with explicit denominators. A confirmed grant is a
   *resolved* check, not an inconclusive one. `CLEAN` requires every relevant
   eligible check to have been attempted and resolved; a proven finding keeps
   `FINDINGS` precedence; otherwise the verdict is `INCONCLUSIVE`.

The adversarial collaborator case (read allowed, write rejected) now produces
**no L2 finding and one L3 finding** through the real validation pipeline.
A read+write grant produces no findings and a `CLEAN` verdict. Serial and
parallel CLI execution agree.

## 2. Exact pre-fix defects and their reproduction

| Defect | Pre-fix behaviour | Reproduction |
|---|---|---|
| Action-agnostic grant | `OwnershipGraph.explained_by_sharing(owner, other, resource_key)` considered only the relationship state; `SHARED_WITH` and `MEMBER_OF` suppressed findings regardless of operation | A collaborator with the fixture's `authorization_grant` declaration could write to `item-alice-1`; the engine recorded the write as `inconclusive` ("explicit sharing relationship explains the write") and produced no L3 finding |
| Mislabelled authorized checks | `TaintAnalyzer._graph_l3()` called `_record()` after a confirmed grant, so an explained write was appended to `inconclusive` | Any confirmed grant in graph mode increased `inconclusive_checks` without a violation |
| False CLEAN | `ValidationResult.verdict` returned `CLEAN` whenever `coverage.meaningful` and `finding_count == 0`, regardless of unresolved checks | A scan with one resolved resource and one write whose database row could not be mapped uniquely still returned `CLEAN` |
| Merged coverage | `ScanCoverage` had global counters only; completed L2 probes could stand in for an unresolved L3 check | A read grant plus an unresolved write check satisfied the old clean condition |

The RED suite was authored before the production change. Its first run failed
at collection with `ImportError: cannot import name 'AuthorizationOutcome' from
'mizan.core'`, which is itself the missing result model. The behavioural cases
target the two intended pre-fix reasons: a read grant suppressing L3 (and being
recorded as inconclusive), and a `CLEAN` verdict with an unresolved L3 counter.
Both paths were corrected in the implementation below and are now green.

## 3. Root-cause analysis

- The contract parser stored a four-field tuple
  `(resource_fk, principal_fk, semantics, table)` and validated only table,
  column and foreign-key shape. It had no operation dimension, so the only
  possible authorization decision was "grant / no grant".
- `explained_by_sharing` bound a subject and an object but not an action, and
  accepted `MEMBER_OF` as well. Every confirmed relationship therefore applied
  to every operation.
- All three call sites (L2 probe, L3 probe, `TaintAnalyzer._graph_l3`) used that
  action-agnostic predicate. Both the direct and the ledger path shared the
  defect, and a confirmed grant was mislabelled as inconclusive instead of
  being counted as a decision.
- `ScanCoverage.meaningful` described discovery and probe execution, not the
  outcome of individual checks. `ValidationResult.verdict` treated the absence
  of findings as proof of safety, so an unresolved check could not change the
  verdict. There was no per-law denominator to consult.

## 4. New action-scoped grant contract

```json
{
  "version": 1,
  "identity": { "endpoint": "/whoami", "field": "p_key" },
  "ownership": {
    "assets": { "source": "database_foreign_key", "column": "originator_ref" }
  },
  "sharing": {
    "item_relations": {
      "resource_fk": "item_ref",
      "principal_fk": "collaborator_ref",
      "semantics": "authorization_grant",
      "actions": ["read"]
    }
  }
}
```

Supported actions are `read` and `write` — exactly the values returned by
`core.actions_for`: `read` for GET/HEAD/OPTIONS, `write` for
POST/PUT/PATCH/DELETE. L2 uses `read`, L3 uses `write`; there is one operation
vocabulary. The contract tuple is now
`(resource_fk, principal_fk, semantics, table, frozenset(actions))`, and a
confirmed `SHARED_WITH` relationship carries that action set.

Strict contract validation (`RelationshipContract.from_dict(..., strict=True)`
and `RelationshipContract.load(..., strict=True)`) rejects, with a named
diagnostic:

- a missing or empty `actions` field;
- an action outside `{read, write}` (the offending value is named);
- a non-array or non-string action value;
- an invalid action declaration in a variant override (the override is
  re-validated with the same rules).

Duplicate values are normalized deterministically into a set. Lenient mode
drops an undeclared or invalid grant entirely (least permissive) instead of
inventing permissions. `validate_schema()` still requires the exact table,
`resource_fk`, `principal_fk`, anchored principal and uniquely mapped resource;
no ownership inference was introduced.

`OwnershipGraph.explained_by_sharing(owner, other, resource_key, action)` now
requires an action and returns `True` only for a `CONFIRMED` `SHARED_WITH`
relationship with the exact `other` principal, exact `resource_key`, and the
action in its declared scope. `MEMBER_OF`, candidates, ambiguous and
contradicted relationships never suppress a finding. All three call sites were
updated; the engine passes `"read"` in L2 and the event's action in L3 and the
analyzer.

## 5. Backward-compatibility behavior

- A contract file without `sharing` is unchanged; no grant exists.
- An old declaration with `semantics: authorization_grant` but no `actions` is
  a configuration error in strict mode and is dropped in lenient mode. It is
  never interpreted as permission for all operations.
- Repository-owned contracts (`adversarial_store`, `linked_store`) now declare
  actions explicitly; all variant overrides were updated too.
- Graph serialization does not lose action scope: `Relationship.to_dict()`
  emits a sorted action list and `from_dict()` restores it.
- Old ledgers without `row_key` still load. Ledger-only deployments keep the
  historical policy-level analyzer; the graph is used only for
  database-backed scans.
- No proof-bundle, SARIF, replay, masking or token-handling format changed.

## 6. Changes to L2 and L3 authorization decisions

| Path | Before | After |
|---|---|---|
| L2 direct probe | any confirmed sharing suppressed the finding; grant recorded as inconclusive | only a confirmed **read** grant resolves the check as `ALLOWED_BY_GRANT`; a refusal or no disclosure is `DECIDED`; a proven disclosure is `VIOLATION` |
| L3 direct probe | any confirmed sharing suppressed the write | only a confirmed **write** grant resolves it; a read grant does not; refused writes are `DECIDED` |
| `TaintAnalyzer._graph_l3` | confirmed sharing appended an inconclusive reason | grant produces `ALLOWED_BY_GRANT` with no inconclusive reason; a read grant yields an L3 `VIOLATION` |
| Direct probe ↔ analyzer | could disagree on the same event | both use the same graph, action and deduplication key; the same write yields one finding |

The exact adversarial case uses the independent `adversarial_store` fixture:
the collaborator FK on `item_relations` declares `actions: ["read"]`, the app
returns `item-alice-1` to Bob, but rejects his `PUT`. Result: **L2 no finding**
(the read is explained by the grant) and **L3 one finding** (the write is not).

## 7. New per-law coverage model

`ScanCoverage.laws` holds `LawCoverage` records keyed by law. Each record has:

- `eligible` — checks that could legitimately run (the denominator);
- `attempted` — eligible checks actually started;
- `decided` — decisions without a grant;
- `allowed_by_grant` — decisions resolved by a confirmed, scoped grant;
- `findings` — proven violations;
- `inconclusive` — attempted checks that could not be decided.

Derived fields are explicit: `resolved` (decided + grant + findings),
`unresolved`, `pending` (eligible − attempted), `attempt_rate` and
`resolution_rate`, all with `eligible` as the denominator. L2 and L3 are never
merged, and the counts are exposed through `coverage.to_dict()["laws"]`.
Eligibility now counts individual checks (per object and identity for L2, per
`(attacker, resource, method)` for L3), not probe groups. HTTP request counts
are reported separately and are never used as coverage.

## 8. Exact verdict invariants

1. Setup or execution error (`setup_error` / `error`) ⇒ `ERROR`.
2. `finding_count > 0` ⇒ `FINDINGS`, even if coverage is incomplete.
3. `CLEAN` only if meaningful coverage, at least one law with `eligible > 0`,
   and for every relevant L2/L3 law `pending == 0` and `unresolved == 0`, with
   the request budget not exhausted.
4. Confirmed grants count as `allowed_by_grant` (resolved), never as
   unresolved checks.
5. Any relevant eligible-but-unattempted or unresolved check, budget
   truncation, or lack of meaningful eligible coverage ⇒ `INCONCLUSIVE`.
6. Repeated inconclusive records are deduplicated by
   `(law, action, resource, principal, outcome)`; a grant can never inflate an
   unresolved counter, and an unrelated candidate sharing row cannot by itself
   invalidate a scan.

## 9. Adversarial test matrix (expected → actual)

| Scenario | Expected | Actual |
|---|---|---|
| Owner-only read (`clean`) | no finding | no finding |
| Explicit read grant, legitimate read (`grant`) | no L2 | no L2; L2 `allowed_by_grant` ≥ 1 |
| Explicit read grant, unauthorized write (`grant_write`) | L3 only | L3 only; L2 `allowed_by_grant` ≥ 1 |
| Explicit read+write grant, read (`read_write_grant`) | no L2 | no L2 |
| Explicit read+write grant, write (`read_write_grant`) | no L3; CLEAN | no L3; CLEAN |
| Write-only grant, unauthorized read (`write_only_grant`) | L2; no L3 | L2; no L3 |
| Creator FK with no grant (`creator_only`) | L2 | L2 |
| Observer FK with no grant (`observer_only`) | L2 | L2 |
| Wrong principal FK in contract (`declared_creator`) | L2 | L2 |
| Candidate relationship | no suppression | no suppression |
| Ambiguous/contradicted relationship | no suppression | no suppression |
| Candidate ownership / unmapped row / unresolved identity | INCONCLUSIVE | INCONCLUSIVE |
| Budget exhausted before required checks | INCONCLUSIVE | INCONCLUSIVE |
| Setup / execution failure | ERROR | ERROR |
| Mixed resolved resource + unmapped write | not CLEAN | INCONCLUSIVE |
| Serial and parallel CLI (`grant_write`, `read_write_grant`) | same action scope | same action scope |

Concrete example: Bob reads `assets:item-alice-1` under a read-only grant —
outcome `ALLOWED_BY_GRANT`, no L2 finding. The same Bob writes the same row —
outcome `VIOLATION`, one L3 finding. In a second scan where the write is
permitted by a read+write grant but another resource's write has no unique row
mapping, the unresolved L3 check forces `INCONCLUSIVE`: an inability to map the
row is never treated as proof that the write was safe.

## 10. Full regression results

- **Full `pytest` suite:** `556 passed, 1 warning in 455.82s` (508 pre-existing
  + 48 new Phase V.2.1 tests). No test was deleted, skipped, relaxed or
  excluded. The warning is an unrelated Starlette/httpx deprecation notice.
- **New failing-first suite:** `tests/test_phase_v2_1_soundness.py` — 48 tests
  covering contract validation, action-scoped graph queries, analyzer outcomes,
  the verdict matrix, per-law separation and real serial/parallel CLI pipeline
  runs. RED evidence is recorded in section 2.
- **Existing security/adversarial/independence gates:** 92 passed for
  `test_adversarial_store.py`, `test_linked_store.py`,
  `test_phase_v2_integration.py`, `test_ownership_graph.py` and
  `test_ownership_semantics.py`; 120 passed for the combined cross-framework
  test module, adversarial suite, PostgreSQL audits, Mīzān-scans-Mīzān
  (`test_dogfood.py`), evidence integrity, SARIF and replay regression modules.
- **Cross-framework benchmark:** `--repetitions 1` — **8/8 scenarios as
  expected** (2 frameworks × 4 variants), 8 true positives, 0 false positives,
  0 false negatives, 8/8 reproductions, 14 requests per scenario.
- **Independent application / self-scan / PostgreSQL / security regression:**
  included in the full suite and in the 120-test gate run above, all passing.
- **Ownership benchmark:** 21 cases, all denominators in section 11;
  `results.json` regenerated from clean workspaces.
- **Static gates:** `ruff check src tests benchmarks` — all checks passed;
  `ruff format --check src tests benchmarks` — 82 files already formatted;
  `git diff --check` — clean (no trailing whitespace).

## 11. Benchmark metrics with denominators

`python -m benchmarks.ownership.run` — 21 cases, budget 90 per scan, fixed
fixture identifiers and a fresh workspace per case (no reuse). Full data is in
`benchmarks/ownership/results.json`.

| Metric | Result | Denominator |
|---|---|---|
| Law detection, all expected laws | 12 detected | 12 eligible cases |
| L2 detection | 8 detected | 8 cases expecting L2 |
| L3 detection | 5 detected | 5 cases expecting L3 |
| Clean-control false positives | 0 findings | 9 clean controls |
| Read-only grants (`grant`, `grant_write`) | 1 L3 finding, 0 L2 findings | 2 cases; L2 resolved by grant 2×, L3 by grant 0× |
| Read+write grant | 0 false-positive findings | 1 case |
| Write-only grant | 1 L2 finding, 0 L3 allowed-by-grant | 1 case |
| Incorrect grant suppression | 0 suppressed | 4 action-scope cases |
| L2 per-law coverage | 44 eligible / 44 attempted / 26 decided / 4 allowed-by-grant / 14 findings / 0 inconclusive | 44 eligible L2 checks |
| L3 per-law coverage | 47 eligible / 47 attempted / 34 decided / 1 allowed-by-grant / 9 findings / 3 inconclusive | 47 eligible L3 checks |
| Inconclusive classification | 3 correct | 3 cases expected inconclusive |
| Duplicate findings | 0 L2, 0 L3 | 21 cases |
| Resource↔row mapping | 44 resolved | 50 discovered resources |
| Requests consumed | 400 | 21 scans × budget 90 (1,890 available) |
| Invalid contracts rejected | 9 | 9 invalid contracts |
| Duplicate actions normalized | 1 | 1 normalization case |
| Principal-FK selection | 3 detected | 3 eligible cases |
| CLI contract propagation | 1 propagated | 1 case; 0 invented ownership without contract (1 control) |

## 12. Remaining technical limitations

- The contract is trusted operator-provided metadata. It declares intent; it
  does **not** prove that the target application enforces it. Behavioral
  enforcement is still tested through observations and attributed writes.
- A grant cannot be confirmed without an anchored principal and a unique API
  resource mapping; an unanchored identity or unmapped row is reported as
  unresolved, not as a finding.
- Only single-column resource/principal foreign keys are supported; composite
  grant keys remain rejected.
- Ownership-graph evidence is SQLite-specific. PostgreSQL deployments keep
  their existing behavior; no claim is made that they support the new
  SQLite-specific graph semantics.
- A refused or unmapped write is not a proven violation; where a write cannot
  be attributed to a unique API resource, the scan returns `INCONCLUSIVE`
  rather than guessing.
- No new law was added and JWT subjects are still extracted, not verified.

## 13. Final exact commit SHA

Implementation commit: `94bb98a78680f0f9b9071df85773694413c69462`
(`feat(authz): scope grants by action and harden verdict soundness`). It is the
commit whose code, tests, fixtures, benchmark and CI results are measured in
this report. A documentation-only follow-up commit adds this report to the
branch; its SHA is recorded in the final delivery message. Both commits are on
`feat/ownership-graph-v1`, and local and remote heads match after the final
push.

## 14. CI run ID and results on that exact SHA

GitHub Actions run **`44102170895`** (run number **225**) on the exact
implementation SHA `94bb98a78680f0f9b9071df85773694413c69462`:
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
| G — external target (opt-in) | **skipped by design — not passed** |

The optional external-target job is opt-in and was skipped; it is reported as
skipped, not as a passed gate. All seven mandatory jobs succeeded on the exact
SHA above.

PR #9 remains open and unmerged; `main` was not modified. Local and remote
`feat/ownership-graph-v1` heads match the final SHA.
