# Phase VIII — PostgreSQL Security Law Expansion

## 1. Verdict

_TBD after final verification._

## 2. Baseline and final SHA

- Baseline / merged `origin/main`: `c131faecb5438617aeaa31ba4e23a4dc752ad46a`
- Final SHA: `_TBD_`
- Branch: `feat/phase-viii-pg-l4-l6`

## 3. Architecture audit

- Verified `origin/main` equals the expected baseline; PRs #11/#12 branches and
  `main` were never modified.
- Post-merge CI #288 on the baseline: mandatory jobs were in progress at audit
  time; the pre-change smoke suite was green (40 passed).
- L4 previously used authority-field name heuristics and response echo; L6 was
  only inferred from L5 races. Neither had an independent evidence path.

## 4. L4 implementation and evidence

- Trusted `authority.fields` declarations in `RelationshipContract` require a
  field, source, confidence and optional authorized roles. A field name alone
  never creates a policy.
- Probe: original state from the learning snapshot → real HTTP method and
  actor → attributed database write whose persisted column carries the
  controlled sentinel → state readback path for regressions.
- Outcomes: unauthorized persisted mutation (finding), blocked/no persisted
  change (decided), unattributed mutation (inconclusive), missing policy/readback
  (unsupported). Response echo and HTTP 200 are never proof.

## 5. L4 fixture results

- `l4_vulnerable`: one confirmed `L4` finding, evidence `field=role`,
  `original_value=user`, `attempted_value=mizan-probe-role`,
  `persisted_value=mizan-probe-role`, `attribution=confirmed`,
  `state_verification=attributed database write`, confidence `confirmed`,
  policy source `trusted_application_policy`.
- `l4_secure`: no `L4` finding — the same mutation is rejected and no attributed
  persisted role change exists.
- Generated regression for the vulnerable finding verifies the role in a state
  readback; it does not rely on status or response echo.

## 6. L6 invariant model

- Explicit `cardinality` declarations with bound, scope (`principal`/`global`),
  unit, source and enforcement (`reject_beyond` or `single_use`).
- Supported categories verified: per-principal collection bounds and single-use
  capabilities. Bound-input arrays and global quotas are declared but not yet
  fixture-verified (see section 16).
- L6 has its own probe group and execution record; a race is classified as L5
  whenever an explicit L6 invariant is available.

## 7. L6 boundary and concurrency results

- Collection bound: per principal, maximum 2 objects. At the vulnerable
  variant, `initial_count` 1 → `final_count` 4 after 3 creates (alice), and
  0 → 3 (bob); both exceed the bound and are findings verified from database
  row counts.
- Single-use capability: two sequential uses of `cap-alice` produced two 200
  responses and a persisted consumption record, reported as an L6 violation.
- `l6_secure`: no `L6` finding — quota and single-use checks block the boundary
  violations. A race on the capability endpoint is classified as `L5`, not `L6`,
  when the explicit invariant is available.

## 8. Per-law coverage matrix

| Law | Generic/SQLite | PostgreSQL | Evidence basis |
|---|---|---|---|
| L1 | supported | supported | trusted identity endpoint |
| L2 | supported | supported | confirmed ownership |
| L3 | supported | supported | confirmed attributed write |
| L4 | partial | **supported** | trusted protected-field policy + persisted state |
| L5 | supported | partial | POST race probe |
| L6 | partial | **supported** | explicit cardinality invariant + database state |
| L7 | unsupported | unsupported | no indirect-path provider |

`laws_executed` remains derived from real probe records. A declared L6 produces
`supported=True, skipped=False` only when a cardinality invariant exists;
otherwise it stays unsupported, never an L5 by-product.

## 9. Proof and regression validation

- L4 proof bundles contain actor, resource, original HTTP method, protected
  field, original/attempted/persisted values, expected invariant, policy source,
  confidence, attribution, state verification path and explicit outcome.
- L6 proof bundles contain the invariant (bound, scope, unit, source,
  enforcement), initial/final counts, operation count, statuses and the
  verification method.
- `mizan replay` reproduces the L4 attack from bundle evidence; `mizan regress`
  generates a state-verifying L4 regression and an explicit `unsupported` skip
  for L6 (no HTTP cardinality state endpoint is available in the fixture).

## 10. PostgreSQL lifecycle and safety

No ownership, OID, marker, deletion-intent or cleanup control was changed. The
same disposable twin and verified-drop path is used; probes fail closed when
state evidence is missing (`tests/test_law_failure_modes.py`).

## 11. Benchmark results by law

| Law | variant | learning | resources | rules | eligible | attempted | executed | findings | DB ops | duration |
|---|---|---|---|---|---|---|---|---|---|---|
| L4 | `l4_vulnerable` | 10 | 3 | 3 | 4 | 2 | 1 | 1 | 2 | 4.2871 s |
| L6 | `l6_vulnerable` | 10 | 3 | 3 | 4 | 4 | 1 | 3 | 8 | 5.1380 s |

Both law workloads are measured on their own disposable worker with the
`mizan-laws.json` policy and `openapi-laws.json` traffic. The benchmark fails if
either executes zero probes. The main replicated workload remains unchanged and
still reports no speedup.

## 12. Tests

_TBD._

## 13. CI

_TBD._

## 14. Remaining limitations

- Generic/SQLite L4 and L6 remain partial; only PostgreSQL has the new
  declaration-backed evidence path.
- L6 proof bundles intentionally produce an `unsupported` regression unless an
  HTTP state endpoint is supplied; status-only regressions are not generated.
- Bounded input collections (OpenAPI `maxItems`) are treated as input contracts,
  not as server-side resource quotas.
- Single-use capability concurrency is detected as L5 when a real race occurs;
  L6 requires the persisted consumption evidence.

## 15. L7 feasibility

See `PHASE_VIII_L7_FEASIBILITY.md`. L7 remains `unsupported` for both backends;
no weak detector was added.

## 16. Outstanding technical debt

- Add provider interfaces for cache/queue/log/metric L7 evidence.
- Extend L6 to bounded input collections and global quota verification.
- Extend L4 declarations to relationship-based authority changes.

## 17. Git state

_TBD._
