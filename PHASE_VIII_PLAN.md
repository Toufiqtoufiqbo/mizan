# Phase VIII implementation plan

Baseline: `c131faecb5438617aeaa31ba4e23a4dc752ad46a` (merged main, verified).
Branch: `feat/phase-viii-pg-l4-l6`.

## Audit (baseline)
- origin/main == expected baseline; PR #11/#12 branches untouched.
- Post-merge CI #288 in progress, no mandatory failure observed so far.
- Smoke tests: 40 passed (regression, states, benchmark validation, packaging).

## Architecture decisions
- No second attack engine. Both laws live in `Mizan` and reuse ownership graph,
  ledger/attribution, disposable twin and proof/regression pipeline.
- New *trusted* law declarations in `RelationshipContract`:
  - `authority.fields`: protected field + source + confidence + authorized roles.
  - `cardinality`: bound, scope, unit, source, enforcement, table.
  Name heuristics alone never classify a field or an invariant.
- L4 evidence: original row state -> real HTTP mutation -> audit event with
  confirmed attribution and persisted column value -> state readback. Response
  echo and status 200 are never proof.
- L6 evidence: declared invariant -> before count/consumption -> boundary
  operations -> after count/consumption from database state. L6 gets its own
  probe group and execution record, independent of L5.

## Files
- `src/mizan/ownership.py` — law declarations, parsing and validation.
- `src/mizan/engine.py` — L4/L6 probes, outcomes, coverage states.
- `src/mizan/regression.py`, `src/mizan/proof.py` — law evidence serialization.
- `tests/fixtures/external_apps/postgres_store/app.py` — create/capability
  endpoints and vulnerable/secure variants.
- `tests/test_pg_l4_l6.py`, `tests/test_law_policy.py` — new tests.
- `README.md`, `ROADMAP.md`, `PHASE_VIII_REPORT.md`,
  `PHASE_VIII_L7_FEASIBILITY.md` — documentation.
- `benchmarks/postgres_engine/run.py` — per-law workloads (P1).

## Increments
1. plan
2. trusted law policy schema + tests
3. L4 probe + evidence + proof/regression + tests
4. L6 invariant + probe + tests
5. coverage consistency, CLI, benchmark, docs
6. full verification, PR, report
