# Mīzān Phase VI — PostgreSQL Ownership Graph Parity

## 1. Original architectural gap

PostgreSQL had trigger-based write auditing (`PostgresAuditor`) but no provider
for the engine's database view. `Mizan.learn()` called `attributor.schema()` and
`attributor.rows()` only when present; with no such provider a PostgreSQL scan
silently degraded to ledger-only mode — no ownership graph, no confirmed
ownership, and weaker L2/L3 semantics. The audit cursor used timestamps, row
identity for composite keys was delimiter-joined in alphabetical order, there
was no request correlation, and the CLI had no PostgreSQL interface. The full
gap analysis is in `PHASE_VI_POSTGRES_GAP_AUDIT.md`.

## 2. Implementation design

- `src/mizan/attribution.py`: `DatabaseAttributor` protocol, `AuditCursor` and
  `AttributionUnavailable`; `SqliteAttributor` keeps its behavior and now accepts
  ignored request-context keywords.
- `src/mizan/postgres_attribution.py`: `PostgresAttributor` supplies
  schema-qualified `DatabaseSchema`, rows, snapshot/diff and row identity to the
  existing `build_ownership_graph()`; explicit schema allowlist; monotonic
  cursor; transaction-local request correlation; explicit attribution states.
- `src/mizan/postgres_audit.py`: audit table/function record `mizan.request_id`;
  `read(since_id=...)` orders by the `BIGSERIAL id`; old 9-column event rows
  still load. Trigger installation remains an explicit operation.
- `src/mizan/taint.py`: `WriteEvent.attribution` distinguishes confirmed,
  unknown-principal, missing-request and ambiguous writes; only confirmed
  writes can become L3 findings.
- `src/mizan/ownership.py`: contract declarations resolve bare or qualified
  table names and reject ambiguous bare names; ownership declarations may name
  the database table explicitly.
- `src/mizan/engine.py`: each request receives a unique correlation id, passes
  it to `snapshot()`/`diff()` and sends it as `X-Mizan-Request-Id`; unconfirmed
  writes are recorded as inconclusive.
- `src/mizan/cli.py`: `mizan postgres-evidence --dsn-env ... --schema ...`.
  Read-only, redacts the DSN, requires `--install-audit` for schema changes,
  and refuses to claim attack support.
- `.github/workflows/mizan.yml`: stage B runs both PostgreSQL test modules and
  the new benchmark with `MIZAN_REQUIRE_POSTGRES=1`; skips fail the job.

## 3. Changed files

`PHASE_VI_POSTGRES_GAP_AUDIT.md`, `README.md`, `ROADMAP.md`,
`PHASE_V_DESIGN.md`, `.github/workflows/mizan.yml`,
`src/mizan/{attribution,engine,taint,ownership,postgres_audit,postgres_attribution,cli}.py`,
`tests/test_postgres_attribution.py`,
`tests/test_postgres_ownership_integration.py`,
`tests/fixtures/external_apps/postgres_store/*`,
`benchmarks/postgres_ownership/*`, and this report.

## 4. Test counts and actual outputs

- **Full `pytest` suite:** `624 passed, 1 warning in 370.23s` (all tests,
  including PostgreSQL integration modules, actually ran locally; no skips).
- **PostgreSQL unit tests** (`tests/test_postgres_attribution.py`): 12 passed —
  interface, monotonic cursor, request correlation, all four attribution
  states, contract table resolution and SQLite backward compatibility.
- **PostgreSQL integration tests**
  (`tests/test_postgres_ownership_integration.py`): 16 passed against a real
  `pgserver` instance — schema-qualified introspection, composite keys/FKs,
  unique indexes, ambiguous bare table rejection, cursor ordering, rollback,
  pooled identity cleanup, candidate vs confirmed ownership, and L3 findings.
- **Independent fixture self-validation:** parametrized clean/read/write and
  read-only/write-scoped grant scenarios verify the fixture's own behavior
  using its HTTP API before Mīzān inspects it.
- **CLI:** `mizan postgres-evidence` runs read-only, reports `INCONCLUSIVE`,
  requires explicit `--install-audit` for schema changes and never prints the DSN.
- **Legacy PostgreSQL round trip:** all 15 tests still pass; `auditor.read()`
  keeps its historical behavior and explicit attribution states are set by the
  new provider only.
- **Stage A locally:** `593 passed, 31 deselected, 0 skipped` with
  `-m "not postgres_integration"`.
- **Static gates:** `ruff check`, `ruff format --check`, `git diff --check` clean.

## 5. Benchmark results with denominators

`python -m benchmarks.postgres_ownership.run` — 8 controlled scenarios, each
with its own disposable schema, one request per scenario, independent expected
outcomes and a separate checker (`benchmarks/postgres_ownership/check.py`).
Result: **8 passed / 8 scenarios**; zero deviations, zero skipped scenarios.

| Metric | Result | Denominator |
|---|---|---|
| Scenarios passed | 8 | 8 scenarios |
| Confirmed-ownership checks | 7 | 8 scenarios |
| Candidate-ownership checks | 1 | 8 scenarios |
| Unknown-ownership checks | 1 | 8 scenarios |
| L3 findings | 3 | 8 scenarios |
| L3 inconclusive outcomes | 2 | 8 scenarios |
| Resolved through grant | 1 | 8 scenarios |
| Attribution failures | 1 | 8 scenarios |
| Requests consumed | 8 | 8 scenarios × 1 request |
| False positives / false negatives | 0 / 0 | 8 scenarios |

These numbers describe a small controlled fixture only; they are not a claim
of general PostgreSQL accuracy.

## 6. Database restoration guarantees

**Phase VI.1 addendum:** a disposable PostgreSQL Twin now exists
(`postgres_twin.py`) with immutable seed cloning, per-worker databases,
canonical baseline verification and idempotent cleanup. PostgreSQL attack/twin
execution is available through `mizan postgres-twin --allow-disposable`; see
`PHASE_VI_1_POSTGRES_TWIN_REPORT.md` for the demonstrated guarantees. The
statements below describe Phase VI at the time it was written.

**PostgreSQL attack/twin mode is not implemented and fails closed.** `Twin`
restores filesystem snapshots of file-backed data; a live PostgreSQL database
cannot be restored that way. No disposable clone, no per-worker schema restore
and no verified isolation strategy exists. The `postgres-evidence` command
performs no attacks and reports `INCONCLUSIVE`. Claiming PostgreSQL twin parity
would be false; see the gap audit for the required design.

## 7. Remaining limitations

- PostgreSQL ownership evidence is verified against a controlled fixture and a
  small benchmark; no generalization to arbitrary production schemas is claimed.
- The contract remains trusted metadata: it declares intent, not application
  enforcement.
- `application_name` and request correlation are metadata, not authentication.
  They are only as trustworthy as the application's control of its connections.
- Background writes without request correlation are recorded as inconclusive
  and are not folded into nearby HTTP requests.
- Composite row identity is canonical in `row_key`; the legacy trigger `row_id`
  remains a compatibility field.
- SQLite behavior, proof bundles, replay and SARIF compatibility are preserved.

## 8. Explicitly unsupported scenarios

- PostgreSQL end-to-end attack/twin/parallel probing (no disposable restoration).
- Automatic trigger installation or reset of a production/shared database.
- Unqualified table declarations when several allowlisted schemas match.

## 9. Exact implementation SHA

`37b507b6a7ba7ef2016f381ca852bea8986e8674`
(`feat(postgres): add ownership evidence provider and safe attribution`). This
is the commit whose code, tests, fixture, benchmark and CI results are measured
above.

## 10. Exact final HEAD SHA

The documentation-only commit adding this report is the final HEAD of
`feat/postgres-ownership-graph`; its exact SHA is recorded in the final delivery
message. Local and remote heads match after the final push. `main` and
`stash@{0}` are unchanged.

## 11. CI run IDs and job conclusions

- Implementation commit `37b507b` was verified with workflow dispatch run
  **44177549441** (#232): conclusion **failure**. Jobs B (PostgreSQL), C
  (security regression), D (benchmark), E (self-scan), F (independent
  application) and G (cross-framework) succeeded; G external target was
  `SKIPPED`. Job A failed only in "No skipped tests": the new PostgreSQL
  integration module resolved its server at import time, which pytest counted
  as a skip when stage A deselected `postgres_integration`. No test failed.
- This was fixed by resolving the DSN lazily inside executing fixtures only.
  Local stage A now reports `593 passed, 31 deselected`, zero skipped.
- A second CI run exposed a timing-dependent `INCONCLUSIVE` in the adversarial
  `clean` control: writes to rows created only by mutation probes, with no
  discovered API resource, were counted as unresolved checks. Their relevance
  filter now requires a known resource key, table, or row identity; genuinely
  ambiguous mappings for known resources remain inconclusive. Local stage A,
  V.2.x soundness suites and both benchmarks pass after the fix.
- The CI run ID and conclusions for the final HEAD are recorded in the final
  delivery message. The optional external-target job remains `SKIPPED`, not
  `PASSED`.
