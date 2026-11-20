# Phase VI — PostgreSQL Ownership Graph Parity: Mandatory Gap Audit

Audit date: 2026-11-17. Verified starting point: `main` at
`0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238` (PR #9 merged), clean working tree,
`stash@{0}` preserved. Work branch: `feat/postgres-ownership-graph`.

This audit was completed before any production edit. It records what exists,
what is missing, and which guarantees cannot be claimed yet.

## 1. Files audited

- `src/mizan/attribution.py` (389 lines) — schema/snapshot/diff attributor.
- `src/mizan/postgres_audit.py` (460 lines) — trigger-based write auditor.
- `src/mizan/ownership.py` (1,192 lines) — evidence graph and contract parsing.
- `src/mizan/engine.py` (1,789 lines) — learning, probes, attribution, coverage.
- `src/mizan/cli.py`, `src/mizan/twin.py` — runtime and filesystem restoration.
- `tests/test_postgres_audit.py`, `tests/test_postgres_roundtrip.py`.
- `.github/workflows/mizan.yml` (stage B — PostgreSQL).

## 2. Existing PostgreSQL capabilities

- `PostgresAuditor` generates safe, schema-qualified SQL
  (`quote_identifier`, `qualified_name`), installs a trigger function and
  per-table triggers, and records row images in `mizan_write_audit`.
- It already handles INSERT/UPDATE/DELETE, UUID/text/composite primary keys and
  tables without a primary key (`IDENTITY_NONE`) at the SQL-generation level.
- Identity is taken from transaction-local `application_name` via `SET LOCAL`
  / `set_config(..., true)`. `principal_from()` maps an absent or malformed
  name to `UNKNOWN_PRINCIPAL` (never an arbitrary identity).
- Rolled-back writes are not recorded (trigger rows participate in the
  transaction) and a pooled connection does not leak a `SET LOCAL` identity.
  These behaviors are covered by `tests/test_postgres_roundtrip.py` against a
  real server (CI stage B sets `MIZAN_REQUIRE_POSTGRES=1`).
- `PostgresLogParser` can parse statement logs into write events, but it is a
  separate legacy path and does not supply schema or rows.
- `ownership.py` already expresses relationships and evidence states
  independently of a backend, provided it receives a `DatabaseSchema` and row
  dictionaries.

## 3. Missing PostgreSQL capabilities

1. **Attribution interface.** `PostgresAuditor` has `schema`-like helpers only
   (`user_tables`, `primary_key_columns`); it has no `schema()`,
   `rows(table)`, `snapshot()`, `diff()` or `row_identity()`. The engine's
   `learn()` calls only `attributor.schema()` and `attributor.rows(name)` when
   present, then passes the result to `build_ownership_graph()`. Without a
   provider, a PostgreSQL scan silently becomes ledger-only: no graph, no
   confirmed ownership, and weaker L2/L3 semantics.
2. **Snapshot/diff.** `engine._request()` calls
   `attributor.snapshot()` before each request and `attributor.diff(...)`
   afterwards. PostgreSQL cannot cheaply diff whole tables, so the provider
   must use an audit cursor while preserving the same `WriteEvent` contract.
3. **Stable cursor.** `PostgresAuditor.read(since=...)` filters on
   `occurred_at > %s`. Timestamps are not a monotonic event identity: two
   writes in one microsecond, clock adjustment or replication delay can drop
   or duplicate events. The audit table has a `BIGSERIAL id` and already
   orders by it, but `read()` does not expose it as a cursor.
4. **Request correlation.** An `application_name` principal alone cannot
   distinguish two concurrent requests by the same principal, or a background
   worker writing under that principal. There is no request identifier in the
   audit record, and no propagation from the scan proxy into a transaction-local
   PostgreSQL setting. Attribution is therefore ambiguous under concurrency.
5. **Composite row identity.** The trigger builds `row_id` with
   `string_agg(... ORDER BY column_name)`, i.e. alphabetical order and a
   delimiter-joined scalar. `ownership.parse_identity()` expects a canonical
   JSON array for composite keys, and `WriteEvent.row_key` must match the
   graph's `canonical_key()`. Composite-key writes therefore cannot be mapped
   reliably to the graph.
6. **Schema-qualified identity.** `DatabaseSchema.tables` is keyed by a bare
   table name and `RelationshipContract.validate_schema()` looks up
   `schema.get(table)`. Two PostgreSQL schemas containing the same table name
   collide or resolve to an arbitrary table. No qualification rule exists.
7. **Ownership evidence for foreign keys.** `primary_key_columns()` exists,
   but there is no catalog reader for columns, NOT NULL/UNIQUE flags, or
   foreign keys (including composite FK ordering and target resolution).
   Without it, `build_ownership_graph()` cannot apply any of its rules.
8. **Explicit opt-in for database changes.** `PostgresAuditor.install()`
   creates a schema, table, function, index and triggers by default;
   `uninstall()` drops them. Nothing in the CLI requires an explicit opt-in,
   and nothing prevents instrumentation outside an allowlisted schema.
9. **No CLI/runtime integration.** `cli.py` has no PostgreSQL option;
   validation launch specs know only SQLite-style fixture conventions.
10. **No restoration strategy.** `Twin.snapshot()`/`restore()` copy files in
    `data_paths`. A PostgreSQL connection is not a file: restoring an ordinary
    shared database by copying files is unsafe and would not isolate parallel
    probes. No disposable clone/restore mechanism exists.
11. **No independent PostgreSQL fixture or benchmark.**
    `tests/fixtures/external_apps/postgres_store/` and
    `benchmarks/postgres_ownership/` do not exist. Existing PostgreSQL tests
    exercise the auditor in isolation, not the L2/L3 ownership pipeline.
12. **Secret handling not exercised end-to-end.** No CLI path exists that
    could accidentally echo a DSN; a DSN option must read from an environment
    variable and redact errors.

## 4. Exact interface required by the ownership graph

`build_ownership_graph()` consumes:

```
resources: dict[str, Resource]
traffic: Iterable[Observation]
ledger: Iterable[WriteEvent]
schema: DatabaseSchema | None
rows: dict[str, list[dict[str, Any]]]   # keyed exactly like schema.tables
contract: RelationshipContract | None
```

`DatabaseSchema` requires `TableSchema(name, columns, foreign_keys)` with
`Column(name, type, primary_key (1-based), not_null, unique)` and
`ForeignKey(column, table, column_ref, composite)`. Therefore a PostgreSQL
provider must expose:

- `schema() -> DatabaseSchema` with deterministic, schema-qualified keys;
- `rows(table) -> list[dict]` for every key returned by `schema()`;
- `snapshot()` and `diff(before, *, principal, method, path, request_id,
  source_fields) -> list[WriteEvent]`;
- an audit cursor returning every event exactly once in insertion order;
- explicit unavailable-state reporting (never an empty schema that looks like
  an empty database).

## 5. Transaction and request-attribution risks

- `application_name` is metadata, not authentication. It must never become an
  authorization identity by itself; the authenticated HTTP principal remains
  authoritative.
- A request-level correlation value must be unique per request, propagated by
  the recording proxy, stored in a transaction-local setting, and recorded in
  the audit row. It must be treated as correlation only — never as a principal.
- Four attribution states must remain distinct: **confirmed principal+request**,
  **unknown principal**, **missing request correlation**, **ambiguous
  attribution**. Only the first may support an L3 finding; the rest must be
  explicit inconclusive outcomes.
- Cursor reads must be ordered by the monotonic audit id, not time.
- Background writes without a request context must be reported as
  unattributed, not folded into the nearest HTTP request.
- Transaction-local settings must be cleared at request boundaries so pooled
  connections cannot leak identity or correlation state.

## 6. Database reset and isolation requirements

- The existing `Twin` restores filesystem snapshots; this is meaningful only
  for file-backed SQLite data.
- Before PostgreSQL attack mode is considered safe, a disposable database or
  schema clone must be created per worker and restored deterministically
  between probes, with the audit schema/triggers recreated inside it.
- A shared or production database must never be auto-reset. Without a verified
  disposable clone, PostgreSQL attack mode must fail closed and be documented
  as unsupported rather than exposed as a safe twin.
- Schema allowlists must prevent trigger installation outside configured
  schemas, including schemas with identical table names.

## 7. Backward-compatibility risks

- `SqliteAttributor` must keep its exact public methods and event semantics;
  existing ledgers, proof bundles, SARIF and replay must remain byte-compatible.
- Adding schema qualification to `DatabaseSchema` keys must not change SQLite
  keys; only the PostgreSQL provider uses qualified names.
- Relationship contracts for SQLite must keep working unchanged; PostgreSQL
  contracts may add an optional schema-qualified form.
- No new law, second ownership engine, ORM, graph database or LLM component is
  permitted.
- `--identity-map` already exists in `cli.py` with dedicated tests; the
  roadmap entry claiming it is pending is stale and must be corrected.

## 8. Audit conclusion

PostgreSQL currently has **write auditing only**, not ownership-graph parity.
A schema reader alone would not be sufficient. Full completion requires the
attribution provider, monotonic cursor, request correlation, schema-qualified
contracts, independent fixture, benchmark, verified isolation and safe CLI
integration. Until those exist, PostgreSQL end-to-end attack mode must fail
closed; read-only evidence integration may proceed but must not claim stronger
semantics than it establishes.
