# Phase VI.1 — Disposable PostgreSQL Twin: Mandatory Design Audit

Starting state verified: branch `feat/postgres-ownership-graph` at
`09a28db07d6fbc11f6bcb972418d544e42b1ad19`; `main` at
`0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`; clean tree; `stash@{0}` intact.
This audit was written before any production edit.

## 1. Current database lifecycle

Phase VI added `PostgresAttributor` (schema/rows/snapshot/diff, monotonic audit
cursor, request correlation) and `PostgresAuditor` (trigger-based audit table).
There is no PostgreSQL attack lifecycle. `scan_application()` always creates a
filesystem `Twin` over a SQLite file (`validation.py:613-622`), and the CLI
`mizan postgres-evidence` is explicitly read-only and reports `INCONCLUSIVE`.

## 2. Current snapshot and restore assumptions

`Twin.snapshot()` copies files listed in `TwinSpec.data_paths` into a directory;
`Twin.restore()` copies them back (`twin.py:189-243`). This assumes state is a
set of files, that no other process holds them open, and that overwriting the
files restores the database. A live PostgreSQL server owns its data directory,
buffers, WAL and connections; copying files underneath it is unsafe and does not
restore transactional state.

## 3. Why the filesystem Twin cannot restore PostgreSQL

- A PostgreSQL connection pool keeps sessions bound to a database; copying
  files does not rebind sessions or invalidate prepared plans/caches.
- `CREATE DATABASE`/`DROP DATABASE` cannot run inside a transaction block, and
  a template database cannot be cloned while sessions are connected to it.
- Restoring requires terminating only this run's sessions; a filesystem copy
  cannot identify or release them.
- Audit triggers and audit rows live inside the database; file copies do not
  reinitialize them in a connection-consistent way.
- There is no proof that the restored state equals the baseline (canonical row
  identities, sequences, schema, indexes, constraints).

## 4. How probes are scheduled and executed

`Mizan.attack()` resets accounting, records unresolved checks, then iterates
`probe_groups()` (L5, L1, L2, L3, L4, T). Each fixed probe calls
`self._restore()` at its start, so **probe-level restoration** happens between
independent probes. Race experiments submit several requests concurrently and
must share one worker database for the duration of the experiment. Guided
multi-step sequences likewise need stable state across steps.

## 5. How workers interact with the database

`parallel.run_parallel()` builds one `TwinPool` with one process/port per worker,
copies `data_paths` by filename, then assigns every Nth probe group to worker N.
`build_engine(base_url, data_paths, twin)` creates one engine per worker. Today
there is no PostgreSQL worker database: all workers would point at the same DSN
and could overwrite each other's state.

## 6. Where connections and pools are created/closed

The fixture app creates a new `psycopg.connect()` per request and closes it in
`finally`; it uses transaction-local `set_config(..., true)` for identity and
request correlation. The PostgreSQL provider holds a long-lived connection for
catalog reads and cursor reads. The audit table is installed explicitly via
`PostgresAuditor.install()` with `connection.commit()`. None of these handles is
owned by a worker lifecycle today, so a restore could race with an open reader
or writer.

## 7. How request correlation reaches PostgreSQL

`Mizan._request()` generates a fresh UUID, passes it to
`attributor.snapshot()`/`diff()` and sends `X-Mizan-Request-Id`. The fixture app
stores it with `set_config('mizan.request_id', value, true)` in the same
transaction as the write; the trigger records it. Transaction-local settings
expire at commit/rollback. A correlation id is metadata, never authentication.

## 8. Components that can be reused

- `PostgresAttributor` for schema evidence and attribution states.
- `PostgresAuditor` for trigger installation/removal inside disposable databases.
- `Twin` process/health management (base URL, health polling, stop/reap) as a
  reference implementation, not with PostgreSQL-specific behavior bolted on.
- `engine._restore()` as the single hook that asks the twin for a baseline.
- `parallel.run_parallel()`'s probe assignment model, with a PostgreSQL-aware
  worker factory.

## 9. New abstractions required

`src/mizan/postgres_twin.py` with explicit states
`CREATED → INITIALIZED → READY → RUNNING → RESTORING → VERIFIED → CLEANED`
plus `FAILED`:

- `PostgresSource` — DSN from environment only; read-only baseline preparation;
  never an attack target.
- `ImmutableBaseline` — seed database built once per run via logical dump of
  the source (or an explicit seed builder when pg_dump is unavailable), with a
  canonical fingerprint and no active sessions before cloning.
- `DisposableDatabase` — generated name, durable ownership record (run id,
  worker id, state, creation time), template clone from the baseline, explicit
  cleanup authorization, and verified non-identity with the source.
- `PostgresTwin` — owns one disposable database and one application process;
  `restore()` stops/reaps the app, closes this run's connections, terminates
  only this run's remaining sessions, re-clones from the baseline, reinstalls
  audit infrastructure, restarts the app, waits for real health, verifies the
  baseline fingerprint, then marks `VERIFIED`/`READY`.
- `PostgresTwinPool` — creates independent databases/processes per worker and
  guarantees cross-worker isolation.

## 10. Clone strategy decision

**Selected: hybrid — immutable seed + per-worker template cloning.**
`pg_dump --format=custom` from the source into a seed database gives a
consistent baseline without modifying the source; each worker database is then
created with `CREATE DATABASE ... TEMPLATE seed`. Template cloning is fast and
copies schema, data, indexes, constraints, sequences and extensions. It does
not copy database-level grants, so each clone explicitly re-applies the run
role's privileges. Active sessions on the seed are prohibited and checked.

Rejected:
- **Pure dump/restore per probe**: correct but too slow for many probes; still
  requires a one-time seed anyway.
- **Filesystem copy**: unsafe for a live server (section 3).
- **Reusing one database for all workers**: no isolation.

Required privileges: `CREATEDB`, ability to create/drop the run's own databases,
`CONNECT` on source and seed, and permission to terminate only this run's
sessions. Missing privileges fail closed before any attack.

Failure conditions that disable attack execution: source/seed identity
ambiguous, seed has active sessions, clone verification mismatch, ownership
record invalid, health check timeout, audit reinitialization failure, cleanup
failure, untracked process/session ownership, or any attempt to target the
source database.

## 11. Verification plan

Baseline verification uses a canonical digest over schema-qualified table names,
column definitions, primary/unique keys, foreign keys, indexes, constraints,
row counts **and canonical row identities** (`[table, [(pk columns, values)]]`
serialized deterministically), sequence values, and audit-table presence. A
worker may only be marked `READY` when its digest equals the seed digest.

Source protection is proven by hashing the source digest before and after
prepare/attack/restore/cleanup and asserting equality, plus assertions that no
audit objects were installed there and no attack URL targets its DSN.

## 12. Scope boundary

This phase introduces the database lifecycle and orchestration. L2/L3 law
semantics, outcome reconciliation and attribution rules are unchanged. The
unsafe attack path stays disabled until clone, isolation, restore, cleanup and
failure-injection tests pass against a real PostgreSQL server.
