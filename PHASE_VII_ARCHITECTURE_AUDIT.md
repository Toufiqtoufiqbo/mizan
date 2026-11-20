# Phase VII — PostgreSQL Engine Integration Architecture Audit

Starting state verified before this audit:

- Branch `feat/postgres-engine-integration`; HEAD `cac413733307651788670d42eaeb083c6ad8c946`
  (local = remote).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238` and merged PR #10 at
  `cac413733307651788670d42eaeb083c6ad8c946`, untouched by development.
- Clean worktree; `stash@{0}` preserved.
- No code edited before this audit was written.

## Audit map — data flow before integration

`Traffic → Identity → Attribution → Ownership Graph → Policy → Planner → Probe → Evaluation → Proof`

Existing SQLite and PostgreSQL-specific paths:

| Stage | SQLite | PostgreSQL | Shared? |
|---|---|---|---|
| Identity provenance | `SqliteAttributor` reads the provenance ledger | `PostgresAttributor` reads audit-table events with `mizan.principal`/request-id correlation | separate providers behind one duck-typed interface |
| Ownership/access evidence | `DatabaseAttributor` + data views | `PostgresAttributor` + audit-table diffs | shared engine consumes both |
| Learning | `learn_from_spec`/`Mizan.learn` | same `Mizan.learn` with PostgreSQL attributor | shared |
| Planner | `Mizan.attack`/probes | same | shared |
| Execution | filesystem `Twin` | dedicated `postgres-twin --exercise` | NOT shared yet |
| Proof | `Mizan.write_bundles` | shared (replay/regress paths work on violations) | shared |

Reasons the generic path did not use PostgreSQL by default:

1. `Mizan` only constructs an attributor when a `.sqlite*` data path is passed.
2. The CLI's twin command starts `TwinSpec` over files; it has no Postgres backend
   and never connects to a DSN.
3. Parallel execution uses `mizan.parallel.run_parallel`, which is file-based.
4. The PostgreSQL evidence module intentionally implements no second engine.

## Backend contract (smallest maintainable)

One logical engine stays in `Mizan`. The backend-neutral contract:

- `attributor`: already exists (`SqliteAttributor`, `PostgresAttributor`).
- `schema()/rows()/snapshot()/diff()/audit cursor`: reused by the engine.
- A Postgres run is described by `PostgresSource` + `ImmutableBaseline` +
  `PostgresTwin`, producing a `Target` and a `Mizan` for one worker.
- The generic CLI gains `mizan twin --backend postgres`.
- Backend capability reporting distinguishes `SUPPORTED`, `PARTIAL`,
  `UNSUPPORTED`, `INCONCLUSIVE`; missing evidence never upgrades to clean.

## Design decisions

- No second engine; `Mizan` is reused unchanged.
- No parallel worker DB sharing: each worker has its own `PostgresTwin`.
- L5 reuse: the existing race harness is reused; race groups stay on one
  worker. Parallel execution runs one clean run per worker and compares
  normalized findings to the serial run.
- L4/L6/L7 are reported `UNSUPPORTED` unless concrete evidence exists.
- Undefined generic failures are written as machine-readable status with
  `errors`/`skipped` details instead of false `CLEAN`.
