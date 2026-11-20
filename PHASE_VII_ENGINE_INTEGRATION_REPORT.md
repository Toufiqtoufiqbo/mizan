# Phase VII — PostgreSQL Engine Integration Report

## 1. Starting state

- Branch `feat/postgres-engine-integration`, created from verified `main`
  `cac413733307651788670d42eaeb083c6ad8c946`.
- PR #10 merged into `main`; PR #10 not modified by this phase.
- Clean worktree; stashes preserved.
- Architecture audit: `PHASE_VII_ARCHITECTURE_AUDIT.md` (data-flow map) and
  `PHASE_VII_SECURITY_ARCHITECTURE_AUDIT.md`, both written before code edits.

## 2. Architecture before and after

Before: `Mizan` was shared for learning/planning/proof, but execution used a
filesystem `Twin` with `SqliteAttributor`. PostgreSQL had two dedicated CLI
commands (`postgres-evidence`, `postgres-twin --exercise`) and a separate
`run_l2_l3_probes` path.

After: `mizan twin --backend postgres` selects a `PostgresRun` adapter that
creates `PostgresTwin` workers and a `PostgresAttributor`, then feeds the
unchanged `Mizan.learn() -> attack() -> write_bundles()` path. No second engine,
no second ownership graph, no duplicated probe planner.

## 3. Backend contract and design decisions

- Backend-neutral pieces: `Target`, `Mizan`, `DatabaseAttributor` interface,
  `RelationshipContract`, evidence states, `Violation`, proof bundles.
- PostgreSQL adapter: `PostgresSource` + `ImmutableBaseline` + `PostgresTwin`
  + `PostgresAttributor`; no new global plugin framework.
- Attribution states (`confirmed`, `unknown`, `ambiguous`, `missing_request`,
  `candidate`, `contradictory`) remain distinct; only confirmed writes can yield
  L3.
- Parallel execution creates isolated worker databases/processes and compares
  normalized findings; race groups stay on one worker.

## 4. Generic CLI

```bash
mizan twin --backend postgres \
  --command "python tests/fixtures/external_apps/postgres_store/app.py --port {port}" \
  --dsn-env MIZAN_DATABASE_URL --schema pgstore \
  --allow-disposable --workers 4 --spec app/openapi.json \
  --token alice=twin-alice --token bob=twin-bob \
  --workdir mizan-run --out mizan-proofs
```

The DSN is an environment variable name, `--schema` is mandatory, destruction
requires `--allow-disposable`, and the source fingerprint is asserted before
and after the run. `postgres-evidence` and `postgres-twin` are unchanged.

## 5. Learning, attribution and law matrix

`Mizan.learn()` consumes schema-qualified PostgreSQL introspection and row
evidence through `PostgresAttributor`; request correlation and transaction-local
identity are unchanged. L3 requires confirmed attribution.

| Law | Status | Evidence |
|---|---|---|
| L1 | SUPPORTED | identity provenance from existing engine |
| L2 | SUPPORTED | PostgreSQL ownership evidence + generic read probes |
| L3 | SUPPORTED | PostgreSQL audit events + generic write probes |
| L4 | UNSUPPORTED | no client-field provenance from database alone |
| L5 | PARTIAL | existing race harness on one isolated worker |
| L6 | UNSUPPORTED | no bounded-state evidence providers |
| L7 | UNSUPPORTED | no cache/queue/log/metric providers |

## 6. Verification

Local final tree: `python -m pytest -q` → **722 passed, 3 skipped, 1 warning
in 646.28 s**. The 3 skips are the POSIX-only signal-delivery tests on Windows
(`test_signal_during_probes_cleans_up_and_exits_nonzero` for SIGINT and SIGTERM,
and `test_signal_during_restore_cleans_up`), reported as SKIPPED and executed by
CI B2 on Linux. The four new real-PostgreSQL engine integration tests pass in
**86.36 s**.

`ruff check .`, `ruff format --check .`, YAML parsing and `git diff --check`
pass. PostgreSQL local 16.2 via pgserver, psycopg 3.3.9.

Integration evidence:

- `test_mizan_engine_l3_with_postgres_attributor`: generic worker plus
  PostgreSQL audit attribution produced `law_types == ["L3"]` with at least one
  confirmed finding; source fingerprint unchanged.
- `test_mizan_engine_parallel_workers_are_isolated`: distinct worker databases
  and DSNs; a mutation in w0 changed only w0's fingerprint; restoring w0 left
  w1 unchanged; both cleaned.
- `test_mizan_twin_cli_uses_postgres_backend_safely`: the generic CLI path ran
  with `--backend postgres --workers 2`, printed the backend status and
  `cleanup: N database(s) removed`, source unchanged.
- `test_postgres_engine_source_and_cleanup_are_verified`: source fingerprint
  before and after restore identical; verified cleanup removed seed and worker.

Benchmark (`python -m benchmarks.postgres_engine.run`, 1 repetition per size):
serial 9.4656 s (1 worker), parallel 11.1587 s (2 workers) and 20.7607 s
(4 workers); no failures. **Parallel is slower than serial in this workload**
because worker provisioning and restore dominate, so no speedup is claimed.
All configurations produced identical normalized finding sets (empty on the
clean variant). The generated `benchmarks/postgres_engine/results.json`
contains the environment, durations and findings.

CI evidence is recorded in the delivery message.

## 7. Limitations

- Separate PostgreSQL data directories/clusters per worker are out of scope.
- L4, L6 and L7 are unsupported for PostgreSQL, and L5 is partial.
- Only one independent PostgreSQL-backed fixture is available.
- Parallel equivalence is asserted for the deterministic workload covered by
  the tests, not for every possible application.
