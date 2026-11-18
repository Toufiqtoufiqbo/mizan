# Mīzān Phase VI.1 — Disposable PostgreSQL Twin

## 1. Executive summary

Phase VI.1 adds a genuine disposable PostgreSQL Twin lifecycle. The source
database is never an attack target: an immutable seed is prepared once and each
worker receives a cloned database with a durable ownership record. Before a
worker is marked READY, its canonical fingerprint (schema, keys, indexes,
constraints, sequences and canonical row identities) must match the baseline.
Restoration stops the application, closes this run's connections, replaces the
worker database from the seed, reinstalls audit infrastructure, restarts the
application and re-verifies the baseline. Cleanup drops only databases with a
matching run ownership record.

Real L2/L3 probes were executed against an isolated clone: the `write` fixture
produced a confirmed L3 finding while the source fingerprint remained unchanged.

## 2. Architecture

- `src/mizan/postgres_twin.py` — `PostgresSource`, `ImmutableBaseline`,
  `DatabaseRegistry`, `DisposableDatabase`, `PostgresTwin`, `cleanup_run` and
  `run_l2_l3_probes`.
- Explicit states: `CREATED → INITIALIZED → READY → RUNNING → RESTORING →
  VERIFIED → CLEANED`, plus `FAILED`; invalid transitions raise and disable use.
- `src/mizan/cli.py` — `mizan postgres-twin` with `--dsn-env`, `--schema`,
  `--allow-disposable`, `--dry-run`, `--exercise`, `--cleanup-run`, `--workers`.
- `src/mizan/engine.py` — `_restore()` rebinds a provider to a freshly restored
  database through a duck-typed `rebind()` hook.
- `src/mizan/postgres_attribution.py` — `rebind()` after a clone replacement.
- `src/mizan/ownership.py` — schema-qualified resolution for sharing contracts.

## 3. Clone strategy and rationale

Hybrid: `pg_dump -Fc` from the source into a seed database, then
`CREATE DATABASE worker TEMPLATE seed` per worker. Template cloning copies
schema, data, indexes, constraints and sequences quickly; database-level grants
are explicitly re-applied by owning the clone as the run role. Logical dump per
probe was rejected as too slow; filesystem copies are unsafe for a live server.
`CREATE DATABASE` runs outside a transaction; active seed sessions are checked
before cloning. Missing `pg_dump`/`pg_restore` fails closed.

## 4. Source database protection

The source DSN is read from an environment variable only. Source access is
limited to read-only catalog/dump operations; no audit triggers are installed
there and no attack request targets it. Its canonical fingerprint is asserted
before and after prepare, restore, probe execution and cleanup. Cleanup refuses
any database without a run-owned record and never drops the source or seed by
name. Evidence from the CLI run: `source_unchanged: true`.

## 5. Worker isolation

Each worker receives a distinct generated database and port. Isolation was
experimentally proven by creating a table in worker 0 and observing that the
canonical digest of worker 1 remained the baseline digest. Restoring worker 0
did not change worker 1. Fingerprints after mutation differed.

## 6. Restoration procedure

`restore()`: stop and reap the application process, close Mīzān-owned
connections, terminate only sessions whose `application_name` carries this
run/worker id, drop and re-clone the worker database from the seed, reinstall
audit triggers, restart the application, wait for a real health check, compare
the canonical fingerprint, then mark `VERIFIED`/`READY`. Cleanup is idempotent.

## 7. Attribution model

Existing states are preserved: `confirmed`, `unknown_principal`,
`missing_request`, `ambiguous`. Only confirmed attribution may produce L3; all
other states remain inconclusive. Correlation is request metadata, never
authentication; the fixture stores it in transaction-local PostgreSQL context.

## 8. CLI usage

```bash
export MIZAN_DATABASE_URL='postgresql://user:password@host/source'
mizan postgres-twin --dsn-env MIZAN_DATABASE_URL --schema app \
  --allow-disposable --workers 2 --dry-run
mizan postgres-twin --dsn-env MIZAN_DATABASE_URL --schema app \
  --allow-disposable --workers 2 --exercise
mizan postgres-twin --dsn-env MIZAN_DATABASE_URL --cleanup-run RUN_ID
```

DSNs never appear in arguments, logs, reports or proof bundles.

## 9. Tests executed

Commands and results (all against real PostgreSQL via `pgserver` unless noted):

- `python -m pytest -q` — **633 passed** before the three final failure-injection
  tests were added; final full-suite count recorded below.
- `python -m pytest tests/test_postgres_twin.py -q` — **12 passed**
  (9 unit/failure injection + 3 real-server integration).
- `python -m pytest tests/test_postgres_ownership_integration.py -q` — 16 passed.
- `python -m pytest tests/test_postgres_audit.py tests/test_postgres_roundtrip.py
  tests/test_postgres_attribution.py -q` — legacy + Phase VI attribution tests pass.
- CLI lifecycle with `--exercise`: `status: VERIFIED`, `source_unchanged: true`;
  `write` variant produced `law_types: ["L3"]` with one L3 finding, L2 DECIDED.
- `ruff check`, `ruff format --check`, `git diff --check` — clean.

Final full suite: **`641 passed, 1 warning in 490.66s`** (`python -m pytest -q`).

## 10. Benchmark results

`python -m benchmarks.postgres_twin.run` (Python 3.11.9, PostgreSQL 16.2,
2 workers, local disposable pgserver, `pgstore` fixture schema):

| Measurement | Value | Denominator |
|---|---|---|
| Baseline prepare | 1.329 s | 1 seed |
| Worker 0 startup | 3.734 s | 1 worker |
| Worker 1 startup | 4.109 s | 1 worker |
| Mutation | 0.016 s | 1 mutation |
| Restore | 8.171 s | 1 restore |
| Cleanup (2 workers) | 4.703 s | 2 cleanups |
| Workers isolated | true | 2 workers |
| Restore matches baseline | true | 1 restore |
| Source unchanged | true | 1 source |

These are local measurements on a controlled fixture, not production performance.
Full breakdown: `benchmarks/postgres_twin/results.json`.

## 11. Failure injection results

- Invalid lifecycle transition `CREATED → RUNNING`: rejected by
  `TwinLifecycleError`; execution disabled.
- Missing DSN environment variable: `SourceProtectionError` before any connect.
- Clone failure: `PostgresTwin.start()` raises and state becomes `FAILED`.
- Application/health failure: state becomes `FAILED`; no attack is attempted.
- Cleanup with an ownership record naming the source: rejected with
  `SourceProtectionError`; no database is dropped.
- Cleanup with a run id that does not own the recorded database: no-op.
- Cleanup is idempotent (called twice on the same twin).

## 12. CI results

- CI on implementation commit `3bd6601dee170ae065119ad9c4953fbbe18c80fb`:
  run **44388731217** (#237), conclusion **success**. Jobs A (static & unit),
  B (PostgreSQL, now including the Twin lifecycle and both PostgreSQL
  benchmarks), C (security regression), D (benchmark), E (self-scan),
  F (independent application) and G (cross-framework) all succeeded.
  Job `G - external target (opt-in)` was **SKIPPED**, not PASSED.
- Earlier CI runs #235 and #236 failed in stage B because the hosted runner's
  `pg_dump`/`pg_restore` client emitted `transaction_timeout`, which PostgreSQL
  16 does not recognize. The baseline now uses plain SQL with session-parameter
  filtering; run #237 passed.
- The final documentation commit's CI result is recorded in the delivery message.

## 13. Known limitations

- Only schemas listed in the allowlist are fingerprinted and cloned.
- Cluster-wide roles/tablespaces are outside the dump; the run role must exist.
- Template cloning requires `CREATEDB` and no active sessions on the seed.
- Restoration time is dominated by cloning and application restart (measured).
- The fixture is controlled; no claim of arbitrary production compatibility.

## 14. Exact Git state and commit SHA

Implementation commits: `08b434631b612744c6c9a68b5f7cbee59037f408`
(Twin lifecycle), `2b9c6ce8a7d806f4c9be9d07e7fbeff1f6623569` (portable
dump/restore) and `3bd6601dee170ae065119ad9c4953fbbe18c80fb` (client-version
compatibility). CI run #237 succeeded on the last implementation commit.

Final HEAD (documentation commit adding this report): PENDING_HEAD_SHA
Branch `feat/postgres-ownership-graph`; base `main` at
`0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`; `stash@{0}` preserved.

## 15. Final verdict

**INCOMPLETE.** The disposable Twin lifecycle is implemented and demonstrated:
source protection, worker isolation, canonical baseline restoration, L2/L3
probe execution, cleanup and the listed failure injections all have real
evidence. The following guarantees remain unverified, so the phase is not
declared `READY FOR REVIEW`:

- SIGINT/SIGTERM and abrupt process interruption during a probe were not
  injected; orphan handling is designed but not experimentally proven.
- Termination of unrelated PostgreSQL sessions was not injected; the code
  filters by database and run-owned `application_name`, but no adversarial
  session was created to prove the filter.
- Connection-pool shutdown injection was not performed; the fixture opens a
  connection per request, so no long-lived application pool exists to test.
- Cluster-wide role/tablespace objects are outside the dump; required roles are
  assumed to exist.

No PR was opened. The unsafe capability remains gated behind the explicit
`--allow-disposable` opt-in.
