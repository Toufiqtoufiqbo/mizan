# Phase VI.2 — PostgreSQL Twin Security Hardening Report

## 1. Executive summary

Phase VI.1 delivered a working disposable PostgreSQL Twin but its cleanup
boundary and several trust assumptions did not survive adversarial review. This
phase treats the Twin as a destructive capability and proves, with executed
tests, that it cannot be steered into dropping a database it does not own.

The two release-blocking defects were:

1. **Cleanup trusted a local JSON file.** A registry entry alone could name any
   database and the name was interpolated into `DROP DATABASE`. Fix: deletion
   now requires a local record **and** a server-side marker that agrees on run,
   kind, worker, source, cluster identity, owner role and nonce, with every
   identifier composed through `psycopg.sql.Identifier`. No
   `DROP DATABASE ... WITH (FORCE)` is used.
2. **Verification compared the database to itself.** The expected fingerprint
   was overwritten with the live fingerprint after the application started, so
   any bootstrap write became "expected". Fix: expected state is always the
   immutable baseline; audit installation is verified as an explicit, separate
   effect before the application can write.

The remaining confirmed findings (schema allowlist, credentials in child
arguments, swallowed stop errors, session-identity mismatch, non-canonical
fingerprint, non-atomic registry, documentation drift) are addressed below with
the test that demonstrates each one.

## 2. Starting state

Verified before the first edit:

- Branch `feat/postgres-ownership-graph`; HEAD
  `3f3f779d074a7ee05c76fbd2ff59477c126a8ce5`.
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- Last CI before this phase: run **44390730758** (#238) on `3f3f779`, A–G
  green, external-target opt-in **SKIPPED** (not passed).

The audit is `PHASE_VI_2_SECURITY_AUDIT.md`; it was written before any
production edit and its line references point at that commit.

## 3. Findings and remediation

| Finding | Severity | Remediation | Demonstrated by |
|---|---|---|---|
| A. Registry-only, interpolated drop | critical | Server marker + cluster identity + source + owner + nonce; `sql.Identifier`; whole-set pre-validation | `test_cleanup_refuses_a_forged_registry_record`, `test_cleanup_refuses_a_foreign_marker_and_keeps_the_database`, `test_cleanup_rejects_record_naming_the_source`, the unit injection tests |
| B. Dump ignored the schema allowlist | high | One `--schema` per allowlisted schema; post-restore check for non-allowlisted relations; cross-schema dependency fails closed and rolls back the seed | `test_clone_does_not_contain_a_non_allowlisted_schema`, `test_cross_schema_dependency_fails_closed_and_rolls_back` |
| C. Password-bearing DSN in argv | high | Temporary `PGPASSFILE` (0600) plus non-secret `PG*` environment; DSN never included in child arguments; redaction of errors/logs/reports | `test_child_process_environment_never_contains_the_password`, `test_redact_removes_dsn_passwords_and_named_secrets`, `test_cli_never_claims_verified_before_a_successful_cleanup` |
| D. Stop failures swallowed; `VERIFIED` before cleanup | high | `_stop_application(strict=True)` observes the exit and raises; destructive drops are blocked on failure; final status is emitted only after cleanup; non-zero exit with `cleanup_failed` | `test_stop_failure_blocks_the_destructive_drop`, `test_cleanup_failure_fails_closed`, `test_cleanup_run_cli_reports_a_machine_readable_failure`, `test_cli_never_claims_verified_before_a_successful_cleanup` |
| E. Session identity collided with the principal | high | Stable session identity `mizan:<run_id>:<worker_id>`; principal/request id in transaction-local settings; the trigger prefers `mizan.principal`, rejects a session identity as a principal, keeps legacy names | `test_a_stable_session_identity_is_never_a_principal`, `test_the_trigger_prefers_the_transaction_local_principal`, `test_pooled_idle_and_active_sessions_are_released`, `test_cleanup_refuses_while_an_unrelated_session_is_active` |
| F. Fingerprint not canonical | high | Schema-qualified discovery; exact-schema column metadata; PK-ordered rows or canonical typed sort; type-tagged values; `pg_get_indexdef`/`pg_get_constraintdef`/`pg_get_triggerdef`/`pg_get_functiondef`; sequence `last_value` + `is_called` + configuration | `test_fingerprint_is_schema_qualified_and_sequence_aware`, `test_typed_values_preserve_type_and_scale`, `test_baseline_mismatch_fails_closed` |
| G. Verification compared to itself | critical | Expected value comes only from the immutable baseline; audit state is a separately expected effect, checked before the application starts | `test_audit_initialization_failure_fails_closed`, `test_application_start_failure_fails_closed`, `test_baseline_mismatch_fails_closed` |
| H. Registry not atomic | medium | Temp-file replace, `fsync`, `0600`, lock file, strict key/record parsing | `test_registry_writes_atomically_and_rejects_key_mismatch`, `test_registry_rejects_malformed_json` |
| I. Documentation drift | medium | Reports, README, ROADMAP, CLI help and CI corrected to actual behavior | This report and the corrected documents |

## 4. Ownership and cleanup boundary

Each seed and worker database carries a JSON marker in its database comment:

```json
{"v":1,"run_id":"...","kind":"worker","worker_id":"w0","source":"...",
 "cluster":"<system_identifier>","owner":"<role>","nonce":"<32 hex>",
 "created_at":1234.5}
```

`verified_drop()` refuses unless all of the following hold:

- the run id is 12 lowercase hex characters and the name matches the
  deterministic generated format for that run/kind/worker;
- a local record exists, matches the registry key, and equals the record being
  dropped;
- the server marker exists and agrees on run, kind, worker, source and nonce;
- the marker's cluster equals `pg_control_system().system_identifier` for the
  connection performing the drop;
- the marker's owner equals the database's actual owner role;
- no unrelated session is connected (an unrelated session aborts; it is never
  terminated), and only the exact owned session identity may be terminated.

`cleanup_run()` validates the **whole** recorded set before dropping anything,
so one forged record cannot leave a run half-cleaned. If `pg_control_system()`
is not permitted, cleanup fails closed and reports the missing privilege.

The local registry is still useful for recovery (`--cleanup-run`) but it is
never sufficient authority on its own.

## 5. Source isolation and the schema allowlist

`pg_dump --format=plain --no-owner --no-privileges` is invoked with one
`--schema` flag per allowlisted schema. The seed is then checked: any
non-allowlisted schema that contains a relation aborts the run, and a baseline
failure rolls back the seed using the OID captured immediately after
`CREATE DATABASE`, so no untracked seed survives. A cross-schema dependency
(for example an allowlisted view over a non-allowlisted table) makes the restore
fail closed rather than silently producing a partial clone.

The source is only read: catalog queries and `pg_dump`. No audit trigger is
installed there, and its fingerprint is asserted before and after prepare,
restore, probes and cleanup.

## 6. Credentials

`pg_dump` and `psql` never receive a password-bearing DSN in their arguments or
environment. The target is split into host/port/user/database; the password is
written to a temporary `PGPASSFILE` with `0600` (POSIX) and removed in a
`finally`. Non-secret settings travel through `PGHOST`, `PGPORT`, `PGUSER`,
`PGDATABASE`, `PGSSLMODE` and `PGAPPNAME`. Error messages, CLI output and
reports pass through `redact()`, which removes the DSN and any named secret.

A unit test asserts that neither `PGPASSWORD` nor the secret appears in the
child environment or in the password-free DSN, and that the password file is
deleted afterwards.

## 7. Fingerprint scope and audit effects

The digest covers, for the allowlisted schemas only:

- tables (including partitioned tables), persistence and row security;
- columns with type, UDT, nullability, default, identity/generation and
  generation expression, read for the exact schema and table;
- primary keys, indexes (`pg_get_indexdef`), constraints
  (`pg_get_constraintdef`) and triggers (`pg_get_triggerdef`);
- functions (`pg_get_functiondef`);
- rows in primary-key order when a key exists, otherwise a canonical sort of
  type-tagged encodings; `NULL` is explicit and `int`, `decimal`, `str`, `bool`,
  `bytes`, `uuid`, `datetime`, `json` and arrays keep their type;
- sequences with `last_value`, `is_called` and their configuration.

Mīzān's own audit table, sequence, index and triggers are excluded from the
application digest and verified separately against an expected audit state
derived from the allowlisted user tables. Expected application state always
comes from the immutable baseline; it is never copied from the live database.

**Documented scope boundary:** cluster-wide objects — roles, tablespaces,
extensions, user-defined types and publications — are outside this digest and
outside the clone guarantee. They are not claimed as verified.

## 8. Process, pooled sessions, signals and orphans

- The application process is stopped through `Twin.stop()`, then its exit is
  observed by polling `process.poll()`; a process still alive after the grace
  period is killed and reaped. `_stop_application(strict=True)` raises, and the
  caller blocks every destructive drop when it fails.
- Application connections use the stable identity
  `mizan:<run_id>:<worker_id>`. The fixture now has a real connection pool
  (`/pool`, `MIZAN_PG_POOL_SIZE`, optional leak mode), so restore and cleanup are
  exercised with idle and active pooled connections. After a restore, the old
  pool's PIDs are gone and a new pool is established, proving the pool was
  released before the drop.
- A session with any other identity aborts the drop with `CleanupError`; only
  the exact owned identity may be terminated.
- `CancellationToken` translates SIGINT, SIGTERM and SIGBREAK into a catchable
  `RunInterrupted`, so the normal cleanup path runs and the command exits
  non-zero. Handlers are restored before cleanup so it cannot be interrupted
  twice.
- Abrupt termination leaves the registry and server markers; `--cleanup-run`
  performs full verification before dropping the orphan. `SIGKILL` (POSIX) and
  `TerminateProcess` (Windows, via `Popen.kill()`) are the tested abrupt cases.

## 9. CLI behavior

- The final status is emitted **after** the `finally` cleanup block. `VERIFIED`
  is never printed before cleanup succeeds.
- A cleanup failure prints `cleanup_failed` with `cleanup_errors` and exits 2.
  Records and markers are preserved for `--cleanup-run`.
- `--dry-run` creates no database and reports `DRY_RUN_OK`, not `VERIFIED`.
- `--workers N` provisions N isolated databases/processes. `--exercise` runs
  the L2/L3 probes against **worker `w0` only**; the other workers are
  isolation evidence. This is stated in the option help and documented.
- `--cleanup-run RUN_ID` validates the whole recorded set, verifies markers and
  drops only this run's databases; it is idempotent.

## 10. Adversarial test evidence

Final local run on this tree: `python -m pytest -q` →
**667 passed, 3 skipped, 1 warning in 580.36 s**. The Twin module contributes
44 tests (24 unit/failure injection and 20 real-server integration). The three
skips are the POSIX-only signal-delivery tests on Windows; they are reported as
`SKIPPED`, never as passed, and are executed by CI job B2 on Linux. The
PostgreSQL round-trip, audit and ownership-integration modules also pass
(54 tests).

Unit and failure-injection tests (no server):

- name format/injection rejection, similar-name rejection, record identity
  mismatches, registry atomicity/malformed JSON, invalid transitions;
- missing DSN environment, generated-database source, password-free child
  environment and password-file lifecycle, redaction, type-preserving values;
- clone/application/audit/restore/cleanup failure injection, stop failure
  blocking the drop, `cleanup_failed` exit code, no `VERIFIED` before cleanup.

Real PostgreSQL integration tests:

- full two-worker lifecycle, source protection, isolation and idempotent
  cleanup; L3 probe with a confirmed finding on a clone;
- non-allowlisted schema absent from the clone; cross-schema dependency fails
  closed with seed rollback;
- schema-qualified, sequence-aware fingerprint changes on `nextval` and on a
  row update;
- forged registry record, foreign marker, similar name, unrelated session,
  owned stale session, pooled idle/active sessions across restore;
- concurrent requests sharing one worker database with confirmed attribution;
- interruption and signals during probes/restore; SIGKILL orphan recovery via
  `--cleanup-run`.

The Windows run skips the POSIX-only signal-delivery tests and records them as
`SKIPPED` (3), not as passed. The Linux CI job runs them and fails on any skip.

## 11. Benchmark

`benchmarks/postgres_twin/run.py` now computes every verification flag from an
observation (no hard-coded booleans), repeats restore/cleanup, and records
repetitions, min, median, P95 and max, plus Python/PostgreSQL/psycopg versions,
worker count, pool size, dataset description, git SHA/dirty flag, raw timings
and failures. A local fixture result is explicitly separated from any
production claim. See `benchmarks/postgres_twin/results.json`.

Local observation (Python 3.11.9, PostgreSQL 16.2, psycopg 3.3.9, 2 workers,
pool size 2, 3 restore repetitions, local disposable pgserver): baseline
prepare 1.359 s (n=1), worker startup median 2.297 s / P95 2.547 s (n=2),
restore median 3.406 s / P95 4.828 s (n=3), cleanup median 0.5315 s /
P95 2.328 s (n=4). Every verification flag (`workers_isolated`,
`restore_matches_baseline`, `cleanup_idempotent`, `seed_cleaned`,
`workers_cleaned`, `source_unchanged`) is `true` and `failures` is empty. These
are local controlled-fixture measurements, not production performance.

## 12. CI

Stages A–G are preserved. The PostgreSQL stage now has two jobs:

- `B - PostgreSQL`: round trip, ownership evidence, Twin lifecycle and both
  PostgreSQL benchmarks;
- `B2 - PostgreSQL lifecycle & destructive cleanup`: runs every destructive
  Twin test (creation, verified drops, signals, pooled sessions, orphan
  recovery) and fails on a skip or on "no tests ran".

A final `S - status summary` job reads every job result and prints
`PASSED`/`FAILED`/`SKIPPED`. The opt-in external target prints
`NOT CONFIGURED` when its variable is empty and `NOT EXECUTED` if it was
configured but produced no result; it is never shown as passed.

Result for implementation commit `1ed2f779acce705a55f3272fa013dd9a9061f8ad`:
workflow run **44515424790** (#239), conclusion **success**. Jobs A (static &
unit), B (PostgreSQL), B2 (PostgreSQL lifecycle & destructive cleanup), C
(security regression), D (benchmark), E (self-scan), F (independent
application), G (cross-framework gate) and S (status summary) all succeeded.
`G - external target (opt-in)` was **SKIPPED**, never passed.

## 13. Documentation reconciliation

- `PHASE_VI_1_POSTGRES_TWIN_REPORT.md`: plain `pg_dump` + `psql` (not `-Fc`),
  17 Twin tests (not 12), run #238 on `3f3f779` (not #237 on a future commit),
  `PENDING_HEAD_SHA` removed, `--workers`/`--exercise` semantics stated, VI.2
  supersession note added.
- `PHASE_VI_1_DESIGN.md`: plain-SQL dump with allowlist and `PGPASSFILE`; no
  silent fallback seed builder; fingerprint scope reconciled.
- `PHASE_VI_POSTGRES_REPORT.md`: principal setting vs session identity,
  verified cleanup boundary, current twin capability and run history.
- `README.md`, `ROADMAP.md`: allowlist, verified ownership, pool/session
  behavior, signals, `--workers`, dry-run status.
- CLI help and the workflow comments match the code.

## 14. Remaining limitations

- Cluster-wide roles, tablespaces, extensions, user-defined types and
  publications are outside the clone and fingerprint guarantee.
- Template cloning requires `CREATEDB`, `CONNECT` and permission to read
  `pg_control_system()`; missing privileges fail closed.
- `CREATE DATABASE` cannot participate in a transaction. A `SIGKILL` in the
  narrow window between the database creation and its marker write (two catalog
  reads) leaves a database that no proof can attribute. Cleanup refuses to drop
  it; an operator must remove it explicitly. Every later abrupt termination is
  recoverable through the marker and `--cleanup-run`.
- The external target remains opt-in and unexecuted in ordinary CI.
- The fixture is controlled; no general production-compatibility claim is made.

## 15. Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | Cleanup requires server-side ownership evidence, cluster identity, source identity and owner | `_verify_database_ownership`; forged/foreign-marker/similar-name tests |
| 2 | Identifiers validated and composed; no `WITH (FORCE)` | `require_generated_name`/`sql.Identifier`; `test_generated_names_reject_injection_and_bad_identifiers`; grep shows two `DROP DATABASE` sites, both `sql.Identifier` |
| 3 | A local JSON record alone never authorizes deletion | `verified_drop` marker checks; `test_cleanup_refuses_a_forged_registry_record`; seed/worker OID rollback |
| 4 | Schema allowlist applied to the dump; non-allowlisted sentinel never reaches the seed; cross-schema fails closed | `--schema` per schema; `_assert_allowlisted`; two allowlist tests |
| 5 | No password-bearing DSN in child args/logs/exceptions/reports | `PGPASSFILE`; `child_environment`; password/redaction tests |
| 6 | Baseline-preparation failure rolls back created resources | `_rollback_seed`; `_rollback_created`; cross-schema rollback test |
| 7 | Canonical, schema-qualified, type-preserving, PK-ordered, NULL-explicit, `is_called`-aware fingerprint | `database_fingerprint`; fingerprint and typed-value tests |
| 8 | Expected state never copied from the live database; audit effects explicit | baseline expected value; `expected_audit_state`; `test_baseline_mismatch_fails_closed`, `test_audit_initialization_failure_fails_closed` |
| 9 | Shutdown observable/mandatory and blocks destructive operations | `_stop_application(strict=True)`; `test_stop_failure_blocks_the_destructive_drop`; start-failure reaping |
| 10 | Stable session identity separate from principal, transaction-local principal/request id | `app_session_identity`; `mizan.principal`; audit tests |
| 11 | Pooled fixture: idle/active, reuse, shutdown and leak/failure mode | `ConnectionPool`; `/pool`; pooled and pool-leak tests |
| 12 | Pools released before restore/drop | disjoint PID sets across restore; leak-mode drop |
| 13 | Unrelated sessions never terminated; cleanup refuses; only exact owned stale session terminated | unrelated refusal test; exact-owned-session termination test |
| 14 | Real SIGINT/SIGTERM during probes and restore/cleanup | parametrized signal tests (POSIX; run in CI B2, skipped on Windows) |
| 15 | SIGKILL orphan recovery through `--cleanup-run` | `test_sigkill_then_cleanup_run_recovers_the_orphan` |
| 16 | `--cleanup-run` strict verification: forged record, other cluster, similar name, marker mismatch, unrelated sessions | forged/foreign/similar/unrelated tests; whole-set pre-validation |
| 17 | CLI: no `VERIFIED` before cleanup; non-zero + `cleanup_failed`; records preserved; `--workers` documented | `test_cli_never_claims_verified_before_a_successful_cleanup`, `test_cleanup_run_cli_reports_a_machine_readable_failure`; option help |
| 18 | Benchmark: executed assertions, repetitions/median/P95, versions, workers, dataset, timings, failures | `benchmarks/postgres_twin/run.py`; `results.json` with `verification` and `failures` |
| 19 | Docs reconciled; no `PENDING_HEAD_SHA`; no run attributed to a future commit | corrected reports/README/ROADMAP; this report |
| 20 | CI stages A–G preserved; lifecycle + destructive job; honest status states | `.github/workflows/mizan.yml` jobs `postgres-lifecycle` and `status-summary` |
| 21 | Exact verdict; destructive path stays disabled when ownership is unverified; no unsupported claims | this section; `--allow-disposable` gate; fail-closed paths |

## 16. Final verdict

Local verification gave `667 passed, 3 skipped, 1 warning in 580.36 s`. CI on
the implementation commit `1ed2f779acce705a55f3272fa013dd9a9061f8ad` was run
**44515424790** (#239), conclusion **success**, with A, B, B2, C, D, E, F, G
and S all PASSED and the external target SKIPPED. The destructive path stays
behind `--allow-disposable` and refuses to act unless every ownership proof
agrees.

**Verdict: READY FOR REVIEW.**
