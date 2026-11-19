# Phase VI.2.1 — Session Ownership & Atomic Cleanup Audit

Starting state verified before this audit was written:

- Branch `feat/postgres-ownership-graph`; HEAD
  `696a85ae3b3d752054e4ad306c3d150908ffba4f` (local and remote match).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- Previous verified CI: run #239 (`44515424790`) on the implementation commit
  and run #240 (`44516914315`) on `696a85a`, both success; the external-target
  opt-in was SKIPPED.

Line numbers in this audit refer to `696a85a`. The audit was written before any
production edit.

## Scope

- `src/mizan/postgres_twin.py`
- `src/mizan/cli.py` (`postgres-twin --cleanup-run`)
- `src/mizan/twin.py`
- `src/mizan/postgres_audit.py`
- `tests/test_postgres_twin.py`
- `tests/fixtures/external_apps/postgres_store/app.py`
- `.github/workflows/mizan.yml`
- `PHASE_VI_2_SECURITY_HARDENING_REPORT.md`

## Finding A — `application_name` is treated as ownership (CONFIRMED, critical)

The stable identity `mizan:<run_id>:<worker_id>` is applied to application
connections (`postgres_twin.py:1650-1656`) and then used in SQL that terminates
backends:

```python
# postgres_twin.py:1183-1201
SELECT count(*) FROM pg_stat_activity
WHERE datname = %s AND application_name = %s AND pid <> pg_backend_pid()
...
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
WHERE datname = %s AND application_name = %s AND pid <> pg_backend_pid()
```

Call chain:

- `verified_drop()` (`:1217-1264`) receives `application_identity` and calls
  `_terminate_owned_sessions()` at `:1248`, then waits only for sessions whose
  label matches (`:1252-1257`) and treats any remaining session as unrelated.
- `DisposableDatabase.drop()` (`:1798-1813`) passes
  `app_session_identity(run_id, worker_id)`.
- `cleanup_run()` (`:2057-2067`) derives the same identity from a registry
  record for every worker.
- `PostgresTwin.restore()` (`:1968-1989`) and `PostgresTwin.cleanup()`
  (`:1994-2006`) reach the drop through `DisposableDatabase.drop()`.
- `_stop_application()` (`:1910-1938`) stops the process and closes the Mīzān
  control connection, but it does not call any pool shutdown API and does not
  wait for sessions to drain before the drop.

A PostgreSQL client sets its own `application_name` at connect time or with
`SET application_name`. An unrelated process can therefore copy the expected
label and:

1. be killed by `_terminate_owned_sessions()`, which is an availability attack;
2. be misclassified as "owned" while a genuinely owned session with a different
   label is misclassified as "unrelated" and blocks cleanup.

The label is metadata, not server-authenticated identity. Matching it is not
proof of ownership. The existing test
`test_cleanup_terminates_only_the_exact_owned_session` asserts the unsafe
behaviour and must be replaced. `test_pool_leak_mode_still_releases_connections`
also relies on termination and must be revised.

## Finding B — markers are checked per drop, not per run (CONFIRMED, critical)

`cleanup_run()` (`:2014-2072`) performs two checks over the whole set:

- structural `validate_record()` before opening a connection (`:2037-2043`);
- cluster identity validation for every record after connecting (`:2047-2056`).

It then enters a sequential loop (`:2057-2069`) in which `verified_drop()`
reads and validates each server-side marker immediately before that one drop.
Consequences:

- Worker 0 with a valid marker is dropped, then Worker 1 with a tampered marker
  raises `OwnershipError`; the run is left half destroyed.
- Active-session safety is likewise only checked per item, so the first drop
  can succeed while the second is refused because of a session.
- A "missing database with inconsistent ownership state" is silently turned
  into success by `verified_drop()` (`:1240-1242`, it marks it CLEANED and
  returns `False`) even if the local record still says READY.
- There is no run-level coordination: `DatabaseRegistry._lock()` (`:1047-1072`)
  protects a single write, not the multi-database sequence. Two concurrent
  `--cleanup-run` invocations can interleave preflight and deletion.
- The CLI (`:904-914`) reports `CLEANED` after any list return and uses one
  generic `cleanup_failed` status for every exception; it cannot express a
  preflight rejection or a partial cleanup.

## Design decisions

### Session ownership

Do not terminate sessions by `application_name`. Remove
`_terminate_owned_sessions()` from the destructive path entirely.

The session lifecycle becomes non-destructive from the server's perspective:

1. Stop the explicitly owned application process and reap it (existing
   `_stop_application()` guarantee).
2. Close Mīzān-owned connections, including an explicit pool shutdown through
   the fixture's pool API.
3. Wait briefly for the expected backends to disappear on their own.
4. Query `pg_stat_activity` for the target database.
5. If any backend remains, refuse the drop, preserve records/markers and report
   the active-session condition; never terminate it.
6. Allow a retry after the session disconnects.

If a session cannot be proven to belong to Mīzān, leave it untouched. A process
that dies while holding a connection is reaped by the OS; that is the only
mechanism that releases its backends. No role, label, request id or local
setting is accepted as standalone proof of backend ownership.

### Whole-run cleanup

Refactor `cleanup_run()` into phases:

```
DISCOVER → VALIDATE_ALL → BUILD_PLAN → RECHECK → DELETE → VERIFY_COMPLETE
```

- DISCOVER: load records for the run, reject malformed/duplicate/inconsistent
  entries, classify each as valid existing, already cleaned, missing but
  inconsistent, or protected/source violation.
- VALIDATE_ALL: read and verify every marker, owner, cluster, source, nonce and
  local record, and check session safety, before the first destructive call.
- BUILD_PLAN: an explicit ordered list of only validated databases (workers
  before seed).
- RECHECK: before every individual drop, re-read the marker, owner, cluster
  and session state; a stale proof blocks that drop.
- DELETE: drop one database at a time; `DROP DATABASE` cannot be transactional
  across databases and this phase will not claim that it is.
- VERIFY_COMPLETE: confirm every planned database is gone.

Run-level coordination uses a session-scoped PostgreSQL advisory lock keyed by
the run id and a Mīzān namespace. It is acquired with a bounded try-lock, so a
crashed process releases it when its connection closes; a lock that cannot be
acquired is a preflight failure. The registry lock remains only for file writes.
The advisory lock conveys coordination, never deletion authority.

### Failure reporting

- `CleanupPreflightError` (subclass of `OwnershipError`) → `PREFLIGHT_FAILED`,
  zero deletions, all records and markers preserved, categories and reasons
  reported.
- `PartialCleanupError` (subclass of `CleanupError`) → `PARTIAL_CLEANUP`, with
  exact completed and remaining database lists, recoverable by retry.
- Any other exception → `CLEANUP_FAILED`.
- Success → `CLEANED` only after VERIFY_COMPLETE.

No report or log includes a DSN or password.

## Failure conditions that must stop cleanup

Unrelated active session (including one spoofing the expected label), missing
or mismatched marker, wrong cluster/source/owner/nonce, malformed or duplicate
record, inconsistent missing database, source/seed protection violation,
inability to acquire the run lock, failed process shutdown, pool session that
will not close, and any recheck failure.

## Scope boundary

This phase changes session handling, the cleanup preflight/plan, CLI cleanup
statuses, the destructive tests and documentation. Fingerprinting, ownership
graph semantics, source isolation, credential handling and the rest of the TWIN
lifecycle are unchanged.
