# Mīzān Phase VI.2.1 — Session Ownership & Whole-Run Cleanup Verification

> **Phase VI.2.2 adds durable deletion intents and orphan-aware recovery.**
> `--cleanup-run` now requires an explicit workspace; a missing registry fails
> closed, and a crash after `DROP DATABASE` is recoverable. See
> `PHASE_VI_2_2_DURABLE_RECOVERY_REPORT.md`.

## 1. Executive summary

Phase VI.2 left two destructive-boundary assumptions unproven. This phase
removes both.

1. `application_name` was used as if it identified Mīzān-owned backends. It is
   a client-controlled label: any client can copy it. It is now used only as
   diagnostic metadata. **No PostgreSQL session is terminated by Mīzān.**
   Sessions disappear because their explicitly owned process is stopped and
   reaped, or because the client disconnects. If any backend remains, the
   destructive operation is refused.
2. Cleanup validated records and cluster identity for the whole run but checked
   server-side markers one database at a time, immediately before each drop.
   A tampered second worker could therefore be discovered only after the first
   worker had already been deleted. Cleanup is now a whole-run preflight
   (`DISCOVER → VALIDATE_ALL → BUILD_PLAN → RECHECK → DELETE → VERIFY_COMPLETE`):
   every marker, owner, cluster, nonce, record and session must pass before the
   first `DROP DATABASE`.

PostgreSQL cannot delete several databases in one transaction. The guarantee
is **no deletion before complete proof**, not atomic physical deletion. A failure
during the sequential delete phase is reported as `PARTIAL_CLEANUP` with exact
completed and remaining databases, and is recoverable by retry.

## 2. Starting state

Verified before the audit and before any production edit:

- Branch `feat/postgres-ownership-graph`; HEAD
  `696a85ae3b3d752054e4ad306c3d150908ffba4f` (local and remote match).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- Previous CI: run #239 (`44515424790`) on `1ed2f77` and run #240
  (`44516914315`) on `696a85a`, both success; external-target opt-in SKIPPED.

The mandatory pre-edit audit is `PHASE_VI_2_1_SECURITY_AUDIT.md`.

## 3. Finding A — the spoofable session label

### Previous trust assumption

`_terminate_owned_sessions()` selected backends with
`application_name = 'mizan:<run_id>:<worker_id>'` and called
`pg_terminate_backend(pid)`. `verified_drop()` passed that label from the
registry, so a client that copied the label could be killed, and a genuinely
owned session with a different label could block cleanup. The label was treated
as an ownership credential even though any PostgreSQL client sets it freely.

### Final design

- The termination helper and every call to `pg_terminate_backend` were removed.
- `verified_drop()` waits briefly for backends to disappear on their own, then
  queries `pg_stat_activity` by database name only. Any remaining backend
  aborts the drop with `CleanupError`; its label is never inspected for trust.
- The owned process lifecycle is unchanged and mandatory:
  `_stop_application(strict=True)` stops and reaps the process, observes its
  exit and closes Mīzān's control connection. A stop failure blocks every
  destructive operation.
- The fixture exposes `/pool`, `/pool/shutdown?leak=1` and `/pool/release`, so
  idle/active connections, reuse, pool shutdown and a simulated shutdown
  failure are observable. After the process exits the OS releases its sockets;
  Mīzān never kills the backends itself.

### What is terminated and what is refused

- **Terminated:** nothing by Mīzān. Only the explicitly owned *process* is
  stopped through `Twin.stop()`, which reaps it; its database backends then
  close with the process.
- **Refused:** any `DROP DATABASE` while any backend is connected, including a
  stale session, an unrelated session with a different label, and an unrelated
  session deliberately using the exact Mīzān label.
- **Missing evidence:** a backend whose provenance cannot be established is
  left untouched and cleanup fails closed.

### Spoofing test

`test_unrelated_session_spoofing_application_name_is_never_terminated` starts a
real worker, opens a second connection whose `application_name` is exactly the
worker's identity, and proves by PID and by `SELECT 1` that the backend is still
alive after cleanup refused. The database also still exists. After that client
disconnects, the cleanup retry succeeds. No mocked `pg_stat_activity` is used.

### Pool evidence

`test_pooled_idle_and_active_sessions_are_released` proves the old pool's PIDs
are gone after a restore and a new pool is established.
`test_pool_leak_mode_still_releases_connections` proves a failed pool shutdown
leaves its server sessions open, and that explicit release lets cleanup finish.

## 4. Finding B — whole-run cleanup preflight

### Final design

`cleanup_run()` now executes:

1. **DISCOVER** — read all records for the run, reject malformed or duplicate
   entries, and classify each database as valid existing, already cleaned,
   missing-but-inconsistent, or protected.
2. **VALIDATE_ALL** — for every record: structure, run id, worker id, kind,
   generated name, source, seed relationship, cluster identity, owner, nonce,
   server-side marker and active-session safety. Every reason is collected and
   reported with a category.
3. **BUILD_PLAN** — an ordered plan of only fully validated databases, workers
   before the seed.
4. **RECHECK** — `verified_drop()` re-reads the marker, owner, cluster and
   session state for each target immediately before its own drop.
5. **DELETE** — one database per operation, with the completed state persisted
   after each success.
6. **VERIFY_COMPLETE** — confirm every planned database is absent before
   reporting `CLEANED`.

If preflight fails, **zero** databases are dropped, all registry records and
markers are preserved, and `CleanupPreflightError` carries categories and
reasons. A failure during DELETE raises `PartialCleanupError` with the exact
`cleaned` and `remaining` lists; retry is idempotent because already-cleaned
records are recognized.

### Coordination

A session-scoped PostgreSQL advisory lock, keyed by the run id in a Mīzān
namespace, serializes concurrent cleanups of the same run. It is acquired with
a bounded try-lock. If the process dies, the connection closes and the lock is
released automatically. The local registry lock still protects file writes
only; neither lock grants deletion authority.

### Central regression

`test_invalid_second_worker_marker_blocks_whole_run` builds a seed and two
validly marked workers, tampers with worker 1's marker and calls cleanup. The
preflight rejects the run with category `invalid marker`; worker 0, worker 1
and the seed all still exist, and every registry record is unchanged.
`test_invalid_seed_marker_leaves_workers_untouched` does the same for the seed.

## 5. CLI status contract

`mizan postgres-twin --cleanup-run RUN_ID` emits exactly one of:

- `CLEANED` — all expected resources verified absent;
- `PREFLIGHT_FAILED` — preflight rejected the run; nothing was deleted;
- `PARTIAL_CLEANUP` — some databases were deleted before a failure;
- `CLEANUP_FAILED` — another failure.

Preflight and partial failures exit non-zero, include `reasons` and the
completed/remaining database lists, preserve recoverable records, and never
include a DSN or password. The normal run path sets `cleanup_status` for
preflight/partial failures while keeping its existing `cleanup_failed` contract.

## 6. Test evidence

### Commands and results

Local exact results are recorded in section 9 after the final run. The
PostgreSQL server used locally is the bundled `pgserver` PostgreSQL 16.2;
CI uses the `postgres:16-alpine` service.

### Adversarial cases

- Spoofed `application_name` backend survives; cleanup refuses, then succeeds
  on retry after disconnect.
- Different `application_name` backend blocks deletion.
- Idle and active pooled sessions are released before restore/drop.
- Failed pool shutdown leaves sessions open; explicit release allows cleanup.
- Session created during preflight blocks every drop.
- Session that disappears during preflight allows a safe cleanup.
- Failure before the first drop → `PARTIAL_CLEANUP` with zero deletions.
- Failure after the first drop → `PARTIAL_CLEANUP` with the first database
  recorded as deleted and the others recoverable by retry.
- Concurrent cleanup attempts are serialized by the advisory lock; the lock
  is released when its connection closes and after the holder process is killed.
- All-valid run cleanup removes seed and both workers.
- Invalid second-worker marker and invalid seed marker block the entire run.
- Forged records, foreign cluster, similar names and malformed registries are
  rejected by the existing Phase VI.2 tests.
- SIGINT/SIGTERM, SIGKILL orphan recovery and `--cleanup-run` remain covered.

## 7. CI

Stages A–G, B2 and S are preserved. The destructive PostgreSQL job B2 adds
named steps for the spoofed-session test, the invalid worker/seed marker tests,
partial-cleanup/coordination tests, and still fails on any skip. The external
target remains opt-in and SKIPPED when not configured.

CI on implementation commit `b27f94682893dd4991c2cd8c11c942a6e5ab2cc1`:
workflow run **44570972080** (#241), conclusion **success**. Jobs A, B, B2,
C, D, E, F, G and S all succeeded; `G - external target (opt-in)` was SKIPPED,
never passed. A second run on the final documentation commit is recorded in the
delivery message.

## 8. Documentation and compatibility

- `PHASE_VI_2_SECURITY_HARDENING_REPORT.md` now points here for the current
  session/cleanup guarantees.
- `PHASE_VI_1_POSTGRES_TWIN_REPORT.md`, `README.md` and `ROADMAP.md` no longer
  claim that Mīzān terminates sessions by `application_name`.
- Phase VI.2 ownership markers, source isolation, allowlist, credential
  handling, canonical fingerprints, signal handling and CLI cleanup contracts
  are unchanged.

## 9. Final verification

Local final tree: `python -m pytest -q` → **680 passed, 3 skipped, 1 warning
in 574.43 s**. The Twin module has 57 tests (27 unit/failure injection and 30
real-server integration). The three skips are POSIX-only signal delivery tests
on Windows; they are reported as SKIPPED and executed by CI job B2 on Linux.
`ruff check .`, `ruff format --check .` and `git diff --check` are clean.

PostgreSQL server: 16.2 (bundled `pgserver`) locally; `postgres:16-alpine` in
CI; psycopg 3.3.9 locally.

Adversarial outcomes (real server): spoofed label backend survived and cleanup
refused; invalid second-worker and invalid seed markers rejected the whole run
with zero deletions; all-valid run cleaned seed and both workers; preflight
session injection blocked every drop; disappearing session allowed cleanup;
failure before/after the first drop produced `PARTIAL_CLEANUP` with exact lists
and was recoverable; concurrent cleanup was serialized; the advisory lock was
released on connection close and after the holder process was killed.
Phase VI.2 ownership, allowlist, credential, fingerprint, signal and source
protection suites still pass.

CI evidence is recorded in section 7 and in the delivery message.

## 10. Remaining limitations

- PostgreSQL offers no transaction across multiple `DROP DATABASE` statements;
  partial physical deletion after a valid preflight is possible and reported.
- Cleanup requires `pg_control_system()` permission, `CREATEDB`, `CONNECT`, and
  permission to take an advisory lock in the source database.
- A third-party client may hold a connection indefinitely; cleanup will refuse
  until it disconnects. Mīzān deliberately has no override.
- Cluster-wide roles, tablespaces, extensions and publications remain outside
  the clone and fingerprint guarantee.
- The external target is not exercised in ordinary CI.

## 11. Final verdict

**Verdict: READY FOR REVIEW.**
