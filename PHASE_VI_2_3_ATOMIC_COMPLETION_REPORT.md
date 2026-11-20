# Mīzān Phase VI.2.3 — Atomic Deletion Completion & Strict Missing-Intent Recovery

## 1. Executive summary

Two state-machine defects in the VI.2.2 deletion journal were closed.

1. An absent database with no deletion intent was accepted whenever its local
   ownership record said `CLEANED`. A local state is not proof of a deletion.
   Recovery now requires a valid deletion intent for every absent database;
   the only exception is the explicitly documented legacy split state from
   VI.2.2, which still requires a complete, validated CLEANED intent.
2. Deletion completion used two separate registry writes (intent, then record),
   so a crash in between left a split state. A single
   `DatabaseRegistry.complete_deletion()` now updates both objects in one
   locked snapshot and one atomic `_write()`.

The registry write path now creates the temp file with `0600` from the start,
fsyncs content **and** permissions before rename, attempts directory `fsync()`
on the actual registry parent, and reports the result instead of assuming a
probe proved support. Process-interruption tests exercise the boundaries
immediately before and after the atomic replacement.

## 2. Starting state

- Branch `feat/postgres-ownership-graph`; starting HEAD
  `ddd84319e334ce24886cfee92d1048da7a876ac9` (local = remote).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- PR #10 open and unmerged; prior CI #245/#246-success runs recorded in the
  VI.2.2 report.
- Mandatory pre-edit audit: `PHASE_VI_2_3_SECURITY_AUDIT.md`.

## 3. Strict absent-database state machine

| Case | Evidence | Outcome |
|---|---|---|
| A | absent, no intent, record not CLEANED | `PREFLIGHT_FAILED`, category `missing without deletion intent` |
| B | absent, no intent, record CLEANED | same rejection; no inferred deletion, no invented intent |
| C | absent, valid DELETE_PENDING intent | validate against record, cluster, source, owner, nonce, OID, marker digest; atomic completion |
| D | absent, valid CLEANED intent, record CLEANED | idempotent accept |
| E | absent, valid CLEANED intent, record not CLEANED | legacy VI.2.2 split state; atomic reconciliation, same `operation_id` |
| F | present, record CLEANED | reject |
| G | present, CLEANED intent | reject |
| H | present, pending intent | full live recheck (OID, marker digest, owner, cluster, sessions), then resume |
| I | malformed/tampered/contradictory intent | reject and preserve everything |

New-style intents carry an `integrity` digest over all persisted fields except
itself, so tampering with the operation id, nonce, OID or marker digest is
detected when the journal is read. VI.2.2 intents without that field remain
readable only for the legacy reconciliation path; their identity is preserved
verbatim and no new intent is created.

Case E exists to reconcile workspaces produced by VI.2.2's two-write
completion. It requires the database to be absent, the full intent to be valid
and bound to the exact local record, source, run, cluster, owner, nonce and
marker digest, and performs one atomic registry replacement.

## 4. Atomic completion

`DatabaseRegistry.complete_deletion(record, intent, *, allow_legacy=False)`:

1. acquire the registry lock;
2. reload the latest registry from disk;
3. locate the exact record and intent;
4. require the on-disk objects to equal the supplied objects (no stale overwrite);
5. verify names, run, database, OID, nonce, marker digest and operation id;
6. require `DELETE_PENDING` (or the explicit legacy CLEANED/non-CLEANED pair);
7. update both objects in the same registry dictionary;
8. call `_write()` **exactly once**;
9. return only after replacement and supported durability operations complete.

After an interruption, the registry shows either the old complete state
(`DELETE_PENDING` + non-CLEANED record) or the new complete state (`CLEANED` +
`CLEANED`). This is one file's atomic replacement; it is **not** a transaction
spanning PostgreSQL and the filesystem. The durable intent bridges them.

Every completion call site now uses this method: `verified_drop()` after
PostgreSQL confirms absence, `_reconcile_absent_database()` for cases C/E, and
the post-preflight recovery loop in `cleanup_run()`. A repository search finds
no remaining `put_intent(CLEANED)` followed by `update_state(CLEANED)`.

## 5. Durability and permissions

`_write()` now: creates the temp file with `os.open(..., O_CREAT|O_EXCL|O_WRONLY,
0o600)`, writes the payload, flushes, applies/verifies `0600`, `fsync()`s the
file, replaces the registry atomically, then attempts `fsync()` on the **actual**
parent directory. Unsupported errors (Windows, EACCES/EPERM/EINVAL/ENOSYS…) are
reported through `last_directory_sync_supported=False` and
`last_directory_synced=False`. Other I/O errors are raised; if one occurs after
`os.replace()`, the error explicitly says the new snapshot may already be
visible. No temporary-directory probe is used to claim support.

Killing a process before or after `os.replace()` is not a power-loss test. It
can prove which complete snapshot is visible, not that a filesystem flush
survived sudden power loss. The report makes this distinction explicitly.

## 6. Verification

Final local tree: `python -m pytest -q` → **711 passed, 3 skipped, 1 warning
in 719.40 s**. The Twin module has 88 tests (32 unit/failure-injection and 56
real-server integration). The 3 skips are the POSIX-only signal tests on
Windows (`test_signal_during_probes_cleans_up_and_exits_nonzero` for SIGINT and
SIGTERM, and `test_signal_during_restore_cleans_up`); they are reported as
SKIPPED and executed by CI B2 on Linux. `ruff check .`, `ruff format --check .`,
YAML validation and `git diff --check` pass.

PostgreSQL: local 16.2 via `pgserver`, psycopg 3.3.9; CI `postgres:16-alpine`.
On this Windows host the actual registry parent does not support directory
`fsync()`, so `last_directory_sync_supported` and `last_directory_synced` are
reported as `False`; no stronger claim is made.

Real process interruption: with the child killed before `os.replace()`, the
registry showed `DELETE_PENDING + non-CLEANED record`; killed after replacement,
it showed `CLEANED + CLEANED`. The split state was never visible in either case.
The CLI retry completed successfully from the old state and was idempotent from
the new state, preserving the original `operation_id`. This process-kill
evidence does **not** prove power-loss durability.

CI evidence is recorded in the delivery message.

## 7. Remaining limitations

- PostgreSQL cannot transactionally drop several databases; a valid preflight
  can still be followed by partial physical deletion (`PARTIAL_CLEANUP`).
- Directory `fsync()` is unsupported on Windows; durability there is the OS
  rename guarantee.
- Process interruption is not power loss or filesystem corruption testing.
- A `SIGKILL` between `CREATE DATABASE` and marker/record creation leaves an
  unprovable orphan; cleanup refuses to remove it.
- Legacy intents without an `integrity` field cannot detect tampering of their
  own fields; they are accepted only for reconciliation and their identity is
  preserved.
- Cluster-wide objects and the external target remain outside this guarantee.
