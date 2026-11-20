# Phase VI.2.3 — Atomic Deletion Completion & Strict Missing-Intent Recovery Audit

Starting state verified before this audit was written:

- Branch `feat/postgres-ownership-graph`; HEAD and remote
  `ddd84319e334ce24886cfee92d1048da7a876ac9`.
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- PR #10 open, unmerged, head equal to the starting SHA.
- Prior CI: #245 (`44626896384`) and #247 (`44628272698`), both success.

Line numbers refer to `ddd8431`. This audit was written before any production
edit.

## Finding A — a CLEANED record alone accepts an absent database (CONFIRMED)

`cleanup_run()` (`postgres_twin.py:2499-2501`) adds a preflight rejection only
when the database is absent, no intent exists **and** the record is not
`CLEANED`. `verified_drop()` (`:1599-1600`) similarly returns `False` for an
absent database whose record says `CLEANED`. The local lifecycle state is
therefore treated as proof of a deletion for which no journal evidence exists.

A registry containing `CLEANED` without an intent can be produced by truncation,
tampering, or an interrupted older implementation. It must not be accepted. An
absent database is a verified deletion only when a valid intent proves the
operation.

## Finding B — completion uses two registry writes (CONFIRMED)

`_reconcile_absent_database()` (`:1563-1564`) and `verified_drop()`
(`:1619-1620`) call:

```
registry.put_intent(intent.with_state(CLEANED))
registry.update_state(name, TwinState.CLEANED)
```

Each call takes its own lock and performs its own `_write()`. A kill between
them leaves a CLEANED intent and a non-CLEANED record. The next cleanup treats
that as `invalid deletion intent` and cannot recover. The fix must be one
locked operation, one in-memory snapshot and exactly one atomic `_write()`.

## Callers inspected

- `put_intent`: `prepare_deletion_intent()` (`:1514`), both completion sites.
- `update_state`: both completion sites, plus general lifecycle state updates
  (not deletion completion).
- `verified_drop`: `DisposableDatabase.drop()`, `PostgresTwin.cleanup()`,
  `PostgresTwin.restore()`, `cleanup_run()`.
- `_reconcile_absent_database`: `verified_drop()` and the post-preflight
  reconciliation loop in `cleanup_run()` (`:2542-2559`).

## Design decisions

### Strict absent-database state machine

| Case | Evidence | Outcome |
|---|---|---|
| A | absent, no intent, record not CLEANED | reject: `missing without deletion intent` |
| B | absent, no intent, record CLEANED | reject: same category; no inferred deletion |
| C | absent, valid DELETE_PENDING intent | validate against record; atomic completion |
| D | absent, valid CLEANED intent, record CLEANED | idempotent accept |
| E | absent, valid CLEANED intent, record not CLEANED | legacy VI.2.2 split state; atomic reconciliation preserving `operation_id` |
| F | present, record CLEANED | reject |
| G | present, CLEANED intent | reject |
| H | present, pending intent | full live recheck, OID/marker/session checks, then resume |
| I | malformed/tampered/contradictory intent | reject, never repair |

Case E exists only to reconcile workspaces produced by VI.2.2's two-write
completion. It validates the full existing intent and its binding to the exact
record, source, run, cluster, owner, nonce and marker digest, requires the
database to be absent, and never creates or replaces an intent identity.

### Atomic completion

`DatabaseRegistry.complete_deletion(record, intent, *, allow_legacy=False)`:

- one lock; reload from disk; locate exact record and intent;
- require the on-disk objects to equal the supplied ones (no stale overwrite);
- verify names, run, database, OID, nonce, marker digest and `operation_id`;
- require `DELETE_PENDING`, except the explicit legacy path which requires a
  CLEANED intent and a non-CLEANED record;
- update both objects in the same dictionary; call `_write()` **exactly once**;
- return the durability result only after the replacement completes.

After an interruption, the registry is either the old complete state
(`DELETE_PENDING` + non-CLEANED record) or the new complete state (`CLEANED` +
`CLEANED`); a split state is never produced by this operation.

### File durability and permissions

Create the temp file with `os.open(..., O_CREAT|O_EXCL|O_WRONLY, 0o600)`, write
the full payload, flush, verify/apply restrictive permissions, `fsync()` the
file after both content and permission changes, `os.replace()`, then attempt
directory `fsync()` on the **actual registry parent**. Unsupported platforms are
reported explicitly; genuine I/O errors are raised, including after replace
(with an honest message that the new snapshot may already be visible). Process
interruption is not power-loss testing; the report will say so.

### Scope

No change to ownership markers, credentials, fingerprint, session handling,
advisory lock, schema allowlist, or the narrow OID-based creation rollback.
"No second PR, no merge, no `main` modification.
