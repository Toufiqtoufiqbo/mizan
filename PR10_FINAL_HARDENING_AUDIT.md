# PR #10 Final Hardening — Legacy Registry Compatibility & Directory Sync Cleanup Audit

Starting state verified before any edits:

- Branch `feat/postgres-ownership-graph`; HEAD `8b8b52fdc3496b3ee63290bc04a1b9fd0b7be124`
  (local = remote).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- PR #10 open and unmerged; `head` equals the starting SHA; `mergeable_state: clean`.
- VI.2.2 commit `f3f6c0054230681060054fc2cbac4b3e3cb42f3b`.
- No code edited before this audit was written.

## Finding A — The legacy fixture must reproduce the real VI.2.2 format

`test_legacy_split_state_reconciles_atomically` (VI.2.3) previously built a
legacy intent with the current `DeletionIntent` dataclass and then removed
`integrity`. The VI.2.2 implementation did not have `integrity`; its
`DeletionIntent` schema (from `git show f3f6c00`) is:

```
run_id, database_name, kind, worker_id, source_database, cluster_id,
owner_role, nonce, oid, marker_digest, operation_id, created_at, state
```

and `to_dict()` wrote exactly those keys with no `integrity` field. VI.2.2
completion used two separate registry writes:

```
registry.put_intent(intent.with_state(IntentState.CLEANED))
registry.update_state(record.database_name, TwinState.CLEANED)
```

A valid historical VI.2.2 split state is therefore: database absent, journal
intent `state = "CLEANED"`, ownership record not `CLEANED`.

New compatibility tests must build this state as historical JSON written
directly to the registry, and must reject it unless it matches that state.

## Finding B — Remove the obsolete import-time filesystem probe

VI.2.2 added:

```
def _directory_fsync_supported() -> bool:
    if os.name != "posix":
        return False
    probe = Path(tempfile.gettempdir()) / f".mizan-dirfsync-{os.getpid()}"
    ...  # creates probe directory in system temp, opens and fsyncs it
DIRECTORY_FSYNC_SUPPORTED = _directory_fsync_supported()
```

That probe runs at module import and touches the system temporary directory even
when no registry write happens. VI.2.3's `DatabaseRegistry._write()` already
attempts `fsync()` on the actual registry parent, so this is unnecessary and was
replaced with actual-parent behavior plus honest reporting.

Repository search now shows `_directory_fsync_supported`,
`DIRECTORY_FSYNC_SUPPORTED`, and the obsolete import-time probe only in this
audit document; they were removed from code and tests.

## Scope boundary

This phase changes only tests, CI steps and documentation. Production security
guarantees are unchanged from Phase VI.2.3.
