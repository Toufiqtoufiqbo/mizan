# PR #10 Final Hardening — Legacy Registry Compatibility & Directory Sync Cleanup

Starting state verified before any edits:

- Branch `feat/postgres-ownership-graph`; HEAD `8b8b52fdc3496b3ee63290bc04a1b9fd0b7be124`
  (local = remote).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- PR #10 open and unmerged; `head` equals the starting SHA; `mergeable_state: clean`.
- VI.2.2 commit `f3f6c0054230681060054fc2cbac4b3e3cb42f3b`; VI.2.3 commits
  `9fff26d9bcef396fb9cc191b4419104b6d05f600` (implementation) and
  `fa992864e78e4c98be854e389019dd03ecab7d96` (Windows fsync classification
  fix); PR body updated to include VI.2.3.
- No code edited before `PR10_FINAL_HARDENING_AUDIT.md` was written.

## Finding A — The legacy fixture reproduces the real VI.2.2 format

The previous test recreated a split state with the current dataclass; the new
`test_vi22_historical_registry_without_integrity_reconciles` writes a literal
historical JSON object whose shape was read from the VI.2.2 implementation
(`git show f3f6c00:src/mizan/postgres_twin.py`, `DeletionIntent.to_dict()`).
It omits the `integrity` field that VI.2.3 added. Real PostgreSQL run:

1. seed + two workers built with `_build_run()`;
2. `_intent_for()` captures the live ownership identity and original
   `operation_id`;
3. worker 0 is dropped with a controlled real `DROP DATABASE`;
4. the historical JSON is written to the real registry path and re-read by the
   current implementation through the public cleanup path;
5. reconciliation upgrades it to the current format; the original `operation_id`,
   nonce, OID, marker digest, run identity and database identity are unchanged;
6. remaining workers and the seed are cleaned; a second cleanup is a no-op.

The persisted `integrity` is valid, so `DeletionIntent.from_dict(reconciled.to_dict())`
round-trips the upgraded record.

## Finding B — Legacy state cannot authorize deletion of an existing database

- `test_vi22_legacy_intent_without_integrity_cannot_delete_an_existing_database`:
  writes the historical intent with `state=DELETE_PENDING` against the existing
  database and asserts cleanup refuses with category `legacy intent for an
  existing database`; both worker and seed remain.
- `test_vi22_legacy_intent_tampered_marker_is_rejected`: a legacy intent whose
  marker digest is tampered is rejected by record validation; no database is
  dropped.
- `test_current_intent_bad_integrity_remains_rejected`: a current intent with a
  bad `integrity` value is rejected and the database remains.

## Finding C — The import-time probe is gone

`_directory_fsync_supported()` and `DIRECTORY_FSYNC_SUPPORTED` were removed from
the module. `DatabaseRegistry._write()` now:

1. creates the temp file with `os.open(..., O_CREAT|O_EXCL|O_WRONLY, 0o600)`;
2. writes and flushes the payload;
3. applies/verifies restrictive permissions;
4. `fsync()`s the file after content and permission changes;
5. atomically replaces the registry;
6. attempts `fsync()` on the **actual registry parent**;
7. closes the descriptor on success and failure.

`test_no_import_time_directory_probe` asserts the constants/helpers do not exist
and that no `.mizan-dirfsync` marker exists in the system temp dir.

## Actual registry-parent fsync behavior

New unit tests:

- `test_registry_write_reports_actual_parent_sync`: on POSIX, both
  `last_directory_sync_supported` and `last_directory_synced` are true; on
  Windows both are false.
- `test_directory_fsync_failure_is_reported`: a permission-class fsync failure
  on the directory reports `supported=False, synced=False`.
- `test_directory_fsync_io_error_is_raised`: a genuine `EIO` after replace
  raises `OwnershipError`.

## CI

- Implementation `5cb2712ba15a0d824b2052a2b9be3bc111f34f57` — run
  **44746934428** (#255), conclusion **success**. Jobs A, B, B2, C, D, E, F, G
  and S all succeeded; external target SKIPPED.
- Implementation `fa992864e78e4c98be854e389019dd03ecab7d96` — run
  **44744159074** (#254), conclusion **failure**: Windows directory-fsync
  classification raised for `PermissionError`; fixed by the 5cb2712 commit.
- Implementation `9fff26d9bcef396fb9cc191b4419104b6d05f600` — run
  **44732663358** (#249), conclusion **success**. Jobs A–G, B2 and S PASSED;
  external target SKIPPED.
- Documentation commit for this report is pending; its run is recorded in the
  delivery message.
- Workflow: https://github.com/Toufiqtoufiqbo/mizan/actions/runs/44746934428

## Verification

Final local tree: `python -m pytest -q` → **717 passed, 3 skipped, 1 warning
in 861.09 s**. The Twin module has 94 tests (35 unit/failure-injection and 59
real-server integration). The 3 skips are the POSIX-only signal tests on
Windows (`test_signal_during_probes_cleans_up_and_exits_nonzero` for SIGINT and
SIGTERM, and `test_signal_during_restore_cleans_up`); they are reported as
SKIPPED and executed by CI B2 on Linux.

`ruff check .`, `ruff format --check .`, YAML parsing and `git diff --check`
pass. PostgreSQL: local 16.2 via `pgserver`, psycopg 3.3.9; CI
`postgres:16-alpine`. On Windows, the real registry parent does not support
directory `fsync()`; `last_directory_sync_supported` and `last_directory_synced`
are reported as `False`.

Legacy compatibility was proven with real PostgreSQL 16.2 against a historical
VI.2.2 serialization (no `integrity` field, float `created_at`):
`test_vi22_historical_registry_without_integrity_reconciles` performed a real
`DROP DATABASE`, wrote the historical JSON to the real registry path, invoked
the public cleanup path, and asserted reconciliation of both states while
preserving the original `operation_id`, nonce, OID, marker digest, run identity
and database identity; the upgraded registry passes `DeletionIntent.from_dict()`
round-trip. `test_vi22_legacy_intent_without_integrity_cannot_delete_an_existing_database`
and `test_vi22_legacy_intent_tampered_marker_is_rejected` prove legacy intents
cannot authorize deletion of an existing database or tolerate tampering.

Directory fsync behavior: `test_registry_write_reports_actual_parent_sync`,
`test_directory_fsync_failure_is_reported`, `test_directory_fsync_io_error_is_raised`,
`test_directory_open_failure_is_reported` and `test_no_import_time_directory_probe`
all pass.

CI evidence is recorded in the delivery message.

## Remaining limitations

- Windows lacks directory `fsync()`; durability there is the OS rename guarantee.
- Process-kill tests do not prove power-loss durability.
- Legacy intents without `integrity` cannot have tampering detected on their own
  identity; they are accepted only for reconciliation of a genuinely absent
  database, with identity preserved.
