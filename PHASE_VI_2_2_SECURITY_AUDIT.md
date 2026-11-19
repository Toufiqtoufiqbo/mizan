# Phase VI.2.2 — Durable Cleanup Journal & Orphan-Aware Recovery Audit

Starting state verified before this audit was written:

- Branch `feat/postgres-ownership-graph`; HEAD
  `68b8f796fee2238319f6a0ab95363f1da07e8b4a` (local and remote match).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Clean worktree; `stash@{0}` preserved.
- PR #10 open, unmerged, `mergeable_state: clean`, head equal to the expected
  HEAD.
- Prior CI: #241 (`44570972080`) on `b27f946` and #242 (`44572579333`) on
  `68b8f79`, both success; external-target opt-in SKIPPED.

Line references below point at `68b8f79`. This audit was written before any
production edit.

## Finding A — an empty local registry is reported as CLEANED (CONFIRMED, critical)

`cli.py:902-908` creates a workspace with
`Path(tempfile.mkdtemp(prefix="mizan-v62-"))` whenever `--workspace` is omitted,
then calls `drop_run()`. `postgres_twin.py:2075-2078` builds a `DatabaseRegistry`
and returns `[]` when no record for the requested run exists. The CLI then emits
`CLEANED` (`cli.py:942`).

The caller therefore receives a success status without any proof that the
generated databases are absent. Omitting `--workspace` makes this worse: a brand
new temporary workspace with an empty registry is sufficient to "clean" any run
id.

The same function treats a missing run as a no-op even when a real workspace is
supplied but its registry was deleted, truncated, or replaced. No status
distinguishes "there is no evidence" from "every resource was verified absent".

*Required fix:* require an explicit, existing workspace and an existing regular
`ownership.json`; never create a registry for recovery; fail closed with
`OWNERSHIP_UNPROVABLE` when the requested run has no trustworthy local record;
add a strictly read-only server-side marker diagnostic that reports candidate
orphans without authorizing any deletion.

## Finding B — DROP DATABASE is not write-ahead journaled (CONFIRMED, critical)

`verified_drop()` (`postgres_twin.py:1278-1315`) does:

```
DROP DATABASE (line 1313) → registry.update_state(CLEANED) (line 1314)
```

A crash in that window leaves the database absent and the record non-CLEANED.
`cleanup_run()` preflight (`2120-2126`) then classifies it as "missing
inconsistent" and refuses the whole run forever. There is no durable record of
which operation removed the database, so automated recovery is impossible
without weakening the ownership checks.

`DatabaseRegistry._write()` (`1140-1155`) flushes and `fsync()`s the file before
`os.replace()`, but does not `fsync()` the containing directory, so the rename
itself may not survive a crash on some filesystems.

*Required fix:* persist a complete, validated deletion intent before the SQL,
including the database OID; reconcile absent databases only when a matching
intent proves the deletion; revalidate the intent (including the OID) before
resuming or reconciling; add directory `fsync()` where supported and document
where it is not.

## Inventory of `DROP DATABASE` call sites

| # | Location | Current proof | Journal required? |
|---|---|---|---|
| 1 | `verified_drop()` `postgres_twin.py:1313` | local record + marker + cluster + owner + nonce + OID recheck + no sessions | **Yes** — normal owned deletion |
| 2 | `_rollback_seed()` `postgres_twin.py:1659` | OID captured immediately after `CREATE DATABASE`, cluster and owner, no sessions; marker verified when present | No — creation rollback; a complete marker/record may not exist yet. Must keep OID-only authority narrow and report unprovable orphans |
| 3 | `_rollback_created()` `postgres_twin.py:1802` | same OID-based evidence for a worker created in this call | No — same narrow creation rollback case |

`DisposableDatabase.drop()` (`1849`), `PostgresTwin.cleanup()` (`2044`),
`PostgresTwin.restore()` (`2018`) and `cleanup_run()` (`2064`) all reach site 1.
There is no other deletion helper.

## Design decisions

### Deletion intent

A reserved key inside the ownership registry holds per-database intents. It is
written with the same locked, atomic, fsynced path as records and is excluded
from `DatabaseRegistry.records()`. Fields: `run_id`, `database_name`, `kind`,
`worker_id`, `source_database`, `cluster_id`, `owner_role`, `nonce`, `oid`,
`marker_digest`, `operation_id`, `created_at`, `state`. States:
`DELETE_PENDING` → `CLEANED`. The marker digest is SHA-256 of the canonical
marker JSON, recomputed from the local record before every use.

The intent is not a new authority. It binds an already fully verified deletion
to an exact database OID and must be revalidated against the live catalog before
resuming (Case B), and against the local record, cluster and source when the
database is already gone (Case C).

### Recovery state machine

- **A — crash before intent:** DB exists, no intent, record unchanged → normal
  preflight on retry.
- **B — crash after intent, before DROP:** DB exists, `DELETE_PENDING` intent →
  revalidate OID, marker, owner, cluster, source, nonce and sessions, then
  resume the same intent.
- **C — crash after DROP, before registry completion:** DB absent,
  `DELETE_PENDING` intent valid against the record → mark intent and record
  `CLEANED`, continue the run. This is the central case.
- **D — DB absent without a valid intent:** fail closed, report the missing
  database, preserve records.
- **E — invalid/tampered intent:** refuse, do not repair or overwrite.
- **F — OID mismatch (name reused):** refuse; a name is not identity.
- **G — record CLEANED but DB exists:** inconsistent; refuse.

### Durability

`_write()` writes a temp file, flushes, `fsync()`s it, `chmod 0600`, replaces the
registry, then `fsync()`s the parent directory where the OS supports it. On
platforms without directory `fsync()` (notably Windows), the limitation is
recorded and exposed explicitly rather than claimed as a stronger guarantee.

### Orphan diagnostics

When no local record matches, cleanup attempts a read-only scan of database
comments for markers naming the run. Candidates are reported with reasons; no
database, marker, owner or registry file is modified, and no candidate is ever
automatically adopted or deleted.

### Scope

No change to ownership markers, schema allowlist, credentials, fingerprint,
session protections, advisory lock, or process lifecycle. No new PR, no merge,
no modification of `main`.
