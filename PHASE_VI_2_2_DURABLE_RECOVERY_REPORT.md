# Mīzān Phase VI.2.2 — Durable Cleanup Journal & Orphan-Aware Recovery

## 1. Executive summary

Two recovery defects were closed.

1. An empty or missing local registry allowed `--cleanup-run` to emit `CLEANED`
   without examining any database. Recovery now requires an explicit existing
   workspace; a missing registry or missing run record fails closed with
   `OWNERSHIP_UNPROVABLE` and a strictly read-only list of server-side marker
   candidates. A marker is a clue for an operator, never deletion authority.
2. A crash between `DROP DATABASE` and the registry update left an absent
   database with a non-CLEANED record. Every owned deletion now writes a durable
   deletion intent — bound to the exact database OID, marker digest and full
   ownership identity — before the SQL. A later cleanup can reconcile that
   completed operation, resume a pending one, or reject a reused name with a
   different OID. Nothing is deleted before the whole-run preflight completes.

No session is terminated by Mīzān; all prior ownership, allowlist, credential,
fingerprint and session protections are unchanged. PostgreSQL still cannot
transactionally drop several databases: the guarantee is complete proof before
the first drop and honest `PARTIAL_CLEANUP` reporting afterwards.

## 2. Starting state

- Branch `feat/postgres-ownership-graph`; starting HEAD
  `68b8f796fee2238319f6a0ab95363f1da07e8b4a` (local = remote).
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238`, untouched.
- Worktree clean; `stash@{0}` preserved.
- PR #10 open, unmerged, head equal to the starting SHA.
- Prior CI: #241 (`44570972080`) and #242 (`44572579333`), both success.

The mandatory pre-edit audit is `PHASE_VI_2_2_SECURITY_AUDIT.md`.

## 3. Root cause and fix — registry-missing behaviour

`cli.py` created a temporary workspace when `--workspace` was omitted, then
`cleanup_run()` returned `[]` for a run with no local records; the CLI printed
`CLEANED`. The success status therefore meant "no local records" rather than
"all resources verified absent".

Fixes:

- `--workspace` is mandatory with `--cleanup-run`; no temporary workspace or
  registry is ever created for recovery. A symlinked registry is rejected.
- `cleanup_run()` fails closed with `OwnershipUnprovable` when the registry file
  is missing or no record matches the run.
- `discover_orphan_candidates()` reads database comments only. It reports
  matching markers, malformed markers and candidate names with reasons; it
  modifies no database, marker, owner or registry file and never authorizes
  deletion or adoption.
- CLI emits `OWNERSHIP_UNPROVABLE` with `cleaned: []`, `remaining: []`,
  `reasons`, `category` and `orphan_candidates`, and exits non-zero.

## 4. Deletion intent schema and state machine

Reserved registry key `__deletion_intents__` (excluded from ownership records)
holds one intent per database:

```
run_id, database_name, kind, worker_id, source_database, cluster_id,
owner_role, nonce, oid, marker_digest, operation_id, created_at, state
```

`marker_digest` is SHA-256 of the canonical marker JSON. Intents are strictly
parsed and validated (run id, kind, generated name, nonce, digest, positive OID,
operation id, timestamp). State model:

```
(created) → DELETE_PENDING → CLEANED
```

Sequence: acquire run lock → validate record → verify cluster → verify marker,
source, owner, nonce and generated name → verify OID → check sessions → recheck
all facts → persist `DELETE_PENDING` durably → `DROP DATABASE` via
`psycopg.sql.Identifier` → verify absence → persist `CLEANED` intent and record.

### Recovery cases

| Case | State | Behaviour |
|---|---|---|
| A | DB exists, no intent, record unchanged | full preflight on retry |
| B | DB exists, `DELETE_PENDING`, matching OID/evidence | revalidate and resume the same `operation_id` |
| C | DB absent, valid `DELETE_PENDING` intent | reconcile intent and record to `CLEANED`, continue run |
| D | DB absent, no valid intent | fail closed; no reconciliation |
| E | tampered/invalid intent | refuse; never repaired or overwritten |
| F | same generated name, different OID | refuse; name is not identity |
| G | record `CLEANED`, DB exists | inconsistent; refuse |

### File durability

`DatabaseRegistry._write()` writes a temp file, flushes, `fsync()`s it, sets
`0600`, atomically replaces the registry and `fsync()`s the parent directory on
POSIX. On Windows (and any platform where directory `fsync` is unavailable) the
module exposes `DIRECTORY_FSYNC_SUPPORTED = False`; the rename relies on the
OS's own guarantees and this report does not claim stronger durability there.
Malformed or truncated registries are rejected rather than silently accepted.

## 5. Inventory of `DROP DATABASE` call sites

| # | Site | Authority |
|---|---|---|
| 1 | `verified_drop()` | durable intent + record + live marker + cluster + owner + nonce + OID + no sessions; rechecked immediately before SQL |
| 2 | `_rollback_seed()` | OID captured immediately after `CREATE DATABASE`, plus cluster and owner; marker verified when available; only for a seed created by the failed call |
| 3 | `_rollback_created()` | same narrow OID-based proof for a worker created by the failed call |

Sites 2 and 3 cannot use the normal journal because a complete marker/record may
not exist yet; their authority is the server-assigned OID of an object created in
that same call, never a generated name or local record alone. A failure to prove
the OID leaves the object and records untouched and is reported. No other
deletion helper exists.

## 6. Real PostgreSQL adversarial evidence

Tests use the live `pgserver` fixture; the crash tests spawn real child processes
and kill them with `Popen.kill()` at instrumented points.

- `test_crash_after_intent_before_drop_recovers`: child persists the intent,
  signals readiness, is killed while the database still exists; retry resumes
  the same `operation_id` and finishes `CLEANED`.
- `test_crash_after_drop_before_registry_completion_recovers`: child executes the
  real `DROP DATABASE`, signals after PostgreSQL confirms absence and before the
  registry completion update, then is killed. The retry reconciles the pending
  intent and cleans the remaining databases; final status `CLEANED`.
- `test_pending_intent_rejects_recreated_database_oid` and
  `test_tampered_deletion_intent_fails_closed`: both refuse with
  `PREFLIGHT_FAILED` and zero deletions.
- Registry-missing, empty-registry, explicit-workspace and read-only orphan
  diagnostics all fail closed with `OWNERSHIP_UNPROVABLE`.
- Prior mandatory tests (spoofed labels, invalid markers, no-deletion-before-
  preflight, partial recovery, lock coordination, sessions, pools, signals,
  source protection) still pass.

## 7. Verification

Final local tree: `python -m pytest -q` → **697 passed, 3 skipped, 1 warning
in 520.54 s**. The Twin module has 74 tests (32 unit/failure injection and 42
real-server integration). The three skips are POSIX-only signal-delivery tests
on Windows; they are reported as SKIPPED and executed by CI B2 on Linux.
`ruff check .`, `ruff format --check .`, `git diff --check` and YAML parsing of
`.github/workflows/mizan.yml` all pass.

PostgreSQL: local 16.2 via `pgserver`, psycopg 3.3.9; CI `postgres:16-alpine`.
`DIRECTORY_FSYNC_SUPPORTED` is `False` on the local Windows host and the report
does not claim an fsynced directory entry there.

Real crash evidence: the "after intent" child was killed while its database
still existed and the pending intent retained its `operation_id`; the retry
resumed that same operation and finished `CLEANED`. The "after DROP" child was
killed after PostgreSQL confirmed the database absent and before the registry
completion update; the retry reconciled the pending intent, cleaned the two
remaining databases, reported all three in `cleaned`, and ended `CLEANED`.
Recreated-OID and tampered-intent tests both rejected with `PREFLIGHT_FAILED`
and left every database present. Exact CI evidence is recorded in the delivery
message.

## 8. Remaining limitations

- PostgreSQL offers no multi-database `DROP` transaction; a valid preflight can
  still be followed by partial physical deletion, reported as `PARTIAL_CLEANUP`.
- Windows lacks directory `fsync()`; durability there is the OS's rename
  guarantee, not an explicitly synced directory entry.
- A crash in the narrow window between `CREATE DATABASE` and the marker/OID
  record leaves an unprovable orphan; cleanup refuses to remove it.
- Orphan markers require an operator decision; no automatic adoption exists.
- Cluster-wide roles, tablespaces, extensions and publications remain outside
  the clone/fingerprint guarantee; the external target is not exercised in CI.
