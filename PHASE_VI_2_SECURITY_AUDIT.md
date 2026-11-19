# Phase VI.2 — PostgreSQL Twin Security Audit

Starting state verified before this audit was written:

- Branch `feat/postgres-ownership-graph`
- HEAD `3f3f779d074a7ee05c76fbd2ff59477c126a8ce5` (matches the expected SHA)
- `main` at `0ffc1f606f9e3e40b60f9fcd23bb54afb2d3d238` (untouched)
- Clean worktree; `stash@{0}` preserved
- Last CI: run #238, run id `44390730758`, head `3f3f779` — A–G green,
  external-target opt-in **SKIPPED** (not passed)

Every finding below was checked against the code at that commit. Line numbers
refer to that commit.

## Audit scope

- `src/mizan/postgres_twin.py`
- `src/mizan/cli.py` (`postgres-twin`)
- `src/mizan/twin.py`
- `src/mizan/postgres_attribution.py`
- `src/mizan/postgres_audit.py`
- `tests/fixtures/external_apps/postgres_store/app.py`
- `tests/test_postgres_twin.py`, `tests/test_postgres_ownership_integration.py`,
  `tests/test_postgres_roundtrip.py`
- `benchmarks/postgres_twin/run.py`
- `.github/workflows/mizan.yml`
- `PHASE_V_1_DESIGN.md`, `PHASE_VI_POSTGRES_REPORT.md`,
  `PHASE_VI_1_POSTGRES_TWIN_REPORT.md`, `README.md`, `ROADMAP.md`

## Finding A — Dangerous cleanup boundary (CONFIRMED, critical)

`cleanup_run()` (`postgres_twin.py:643-663`) reads database names from the
mutable local JSON registry and interpolates them into SQL:

```python
if record.database_name != name or record.source_database == name or record.seed_database == name:
    raise SourceProtectionError(...)
...
cursor.execute(f'DROP DATABASE IF EXISTS "{name}"')  # line 659
```

The only checks are that the JSON key equals the record field and that the name
is not the recorded source/seed. The registry is a plain file an attacker (or a
buggy run) can edit. The code does not establish:

- that `name` matches the deterministic generated-name format;
- that the database belongs to this run on the server;
- that the current server is the cluster that created it;
- that the current DSN still names the same source database;
- that the database owner is the expected role;
- that an independent server-side marker agrees with the local record.

A name containing a quote or `; DROP DATABASE ...` is interpolated verbatim.
The same pattern appears in `_drop_seed()` (`:338-344`) and in the CLI seed
drop (`cli.py:998-1004`).

Risk: arbitrary database deletion through a registry-controlled identifier.
This is a release blocker.

## Finding B — Schema allowlist not applied to the dump (CONFIRMED, high)

`prepare_baseline()` fingerprints only the configured schemas
(`postgres_twin.py:259`) but the dump command is:

```python
[dump_tool, "--format=plain", "--no-owner", "--no-privileges", "-f", str(archive), self.dsn]
```

There is no `--schema` selection. `pg_dump` therefore copies **every**
non-system schema, including data the operator never allowlisted. The clone
boundary does not match the declared boundary.

## Finding C — Credentials in child-process arguments (CONFIRMED, high)

`pg_dump` receives the full DSN (`postgres_twin.py:275`) and `psql` receives
`database_dsn(self.dsn, self.seed_name)` (`:307`). When the DSN contains a
password, it is visible in process listings and in crash dumps. This contradicts
the documented secret-handling guarantee and the CLI contract.

## Finding D — Stop and cleanup errors can be swallowed (CONFIRMED, high)

- `PostgresTwin.stop()` (`:619-626`) appends `Twin.stop()` exceptions to
  `cleanup_errors` and returns normally.
- `Twin.stop()` (`twin.py:149-178`) also records rather than raises; it kills
  after a 10 s wait even if termination failed.
- `cleanup()` calls `stop()` and then drops the database regardless of whether
  the application actually stopped.
- The CLI prints `"status": "VERIFIED"` (`cli.py:988`) **before** the `finally`
  block that cleans up (`:992-1004`). A cleanup failure is printed to stderr but
  the success payload was already emitted; the exit code can remain 0 for the
  success path and the seed drop is unconditional.

Result: a run can claim verified state while the application was not stopped or
cleanup failed.

## Finding E — Session ownership mismatch (CONFIRMED, high)

The fixture sets `application_name` to `mizan:<principal>` per transaction
(`tests/fixtures/.../app.py:76`). The drop path looks for
`mizan:<run_id>:<worker_id>%` (`postgres_twin.py:497-500`, `:500`). These never
match, so Mīzān-owned sessions are never identified. Worse, using
`application_name` for the principal means the session identity changes with
the authenticated user and is reset by `SET LOCAL`, so it cannot be a stable
ownership signal.

Principal attribution and session ownership must be separated: a stable
session identity for ownership, a transaction-local setting for the principal
and the request id.

## Finding F — Fingerprint is not canonical (CONFIRMED, high)

`database_fingerprint()` (`postgres_twin.py:143-226`):

- Rows are read with `ORDER BY 1` (`:197`). If the first column is not unique
  (and for tables without a primary key) the order is unspecified; the digest
  can change without any data change.
- Values are converted with `str(value)` (`:201`). Integer `1` and text `"1"`
  collapse to the same string; decimals lose type information.
- Column metadata is filtered by `table_schema = ANY(%s) AND table_name = %s`
  (`:163-171`) instead of the exact schema, so two same-named tables in
  different allowlisted schemas mix columns.
- Only `last_value` is read for sequences (`:218-224`); `is_called` and the
  sequence configuration are ignored.
- Indexes are reconstructed from `attname` aggregation, losing expressions,
  operator classes and partial predicates.
- Defaults, identity definitions, functions and non-Mizan triggers are absent.

## Finding G — Verification compares the database to itself (CONFIRMED, critical for trust)

After the application starts, the code assigns:

```python
self.database.expected_fingerprint = self.source.fingerprint(self.database.dsn)  # :594
self.database.verify()
```

`verify()` then compares the live database to that just-assigned value. This is
not baseline verification: any mutation the application performed during
bootstrap is accepted as "expected". The expected value must be derived from
the immutable baseline plus a documented, asserted audit installation.

## Finding H — Registry is not atomic or protected (CONFIRMED, medium)

`DatabaseRegistry.save()` (`:375-376`) writes in place with no temp-file
replacement, no `fsync`, no permissions and no locking. A crash can truncate
the file; concurrent runs can lose records. `load()` trusts arbitrary JSON
shapes.

## Finding I — Documentation drift (CONFIRMED, medium)

- `PHASE_VI_1_POSTGRES_TWIN_REPORT.md` says `pg_dump -Fc` and `pg_restore`;
  the code uses plain SQL plus `psql`.
- The report contains `PENDING_HEAD_SHA`.
- It records 12 Twin tests; the file has 17.
- It cites CI run #237; the last verified run is #238.
- `--workers` provisions isolated databases but `--exercise` probes only the
  first worker; this is not stated precisely.

## Design decisions for the remediation

### Ownership model

A local JSON record alone never authorizes deletion. Each database (seed and
worker) carries a server-side marker in its database comment:

```json
{"v":1,"run_id":"...","kind":"worker","worker_id":"w0",
 "source":"...","cluster":"<system_identifier>","owner":"<role>",
 "nonce":"<random>","created_at":...}
```

Deletion requires all of: exact generated name, valid run/worker format,
matching local record, matching server marker and nonce, matching cluster
identity (`pg_control_system().system_identifier`), matching source database,
matching actual database owner, and no unrelated active sessions. Any mismatch
aborts. All identifiers go through `psycopg.sql.Identifier`. No
`DROP DATABASE ... WITH (FORCE)`.

If `pg_control_system()` is not permitted, baseline preparation and cleanup fail
closed and document the required privilege. The JSON registry is hardened
(atomic replace, `0600`, lock file, strict parsing) but remains only a secondary
record.

### Source isolation

`pg_dump` is invoked with one `--schema` per allowlisted schema. The seed is
checked for non-allowlisted schemas that contain relations. Credentials never
appear in argv: a temporary `PGPASSFILE` (0600) plus non-secret `PG*`
environment variables are used, and the file is removed in `finally`.

### Session identity

Application DSNs carry `application_name=mizan:<run_id>:<worker_id>`. The
principal and request id travel in transaction-local `mizan.principal` and
`mizan.request_id`. The audit trigger prefers `mizan.principal` and ignores the
stable session identity; legacy `mizan:<principal>` application names keep
working.

### Canonical fingerprint

Schema-qualified discovery; primary-key ordering when a key exists and
canonical sorting of typed row encodings otherwise; type-tagged values
(`int`, `decimal`, `str`, `bool`, `null`, `bytes`, `uuid`, `datetime`, `json`,
`array`); exact-schema column metadata; `pg_get_indexdef`,
`pg_get_constraintdef`, `pg_get_triggerdef`, `pg_get_functiondef`; sequence
`last_value`, `is_called` and configuration. Mīzān's own audit objects are
excluded from the application digest and verified separately as a documented
initialization effect. Expected state is always derived from the immutable
baseline.

### Lifecycle and status

Process stop is mandatory and observable before any destructive operation.
`restore()` stops the app, verifies it exited, closes Mīzān connections,
terminates only the exact owned session identity, re-clones from the seed,
re-installs audit, restarts, waits for the health check and verifies the
baseline before READY. Cleanup is idempotent and only reports success after the
database is gone. The CLI emits its final status after cleanup; a cleanup
failure yields a non-zero exit and `cleanup_failed`.

### Signals and orphans

SIGINT/SIGTERM/SIGBREAK set a cancellation flag through a controlled handler;
the run then stops through the same safe path. Abrupt termination leaves the
registry and server markers, which `--cleanup-run` uses with full verification.
SIGKILL (POSIX) and `TerminateProcess` (Windows, via `Popen.kill()`) are the
abrupt cases exercised by tests.

## Failure conditions that disable execution

Missing/invalid DSN environment; missing `pg_dump`/`psql`; cluster identity
permission denied; schema allowlist empty or absent from the source; any seed
creation/restore/fingerprint/source-unchanged/marker/registry failure; non-empty
generated-name collision; seed with active sessions; fingerprint mismatch;
audit installation failure; health-check failure; process stop failure; marker
or owner mismatch; unrelated active sessions during drop; any interrupted run
before cleanup completes.

## Scope boundary

L1–L7 semantics, SQLite execution, the filesystem Twin, ownership graph,
proofs, SARIF and traffic recording are unchanged. This phase changes the
PostgreSQL lifecycle, the audit trigger's principal source (with legacy
fallback), the fixture's session context, the Twin tests/benchmark and the CI
PostgreSQL stages.
