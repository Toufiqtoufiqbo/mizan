# Mīzān 0.2.1 — PostgreSQL & CI Hardening Report

**Date:** 2026-11-10
**Branch:** `fix/mizan-021-postgres-ci-hardening` (tip `a041856`)
**Scope:** PostgreSQL write attribution, identity provenance, proof-bundle secret handling, CI reliability.
**Out of scope:** new security laws, an LLM planner, UI, architectural changes.
**Merged into `main`:** no - the branch is pushed for review, as instructed.

---

## 1. Baseline (Phase 0)

| Check | Result before the change |
|---|---|
| Test suite | 88 passed, 1 skipped (PostgreSQL round trip) |
| Lint | not configured |
| Formatting | not configured |
| PostgreSQL support | unit-tested SQL only; the round trip was skipped in every environment |
| CI | one job with a broken token path; no PostgreSQL stage |
| Proof bundles | contained the literal bearer token |
| Unattributed writes | reported as breaches |

### 1.1 The environment

No `psql`, no `pg_ctl`, no Postgres service, no Docker. The integration tests
could not have been run here. A PostgreSQL **16.2** server was obtained through
`pgserver` (PostgreSQL binaries shipped as a Python package), which made the
real round trip possible both locally and in CI.

---

## 2. Defects found (Phase 1)

### 2.1 The row serialization was destroyed

```sql
-- before
columns JSONB NOT NULL DEFAULT '{}'::jsonb,
...
to_jsonb(NEW) - to_jsonb(NEW) - 'id'   -- JSONB minus itself = '{}'
```

**Root cause:** subtracting a JSONB value from itself is always the empty
object, so every INSERT/UPDATE event arrived with `columns = {}`. Without the
changed columns there is no evidence of what a write did, and a write-level
finding collapses.

**Fix:** the trigger stores the whole row before and after the change
(`row_data` = NEW, `old_row` = OLD). The changed columns are computed in Python
by comparing the two, which is exact and testable - no `id` subtraction, no
guessing. DELETE stores the OLD row.

### 2.2 The universal `id` assumption

```sql
COALESCE(NEW.id::text, OLD.id::text)
```

Every table was assumed to have an `id` column. Composite keys, UUIDs and text
keys were silently wrong, and a table without `id` produced `row_id = NULL`
without saying so.

**Fix:** the trigger reads the primary key from the catalog
(`pg_index` / `pg_attribute`, `indisprimary`), and builds the row identity from
its columns:

| Primary key | `row_id` |
|---|---|
| `id text` | `o1` |
| `id uuid` | `9f2c...` |
| composite `(tenant, code)` | `c1|t1` |
| none | `""` with `row_identity = 'none'` |

A table without a stable identity is recorded but explicitly unidentified: it is
never given a made-up identity and its writes are never reported as breaches.

### 2.3 Identifier construction was interpolating raw names

The table name was concatenated into the trigger SQL. A name containing a quote
could break out of the identifier.

**Fix:** a single `quote_identifier()` helper (quotes are doubled, NUL rejected)
used for schemas, tables, triggers and the audit index. `trigger_name()` keeps
the name under PostgreSQL's 63-character limit with a hash instead of
colliding.

### 2.4 Trigger lifecycle

- `install()` is now idempotent: `CREATE TABLE IF NOT EXISTS`,
  `CREATE OR REPLACE FUNCTION`, `DROP TRIGGER IF EXISTS` + `CREATE TRIGGER`.
- `refresh()` instruments tables created after the installation (a migration),
  and is documented as the thing to run after one.
- `uninstall()` drops only Mizan's objects: the triggers, the function, the
  audit table. The application's tables are untouched.
- Only the schemas the auditor was pointed at are instrumented; by default the
  audit schema alone, so a trigger is never installed on an unrelated schema.

### 2.5 Identity provenance

`application_name` was treated as an identity without any parsing rules.

**Fix:** `principal_from()` accepts only `mizan:<principal>` and returns
`unknown` for anything else (absent, malformed, different prefix). A write whose
author cannot be established is recorded with the principal `unknown` and is
**never** reported as a confirmed breach (`TaintAnalyzer.unattributed`).

The documentation states the trust boundary explicitly: `application_name` is
metadata, not authentication. Anyone who can run SQL on that connection can
claim any identity. Attribution is only as trustworthy as the application's
ability to control its own database connections.

---

## 3. Real PostgreSQL integration (Phase 2)

`tests/test_postgres_roundtrip.py` - **15 tests, all against a real server**
(PostgreSQL 16.2 locally via `pgserver`; a disposable service container in CI).

| # | Scenario | Verified |
|---|---|---|
| 1 | INSERT as Alice | the author, the row and `owner_id` are preserved |
| 2 | UPDATE as Bob | Bob is the writer; only the changed column is reported; the original owner is still known |
| 3 | DELETE | recorded with the operation, the identity and the OLD row for attribution |
| 4 | UUID primary key | `row_id` is the UUID |
| 5 | Text primary key | `row_id` is the text key |
| 6 | Composite primary key | `row_id` is the ordered parts |
| 7 | No primary key | recorded, `row_identity = 'none'`, no silent misattribution |
| 8 | Several tables | each audited independently |
| 9 | Two installations | idempotent, no duplicated records |
| 10 | Uninstall | no orphaned triggers, the application's table intact, no audit table left |
| 11 | Refresh | instruments tables created after the installation |
| 12 | Rollback | a rolled-back write produces no audit record |
| 13 | Connection reuse | `SET LOCAL` does not leak the identity into the next transaction |
| 14 | Ownership attribution | an unauthorized modification of another user's row is detected through the evidence (`L3`) |
| 15 | Unattributed write | recorded, not reported as a breach |

The tests assert **database state and emitted `WriteEvent` objects**, not SQL
strings.

### 3.1 The tests fail loudly when the database is missing

A DSN without a reachable server used to hang the suite. Every DSN now gets
`connect_timeout=5`, and `MIZAN_REQUIRE_POSTGRES=1` turns a skip into a failure:
CI cannot pass while the only suite that proves attribution did not run.

---

## 4. Proof and attribution integration (Phase 4)

### 4.1 The bundles no longer carry secrets

A proof bundle used to embed the literal bearer token in `replay.json`.

**Fix:** the token is replaced by a placeholder (`${MIZAN_TOKEN_ALICE}`) when
the bundle is written, and resolved from the environment when it is replayed:

```
bundle                -> Bearer ${MIZAN_TOKEN_ALICE}
replay                -> Bearer <the real token, from MIZAN_TOKENS>
```

`mizan verify` without a resolver fails loudly instead of sending a request
with a literal placeholder.

### 4.2 Insufficient evidence is not a finding

| Situation | Before | After |
|---|---|---|
| A write with no identifiable author | reported as a breach | recorded as `unattributed`, never reported |
| A table with no primary key | silent misattribution | recorded as unidentified, never reported |
| A field change whose origin is unknown | mass assignment claimed from the DB alone | not claimed: `L4` requires `source_fields`, which the database cannot know |

The last one matters: the database cannot tell whether a field was sent by the
client or set by the server, so mass assignment is not proven from Postgres
alone. It is proven from an application ledger (`source_fields`), which is what
Mizan does for SQLite.

### 4.3 What a finding must now identify

Every write-level finding carries: the principal, the table and the schema, the
row identity (and how it was derived), the operation, the changed columns, and
the owner of the affected resource.

---

## 5. CI hardening (Phase 3)

### 5.1 The token path was broken

```yaml
# before
token_var="MIZAN_TOKEN_$principal"
MIZAN_TOKEN="$token_var" mizan verify ...   # passes the NAME, not the value
```

The variable was passed where its value was expected, so the replay ran without
a token and could not prove anything.

**Fix:**

- A `TokenResolver` reads tokens from `MIZAN_TOKENS` (JSON) or
  `MIZAN_TOKEN_<NAME>`, case-insensitively, and fails loudly when a required
  token is missing.
- The workflow passes a single `MIZAN_TOKENS` secret and masks it
  (`::add-mask::` semantics of GitHub secrets). Tokens are never printed: the
  CLI masks them (`super-...alue`).
- The resolver is unit-tested without real secrets (15 tests).
- A replay against an unreachable target exits with code 2 instead of crashing
  or passing.

### 5.2 Four mandatory stages

| Stage | Content |
|---|---|
| **A** - static & unit | ruff lint, format check, unit suite (`-m "not postgres_integration"`) |
| **B** - PostgreSQL | disposable `postgres:16-alpine` service container, the full round trip, and a guard that fails when the suite skipped |
| **C** - security regression | the regression suite, the self-contained proof replay (vulnerable vs patched twin), and the probes-against-guided-search comparison |
| **D** - benchmark | AuthzBugs subset, with an assertion on the detection rate and the false-positive count |
| **E** - external target | opt-in (`if: vars.MIZAN_TARGET != ''`). Ordinary CI never attacks anything it does not own |

Stage B sets `MIZAN_REQUIRE_POSTGRES=1`, so a broken database setup fails the
build instead of quietly removing the only proof of attribution.

### 5.3 Lint and format are now part of CI

`ruff` is configured (`E`, `F`, `I`, `UP`, `W`, line length 120) and clean:
82 issues were fixed automatically, the rest by hand.

---

## 6. Security review (Phase 5)

| Risk | Assessment | Mitigation |
|---|---|---|
| SQL injection through identifiers | Only quoted identifiers reach the SQL | `quote_identifier()`, tested with an injection attempt |
| Trigger privilege assumptions | Requires ownership of the instrumented tables | Documented; the tests create their own tables |
| Transaction consistency | The audit insert shares the transaction | Tested: a rollback leaves no record |
| Connection pooling | A session-wide identity would leak between users | `SET LOCAL`, tested across two transactions |
| Identity spoofing | `application_name` is spoofable by anyone with SQL access | Documented trust boundary; unknown authors are never blamed |
| Audit collection races | Every write gets its own row, ordered by `id` | Tested on concurrent-free paths; ordering is by `id` |
| Data leakage in proof bundles | Tokens were embedded | Placeholders, resolved at replay |
| Resource cleanup | Connections/schemas must not survive a failure | The fixtures close the connection and drop the schema; the local server deletes its data directory |
| Database unavailable | A missing server used to hang or skip | `connect_timeout=5`, and the skip becomes a failure in CI |
| Unbounded audit growth | The audit table never shrinks | Documented limitation: retention is the operator's job |

---

## 7. Changed files

| File | Change |
|---|---|
| `src/mizan/postgres_audit.py` | rewritten: catalog-derived identities, full row before/after, idempotent install, refresh, safe uninstall, schema scoping, explicit unknown identity |
| `src/mizan/taint.py` | unattributed writes are never reported; `L4` requires client-supplied fields |
| `src/mizan/core.py` | `UNKNOWN_PRINCIPAL` constant |
| `src/mizan/tokens.py` | `TokenResolver`, placeholders, header masking/resolution |
| `src/mizan/engine.py` | bundles carry placeholders, never tokens |
| `src/mizan/proof.py` | replay resolves placeholders; a missing resolver fails loudly |
| `src/mizan/cli.py` | `verify`/`replay` use the resolver; unreachable targets exit 2 |
| `tests/test_postgres_audit.py` | rewritten for the new implementation (SQL safety, catalog identities, conversion) |
| `tests/test_postgres_roundtrip.py` | the real-server suite (15 scenarios) |
| `tests/test_tokens.py` | the resolver, tested without secrets |
| `.github/workflows/mizan.yml` | four stages + opt-in external target |
| `pyproject.toml` | ruff config, dev dependencies, the `postgres_integration` marker |
| `README.md`, `ROADMAP.md` | identity provenance, privileges, limits |

---

## 8. Validation (Phase 7)

### 8.1 Local

| Check | Result |
|---|---|
| `pytest -m "not postgres_integration"` | **PASSED** (88) |
| `pytest -m "postgres_integration"` (real PostgreSQL 16.2) | **PASSED** (15) |
| `pytest` (everything) | **PASSED** (103) |
| `ruff check .` | **PASSED** |
| `ruff format --check .` | **PASSED** |
| AuthzBugs-50 | detection **100%**, false positives **0**, regression validity **100%** |
| Probes vs guided search | 49.4 vs 20.6 requests per application, same 10 breaches |
| Skip guard (no server) | **FAILED** as required (no silent pass) |

### 8.2 CI

The workflow is configured but has **not** been executed from this machine: it
needs a GitHub runner. Its stages mirror the local commands exactly.

---

## 9. Remaining limitations

1. **Mass assignment is not provable from Postgres alone.** The database cannot
   distinguish a client-supplied field from a server-set one. An application
   ledger (`source_fields`) is required.
2. **Identity provenance is not cryptographic.** It relies on the application's
   control of its database connections.
3. **The audit table grows without bound.** Retention is not implemented.
4. **`refresh()` must be called after a migration**, or new tables are not
   instrumented.
5. **Only the schemas named at construction are instrumented.** Cross-schema
   auditing requires passing them explicitly.
6. **The external-target job is untested here** (it needs a real target).
7. **No git binary on this machine**, so the branch was created through the
   GitHub Git Data API (blobs -> tree -> commit -> ref) rather than with a
   local `git commit`. The history was not rewritten: the branch therefore
   carries an earlier commit that still lists a few scratch files, while the
   branch tip is clean (37 files against `main`, no build metadata).

---

## 10. Release readiness

| Criterion | Status |
|---|---|
| PostgreSQL JSONB row serialization correct | ✅ |
| No universal `id` assumption | ✅ |
| Primary key behaviour explicit and tested | ✅ |
| INSERT/UPDATE/DELETE verified against real PostgreSQL | ✅ |
| Ownership information survives the pipeline | ✅ |
| Principal attribution tested across connection reuse | ✅ |
| Transaction rollback creates no false evidence | ✅ |
| Trigger installation and removal safe | ✅ |
| The CI token resolver uses actual secret values | ✅ |
| Tokens never appear in CI logs | ✅ |
| Mandatory jobs cannot silently pass after skipping | ✅ |
| Proof bundles preserve the corrected evidence | ✅ |
| Existing tests and benchmarks remain valid | ✅ |
| Documentation matches tested behaviour | ✅ |

**Assessment:** ready for review. The one thing that cannot be claimed from this
machine is the execution of the GitHub Actions workflow itself; everything it
runs was executed locally with the same commands, against a real PostgreSQL.
