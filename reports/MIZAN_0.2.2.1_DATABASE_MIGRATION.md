# Mīzān 0.2.2.1 — Control-Plane Database Migration

**Scope:** Phase 4 of the 0.2.2.1 mission.

---

## 1. The defect

The user table changed from storing the token to storing its hash:

```sql
-- before
CREATE TABLE users (id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, role TEXT NOT NULL DEFAULT 'user');
-- after
CREATE TABLE users (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, role TEXT NOT NULL DEFAULT 'user');
```

`CREATE TABLE IF NOT EXISTS` does not notice that an existing table has a
different shape. A database created by the previous version therefore kept a
plaintext `token` column and had **no** `token_hash` column at all, and the
authentication query

```sql
SELECT id, role FROM users WHERE token_hash = ?
```

found nothing. **Every user of an existing deployment was locked out**, and the
plaintext tokens stayed on disk.

## 2. The migration

`Store.migrate()` runs before the schema is created, and it is idempotent:

```python
def migrate(self) -> list[str]:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
    if "token_hash" in columns:
        return notes  # already current
    if "token" not in columns:
        return notes  # a fresh database
    rows = connection.execute("SELECT id, token, role FROM users").fetchall()
    connection.execute("BEGIN")
    try:
        connection.execute("CREATE TABLE users_migrated (...)")
        for row in rows:
            connection.execute(
                "INSERT INTO users_migrated (id, token_hash, role) VALUES (?, ?, ?)",
                (row["id"], hash_token(row["token"]), row["role"]),
            )
        connection.execute("DROP TABLE users")
        connection.execute("ALTER TABLE users_migrated RENAME TO users")
        connection.execute("COMMIT")
    except Exception as exc:
        connection.execute("ROLLBACK")
        raise RuntimeError(f"the user table could not be migrated safely: {exc}") from exc
```

| Requirement | How it is met |
|---|---|
| detect the legacy schema | `PRAGMA table_info(users)` - the `token` column and no `token_hash` |
| preserve the user ids and the roles | the rows are copied with their `id` and `role` |
| hash the existing tokens before the switch | `hash_token(row["token"])` |
| the existing users can still authenticate | the stored hash is the hash of the token the user already has |
| remove the plaintext storage | the old table is dropped; only `token_hash` remains |
| preserve the data transactionally | `BEGIN` / `COMMIT`, with a `ROLLBACK` on any error |
| a second run is harmless | the current schema returns immediately |
| new installations still work | a database without a `users` table is not migrated |
| never erase users or replace credentials | the ids, the roles and the tokens are carried over |
| fail clearly | `RuntimeError("the user table could not be migrated safely: ...")` |

The rebuild (a new table, a copy, a drop, a rename) is used instead of
`ALTER TABLE ... DROP COLUMN` so that the migration works on every SQLite
version Mīzān supports, and so that a failure cannot leave a half-migrated
table behind.

## 3. One hashing implementation

`DevAuth` (the in-memory issuer) and `Store` (the persistent store) both
hashed the token, each with its own copy of the function. They now share one:

```python
def hash_token(token: str) -> str:
    """The stored form of a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
```

There is still exactly one authentication model: a token is issued by
`DevAuth`, stored (hashed) by `Store`, and looked up (hashed) by `Store`. No
second model was introduced.

## 4. Tests

`tests/test_database_migration.py` builds a database with **the actual previous
schema** (copied from the old `server.py`) and checks:

| Test | Result |
|---|---|
| a legacy database is migrated | PASS - the notes report what happened, `token` is gone, `token_hash` is present, the ids and the roles survived, the tokens are hashed, the `scans` table survived |
| an existing user can still authenticate after the migration | PASS - `user_for_token("token-alice")` returns `("alice", "user")`, and a wrong token returns `None` |
| the migration is idempotent | PASS - the second run does nothing and the data is unchanged |
| a fresh database is created correctly | PASS - a fresh database is not treated as legacy |
| a failed migration leaves the database untouched | PASS - the old schema and the old rows are intact after the failure |
| the migration does not erase users | PASS - both users survive |

The failed-migration test is the important one: it creates a table that
occupies the name the migration wants to use, so the migration fails - and the
assertions prove that the **original** table and its **plaintext** rows are
still there, unchanged.

## 5. Limitations

- The migration handles the `users` table. A database created by an even older
  version, with a different set of tables, is not migrated - the missing tables
  are created by `initialise()` ✔, but their *data* is not recovered.
- The migration hashes the plaintext tokens that are still on disk. The tokens
  themselves keep working; nothing has to be reissued.
