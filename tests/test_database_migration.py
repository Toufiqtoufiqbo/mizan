"""The migration of a control-plane database.

The user table used to store the token itself. A database created by an older
version still has that column, and `CREATE TABLE IF NOT EXISTS` does not notice.
These tests build such a database with the real previous schema and check that
the migration is safe, complete and idempotent.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mizan.server import Store, hash_token

# The schema of the previous version: the token itself, no hash.
LEGACY_SCHEMA = """
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    target TEXT NOT NULL,
    spec TEXT,
    mode TEXT NOT NULL DEFAULT 'probes',
    status TEXT NOT NULL DEFAULT 'queued',
    findings INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    law TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    resource TEXT,
    evidence TEXT NOT NULL DEFAULT '{}'
);
"""


def _legacy_database(path: Path, users: list[tuple[str, str, str]]) -> None:
    """A database exactly as the previous version left it."""
    connection = sqlite3.connect(path)
    try:
        connection.executescript(LEGACY_SCHEMA)
        for user_id, token, role in users:
            connection.execute("INSERT INTO users (id, token, role) VALUES (?, ?, ?)", (user_id, token, role))
        connection.execute(
            "INSERT INTO scans (id, owner_id, target, spec, mode, status, findings, created_at)"
            " VALUES ('scan-1', 'alice', 'http://127.0.0.1:8000/openapi.json', NULL, 'probes', 'queued', 0, 1.0)"
        )
        connection.commit()
    finally:
        connection.close()


def test_a_legacy_database_is_migrated(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite"
    _legacy_database(database, [("alice", "token-alice", "user"), ("root", "token-root", "admin")])

    store = Store(database)
    notes = store.migrate()

    connection = sqlite3.connect(database)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        rows = connection.execute("SELECT id, token_hash, role FROM users ORDER BY id").fetchall()
        scans = connection.execute("SELECT id, owner_id FROM scans").fetchall()
    finally:
        connection.close()

    assert notes, "the migration did not report what it did"
    assert "token" not in columns, "the plaintext token column survived"
    assert "token_hash" in columns
    # The users and their roles survived.
    assert [row[0] for row in rows] == ["alice", "root"]
    assert dict((row[0], row[2]) for row in rows)["root"] == "admin"
    # The tokens were hashed, not copied.
    assert dict((row[0], row[1]) for row in rows)["alice"] == hash_token("token-alice")
    # The other tables survived.
    assert scans == [("scan-1", "alice")]


def test_an_existing_user_can_still_authenticate_after_the_migration(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite"
    _legacy_database(database, [("alice", "token-alice", "user")])

    store = Store(database)
    store.initialise()

    identity = store.user_for_token("token-alice")
    assert identity is not None, "the migrated credential stopped working"
    assert identity[0] == "alice"
    assert identity[1] == "user"
    assert store.user_for_token("not-the-token") is None


def test_the_migration_is_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite"
    _legacy_database(database, [("alice", "token-alice", "user")])

    store = Store(database)
    store.migrate()
    assert store.migrate() == [], "a second migration did something"
    store.migrate()

    connection = sqlite3.connect(database)
    try:
        rows = connection.execute("SELECT id, token_hash FROM users").fetchall()
    finally:
        connection.close()
    assert rows == [("alice", hash_token("token-alice"))]


def test_a_fresh_database_is_created_correctly(tmp_path: Path) -> None:
    database = tmp_path / "fresh.sqlite"
    store = Store(database)
    store.initialise()
    assert store.migrate() == [], "a fresh database was treated as a legacy one"
    store.ensure_user("alice", "token-alice", "user")
    assert store.user_for_token("token-alice") == ("alice", "user")


def test_a_failed_migration_leaves_the_database_untouched(tmp_path: Path) -> None:
    """A migration that cannot complete must not damage the old database."""
    database = tmp_path / "legacy.sqlite"
    _legacy_database(database, [("alice", "token-alice", "user")])

    store = Store(database)
    # A table that already occupies the name the migration wants to use.
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE users_migrated (id TEXT PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="could not be migrated"):
        store.migrate()

    connection = sqlite3.connect(database)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        rows = connection.execute("SELECT id, token FROM users").fetchall()
    finally:
        connection.close()
    assert "token" in columns, "the old schema was changed by a failed migration"
    assert rows == [("alice", "token-alice")], "the users were damaged"


def test_the_scan_endpoint_does_not_erase_users_on_migration(tmp_path: Path) -> None:
    """Migrating must not silently replace credentials."""
    database = tmp_path / "legacy.sqlite"
    _legacy_database(database, [("alice", "token-alice", "user"), ("bob", "token-bob", "user")])
    Store(database).initialise()
    connection = sqlite3.connect(database)
    try:
        count = connection.execute("SELECT count(*) FROM users").fetchone()[0]
    finally:
        connection.close()
    assert count == 2
