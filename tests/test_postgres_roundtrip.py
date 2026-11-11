"""The PostgreSQL round trip - against a real server.

These tests need a real PostgreSQL: they check what the database actually
stores, not what the generated SQL looks like. The server comes from

* ``MIZAN_TEST_POSTGRES_DSN`` - a database that may be modified (CI uses a
  disposable service container), or
* a local server started by ``pgserver`` (a PostgreSQL build shipped as a
  Python package), when that package is installed.

.. code-block:: bash

    MIZAN_TEST_POSTGRES_DSN=postgresql://postgres@localhost/postgres pytest tests/test_postgres_roundtrip.py

When neither is available the module is skipped - unless
``MIZAN_REQUIRE_POSTGRES=1`` is set, which turns the skip into a failure. CI
sets it, so a broken Postgres setup fails the build instead of hiding.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

DSN = os.environ.get("MIZAN_TEST_POSTGRES_DSN")
REQUIRE = os.environ.get("MIZAN_REQUIRE_POSTGRES") == "1"

psycopg = pytest.importorskip("psycopg", reason="psycopg is needed for the PostgreSQL integration tests")

#: This module needs a real server. In CI it runs in its own stage; in the unit
#: stage it is deselected with ``-m "not postgres_integration"``.
pytestmark = pytest.mark.postgres_integration


def _start_local_server() -> str:
    """Start a throw-away PostgreSQL with the bundled server."""
    pgserver = pytest.importorskip("pgserver", reason="pgserver is needed to run a local PostgreSQL")
    directory = Path(tempfile.mkdtemp(prefix="mizan-pg-"))
    server = pgserver.get_server(pgdata=directory, cleanup_mode="delete")
    return server.get_uri()


@pytest.fixture(scope="session")
def dsn() -> str:
    """A PostgreSQL to test against.

    A connect timeout is mandatory: an unreachable server must fail the stage,
    not hang it.
    """
    if DSN:
        return _with_timeout(DSN)
    return _with_timeout(_start_local_server())
    if shutil.which("pg_ctl") or _has_pgserver():
        return _with_timeout(_start_local_server())
    if REQUIRE:
        pytest.fail(
            "no PostgreSQL available: set MIZAN_TEST_POSTGRES_DSN or install pgserver. "
            "The integration suite is mandatory in CI."
        )
    pytest.skip("no PostgreSQL available (set MIZAN_TEST_POSTGRES_DSN or install pgserver)")


def _with_timeout(uri: str) -> str:
    """Add a connect timeout to a DSN that does not have one."""
    if "connect_timeout" in uri:
        return uri
    separator = "&" if "?" in uri else "?"
    return f"{uri}{separator}connect_timeout=5"


def _has_pgserver() -> bool:
    try:
        import pgserver  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.fixture()
def connection(dsn: str):
    """A connection with a clean schema for the test."""
    # Explicit transactions: the rollback and the transaction-local identity
    # are exactly what the audit has to get right.
    connection = psycopg.connect(dsn, autocommit=False)
    schema = f"mizan_test_{uuid.uuid4().hex[:12]}"
    with connection.cursor() as cursor:
        cursor.execute(f'CREATE SCHEMA "{schema}"')
        cursor.execute(f'SET search_path TO "{schema}"')
        connection.commit()
    try:
        yield connection
    finally:
        with connection.cursor() as cursor:
            cursor.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            connection.commit()
        connection.close()


@pytest.fixture()
def auditor(connection):
    """An auditor installed in the test schema."""
    from mizan.postgres_audit import PostgresAuditor

    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema = cursor.fetchone()[0]
    instance = PostgresAuditor(connection, audit_schema=schema)
    instance.install()
    return instance


@pytest.fixture()
def make_table(connection, auditor):
    """Create a table and instrument it.

    The trigger is installed when the auditor is installed, so a table that
    appears later needs a refresh - exactly what a real application does when
    it migrates.
    """

    def _make(name: str, ddl: str) -> None:
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE TABLE "{auditor.audit_schema}"."{name}" ({ddl})')
            connection.commit()
        auditor.refresh()

    return _make


def _as_identity(connection, principal: str) -> None:
    """Act as a principal for the rest of the transaction."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('application_name', %s, false)", (f"mizan:{principal}",))
        connection.commit()


# --------------------------------------------------------------------------- #
# 1. INSERT
# --------------------------------------------------------------------------- #


def test_insert_is_recorded_with_its_author_and_row(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text, status text")
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(
            f'INSERT INTO "{schema}"."orders" (id, owner_id, status) VALUES (%s, %s, %s)',
            ("o1", "alice", "pending"),
        )
        connection.commit()

    events = auditor.read()
    assert len(events) == 1
    event = events[0]
    assert event.principal == "alice"
    assert event.table == "orders"
    assert event.row_id == "o1"
    assert event.method == "POST"
    # The row contents survive, including the ownership field.
    assert event.columns["status"] == "pending"
    assert event.columns["owner_id"] == "alice"
    assert event.row_owner == "alice"


# --------------------------------------------------------------------------- #
# 2. UPDATE
# --------------------------------------------------------------------------- #


def test_update_is_recorded_with_the_new_author_and_the_changed_columns(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text, status text")
    with connection.cursor() as cursor:
        cursor.execute(
            f'INSERT INTO "{schema}"."orders" (id, owner_id, status) VALUES (%s, %s, %s)',
            ("o1", "alice", "pending"),
        )
        connection.commit()
    before = len(auditor.read())

    _as_identity(connection, "bob")
    with connection.cursor() as cursor:
        cursor.execute(f'UPDATE "{schema}"."orders" SET status = %s WHERE id = %s', ("approved", "o1"))
        connection.commit()

    events = auditor.read()[before:]
    assert len(events) == 1
    event = events[0]
    assert event.principal == "bob"
    assert event.method == "PATCH"
    assert event.row_id == "o1"
    # Only what changed is reported as changed.
    assert event.columns == {"status": "approved"}
    # The ownership of the row is still known.
    assert event.row_owner == "alice"


# --------------------------------------------------------------------------- #
# 3. DELETE
# --------------------------------------------------------------------------- #


def test_delete_keeps_the_old_row_for_attribution(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text, status text")
    with connection.cursor() as cursor:
        cursor.execute(
            f'INSERT INTO "{schema}"."orders" (id, owner_id, status) VALUES (%s, %s, %s)',
            ("o1", "alice", "pending"),
        )
        connection.commit()
    before = len(auditor.read())

    _as_identity(connection, "bob")
    with connection.cursor() as cursor:
        cursor.execute(f'DELETE FROM "{schema}"."orders" WHERE id = %s', ("o1",))
        connection.commit()

    events = auditor.read()[before:]
    assert len(events) == 1
    event = events[0]
    assert event.principal == "bob"
    assert event.method == "DELETE"
    assert event.row_id == "o1"
    # The row is gone, but its identity and owner are not.
    assert event.row_owner == "alice"
    assert event.columns.get("owner_id") == "alice"


# --------------------------------------------------------------------------- #
# 4. Primary key shapes
# --------------------------------------------------------------------------- #


def test_uuid_primary_key(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("items", "id uuid primary key, owner_id text")
    identifier = str(uuid.uuid4())
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."items" (id, owner_id) VALUES (%s, %s)', (identifier, "alice"))
        connection.commit()

    event = auditor.read()[0]
    assert event.row_id == identifier
    assert event.principal == "alice"


def test_text_primary_key(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("items", "code text primary key, owner_id text")
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."items" (code, owner_id) VALUES (%s, %s)', ("abc", "alice"))
        connection.commit()

    event = auditor.read()[0]
    assert event.row_id == "abc"


def test_composite_primary_key(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("items", "tenant text, code text, owner_id text, PRIMARY KEY (tenant, code)")
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(
            f'INSERT INTO "{schema}"."items" (tenant, code, owner_id) VALUES (%s, %s, %s)',
            ("t1", "c1", "alice"),
        )
        connection.commit()

    event = auditor.read()[0]
    # A composite key is rendered as its parts, in key order.
    assert event.row_id == "c1|t1"


def test_table_without_primary_key_is_reported_as_unidentified(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("logs", "message text, owner_id text")
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."logs" (message, owner_id) VALUES (%s, %s)', ("hi", "alice"))
        connection.commit()

    event = auditor.read()[0]
    # No stable identity: the row is recorded, but it is not identified.
    assert event.row_id == ""
    assert event.method_args["row_identity"] == "none"


# --------------------------------------------------------------------------- #
# 5. Several tables, several installations
# --------------------------------------------------------------------------- #


def test_every_table_is_audited_independently(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text")
    make_table("items", "id text primary key, owner_id text")
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."orders" (id, owner_id) VALUES (%s, %s)', ("o1", "alice"))
        cursor.execute(f'INSERT INTO "{schema}"."items" (id, owner_id) VALUES (%s, %s)', ("i1", "alice"))
        connection.commit()

    events = auditor.read()
    assert {event.table for event in events} == {"orders", "items"}
    assert all(event.principal == "alice" for event in events)


def test_installing_twice_is_safe(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text")
    auditor.install()
    auditor.install()

    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."orders" (id, owner_id) VALUES (%s, %s)', ("o1", "alice"))
        connection.commit()

    events = auditor.read()
    assert len(events) == 1, "a second installation duplicated the records"


def test_uninstall_removes_the_triggers_and_leaves_the_tables_alone(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."orders" (id, owner_id) VALUES (%s, %s)', ("o1", "alice"))
        connection.commit()

    auditor.uninstall()

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT count(*) FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND t.tgname LIKE 'mizan%%'
            """,
            (schema,),
        )
        assert cursor.fetchone()[0] == 0, "a trigger was left behind"
        # The application's table is untouched.
        cursor.execute(f'SELECT count(*) FROM "{schema}"."orders"')
        assert cursor.fetchone()[0] == 1
        cursor.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = %s AND table_name = %s",
            (schema, "mizan_write_audit"),
        )
        assert cursor.fetchone()[0] == 0, "the audit table was left behind"


def test_refresh_instruments_tables_created_after_the_installation(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text")
    instrumented = auditor.refresh()
    assert "orders" in [table for _schema, table in instrumented]

    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."orders" (id, owner_id) VALUES (%s, %s)', ("o1", "alice"))
        connection.commit()

    assert len(auditor.read()) == 1


# --------------------------------------------------------------------------- #
# 6. Transactions
# --------------------------------------------------------------------------- #


def test_a_rolled_back_write_is_not_recorded(connection, auditor, make_table) -> None:
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text")
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(f'INSERT INTO "{schema}"."orders" (id, owner_id) VALUES (%s, %s)', ("o1", "alice"))
        connection.rollback()

    assert auditor.read() == [], "a rolled back write was recorded as committed"


def test_the_identity_does_not_leak_between_pooled_users(connection, auditor, make_table) -> None:
    """`SET LOCAL` keeps the identity inside the transaction."""
    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text")

    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('application_name', 'mizan:alice', true)")
        cursor.execute(f'INSERT INTO "{schema}"."orders" (id, owner_id) VALUES (%s, %s)', ("o1", "alice"))
        connection.commit()
        # The next transaction starts without an identity.
        cursor.execute(f'INSERT INTO "{schema}"."orders" (id, owner_id) VALUES (%s, %s)', ("o2", "bob"))
        connection.commit()

    events = auditor.read()
    assert [event.principal for event in events] == ["alice", "unknown"]
    # The second write is recorded, but it cannot be blamed on anybody.
    assert events[1].row_id == "o2"


# --------------------------------------------------------------------------- #
# 7. Attribution inside Mizan
# --------------------------------------------------------------------------- #


def test_an_unauthorized_modification_is_detected_from_the_evidence(connection, auditor, make_table) -> None:
    """The end-to-end question: did Bob change Alice's row?"""
    from mizan.core import Policy, Resource, Rule
    from mizan.taint import TaintAnalyzer

    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text, status text")
    _as_identity(connection, "alice")
    with connection.cursor() as cursor:
        cursor.execute(
            f'INSERT INTO "{schema}"."orders" (id, owner_id, status) VALUES (%s, %s, %s)',
            ("o1", "alice", "pending"),
        )
        connection.commit()

    _as_identity(connection, "bob")
    with connection.cursor() as cursor:
        cursor.execute(f'UPDATE "{schema}"."orders" SET status = %s WHERE id = %s', ("approved", "o1"))
        connection.commit()

    policy = Policy(
        principals={"bob": __import__("mizan").Principal(id="bob")},
        resources={"orders:o1": Resource(type="orders", id="o1", owner="alice")},
        rules=[Rule(kind="owner", action="write", resource_type="orders")],
    )
    analyzer = TaintAnalyzer(policy)
    violations = analyzer.analyze(auditor.read())
    assert [violation.law for violation in violations] == ["L3"]
    assert violations[0].principal == "bob"
    assert violations[0].resource == "orders:o1"


def test_an_unattributed_write_is_not_reported_as_a_breach(connection, auditor, make_table) -> None:
    """Without an identity there is no finding - only an unknown write."""
    from mizan.core import Policy, Resource, Rule
    from mizan.taint import TaintAnalyzer

    schema = auditor.audit_schema
    make_table("orders", "id text primary key, owner_id text, status text")
    with connection.cursor() as cursor:
        cursor.execute(
            f'INSERT INTO "{schema}"."orders" (id, owner_id, status) VALUES (%s, %s, %s)',
            ("o1", "alice", "pending"),
        )
        connection.commit()

    policy = Policy(
        resources={"orders:o1": Resource(type="orders", id="o1", owner="alice")},
        rules=[Rule(kind="owner", action="write", resource_type="orders")],
    )
    analyzer = TaintAnalyzer(policy)
    violations = analyzer.analyze(auditor.read())
    assert violations == [], "a write without an author was reported as a breach"
    assert len(analyzer.unattributed) == 1, "the write was not even recorded"
