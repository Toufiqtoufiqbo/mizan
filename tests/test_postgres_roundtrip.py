"""The Postgres round trip - only when a database is available.

The environment of this repository has no Postgres, so the test is skipped
unless ``MIZAN_TEST_POSTGRES_DSN`` points at a database that may be modified::

    MIZAN_TEST_POSTGRES_DSN=postgresql://localhost/postgres python -m pytest tests/test_postgres_roundtrip.py

The database must be a throw-away one: the auditor creates a table and
triggers.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

DSN = os.environ.get("MIZAN_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(not DSN, reason="set MIZAN_TEST_POSTGRES_DSN to run the Postgres round trip")


@pytest.fixture()
def connection():
    psycopg = pytest.importorskip("psycopg")
    connection = psycopg.connect(DSN)
    connection.autocommit = True
    yield connection
    connection.close()


def test_auditor_records_the_write_and_its_author(connection) -> None:
    from mizan.postgres_audit import AUDIT_TABLE, PostgresAuditor

    auditor = PostgresAuditor(connection)
    with connection.cursor() as cursor:
        cursor.execute("DROP TABLE IF EXISTS mizan_test_orders")
        cursor.execute(
            "CREATE TABLE mizan_test_orders (id text primary key, owner_id text, status text)"
        )
    auditor.install()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET application_name = 'mizan:alice'")
            cursor.execute(
                "INSERT INTO mizan_test_orders (id, owner_id, status) VALUES ('o1', 'alice', 'pending')"
            )
            cursor.execute("SET application_name = 'mizan:bob'")
            cursor.execute("UPDATE mizan_test_orders SET status = 'approved' WHERE id = 'o1'")

        events = auditor.read()
        assert events, "the auditor recorded nothing"
        assert any(event.principal == "alice" for event in events)
        assert any(event.principal == "bob" for event in events)
        assert all(event.table == "mizan_test_orders" for event in events)
        update = next(event for event in events if event.principal == "bob")
        assert update.columns.get("status") == "approved"
    finally:
        auditor.uninstall()
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE IF EXISTS mizan_test_orders")
