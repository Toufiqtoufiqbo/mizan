"""Tests for the Postgres auditor.

The database round trip needs a real Postgres, which this environment does not
have. What is tested here is everything that does not: the SQL that is
generated, and the conversion of an audit row into a write event.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from mizan.postgres_audit import AUDIT_TABLE, PostgresAuditor


class _FakeCursor:
    def __init__(self, rows: list[tuple] | None = None) -> None:
        self.rows = rows or []
        self.executed: list[str] = []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def execute(self, query: str, parameters: tuple = ()) -> None:
        self.executed.append(query)

    def fetchall(self) -> list[tuple]:
        return self.rows


class _FakeConnection:
    def __init__(self, rows: list[tuple] | None = None) -> None:
        self.cursor_instance = _FakeCursor(rows)
        self.committed = False

    def cursor(self) -> _FakeCursor:
        return self.cursor_instance

    def commit(self) -> None:
        self.committed = True


def test_trigger_sql_mentions_the_table_and_the_audit_table() -> None:
    auditor = PostgresAuditor(_FakeConnection())
    sql = auditor.trigger_sql("orders")
    assert '"orders"' in sql
    assert AUDIT_TABLE in sql
    assert "application_name" in sql
    assert "AFTER INSERT OR UPDATE OR DELETE" in sql


def test_install_creates_the_audit_table() -> None:
    connection = _FakeConnection()
    auditor = PostgresAuditor(connection)
    auditor.install()
    queries = " ".join(connection.cursor_instance.executed)
    assert f"CREATE TABLE IF NOT EXISTS {AUDIT_TABLE}" in queries
    assert connection.committed


def test_audit_row_becomes_a_write_event() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    row = (now, "mizan:alice", "orders", "42", {"owner_id": "alice", "status": "approved"}, "UPDATE")
    auditor = PostgresAuditor(_FakeConnection([row]))
    event = auditor.to_event(row)
    assert event.principal == "alice"
    assert event.table == "orders"
    assert event.row_id == "42"
    assert event.columns["status"] == "approved"
    assert event.row_owner == "alice"
    assert event.method == "PATCH"


def test_audit_row_with_a_json_string_payload() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    row = (now, "mizan:bob", "users", "7", json.dumps({"role": "admin"}), "INSERT")
    auditor = PostgresAuditor(_FakeConnection([row]))
    event = auditor.to_event(row)
    assert event.columns == {"role": "admin"}
    assert event.method == "POST"
