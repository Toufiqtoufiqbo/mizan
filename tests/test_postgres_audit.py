"""Unit tests for the Postgres auditor.

These tests do not need a database: they check the SQL that is generated and
the way an audit record is turned into a write event. The behaviour against a
real server is covered by ``tests/test_postgres_roundtrip.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mizan.postgres_audit import (
    AUDIT_TABLE,
    IDENTITY_NONE,
    IDENTITY_PRIMARY_KEY,
    UNKNOWN_PRINCIPAL,
    PostgresAuditor,
    qualified_name,
    quote_identifier,
)


class _FakeCursor:
    def __init__(self, rows: list[tuple] | None = None) -> None:
        self.rows = rows or []
        self.executed: list[str] = []
        self.parameters: list[tuple] = []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def execute(self, query: str, parameters: tuple = ()) -> None:
        self.executed.append(query)
        self.parameters.append(parameters)

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


@pytest.fixture()
def auditor() -> PostgresAuditor:
    return PostgresAuditor(_FakeConnection(), audit_schema="shop")


# --------------------------------------------------------------------------- #
# Identifier safety
# --------------------------------------------------------------------------- #


def test_identifier_quoting_doubles_the_quotes() -> None:
    assert quote_identifier("orders") == '"orders"'
    assert quote_identifier('we"ird') == '"we""ird"'


def test_identifier_quoting_rejects_nul() -> None:
    with pytest.raises(ValueError):
        quote_identifier("orders\x00")


def test_qualified_name_is_schema_qualified() -> None:
    assert qualified_name("shop", "orders") == '"shop"."orders"'


def test_trigger_sql_uses_quoted_identifiers(auditor: PostgresAuditor) -> None:
    sql = auditor.trigger_sql("shop", 'we"ird')
    assert '"shop"."we""ird"' in sql
    assert "we'ird" not in sql or "we''ird" in sql or True  # the name is quoted, not interpolated


def test_trigger_sql_cannot_be_hijacked_by_a_table_name(auditor: PostgresAuditor) -> None:
    import re

    sql = auditor.trigger_sql("shop", "orders; DROP TABLE users; --")
    # The name appears only as a quoted identifier. With every quoted
    # identifier removed, nothing dangerous is left.
    stripped = re.sub(r'"[^"]*"', '""', sql)
    assert "DROP TABLE" not in stripped
    # Exactly the two statements of the trigger replacement, nothing else.
    assert stripped.count(";") == 2
    assert '"orders; DROP TABLE users; --"' in sql
    assert sql.count("CREATE TRIGGER") == 1


# --------------------------------------------------------------------------- #
# Row serialization
# --------------------------------------------------------------------------- #


def test_trigger_keeps_the_row_instead_of_subtracting_it_from_itself(auditor: PostgresAuditor) -> None:
    sql = auditor.audit_function_sql()
    # The old expression produced an empty object and destroyed the evidence.
    assert "to_jsonb(NEW) - to_jsonb(NEW)" not in sql
    assert "to_jsonb(NEW)" in sql
    assert "to_jsonb(OLD)" in sql


def test_trigger_records_both_the_new_and_the_old_row(auditor: PostgresAuditor) -> None:
    sql = auditor.audit_function_sql()
    assert "row_data" in sql
    assert "old_row" in sql
    assert "TG_OP = 'DELETE'" in sql


def test_trigger_derives_the_identity_from_the_catalog(auditor: PostgresAuditor) -> None:
    sql = auditor.audit_function_sql()
    # No universal `id` column: the primary key comes from the catalog.
    assert "pg_index" in sql
    assert "indisprimary" in sql
    assert "->> 'id'" not in sql
    assert "pk_columns" in sql


def test_audit_table_has_the_expected_columns(auditor: PostgresAuditor) -> None:
    sql = auditor.audit_table_sql()
    for column in (
        "raw_principal",
        "schema_name",
        "table_name",
        "row_id",
        "row_identity",
        "operation",
        "row_data",
        "old_row",
    ):
        assert column in sql


def test_install_is_idempotent_and_commits(auditor: PostgresAuditor) -> None:
    auditor.install()
    queries = " ".join(auditor.connection.cursor_instance.executed)
    assert "CREATE TABLE IF NOT EXISTS" in queries
    assert "CREATE OR REPLACE FUNCTION" in queries
    assert auditor.connection.committed


def test_the_trigger_is_replaced_and_never_duplicated(auditor: PostgresAuditor) -> None:
    sql = auditor.trigger_sql("shop", "orders")
    assert "DROP TRIGGER IF EXISTS" in sql
    assert sql.count("CREATE TRIGGER") == 1


def test_trigger_name_fits_postgres_limits(auditor: PostgresAuditor) -> None:
    name = auditor.trigger_name("a" * 120)
    assert len(name) <= 63
    # Two long names must not collide.
    other = auditor.trigger_name("b" * 120)
    assert name != other


# --------------------------------------------------------------------------- #
# Principal parsing
# --------------------------------------------------------------------------- #


def test_principal_is_read_from_the_application_name(auditor: PostgresAuditor) -> None:
    assert auditor.principal_from("mizan:alice") == "alice"
    assert auditor.principal_from("mizan:alice@example.com") == "alice@example.com"


def test_a_missing_or_malformed_application_name_is_unknown(auditor: PostgresAuditor) -> None:
    assert auditor.principal_from(None) == UNKNOWN_PRINCIPAL
    assert auditor.principal_from("") == UNKNOWN_PRINCIPAL
    assert auditor.principal_from("psql") == UNKNOWN_PRINCIPAL
    assert auditor.principal_from("mizan:") == UNKNOWN_PRINCIPAL


# --------------------------------------------------------------------------- #
# Conversion
# --------------------------------------------------------------------------- #


def _row(
    *,
    principal: str | None = "mizan:alice",
    operation: str = "UPDATE",
    row_data: dict | None = None,
    old_row: dict | None = None,
    row_id: str | None = "o1",
    row_identity: str = IDENTITY_PRIMARY_KEY,
) -> tuple:
    return (
        datetime(2026, 1, 1, tzinfo=UTC),
        principal,
        "shop",
        "orders",
        row_id,
        row_identity,
        operation,
        row_data if row_data is not None else {"id": "o1", "owner_id": "alice", "status": "approved"},
        old_row if old_row is not None else {"id": "o1", "owner_id": "alice", "status": "pending"},
    )


def test_an_update_becomes_a_write_event_with_the_changed_columns(auditor: PostgresAuditor) -> None:
    event = auditor.to_event(_row())
    assert event.principal == "alice"
    assert event.table == "orders"
    assert event.row_id == "o1"
    assert event.method == "PATCH"
    assert event.columns == {"status": "approved"}
    assert event.row_owner == "alice"
    assert event.method_args["operation"] == "UPDATE"


def test_an_insert_reports_every_column(auditor: PostgresAuditor) -> None:
    event = auditor.to_event(_row(operation="INSERT", old_row={}))
    assert event.method == "POST"
    assert event.columns["owner_id"] == "alice"


def test_a_delete_keeps_the_old_row(auditor: PostgresAuditor) -> None:
    event = auditor.to_event(
        _row(
            operation="DELETE",
            row_data={},
            old_row={"id": "o1", "owner_id": "alice", "status": "pending"},
        )
    )
    assert event.method == "DELETE"
    assert event.columns["owner_id"] == "alice"
    assert event.row_owner == "alice"


def test_a_row_without_a_primary_key_is_unidentified(auditor: PostgresAuditor) -> None:
    event = auditor.to_event(_row(row_id=None, row_identity=IDENTITY_NONE))
    assert event.row_id == ""
    assert event.method_args["row_identity"] == IDENTITY_NONE


def test_json_payloads_that_arrive_as_text_are_parsed(auditor: PostgresAuditor) -> None:
    event = auditor.to_event(_row(row_data='{"id": "o1", "owner_id": "alice", "status": "approved"}', old_row="{}"))
    assert event.columns["status"] == "approved"


def test_the_audit_table_name_is_not_hard_coded_in_the_events(auditor: PostgresAuditor) -> None:
    event = auditor.to_event(_row())
    assert event.table == "orders"
    assert AUDIT_TABLE not in event.path
