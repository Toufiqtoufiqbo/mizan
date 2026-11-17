"""Failing-first tests for Phase VI PostgreSQL attribution parity.

These unit tests do not need a server. They pin the backend-neutral interface,
the monotonic audit cursor, request correlation and attribution states that the
ownership graph and L3 analyzer rely on.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mizan.attribution import (
    AttributionUnavailable,
    AuditCursor,
    Column,
    DatabaseAttributor,
    DatabaseSchema,
    ForeignKey,
    TableSchema,
)
from mizan.core import AuthorizationOutcome, Principal
from mizan.ownership import RelationshipContract
from mizan.postgres_attribution import PostgresAttributor
from mizan.postgres_audit import PostgresAuditor
from mizan.taint import TaintAnalyzer


class _Cursor:
    def __init__(self, rows: list[tuple] | None = None) -> None:
        self.rows = rows or []
        self.executed: list[str] = []
        self.parameters: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executed.append(sql)
        self.parameters.append(params)

    def fetchall(self) -> list[tuple]:
        return self.rows

    def fetchone(self) -> tuple | None:
        return self.rows[0] if self.rows else None


class _Connection:
    def __init__(self, rows: list[tuple] | None = None) -> None:
        self.cursor_instance = _Cursor(rows)

    def cursor(self):
        return self.cursor_instance

    def commit(self) -> None:
        return None


def _audit_row(**overrides):
    row = {
        "occurred_at": datetime(2026, 1, 1, tzinfo=UTC),
        "raw_principal": "mizan:alice",
        "request_id": "req-1",
        "schema_name": "shop",
        "table_name": "orders",
        "row_id": "o1",
        "row_identity": "primary_key",
        "operation": "UPDATE",
        "row_data": {"id": "o1", "owner_id": "alice", "status": "paid"},
        "old_row": {"id": "o1", "owner_id": "alice", "status": "pending"},
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------------- #
# Interface and cursor
# --------------------------------------------------------------------------- #


def test_postgres_provider_implements_the_attribution_interface() -> None:
    provider = PostgresAttributor(_Connection(), schemas=("shop",), audit_schema="shop")
    assert isinstance(provider, DatabaseAttributor)
    for name in ("schema", "rows", "snapshot", "diff", "row_identity"):
        assert callable(getattr(provider, name))


def test_unavailable_audit_state_fails_closed() -> None:
    provider = PostgresAttributor(_Connection(rows=[(None,)]), schemas=("shop",), audit_schema="shop")
    with pytest.raises(AttributionUnavailable):
        provider.snapshot()


def test_audit_read_uses_a_monotonic_id_cursor() -> None:
    connection = _Connection()
    auditor = PostgresAuditor(connection, audit_schema="shop")
    auditor.read(since_id=42)
    sql = connection.cursor_instance.executed[-1]
    assert "id > %s" in sql
    assert "occurred_at >" not in sql
    assert connection.cursor_instance.parameters[-1] == (42,)


def test_audit_record_carries_request_correlation() -> None:
    sql = PostgresAuditor(_Connection(), audit_schema="shop").audit_table_sql()
    assert "request_id" in sql
    function = PostgresAuditor(_Connection(), audit_schema="shop").audit_function_sql()
    assert "mizan.request_id" in function


# --------------------------------------------------------------------------- #
# Attribution states
# --------------------------------------------------------------------------- #


def test_correlated_write_is_confirmed() -> None:
    provider = PostgresAttributor(_Connection(), schemas=("shop",), audit_schema="shop")
    event = provider.event_from_audit_row(_audit_row())
    assert event.principal == "alice"
    assert event.request_id == "req-1"
    assert event.attribution == "confirmed"


def test_missing_request_correlation_is_explicit_and_inconclusive() -> None:
    provider = PostgresAttributor(_Connection(), schemas=("shop",), audit_schema="shop")
    event = provider.event_from_audit_row(_audit_row(request_id=""))
    assert event.attribution == "missing_request"
    policy = __import__("mizan.core", fromlist=["Policy"]).Policy()
    policy.principals["alice"] = Principal("alice", ("user",), "alice-token")
    analyzer = TaintAnalyzer(policy)
    assert analyzer.analyze([event]) == []
    assert all(item["outcome"] == AuthorizationOutcome.INCONCLUSIVE.value for item in analyzer.outcomes)


def test_unknown_principal_is_not_an_authorization_identity() -> None:
    provider = PostgresAttributor(_Connection(), schemas=("shop",), audit_schema="shop")
    event = provider.event_from_audit_row(_audit_row(raw_principal="nobody"))
    assert event.attribution == "unknown_principal"
    assert event.principal == "unknown"


def test_ambiguous_attribution_is_inconclusive() -> None:
    provider = PostgresAttributor(_Connection(), schemas=("shop",), audit_schema="shop")
    event = provider.event_from_audit_row(_audit_row(request_id="shared", attribution="ambiguous"))
    assert event.attribution == "ambiguous"
    policy = __import__("mizan.core", fromlist=["Policy"]).Policy()
    policy.principals["alice"] = Principal("alice", ("user",), "alice-token")
    analyzer = TaintAnalyzer(policy)
    assert analyzer.analyze([event]) == []
    assert all(item["outcome"] == AuthorizationOutcome.INCONCLUSIVE.value for item in analyzer.outcomes)


# --------------------------------------------------------------------------- #
# Schema-qualified contracts
# --------------------------------------------------------------------------- #


def test_qualified_postgres_contract_table_validates() -> None:
    schema = DatabaseSchema(
        tables={
            "shop.orders": TableSchema(
                name="shop.orders",
                columns=(Column("id", primary_key=1), Column("owner_ref")),
                foreign_keys=(ForeignKey("owner_ref", "shop.people", "person_key"),),
            ),
            "shop.people": TableSchema(name="shop.people", columns=(Column("person_key", primary_key=1),)),
        }
    )
    data = {
        "version": 1,
        "ownership": {"orders": {"source": "database_foreign_key", "column": "owner_ref"}},
    }
    contract = RelationshipContract.from_dict(data, strict=True)
    # A bare declaration must resolve to exactly one qualified table when
    # the database has a single matching schema.
    contract.validate_schema(schema)


def test_ambiguous_bare_table_reference_is_rejected() -> None:
    schema = DatabaseSchema(
        tables={"shop.orders": TableSchema(name="shop.orders"), "archive.orders": TableSchema(name="archive.orders")}
    )
    data = {"version": 1, "ownership": {"orders": {"source": "database_foreign_key", "column": "owner_ref"}}}
    contract = RelationshipContract.from_dict(data, strict=True)
    with pytest.raises(ValueError, match="ambiguous"):
        contract.validate_schema(schema)


def test_audit_cursor_is_a_stable_snapshot() -> None:
    cursor = AuditCursor(event_id=17, principal="alice", request_id="req-1")
    assert cursor.event_id == 17
    assert cursor.principal == "alice"
    assert cursor.request_id == "req-1"


def test_sqlite_attributor_is_unchanged() -> None:
    from mizan.attribution import SqliteAttributor

    provider = SqliteAttributor("missing.sqlite")
    assert isinstance(provider, DatabaseAttributor)
    assert provider.schema().tables == {}
