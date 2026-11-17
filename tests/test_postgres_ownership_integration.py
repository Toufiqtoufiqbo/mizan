"""Real PostgreSQL ownership-evidence integration tests.

These tests need a server: MIZAN_PG_DSN / MIZAN_TEST_POSTGRES_DSN, or a local
``pgserver`` instance. They are marked ``postgres_integration`` so stage A can
deselect them; stage B sets MIZAN_REQUIRE_POSTGRES=1 and must see zero skips.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path

import pytest

pytest.importorskip("psycopg")
pytestmark = pytest.mark.postgres_integration

from mizan.attribution import AttributionUnavailable, AuditCursor  # noqa: E402
from mizan.core import AuthorizationOutcome, Policy, Principal, Resource  # noqa: E402
from mizan.ownership import (  # noqa: E402
    EvidenceState,
    RelationshipContract,
    build_ownership_graph,
)
from mizan.postgres_attribution import (  # noqa: E402
    ATTRIBUTION_CONFIRMED,
    ATTRIBUTION_MISSING_REQUEST,
    PostgresAttributor,
)
from mizan.taint import TaintAnalyzer  # noqa: E402


def _server() -> str:
    dsn = os.environ.get("MIZAN_PG_DSN") or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if dsn:
        return dsn if "connect_timeout" in dsn else dsn + ("&connect_timeout=5" if "?" in dsn else "?connect_timeout=5")
    pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required")
    directory = Path(tempfile.mkdtemp(prefix="mizan-v6-pg-"))
    return pgserver.get_server(pgdata=directory, cleanup_mode="delete").get_uri()


DSN = _server()


@pytest.fixture()
def database():
    import psycopg

    connection = psycopg.connect(DSN, autocommit=True)
    schema = f"mizan_v6_{uuid.uuid4().hex[:10]}"
    twin_schema = f"mizan_v6_twin_{uuid.uuid4().hex[:10]}"
    with connection.cursor() as cursor:
        for name in (schema, twin_schema):
            cursor.execute(f'CREATE SCHEMA "{name}"')
        cursor.execute(f'''CREATE TABLE "{schema}".people (person_key TEXT PRIMARY KEY, label TEXT)''')
        cursor.execute(
            f'''CREATE TABLE "{schema}".simple_assets (
                asset_ref TEXT PRIMARY KEY,
                originator_ref TEXT REFERENCES "{schema}".people(person_key),
                label TEXT NOT NULL)'''
        )
        cursor.execute(
            f'''CREATE TABLE "{schema}".assets (
                tenant_ref TEXT NOT NULL, asset_ref TEXT NOT NULL,
                originator_ref TEXT REFERENCES "{schema}".people(person_key),
                label TEXT NOT NULL, PRIMARY KEY (tenant_ref, asset_ref))'''
        )
        cursor.execute(
            f'''CREATE TABLE "{schema}".shares (
                share_key TEXT PRIMARY KEY,
                asset_ref TEXT NOT NULL,
                tenant_ref TEXT NOT NULL,
                collaborator_ref TEXT REFERENCES "{schema}".people(person_key),
                FOREIGN KEY (tenant_ref, asset_ref) REFERENCES "{schema}".assets(tenant_ref, asset_ref))'''
        )
        cursor.execute(f'''CREATE TABLE "{schema}".logs (payload TEXT, UNIQUE (payload))''')
        cursor.execute(f'''CREATE TABLE "{twin_schema}".assets (asset_ref TEXT PRIMARY KEY, label TEXT)''')
        cursor.execute(f'INSERT INTO "{schema}".people VALUES (%s, %s)', ("alice", "Alice"))
        cursor.execute(f'INSERT INTO "{schema}".people VALUES (%s, %s)', ("bob", "Bob"))
        cursor.execute(
            f'INSERT INTO "{schema}".simple_assets VALUES (%s, %s, %s)',
            ("a1", "alice", "Asset A"),
        )
        cursor.execute(
            f'INSERT INTO "{schema}".assets VALUES (%s, %s, %s, %s)',
            ("t1", "a1", "alice", "Asset A"),
        )
        cursor.execute(
            f'INSERT INTO "{schema}".shares VALUES (%s, %s, %s, %s)',
            ("s1", "a1", "t1", "bob"),
        )
    provider = PostgresAttributor(connection, schemas=(schema, twin_schema), audit_schema=schema)
    provider.auditor.install()  # explicit opt-in, never implicit
    yield provider, connection, schema, twin_schema
    provider.auditor.uninstall()
    with connection.cursor() as cursor:
        for name in (schema, twin_schema):
            cursor.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    connection.close()


def _context(connection, principal: str | None, request_id: str) -> None:
    """Set transaction-local identity and correlation, like the fixture app."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('application_name', %s, true)", (f"mizan:{principal}" if principal else "",))
        cursor.execute("SELECT set_config('mizan.request_id', %s, true)", (request_id,))


def _write(connection, schema: str, statement: str, params: tuple = (), *, principal="bob", request_id="req-1") -> None:
    """Run one write in the same transaction as its request context."""
    previous = connection.autocommit
    connection.autocommit = False
    try:
        _context(connection, principal, request_id)
        with connection.cursor() as cursor:
            cursor.execute(statement, params)
        connection.commit()
    finally:
        connection.autocommit = previous


# --------------------------------------------------------------------------- #
# Schema and rows
# --------------------------------------------------------------------------- #


def test_schema_is_schema_qualified_with_composite_keys(database) -> None:
    provider, _connection, schema, twin_schema = database
    declared = provider.schema()
    assert f"{schema}.assets" in declared.tables
    assert f"{twin_schema}.assets" in declared.tables
    assets = declared.tables[f"{schema}.assets"]
    assert assets.primary_key == ("tenant_ref", "asset_ref")
    columns = {column.name: column for column in assets.columns}
    assert columns["originator_ref"].not_null is False
    shares = declared.tables[f"{schema}.shares"]
    fk = next(fk for fk in shares.foreign_keys if fk.column == "asset_ref")
    assert fk.table == f"{schema}.assets"
    assert fk.composite is True
    logs = declared.tables[f"{schema}.logs"]
    assert logs.column("payload").unique is True


def test_rows_are_returned_for_qualified_tables(database) -> None:
    provider, _connection, schema, _twin = database
    rows = provider.rows(f"{schema}.assets")
    assert rows == [{"tenant_ref": "t1", "asset_ref": "a1", "originator_ref": "alice", "label": "Asset A"}]


def test_unqualified_ambiguous_table_is_rejected(database) -> None:
    provider, _connection, _schema, _twin = database
    with pytest.raises(AttributionUnavailable, match="ambiguous"):
        provider.rows("assets")


def test_contract_uses_bare_or_qualified_table_names(database) -> None:
    provider, _connection, schema, _twin = database
    declared = provider.schema()
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "ownership": {f"{schema}.assets": {"source": "database_foreign_key", "column": "originator_ref"}},
        },
        strict=True,
    )
    contract.validate_schema(declared)
    bare = RelationshipContract.from_dict(
        {"version": 1, "ownership": {"assets": {"source": "database_foreign_key", "column": "originator_ref"}}},
        strict=True,
    )
    with pytest.raises(ValueError, match="ambiguous"):
        bare.validate_schema(declared)


# --------------------------------------------------------------------------- #
# Cursor and attribution
# --------------------------------------------------------------------------- #


def test_cursor_only_returns_writes_after_it(database) -> None:
    provider, connection, schema, _twin = database
    provider.schema()
    before = provider.snapshot(principal="bob", request_id="req-1")
    assert isinstance(before, AuditCursor)
    _write(
        connection,
        schema,
        f'UPDATE "{schema}".simple_assets SET label = %s WHERE asset_ref = %s',
        ("changed", "a1"),
        principal="bob",
        request_id="req-1",
    )
    events = provider.diff(before, principal="bob", method="PUT", path="/items/a1", request_id="req-1")
    assert len(events) == 1
    event = events[0]
    assert event.attribution == ATTRIBUTION_CONFIRMED
    assert event.request_id == "req-1"
    assert event.principal == "bob"
    assert event.row_key == "a1"


def test_rollback_is_not_recorded(database) -> None:
    provider, connection, schema, _twin = database
    before = provider.snapshot()
    connection.autocommit = False
    try:
        _context(connection, "bob", "req-rollback")
        with connection.cursor() as cursor:
            cursor.execute(f'UPDATE "{schema}".assets SET label = %s WHERE asset_ref = %s', ("rolled", "a1"))
        connection.rollback()
    finally:
        connection.autocommit = True
    assert provider.diff(before, principal="bob", method="PUT", path="/items/a1", request_id="req-rollback") == []


def test_missing_request_context_is_inconclusive(database) -> None:
    provider, connection, schema, _twin = database
    before = provider.snapshot()
    _write(
        connection,
        schema,
        f'UPDATE "{schema}".simple_assets SET label = %s WHERE asset_ref = %s',
        ("background", "a1"),
        principal="bob",
        request_id="",
    )
    events = provider.diff(before, principal="bob", method="PUT", path="/items/a1", request_id="req-x")
    assert len(events) == 1
    assert events[0].attribution == ATTRIBUTION_MISSING_REQUEST
    analyzer = TaintAnalyzer(Policy(), graph=None)
    assert analyzer.analyze(events) == []
    assert all(item["outcome"] == AuthorizationOutcome.INCONCLUSIVE.value for item in analyzer.outcomes)


def test_connection_pool_identity_does_not_leak(database) -> None:
    provider, connection, schema, _twin = database
    before = provider.snapshot()
    _write(
        connection,
        schema,
        f'UPDATE "{schema}".simple_assets SET label = %s WHERE asset_ref = %s',
        ("alice", "a1"),
        principal="alice",
        request_id="req-alice",
    )
    _write(
        connection,
        schema,
        f'UPDATE "{schema}".simple_assets SET label = %s WHERE asset_ref = %s',
        ("bob", "a1"),
        principal="bob",
        request_id="req-bob",
    )
    events = provider.diff(before, principal="bob", method="PUT", path="/items/a1", request_id="req-bob")
    assert len(events) == 1
    assert events[0].principal == "bob"
    assert events[0].attribution == ATTRIBUTION_CONFIRMED


# --------------------------------------------------------------------------- #
# Ownership graph and verdict consistency
# --------------------------------------------------------------------------- #


def _graph(provider, contract=None):
    from mizan.ownership import Observation

    schema = provider.schema()
    identity = RelationshipContract.from_dict(
        {"version": 1, "identity": {"endpoint": "/whoami", "field": "person_key"}}, strict=True
    )
    merged = contract
    if merged is None:
        merged = identity
    elif merged.identity is None:
        merged = RelationshipContract(
            version=merged.version,
            identity=identity.identity,
            ownership=merged.ownership,
            sharing=merged.sharing,
            variants=merged.variants,
        )
    return build_ownership_graph(
        resources={"items:a1": Resource("items", "a1")},
        traffic=[
            Observation("alice", {"person_key": "alice"}, path="/whoami"),
            Observation("bob", {"person_key": "bob"}, path="/whoami"),
        ],
        ledger=[],
        schema=schema,
        rows={name: provider.rows(name) for name in schema.tables},
        contract=merged,
    )


def test_foreign_key_alone_is_candidate_not_confirmed(database) -> None:
    provider, _connection, _schema, _twin = database
    graph = _graph(provider)
    assert graph.owner_of("items:a1") is None
    assert any(relation.state is EvidenceState.CANDIDATE for relation in graph.relationships)


def test_declared_owner_is_confirmed_and_supports_l3(database) -> None:
    provider, _connection, _schema, _twin = database
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "ownership": {
                "items": {
                    "source": "database_foreign_key",
                    "column": "originator_ref",
                    "table": f"{provider.auditor.audit_schema}.simple_assets",
                }
            },
        },
        strict=True,
    )
    graph = _graph(provider, contract)
    assert graph.owner_of("items:a1") == "alice"
    policy = Policy()
    policy.principals["bob"] = Principal("bob", ("user",), "bob-token")
    before = provider.snapshot()
    _write(
        provider.connection,
        provider.auditor.audit_schema,
        f'UPDATE "{provider.auditor.audit_schema}".simple_assets SET label = %s WHERE asset_ref = %s',
        ("hacked", "a1"),
        principal="bob",
        request_id="req-write",
    )
    events = provider.diff(before, principal="bob", method="PUT", path="/items/a1", request_id="req-write")
    analyzer = TaintAnalyzer(policy, graph=graph)
    findings = analyzer.analyze(events)
    assert [finding.law for finding in findings] == ["L3"]
    assert findings[0].evidence["owner"] == "alice"


# --------------------------------------------------------------------------- #
# Independent fixture and CLI
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "variant,read_status,write_status",
    [
        ("clean", 404, 404),
        ("read", 200, 404),
        ("write", 404, 200),
        ("grant_read", 200, 404),
        ("grant_write", 200, 200),
    ],
)
def test_fixture_verifies_its_own_behaviour(variant: str, read_status: int, write_status: int) -> None:
    """The fixture proves its own expected behavior before Mīzān inspects it."""
    import importlib.util

    import psycopg

    fixture = Path(__file__).parent / "fixtures" / "external_apps" / "postgres_store" / "app.py"
    spec = importlib.util.spec_from_file_location("postgres_store_fixture", fixture)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    schema = f"mizan_app_{uuid.uuid4().hex[:10]}"
    os.environ["MIZAN_PG_DSN"] = DSN
    os.environ["MIZAN_PG_SCHEMA"] = schema
    app = module.create_app(variant, dsn=DSN, schema=schema)
    client = app.test_client()
    try:
        alice = client.post("/login", json={"username": "alice", "password": "alice-secret"}).get_json()["token"]
        bob = client.post("/login", json={"username": "bob", "password": "bob-secret"}).get_json()["token"]
        assert client.get("/items/item-a1", headers={"Authorization": f"Bearer {alice}"}).status_code == 200
        assert client.get("/items/item-a1", headers={"Authorization": f"Bearer {bob}"}).status_code == read_status
        response = client.put("/items/item-a1", json={"label": "changed"}, headers={"Authorization": f"Bearer {bob}"})
        assert response.status_code == write_status
    finally:
        connection = psycopg.connect(DSN, autocommit=True)
        with connection.cursor() as cursor:
            cursor.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        connection.close()


def test_cli_evidence_is_read_only_and_redacts_the_dsn(monkeypatch) -> None:
    import psycopg
    from click.testing import CliRunner

    from mizan.cli import main

    connection = psycopg.connect(DSN, autocommit=True)
    schema = f"mizan_cli_{uuid.uuid4().hex[:10]}"
    with connection.cursor() as cursor:
        cursor.execute(f'CREATE SCHEMA "{schema}"')
        cursor.execute(f'CREATE TABLE "{schema}".items (item_ref TEXT PRIMARY KEY, label TEXT)')
    connection.close()

    monkeypatch.setenv("MIZAN_DATABASE_URL", DSN)
    runner = CliRunner()
    missing = runner.invoke(
        main,
        ["postgres-evidence", "--schema", schema],
    )
    assert missing.exit_code != 0
    assert "install-audit" in missing.output

    result = runner.invoke(
        main,
        ["postgres-evidence", "--schema", schema, "--install-audit"],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["verdict"] == "INCONCLUSIVE"
    assert report["attack_mode"].startswith("unsupported")
    assert "password" not in result.output.lower()
    assert DSN not in result.output

    connection = psycopg.connect(DSN, autocommit=True)
    with connection.cursor() as cursor:
        cursor.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    connection.close()
