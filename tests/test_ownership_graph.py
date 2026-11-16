"""Tests for the evidence-based ownership graph (Phase V).

The rules under test are deliberately conservative: a foreign key is a
reference first, an identity anchor needs repeatable observations from
distinct principals, a disputed owner is never used, and no credential is
copied into the graph.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from mizan.attribution import SqliteAttributor, quote_identifier
from mizan.core import UNKNOWN_PRINCIPAL, Policy, Resource
from mizan.ownership import (
    Evidence,
    EvidenceState,
    Observation,
    OwnershipGraph,
    RelationshipContract,
    RelationshipType,
    build_ownership_graph,
    discover_anchors,
    discover_relationships,
)
from mizan.taint import WriteEvent
from mizan.traffic import TrafficRecord, infer_resource


def _make_db(path: Path, schema: str, rows: dict[str, list[tuple]]) -> SqliteAttributor:
    connection = sqlite3.connect(path)
    with connection:
        connection.executescript(schema)
        for table, values in rows.items():
            placeholders = ",".join("?" for _ in values[0]) if values else ""
            for row in values:
                connection.execute(f"INSERT INTO {quote_identifier(table)} VALUES ({placeholders})", row)
    connection.close()
    return SqliteAttributor(path)


# --------------------------------------------------------------------------- #
# SQLite schema introspection
# --------------------------------------------------------------------------- #


def test_primary_key_and_foreign_key_metadata(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE people (person_key TEXT PRIMARY KEY, label TEXT);
        CREATE TABLE notes (
            note_key TEXT PRIMARY KEY,
            author_ref TEXT NOT NULL REFERENCES people(person_key),
            title TEXT
        );
        """,
        {"people": [("alice", "Alice")], "notes": [("n1", "alice", "Hello")]},
    )
    schema = attributor.schema()
    assert schema.get("people").primary_key == ("person_key",)
    assert schema.get("notes").primary_key == ("note_key",)
    foreign_keys = schema.get("notes").foreign_keys
    assert len(foreign_keys) == 1
    assert (foreign_keys[0].column, foreign_keys[0].table, foreign_keys[0].column_ref) == (
        "author_ref",
        "people",
        "person_key",
    )
    assert schema.to_dict()["people"]["primary_key"] == ["person_key"]


def test_composite_primary_key_and_foreign_key(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE teams (team TEXT, member TEXT, PRIMARY KEY (team, member));
        CREATE TABLE links (
            link_key TEXT PRIMARY KEY,
            team TEXT,
            member TEXT,
            FOREIGN KEY (team, member) REFERENCES teams(team, member)
        );
        """,
        {"teams": [("core", "alice")], "links": [("l1", "core", "alice")]},
    )
    schema = attributor.schema()
    assert schema.get("teams").primary_key == ("team", "member")
    assert {(fk.column, fk.column_ref) for fk in schema.get("links").foreign_keys} == {
        ("team", "team"),
        ("member", "member"),
    }


def test_multiple_foreign_keys_to_the_same_table_and_nullable(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE people (person_key TEXT PRIMARY KEY);
        CREATE TABLE edges (
            edge_key TEXT PRIMARY KEY,
            from_ref TEXT REFERENCES people(person_key),
            to_ref TEXT REFERENCES people(person_key),
            viewer_ref TEXT REFERENCES people(person_key)
        );
        """,
        {"people": [("a",), ("b",)], "edges": [("e1", "a", "b", None)]},
    )
    schema = attributor.schema()
    table = schema.get("edges")
    assert {fk.column for fk in table.foreign_keys} == {"from_ref", "to_ref", "viewer_ref"}
    row = attributor.rows("edges")[0]
    assert row["viewer_ref"] is None


def test_row_identity_uses_the_declared_primary_key_not_rowid(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        "CREATE TABLE docs (document_key TEXT PRIMARY KEY, title TEXT);",
        {"docs": [("doc-1", "One"), ("doc-2", "Two")]},
    )
    before = attributor.snapshot()
    connection = sqlite3.connect(tmp_path / "db.sqlite")
    with connection:
        connection.execute("UPDATE docs SET title = ? WHERE document_key = ?", ("Changed", "doc-2"))
    connection.close()
    events = attributor.diff(before, principal="alice", method="PATCH", path="/docs/doc-2")
    assert len(events) == 1
    assert events[0].row_key == "doc-2"
    assert events[0].row_id != "doc-2"  # rowid is not the public identity


def test_identifier_quoting_cannot_escape() -> None:
    assert quote_identifier('a"b') == '"a""b"'


# --------------------------------------------------------------------------- #
# Convention-free resource discovery
# --------------------------------------------------------------------------- #


def test_resource_id_from_response_field_matching_the_path() -> None:
    kind, identifier, owner = infer_resource(
        {"document_key": "doc-7", "title": "Notes"},
        "/documents/{id}",
        path="/documents/doc-7",
    )
    assert (kind, identifier, owner) == ("documents", "doc-7", None)


def test_conventional_fields_still_work() -> None:
    kind, identifier, owner = infer_resource({"id": "o1", "owner_id": "alice"}, "/orders/{id}", path="/orders/o1")
    assert (kind, identifier, owner) == ("orders", "o1", "alice")


def test_nested_and_collection_responses() -> None:
    kind, identifier, owner = infer_resource(
        {"data": {"id": "o9", "owner_id": "bob"}}, "/orders/{id}", path="/orders/o9"
    )
    assert (kind, identifier, owner) == ("orders", "o9", "bob")
    assert infer_resource([{"id": "o2", "owner_id": "alice"}], "/orders/{id}", path="/orders/o2")[1] == "o2"


# --------------------------------------------------------------------------- #
# Graph semantics
# --------------------------------------------------------------------------- #


def test_relationship_types_are_distinct() -> None:
    graph = OwnershipGraph()
    graph.add_relationship(RelationshipType.REFERENCES, "documents:d1", "workspaces:w1", EvidenceState.CONFIRMED)
    assert graph.owner_of("documents:d1") is None
    assert graph.owner_state("documents:d1") is EvidenceState.UNKNOWN


def test_contradiction_is_preserved_and_not_an_owner() -> None:
    graph = OwnershipGraph()
    evidence_a = graph.add_evidence(Evidence(source="response_field", principal="alice", resource="documents:d1"))
    evidence_b = graph.add_evidence(Evidence(source="sqlite_foreign_key", principal="bob", resource="documents:d1"))
    graph.add_relationship(RelationshipType.OWNS, "alice", "documents:d1", EvidenceState.CONFIRMED, [evidence_a])
    graph.add_relationship(RelationshipType.OWNS, "bob", "documents:d1", EvidenceState.CONFIRMED, [evidence_b])
    assert graph.owner_of("documents:d1") is None
    assert graph.owner_state("documents:d1") is EvidenceState.CONTRADICTED
    assert len(graph.relationships) == 2  # neither observation was overwritten


def test_sharing_explains_access_without_creating_ownership() -> None:
    graph = OwnershipGraph()
    evidence = graph.add_evidence(Evidence(source="association_table", principal="bob", resource="documents:d1"))
    graph.add_relationship(RelationshipType.SHARED_WITH, "bob", "documents:d1", EvidenceState.CONFIRMED, [evidence])
    assert graph.explained_by_sharing("alice", "bob", "documents:d1") is True
    assert graph.owner_of("documents:d1") is None


def test_evidence_is_stable_and_never_contains_tokens() -> None:
    canary = "MIZAN_SECRET_CANARY_OWNERSHIP_3D4A"
    evidence = Evidence(source="identity_anchor", principal="alice", detail="stable")
    assert evidence.id == Evidence(source="identity_anchor", principal="alice", detail="stable").id
    serialized = json.dumps(evidence.to_dict())
    assert canary not in serialized
    assert "token" not in serialized


def test_serialization_round_trip() -> None:
    graph = OwnershipGraph()
    evidence = graph.add_evidence(Evidence(source="response_field", principal="alice", resource="orders:o1"))
    graph.add_entity("orders:o1", "resource")
    graph.add_relationship(RelationshipType.OWNS, "alice", "orders:o1", EvidenceState.CONFIRMED, [evidence])
    graph.inconclusive["orders:o2"] = "no confirmed owner"
    restored = OwnershipGraph.from_dict(json.loads(json.dumps(graph.to_dict())))
    assert restored.owner_of("orders:o1") == "alice"
    assert restored.inconclusive == {"orders:o2": "no confirmed owner"}
    assert restored.report()["confirmed_ownership_edges"] == 1


def test_candidate_owner_is_not_a_confirmed_owner() -> None:
    graph = OwnershipGraph()
    evidence = graph.add_evidence(Evidence(source="sqlite_foreign_key", resource="documents:d1"))
    graph.add_relationship(RelationshipType.OWNS, "alice", "documents:d1", EvidenceState.CANDIDATE, [evidence])
    assert graph.owner_of("documents:d1") is None
    assert graph.report()["candidate_ownership_edges"] == 1


# --------------------------------------------------------------------------- #
# Anchoring and relationship discovery
# --------------------------------------------------------------------------- #


def test_anchor_needs_two_distinct_principals(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        "CREATE TABLE people (person_key TEXT PRIMARY KEY, label TEXT);",
        {"people": [("alice", "Alice")]},
    )
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    records = [Observation("alice", {"person_key": "alice"})]
    graph = OwnershipGraph()
    anchors = discover_anchors(graph, records, schema, rows)
    assert "alice" not in anchors  # one principal cannot confirm an anchor


def test_anchor_ambiguity_is_preserved(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE people (person_key TEXT PRIMARY KEY, label TEXT);
        CREATE TABLE aliases (alias_key TEXT PRIMARY KEY, label TEXT);
        CREATE TABLE links (
            link_key TEXT PRIMARY KEY,
            person TEXT REFERENCES people(person_key),
            alias TEXT REFERENCES aliases(alias_key)
        );
        """,
        {
            "people": [("alice", "Alice"), ("bob", "Bob")],
            "aliases": [("a1", "Alice"), ("b1", "Bob")],
            "links": [("l1", "alice", "a1")],
        },
    )
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    contract = RelationshipContract.from_dict(
        {"version": 1, "identity": {"endpoint": "/session", "field": "identity_key"}}
    )
    records = [
        Observation("alice", {"identity_key": "alice"}, path="/session"),
        Observation("alice", {"identity_key": "a1"}, path="/session"),
        Observation("bob", {"identity_key": "bob"}, path="/session"),
        Observation("bob", {"identity_key": "b1"}, path="/session"),
    ]
    graph = OwnershipGraph()
    anchors = discover_anchors(graph, records, schema, rows, contract)
    assert not anchors  # two equally supported columns: no claim
    assert graph.report()["ambiguous_relationships"] > 0


def test_direct_foreign_key_to_anchored_principal_is_ownership(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE people (person_key TEXT PRIMARY KEY);
        CREATE TABLE docs (document_key TEXT PRIMARY KEY, custodian_ref TEXT NOT NULL REFERENCES people(person_key));
        """,
        {"people": [("alice",), ("bob",)], "docs": [("d1", "alice"), ("d2", "bob")]},
    )
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    records = [
        Observation("alice", {"identity_key": "alice"}, path="/session"),
        Observation("bob", {"identity_key": "bob"}, path="/session"),
    ]
    resources = {"documents:d1": Resource("documents", "d1"), "documents:d2": Resource("documents", "d2")}
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "identity": {"endpoint": "/session", "field": "identity_key"},
            "ownership": {"documents": {"source": "database_foreign_key", "column": "custodian_ref"}},
        }
    )
    graph = build_ownership_graph(
        resources=resources, traffic=records, ledger=[], schema=schema, rows=rows, contract=contract
    )
    assert graph.owner_of("documents:d1") == "alice"
    assert graph.owner_of("documents:d2") == "bob"


def test_foreign_key_to_intermediate_entity_is_only_a_reference(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE workspaces (workspace_key TEXT PRIMARY KEY);
        CREATE TABLE docs (
            document_key TEXT PRIMARY KEY,
            workspace_ref TEXT NOT NULL REFERENCES workspaces(workspace_key)
        );
        """,
        {"workspaces": [("w1",)], "docs": [("d1", "w1")]},
    )
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    graph = OwnershipGraph()
    discover_relationships(
        graph,
        {"documents:d1": Resource("documents", "d1")},
        [],
        schema,
        rows,
        {},  # no anchored principal
    )
    assert graph.owner_of("documents:d1") is None
    assert any(relation.type is RelationshipType.REFERENCES for relation in graph.relationships)


def test_association_table_creates_sharing_not_ownership(tmp_path: Path) -> None:
    attributor = _make_db(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE people (person_key TEXT PRIMARY KEY);
        CREATE TABLE docs (document_key TEXT PRIMARY KEY);
        CREATE TABLE grants (
            document_key TEXT REFERENCES docs(document_key),
            person_ref TEXT REFERENCES people(person_key),
            PRIMARY KEY (document_key, person_ref)
        );
        """,
        {"people": [("alice",), ("bob",)], "docs": [("d1",)], "grants": [("d1", "bob")]},
    )
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "identity": {"endpoint": "/session", "field": "identity_key"},
            "sharing": {
                "grants": {
                    "resource_fk": "document_key",
                    "principal_fk": "person_ref",
                    "semantics": "authorization_grant",
                }
            },
        }
    )
    records = [
        Observation("alice", {"identity_key": "alice"}, path="/session"),
        Observation("bob", {"identity_key": "bob"}, path="/session"),
    ]
    graph = build_ownership_graph(
        resources={"documents:d1": Resource("documents", "d1")},
        traffic=records,
        ledger=[],
        schema=schema,
        rows=rows,
        contract=contract,
    )
    assert graph.explained_by_sharing("alice", "bob", "documents:d1") is True
    assert graph.owner_of("documents:d1") is None


def test_unattributed_write_never_becomes_ownership() -> None:
    event = WriteEvent(
        ts=0.0,
        request_id="r1",
        principal=UNKNOWN_PRINCIPAL,
        method="PATCH",
        path="/documents/d1",
        table="documents",
        row_id="1",
        row_key="d1",
    )
    assert event.principal == UNKNOWN_PRINCIPAL
    graph = OwnershipGraph()
    discover_relationships(graph, {"documents:d1": Resource("documents", "d1")}, [event], _empty_schema(), {}, {})
    assert graph.owner_of("documents:d1") is None


def _empty_schema():
    from mizan.attribution import DatabaseSchema

    return DatabaseSchema()


def test_backward_compatible_policy_and_traffic_serialization() -> None:
    old_policy = {
        "principals": {"alice": {"id": "alice", "roles": ["user"], "token": None}},
        "resources": {"orders:o1": {"type": "orders", "id": "o1", "owner": "alice"}},
        "rules": [{"kind": "owner", "action": "read", "resource_type": "orders"}],
        "notes": ["old"],
    }
    policy = Policy.from_dict(old_policy)
    assert policy.resources["orders:o1"].owner == "alice"
    assert policy.principal("alice").roles == ("user",)
    record = TrafficRecord(
        method="GET",
        path="/orders/o1",
        status=200,
        principal="alice",
        resource_type="orders",
        resource_id="o1",
        resource_owner="alice",
    )
    assert record.resource.owner == "alice"
