"""Adversarial ownership-semantics regressions (Phase V.1).

Each test here reproduces a concrete false-confidence failure mode from the
Phase V graph: a foreign key treated as ownership, an association table
treated as permission, an identity match treated as identity proof, and a
database row treated as if it were the API resource.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mizan.attribution import SqliteAttributor, quote_identifier
from mizan.core import Resource
from mizan.ownership import (
    EvidenceState,
    Observation,
    RelationshipContract,
    RelationshipType,
    build_ownership_graph,
    canonical_key,
    parse_identity,
)


def _database(path: Path, schema: str, rows: dict[str, list[tuple]]) -> SqliteAttributor:
    connection = sqlite3.connect(path)
    with connection:
        connection.executescript(schema)
        for table, values in rows.items():
            if not values:
                continue
            placeholders = ",".join("?" for _ in values[0])
            for row in values:
                connection.execute(f"INSERT INTO {quote_identifier(table)} VALUES ({placeholders})", row)
    connection.close()
    return SqliteAttributor(path)


def _graph(attributor, resources, observations, contract=None, ledger=()):
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    return build_ownership_graph(
        resources=resources,
        traffic=observations,
        ledger=ledger,
        schema=schema,
        rows=rows,
        contract=contract,
    )


def _identity_observations():
    return [
        Observation("alice", {"identity_key": "alice"}, path="/session"),
        Observation("bob", {"identity_key": "bob"}, path="/session"),
    ]


# --- Issue A: a foreign key is not ownership semantics ----------------------

ADVERSARIAL_SCHEMA = """
CREATE TABLE people (person_key TEXT PRIMARY KEY, label TEXT);
CREATE TABLE artifacts (
    artifact_key TEXT PRIMARY KEY,
    created_by TEXT REFERENCES people(person_key),
    assigned_to TEXT REFERENCES people(person_key),
    reviewer_id TEXT REFERENCES people(person_key)
);
"""


@pytest.mark.parametrize("column", ["created_by", "assigned_to", "reviewer_id"])
def test_non_ownership_foreign_key_is_not_a_confirmed_owner(tmp_path: Path, column: str) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        ADVERSARIAL_SCHEMA,
        {
            "people": [("alice", "Alice"), ("bob", "Bob")],
            "artifacts": [("art-1", "alice", "bob", "bob")],
        },
    )
    contract = RelationshipContract.from_dict(
        {"version": 1, "identity": {"endpoint": "/session", "field": "identity_key"}}
    )
    graph = _graph(
        attributor,
        {"artifacts:art-1": Resource("artifacts", "art-1")},
        _identity_observations(),
        contract,
    )
    assert graph.owner_of("artifacts:art-1") is None
    assert graph.owner_state("artifacts:art-1") not in {EvidenceState.CONFIRMED}
    assert any(relation.type is RelationshipType.REFERENCES for relation in graph.relationships)


def test_declared_ownership_signal_still_confirms_owner(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        ADVERSARIAL_SCHEMA,
        {
            "people": [("alice", "Alice"), ("bob", "Bob")],
            "artifacts": [("art-1", "alice", "bob", "bob")],
        },
    )
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "identity": {"endpoint": "/session", "field": "identity_key"},
            "ownership": {"artifacts": {"source": "database_foreign_key", "column": "created_by"}},
        }
    )
    graph = _graph(
        attributor,
        {"artifacts:art-1": Resource("artifacts", "art-1")},
        _identity_observations(),
        contract,
    )
    assert graph.owner_of("artifacts:art-1") == "alice"
    assert any(
        evidence.source == "declared_semantics"
        for relation in graph.relationships
        if relation.type is RelationshipType.OWNS
        for evidence in [graph.evidence[item] for item in relation.evidence]
    )


def test_contradictory_ownership_evidence_is_preserved(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        ADVERSARIAL_SCHEMA,
        {"people": [("alice", "Alice"), ("bob", "Bob")], "artifacts": [("art-1", "alice", "bob", "bob")]},
    )
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "identity": {"endpoint": "/session", "field": "identity_key"},
            "ownership": {"artifacts": {"source": "database_foreign_key", "column": "created_by"}},
        }
    )
    graph = _graph(
        attributor,
        {"artifacts:art-1": Resource("artifacts", "art-1", owner="bob")},
        _identity_observations(),
        contract,
    )
    assert graph.owner_of("artifacts:art-1") is None
    assert graph.owner_state("artifacts:art-1") is EvidenceState.CONTRADICTED


def test_response_field_without_semantic_declaration_is_candidate(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        "CREATE TABLE things (thing_key TEXT PRIMARY KEY, suspicious_user TEXT);",
        {"things": [("t1", "alice")]},
    )
    graph = _graph(
        attributor,
        {"things:t1": Resource("things", "t1")},
        _identity_observations(),
        RelationshipContract.from_dict({"version": 1}),
    )
    assert graph.owner_of("things:t1") is None


# --- Issue B: an association table is not permission ------------------------

ASSOC_SCHEMA = """
CREATE TABLE people (person_key TEXT PRIMARY KEY);
CREATE TABLE artifacts (artifact_key TEXT PRIMARY KEY);
CREATE TABLE watchers (
    artifact_ref TEXT REFERENCES artifacts(artifact_key),
    person_ref TEXT REFERENCES people(person_key),
    PRIMARY KEY (artifact_ref, person_ref)
);
"""


def test_undeclared_association_is_candidate_sharing_not_permission(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        ASSOC_SCHEMA,
        {"people": [("alice",), ("bob",)], "artifacts": [("art-1",)], "watchers": [("art-1", "bob")]},
    )
    contract = RelationshipContract.from_dict(
        {"version": 1, "identity": {"endpoint": "/session", "field": "identity_key"}}
    )
    graph = _graph(
        attributor,
        {"artifacts:art-1": Resource("artifacts", "art-1")},
        _identity_observations(),
        contract,
    )
    assert graph.explained_by_sharing("alice", "bob", "artifacts:art-1", "read") is False
    assert any(
        relation.type is RelationshipType.SHARED_WITH and relation.state is EvidenceState.CANDIDATE
        for relation in graph.relationships
    )


def test_declared_grant_is_confirmed_sharing(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        ASSOC_SCHEMA,
        {"people": [("alice",), ("bob",)], "artifacts": [("art-1",)], "watchers": [("art-1", "bob")]},
    )
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "identity": {"endpoint": "/session", "field": "identity_key"},
            "sharing": {
                "watchers": {
                    "resource_fk": "artifact_ref",
                    "principal_fk": "person_ref",
                    "semantics": "authorization_grant",
                    "actions": ["read"],
                }
            },
        }
    )
    graph = _graph(
        attributor,
        {"artifacts:art-1": Resource("artifacts", "art-1")},
        _identity_observations(),
        contract,
    )
    assert graph.explained_by_sharing("alice", "bob", "artifacts:art-1", "read") is True


# --- Issue C: API resource vs database row, composite keys, WITHOUT ROWID ---


def test_composite_key_requires_every_component(tmp_path: Path) -> None:
    from mizan.ownership import _find_rows

    attributor = _database(
        tmp_path / "db.sqlite",
        "CREATE TABLE parts (a TEXT, b TEXT, payload TEXT, PRIMARY KEY (a, b));",
        {"parts": [("a1", "b1", "one"), ("a2", "b2", "two")]},
    )
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    # A single component must not identify a row.
    assert _find_rows("a1", schema, rows) == []
    # The complete canonical identity does.
    assert len(_find_rows(canonical_key(["a1", "b1"]), schema, rows)) == 1


def test_canonical_keys_do_not_collide() -> None:
    assert canonical_key(["a:b", "c"]) != canonical_key(["a", "b:c"])
    assert canonical_key(["a", "b"]) != canonical_key(["ab"])


def test_without_rowid_table_is_snapshotted_and_differentiated(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE kv (
            k TEXT PRIMARY KEY,
            v TEXT,
            owner_ref TEXT
        ) WITHOUT ROWID;
        """,
        {"kv": [("k1", "v1", "alice"), ("k2", "v2", "bob")]},
    )
    before = attributor.snapshot()
    assert set(before["kv"].rows) == {"k1", "k2"}
    connection = sqlite3.connect(tmp_path / "db.sqlite")
    with connection:
        connection.execute("UPDATE kv SET v = ? WHERE k = ?", ("changed", "k2"))
    connection.close()
    events = attributor.diff(before, principal="bob", method="PATCH", path="/kv/k2")
    assert len(events) == 1
    assert events[0].row_key == parse_identity("k2")[0]


def test_two_tables_with_same_identifier_are_ambiguous(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE files (file_key TEXT PRIMARY KEY);
        CREATE TABLE notes (file_key TEXT PRIMARY KEY);
        """,
        {"files": [("file-17",)], "notes": [("file-17",)]},
    )
    graph = _graph(
        attributor,
        {"files:file-17": Resource("files", "file-17")},
        _identity_observations(),
        RelationshipContract.from_dict({"version": 1}),
    )
    assert graph.owner_of("files:file-17") is None
    assert "ambiguous" in graph.inconclusive.get("files:file-17", "")


# --- Issue D: a document response is not an identity response ---------------


def test_document_endpoint_is_not_an_identity_anchor(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        """
        CREATE TABLE people (person_key TEXT PRIMARY KEY);
        CREATE TABLE docs (doc_key TEXT PRIMARY KEY, holder_ref TEXT REFERENCES people(person_key));
        """,
        {"people": [("alice",), ("bob",)], "docs": [("doc-alice", "alice"), ("doc-bob", "bob")]},
    )
    # Without a declared identity endpoint, response value matches remain candidates.
    graph = _graph(
        attributor,
        {"docs:doc-alice": Resource("docs", "doc-alice")},
        [Observation("alice", {"doc_key": "doc-alice"}), Observation("bob", {"doc_key": "doc-bob"})],
        RelationshipContract.from_dict({"version": 1}),
    )
    assert not any(
        relation.type is RelationshipType.MEMBER_OF and relation.state is EvidenceState.CONFIRMED
        for relation in graph.relationships
    )
    assert graph.inconclusive
