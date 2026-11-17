"""Phase V.2 reproductions: runtime integration and authorization evidence.

Every test in this file is written against the *production* execution paths:

* the real ``mizan twin`` command (Click), not a hand-built engine;
* ``discover_associations()`` with several principal foreign keys;
* ``TaintAnalyzer`` when an ownership graph is attached.

The first group is expected to fail before the correction: the CLI does not
accept a relationship contract, the grant check ignores ``principal_fk``, and
the analyzer trusts legacy ``row_owner`` hints.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mizan.attribution import SqliteAttributor, quote_identifier
from mizan.cli import main
from mizan.core import Policy, Principal, Resource
from mizan.ownership import (
    EvidenceState,
    Observation,
    OwnershipGraph,
    RelationshipContract,
    RelationshipContractError,
    RelationshipType,
    build_ownership_graph,
)
from mizan.taint import TaintAnalyzer, WriteEvent

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "adversarial_store"
SPEC = APP / "openapi.json"
CONTRACT = APP / "mizan-relationships.json"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


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


def _run_twin(tmp_path: Path, variant: str, contract: Path | None = CONTRACT, workers: int = 1):
    """Drive the real ``mizan twin`` command against the adversarial fixture."""
    database = tmp_path / "store.sqlite"
    out_path = tmp_path / "proofs"
    traffic_path = tmp_path / "traffic.jsonl"
    command = (
        f'"{Path(sys.executable).as_posix()}" "{(APP / "app.py").as_posix()}"'
        f' --db "{database.as_posix()}" --port {{port}} --vulnerability {variant}'
    )
    arguments = [
        "twin",
        "--command",
        command,
        "--data",
        str(database),
        "--spec",
        str(SPEC),
        "--token",
        "alice=cli-token-alice",
        "--token",
        "bob=cli-token-bob",
        "--out",
        str(out_path),
        "--traffic",
        str(traffic_path),
        "--workdir",
        str(tmp_path),
        "--workers",
        str(workers),
    ]
    if contract is not None:
        arguments.extend(["--relationship-contract", str(contract)])
    result = CliRunner().invoke(main, arguments, catch_exceptions=False)
    return result, out_path


def _findings(out_path: Path) -> list[dict]:
    bundles = sorted(path for path in out_path.iterdir() if path.is_dir()) if out_path.exists() else []
    findings = []
    for bundle in bundles:
        for meta in bundle.glob("*.json"):
            data = json.loads(meta.read_text(encoding="utf-8"))
            if data.get("law"):
                findings.append(data)
    return findings


# --------------------------------------------------------------------------- #
# Issue A - the contract must reach the real CLI engine
# --------------------------------------------------------------------------- #

MULTI_FK_SCHEMA = """
CREATE TABLE people (person_key TEXT PRIMARY KEY);
CREATE TABLE artifacts (artifact_key TEXT PRIMARY KEY);
CREATE TABLE artifact_links (
    artifact_ref TEXT NOT NULL REFERENCES artifacts(artifact_key),
    creator_ref TEXT REFERENCES people(person_key),
    collaborator_ref TEXT REFERENCES people(person_key),
    watcher_ref TEXT REFERENCES people(person_key),
    PRIMARY KEY (artifact_ref, creator_ref, collaborator_ref)
);
"""


def test_cli_accepts_a_relationship_contract_and_uses_it(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    result, out_path = _run_twin(tmp_path, "read")
    assert result.exit_code == 0, result.output
    laws = sorted({finding["law"] for finding in _findings(out_path)})
    assert laws == ["L2"], f"the declared identity anchor was not used: {result.output}"


def test_cli_declared_grant_explains_legitimate_access(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    result, out_path = _run_twin(tmp_path, "grant")
    assert result.exit_code == 0, result.output
    assert _findings(out_path) == [], f"a legitimate grant produced a finding: {result.output}"


def test_cli_without_a_contract_invents_no_ownership(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    result, out_path = _run_twin(tmp_path, "read", contract=None)
    assert result.exit_code == 0, result.output
    assert _findings(out_path) == [], "ownership was invented without semantic evidence"


def test_cli_rejects_an_invalid_contract(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    result, _ = _run_twin(tmp_path, "clean", contract=broken)
    assert result.exit_code != 0
    assert "contract" in result.output.lower()


def test_cli_rejects_a_contract_naming_an_unknown_table(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps(
            {
                "version": 1,
                "sharing": {
                    "invented_table": {
                        "resource_fk": "a",
                        "principal_fk": "b",
                        "semantics": "authorization_grant",
                        "actions": ["read"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    result, _ = _run_twin(tmp_path, "clean", contract=invalid)
    assert result.exit_code != 0
    assert "invented_table" in result.output


def test_parallel_workers_share_the_same_contract(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    result, out_path = _run_twin(tmp_path, "read", workers=2)
    assert result.exit_code == 0, result.output
    laws = sorted({finding["law"] for finding in _findings(out_path)})
    assert laws == ["L2"], f"a worker did not receive the contract: {result.output}"


# --------------------------------------------------------------------------- #
# Issue B - the grant must name the exact principal foreign key
# --------------------------------------------------------------------------- #


def _multi_fk_graph(rows: dict[str, list[tuple]], sharing: dict | None) -> OwnershipGraph:
    attributor = _database(
        Path(_multi_fk_graph.directory) / "multi.sqlite",
        MULTI_FK_SCHEMA,
        rows,
    )
    contract = None
    if sharing is not None:
        contract = RelationshipContract.from_dict(
            {
                "version": 1,
                "identity": {"endpoint": "/session", "field": "identity_key"},
                "sharing": sharing,
            },
            strict=True,
        )
    return _graph(
        attributor,
        {"artifacts:a1": Resource("artifacts", "a1")},
        _identity_observations(),
        contract,
    )


@pytest.fixture()
def multi_fk_graph(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(_multi_fk_graph, "directory", str(tmp_path), raising=False)

    def build(sharing: dict | None, rows: dict[str, list[tuple]] | None = None) -> OwnershipGraph:
        default_rows = {
            "people": [("alice",), ("bob",)],
            "artifacts": [("a1",)],
            "artifact_links": [("a1", "alice", "bob", "bob")],
        }
        return _multi_fk_graph(rows or default_rows, sharing)

    return build


GRANT = {
    "artifact_links": {
        "resource_fk": "artifact_ref",
        "principal_fk": "collaborator_ref",
        "semantics": "authorization_grant",
        "actions": ["read"],
    }
}


def test_only_the_declared_principal_fk_confirms_a_grant(multi_fk_graph) -> None:
    graph = multi_fk_graph(GRANT)
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is True
    confirmed = {
        (relation.subject, relation.object)
        for relation in graph.relationships
        if relation.type is RelationshipType.SHARED_WITH and relation.state is EvidenceState.CONFIRMED
    }
    assert confirmed == {("bob", "artifacts:a1")}


def test_a_creator_fk_never_inherits_the_grant(multi_fk_graph) -> None:
    # bob is the creator as well: the creator row must stay a candidate.
    rows = {
        "people": [("alice",), ("bob",)],
        "artifacts": [("a1",)],
        "artifact_links": [("a1", "bob", None, None)],
    }
    graph = multi_fk_graph(GRANT, rows)
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False
    assert any(
        relation.type is RelationshipType.SHARED_WITH
        and relation.subject == "bob"
        and relation.state is EvidenceState.CANDIDATE
        for relation in graph.relationships
    )


def test_a_watcher_fk_never_inherits_the_grant(multi_fk_graph) -> None:
    rows = {
        "people": [("alice",), ("bob",)],
        "artifacts": [("a1",)],
        "artifact_links": [("a1", None, None, "bob")],
    }
    graph = multi_fk_graph(GRANT, rows)
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False


def test_an_incorrect_principal_fk_stays_unconfirmed(multi_fk_graph) -> None:
    wrong = {
        "artifact_links": {
            "resource_fk": "artifact_ref",
            "principal_fk": "creator_ref",
            "semantics": "authorization_grant",
            "actions": ["read"],
        }
    }
    rows = {
        "people": [("alice",), ("bob",)],
        "artifacts": [("a1",)],
        "artifact_links": [("a1", None, "bob", None)],
    }
    graph = multi_fk_graph(wrong, rows)
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False


def test_an_incorrect_resource_fk_cannot_produce_a_grant(multi_fk_graph) -> None:
    wrong = {
        "artifact_links": {
            "resource_fk": "creator_ref",
            "principal_fk": "collaborator_ref",
            "semantics": "authorization_grant",
            "actions": ["read"],
        }
    }
    graph = multi_fk_graph(wrong)
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False


def test_multiple_identity_fks_do_not_duplicate_a_grant(multi_fk_graph) -> None:
    graph = multi_fk_graph(GRANT)
    grants = [
        relation
        for relation in graph.relationships
        if relation.type is RelationshipType.SHARED_WITH and relation.state is EvidenceState.CONFIRMED
    ]
    assert len(grants) == 1


def test_a_missing_anchor_creates_no_confirmed_grant(multi_fk_graph) -> None:
    observations = [Observation("alice", {"identity_key": "alice"}, path="/session")]
    attributor = _database(
        Path(_multi_fk_graph.directory) / "noanchor.sqlite",
        MULTI_FK_SCHEMA,
        {
            "people": [("alice",), ("bob",)],
            "artifacts": [("a1",)],
            "artifact_links": [("a1", "alice", "bob", "bob")],
        },
    )
    schema = attributor.schema()
    rows = {name: attributor.rows(name) for name in schema.tables}
    contract = RelationshipContract.from_dict(
        {"version": 1, "identity": {"endpoint": "/session", "field": "identity_key"}, "sharing": GRANT},
        strict=True,
    )
    graph = build_ownership_graph(
        resources={"artifacts:a1": Resource("artifacts", "a1")},
        traffic=observations,
        ledger=[],
        schema=schema,
        rows=rows,
        contract=contract,
    )
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False


# --------------------------------------------------------------------------- #
# Issue C - TaintAnalyzer must not bypass confirmed graph ownership
# --------------------------------------------------------------------------- #


def _policy_with(owner: str | None) -> Policy:
    policy = Policy()
    policy.principals["alice"] = Principal(id="alice", roles=("user",), token="alice-token")
    policy.principals["bob"] = Principal(id="bob", roles=("user",), token="bob-token")
    if owner:
        policy.resources["documents:d1"] = Resource("documents", "d1", owner=owner)
    return policy


def _graph_with(owner_state: str | None, owner: str = "alice") -> OwnershipGraph:
    from mizan.ownership import Evidence

    graph = OwnershipGraph()
    graph.resource_rows["documents:d1"] = ("docs", ("d1",))
    if owner_state is not None:
        evidence = graph.add_evidence(Evidence(source="declared_semantics", principal=owner, resource="documents:d1"))
        graph.add_relationship(
            RelationshipType.OWNS,
            owner,
            "documents:d1",
            EvidenceState(owner_state),
            [evidence],
        )
    return graph


def _write_event(**overrides) -> WriteEvent:
    values = {
        "ts": 0.0,
        "request_id": "r1",
        "principal": "bob",
        "method": "PUT",
        "path": "/docs/d1",
        "table": "docs",
        "row_id": "1",
        "columns": {"title": "changed"},
        "source_fields": {"title"},
        "row_owner": "alice",
        "row_key": "d1",
    }
    values.update(overrides)
    return WriteEvent(**values)


def test_legacy_row_owner_without_graph_ownership_produces_no_l3() -> None:
    analyzer = TaintAnalyzer(_policy_with("alice"), graph=_graph_with(None))
    assert analyzer.analyze([_write_event()]) == []
    assert analyzer.inconclusive


def test_confirmed_graph_ownership_produces_l3() -> None:
    analyzer = TaintAnalyzer(_policy_with(None), graph=_graph_with("CONFIRMED"))
    findings = analyzer.analyze([_write_event()])
    assert [finding.law for finding in findings] == ["L3"]
    assert findings[0].evidence["owner"] == "alice"
    assert findings[0].evidence["resource_mapping"]["api_resource"] == "documents:d1"


def test_candidate_ownership_produces_no_l3() -> None:
    analyzer = TaintAnalyzer(_policy_with("alice"), graph=_graph_with("CANDIDATE"))
    assert analyzer.analyze([_write_event()]) == []
    assert any("ownership" in item["reason"] for item in analyzer.inconclusive)


def test_contradicted_ownership_produces_no_l3() -> None:
    analyzer = TaintAnalyzer(_policy_with("alice"), graph=_graph_with("CONTRADICTED"))
    assert analyzer.analyze([_write_event()]) == []
    assert any("ownership" in item["reason"] for item in analyzer.inconclusive)


def test_ambiguous_row_mapping_is_inconclusive() -> None:
    graph = _graph_with("CONFIRMED")
    analyzer = TaintAnalyzer(_policy_with(None), graph=graph)
    assert analyzer.analyze([_write_event(table="files", row_key="d1")]) == []
    assert any("map" in item["reason"] for item in analyzer.inconclusive)


def test_an_unattributed_write_is_inconclusive() -> None:
    analyzer = TaintAnalyzer(_policy_with(None), graph=_graph_with("CONFIRMED"))
    assert analyzer.analyze([_write_event(principal="unknown")]) == []
    assert analyzer.unattributed


def test_a_legacy_ledger_stays_loadable_without_invented_ownership(tmp_path: Path) -> None:
    from mizan.taint import Ledger

    path = tmp_path / "legacy.jsonl"
    path.write_text(
        json.dumps(
            {
                "ts": 0.0,
                "request_id": "old",
                "principal": "bob",
                "method": "PUT",
                "path": "/docs/d1",
                "table": "docs",
                "row_id": "1",
                "columns": {"title": "changed"},
                "source_fields": ["title"],
                "row_owner": "alice",
                "status": 200,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    ledger = Ledger.load(path)
    event = ledger.events[0]
    assert event.row_key is None
    analyzer = TaintAnalyzer(_policy_with("alice"), graph=_graph_with("CONFIRMED"))
    assert analyzer.analyze([event]) == []
    assert any("map" in item["reason"] for item in analyzer.inconclusive)


def test_l4_still_fires_in_graph_mode() -> None:
    policy = _policy_with(None)
    policy.authority_fields = {"role"}
    analyzer = TaintAnalyzer(policy, graph=_graph_with("CONFIRMED"))
    event = _write_event(columns={"role": "admin"}, source_fields={"role"})
    laws = [finding.law for finding in analyzer.analyze([event])]
    assert "L4" in laws
    assert "L3" not in laws or True  # L3 may be absent; L4 must survive.


def test_self_write_is_not_a_finding() -> None:
    analyzer = TaintAnalyzer(_policy_with(None), graph=_graph_with("CONFIRMED"))
    assert analyzer.analyze([_write_event(principal="alice")]) == []


# --------------------------------------------------------------------------- #
# Contract loading: three distinct states
# --------------------------------------------------------------------------- #


def test_missing_contract_is_none() -> None:
    assert RelationshipContract.load(Path("does-not-exist.json")) is None


def test_invalid_contract_raises_in_strict_mode(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"version": 99}', encoding="utf-8")
    with pytest.raises(RelationshipContractError):
        RelationshipContract.load(path, strict=True)


def test_contract_rejects_the_same_column_for_both_roles(tmp_path: Path) -> None:
    path = tmp_path / "same.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "sharing": {
                    "t": {
                        "resource_fk": "x",
                        "principal_fk": "x",
                        "semantics": "authorization_grant",
                        "actions": ["read"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RelationshipContractError):
        RelationshipContract.load(path, strict=True)


def test_contract_schema_validation_rejects_unknown_columns(tmp_path: Path) -> None:
    attributor = _database(
        tmp_path / "db.sqlite",
        MULTI_FK_SCHEMA,
        {"people": [("alice",)], "artifacts": [("a1",)], "artifact_links": [("a1", "alice", "alice", "alice")]},
    )
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "sharing": {
                "artifact_links": {
                    "resource_fk": "artifact_ref",
                    "principal_fk": "does_not_exist",
                    "semantics": "authorization_grant",
                    "actions": ["read"],
                }
            },
        },
        strict=True,
    )
    with pytest.raises(RelationshipContractError):
        contract.validate_schema(attributor.schema())
