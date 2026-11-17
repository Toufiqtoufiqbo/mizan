"""Phase V.2.1: action-scoped authorization and verdict soundness.

Every test here is written against observable behaviour:

* the relationship contract (strict and lenient loading);
* ``OwnershipGraph.explained_by_sharing`` with an explicit action;
* ``TaintAnalyzer`` outcome classification;
* ``ScanCoverage`` per-law accounting and ``ValidationResult.verdict``;
* the real ``scan_application`` pipeline and the real ``mizan twin`` CLI.

Before the fix these tests fail for the intended reason: grants have no action
scope, a read grant suppresses L3, and a scan with unresolved required checks
can still be reported CLEAN.
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
from mizan.core import (
    AuthorizationOutcome,
    LawCoverage,
    Policy,
    Principal,
    Resource,
    ScanCoverage,
    Verdict,
)
from mizan.ownership import (
    Evidence,
    EvidenceState,
    Observation,
    OwnershipGraph,
    RelationshipContract,
    RelationshipContractError,
    RelationshipType,
    build_ownership_graph,
)
from mizan.taint import TaintAnalyzer, WriteEvent
from mizan.validation import ValidationResult, scan_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "adversarial_store"
CONTRACT = APP / "mizan-relationships.json"
SPEC = APP / "openapi.json"

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


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _database(path: Path, schema: str, rows: dict[str, list[tuple]]) -> SqliteAttributor:
    connection = sqlite3.connect(path)
    with connection:
        connection.executescript(schema)
        for table, values in rows.items():
            for row in values:
                placeholders = ",".join("?" for _ in row)
                connection.execute(f"INSERT INTO {quote_identifier(table)} VALUES ({placeholders})", row)
    connection.close()
    return SqliteAttributor(path)


def _graph(tmp_path: Path, actions: list[str] | None, rows: dict[str, list[tuple]] | None = None):
    rows = rows or {
        "people": [("alice",), ("bob",)],
        "artifacts": [("a1",)],
        "artifact_links": [("a1", "alice", "bob", None)],
    }
    attributor = _database(tmp_path / "multi.sqlite", MULTI_FK_SCHEMA, rows)
    sharing = None
    if actions is not None:
        sharing = {
            "artifact_links": {
                "resource_fk": "artifact_ref",
                "principal_fk": "collaborator_ref",
                "semantics": "authorization_grant",
                "actions": actions,
            }
        }
    # The identity endpoint is always declared: without an anchor no
    # association row would be discovered at all, candidate or otherwise.
    data = {
        "version": 1,
        "identity": {"endpoint": "/session", "field": "identity_key"},
    }
    if sharing is not None:
        data["sharing"] = sharing
    contract = RelationshipContract.from_dict(data, strict=True)
    schema = attributor.schema()
    data = {name: attributor.rows(name) for name in schema.tables}
    return build_ownership_graph(
        resources={"artifacts:a1": Resource("artifacts", "a1")},
        traffic=[
            Observation("alice", {"identity_key": "alice"}, path="/session"),
            Observation("bob", {"identity_key": "bob"}, path="/session"),
        ],
        ledger=[],
        schema=schema,
        rows=data,
        contract=contract,
    )


def _policy(owner: str | None = "alice") -> Policy:
    policy = Policy()
    policy.principals["alice"] = Principal(id="alice", roles=("user",), token="alice-token")
    policy.principals["bob"] = Principal(id="bob", roles=("user",), token="bob-token")
    policy.resources["documents:d1"] = Resource("documents", "d1", owner=owner)
    return policy


def _owned_graph(state: str = "CONFIRMED", owner: str = "alice") -> OwnershipGraph:
    graph = OwnershipGraph()
    graph.resource_rows["documents:d1"] = ("docs", ("d1",))
    evidence = graph.add_evidence(Evidence(source="declared_semantics", principal=owner, resource="documents:d1"))
    graph.add_relationship(RelationshipType.OWNS, owner, "documents:d1", EvidenceState(state), [evidence])
    return graph


def _granted_graph(actions: set[str], owner: str = "alice", other: str = "bob") -> OwnershipGraph:
    graph = _owned_graph(owner=owner)
    evidence = graph.add_evidence(
        Evidence(source="declared_grant", principal=other, resource="documents:d1", detail="test grant")
    )
    graph.add_relationship(
        RelationshipType.SHARED_WITH,
        other,
        "documents:d1",
        EvidenceState.CONFIRMED,
        [evidence],
        actions=frozenset(actions),
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


def _result(
    laws: dict[str, LawCoverage],
    *,
    findings: int = 0,
    error: str | None = None,
    setup_error: str | None = None,
    budget_exhausted: bool = False,
    meaningful: bool = True,
) -> ValidationResult:
    coverage = ScanCoverage(
        learning_operations=1 if meaningful else 0,
        resources_discovered=1 if meaningful else 0,
        probe_candidates=2 if meaningful else 0,
        probes_executed=2 if meaningful else 0,
        budget_exhausted=budget_exhausted,
        laws=laws,
    )
    return ValidationResult(
        application="test",
        variant="test",
        finding_count=findings,
        error=error,
        setup_error=setup_error,
        coverage=coverage,
    )


def _scan(variant: str, budget: int = 90):
    return scan_application(APP, variant=variant, budget=budget)


def _variant_contract(tmp_path: Path, variant: str) -> Path:
    """Write the effective contract for a variant, the way an operator would."""
    contract = RelationshipContract.load(CONTRACT, variant, strict=True)
    assert contract is not None
    data: dict = {"version": contract.version}
    if contract.identity is not None:
        data["identity"] = {"endpoint": contract.identity[0], "field": contract.identity[1]}
    data["ownership"] = {key: {"source": value[0], "column": value[1]} for key, value in contract.ownership.items()}
    data["sharing"] = {
        table: {
            "resource_fk": value[0],
            "principal_fk": value[1],
            "semantics": value[2],
            "actions": sorted(value[4]),
        }
        for table, value in contract.sharing.items()
    }
    path = tmp_path / f"contract-{variant}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _run_twin(tmp_path: Path, variant: str, *, workers: int = 1):
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = tmp_path / "store.sqlite"
    out_path = tmp_path / "proofs"
    command = (
        f'"{Path(sys.executable).as_posix()}" "{(APP / "app.py").as_posix()}"'
        f' --db "{{data}}/store.sqlite" --port {{port}} --vulnerability {variant}'
    )
    result = CliRunner().invoke(
        main,
        [
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
            str(tmp_path / "traffic.jsonl"),
            "--workdir",
            str(tmp_path),
            "--workers",
            str(workers),
            "--relationship-contract",
            str(_variant_contract(tmp_path, variant)),
        ],
        catch_exceptions=False,
    )
    laws: set[str] = set()
    if out_path.exists():
        for bundle in (path for path in out_path.iterdir() if path.is_dir()):
            for meta in bundle.glob("*.json"):
                data = json.loads(meta.read_text(encoding="utf-8"))
                if data.get("law"):
                    laws.add(str(data["law"]))
    return result, sorted(laws)


# --------------------------------------------------------------------------- #
# C2 - contract action validation
# --------------------------------------------------------------------------- #


def _contract_data(**share_overrides) -> dict:
    declaration = {
        "resource_fk": "artifact_ref",
        "principal_fk": "collaborator_ref",
        "semantics": "authorization_grant",
        **share_overrides,
    }
    return {"version": 1, "sharing": {"artifact_links": declaration}}


def test_a_strict_contract_requires_actions() -> None:
    with pytest.raises(RelationshipContractError, match="action"):
        RelationshipContract.from_dict(_contract_data(), strict=True)


def test_an_empty_action_list_is_rejected() -> None:
    with pytest.raises(RelationshipContractError, match="action"):
        RelationshipContract.from_dict(_contract_data(actions=[]), strict=True)


def test_an_unknown_action_is_rejected() -> None:
    with pytest.raises(RelationshipContractError, match="delete"):
        RelationshipContract.from_dict(_contract_data(actions=["read", "delete"]), strict=True)


def test_a_wrong_action_type_is_rejected() -> None:
    with pytest.raises(RelationshipContractError, match="action"):
        RelationshipContract.from_dict(_contract_data(actions="read"), strict=True)


def test_duplicate_actions_are_normalized() -> None:
    contract = RelationshipContract.from_dict(_contract_data(actions=["read", "read"]), strict=True)
    assert contract.sharing["artifact_links"][4] == frozenset({"read"})


def test_a_variant_override_is_validated_identically(tmp_path: Path) -> None:
    data = _contract_data(actions=["read"])
    data["variants"] = {
        "broken": {
            "sharing": {
                "artifact_links": {
                    "resource_fk": "artifact_ref",
                    "principal_fk": "collaborator_ref",
                    "semantics": "authorization_grant",
                }
            }
        }
    }
    contract = RelationshipContract.from_dict(data, strict=True)
    with pytest.raises(RelationshipContractError, match="action"):
        contract.for_variant("broken", strict=True)


def test_a_legacy_declaration_without_actions_is_not_a_grant(tmp_path: Path) -> None:
    contract = RelationshipContract.from_dict(
        {
            "version": 1,
            "identity": {"endpoint": "/session", "field": "identity_key"},
            "sharing": {
                "artifact_links": {
                    "resource_fk": "artifact_ref",
                    "principal_fk": "collaborator_ref",
                    "semantics": "authorization_grant",
                }
            },
        }
    )
    assert contract.sharing == {}
    graph = _graph(tmp_path, None)
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "write") is False


def test_no_contract_has_no_grants(tmp_path: Path) -> None:
    graph = _graph(tmp_path, None)
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False


# --------------------------------------------------------------------------- #
# A4 - action-aware graph authorization
# --------------------------------------------------------------------------- #


def test_a_read_grant_explains_read_only(tmp_path: Path) -> None:
    graph = _graph(tmp_path, ["read"])
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is True
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "write") is False


def test_a_write_grant_explains_write_only(tmp_path: Path) -> None:
    graph = _graph(tmp_path, ["write"])
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "write") is True
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False


def test_a_read_write_grant_explains_both(tmp_path: Path) -> None:
    graph = _graph(tmp_path, ["read", "write"])
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is True
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "write") is True


def test_a_grant_never_crosses_principals(tmp_path: Path) -> None:
    graph = _graph(tmp_path, ["read", "write"])
    assert graph.explained_by_sharing("alice", "carol", "artifacts:a1", "read") is False


def test_a_grant_never_crosses_resources(tmp_path: Path) -> None:
    graph = _graph(tmp_path, ["read", "write"])
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a2", "read") is False


def test_a_candidate_relationship_never_explains(tmp_path: Path) -> None:
    graph = _graph(tmp_path, None)  # structural rows only: CANDIDATE
    assert any(
        relation.type is RelationshipType.SHARED_WITH and relation.state is EvidenceState.CANDIDATE
        for relation in graph.relationships
    )
    assert graph.explained_by_sharing("alice", "bob", "artifacts:a1", "read") is False


def test_a_confirmed_relationship_without_actions_never_explains() -> None:
    graph = _owned_graph()
    evidence = graph.add_evidence(Evidence(source="association_table", principal="bob", resource="documents:d1"))
    graph.add_relationship(RelationshipType.SHARED_WITH, "bob", "documents:d1", EvidenceState.CONFIRMED, [evidence])
    assert graph.explained_by_sharing("alice", "bob", "documents:d1", "read") is False


def test_a_contradicted_relationship_never_explains() -> None:
    graph = _owned_graph()
    evidence = graph.add_evidence(Evidence(source="declared_grant", principal="bob", resource="documents:d1"))
    graph.add_relationship(
        RelationshipType.SHARED_WITH,
        "bob",
        "documents:d1",
        EvidenceState.CONTRADICTED,
        [evidence],
        actions=frozenset({"read", "write"}),
    )
    assert graph.explained_by_sharing("alice", "bob", "documents:d1", "read") is False


# --------------------------------------------------------------------------- #
# A5 - analyzer outcomes
# --------------------------------------------------------------------------- #


def test_a_read_grant_never_suppresses_a_write() -> None:
    analyzer = TaintAnalyzer(_policy(None), graph=_granted_graph({"read"}))
    findings = analyzer.analyze([_write_event()])
    assert [finding.law for finding in findings] == ["L3"]
    outcomes = {(item["action"], item["outcome"]) for item in analyzer.outcomes}
    assert ("write", AuthorizationOutcome.VIOLATION.value) in outcomes
    assert ("write", AuthorizationOutcome.ALLOWED_BY_GRANT.value) not in outcomes


def test_a_write_grant_explains_the_write_and_is_resolved() -> None:
    analyzer = TaintAnalyzer(_policy(None), graph=_granted_graph({"write"}))
    assert analyzer.analyze([_write_event()]) == []
    assert [item["outcome"] for item in analyzer.outcomes] == [AuthorizationOutcome.ALLOWED_BY_GRANT.value]
    assert analyzer.inconclusive == []


def test_an_unauthorized_write_is_classified_as_a_violation() -> None:
    analyzer = TaintAnalyzer(_policy(None), graph=_owned_graph())
    assert [finding.law for finding in analyzer.analyze([_write_event()])] == ["L3"]
    assert [item["outcome"] for item in analyzer.outcomes] == [AuthorizationOutcome.VIOLATION.value]


def test_an_unmapped_write_is_a_required_inconclusive_check() -> None:
    analyzer = TaintAnalyzer(_policy(None), graph=_owned_graph())
    assert analyzer.analyze([_write_event(table="files", row_key="d1")]) == []
    assert [item["outcome"] for item in analyzer.outcomes] == [AuthorizationOutcome.INCONCLUSIVE.value]
    assert analyzer.inconclusive


def test_a_candidate_owner_is_a_required_inconclusive_check() -> None:
    analyzer = TaintAnalyzer(_policy("alice"), graph=_owned_graph("CANDIDATE"))
    assert analyzer.analyze([_write_event()]) == []
    assert [item["outcome"] for item in analyzer.outcomes] == [AuthorizationOutcome.INCONCLUSIVE.value]


def test_a_self_write_is_a_decided_check_not_a_grant() -> None:
    analyzer = TaintAnalyzer(_policy(None), graph=_owned_graph())
    assert analyzer.analyze([_write_event(principal="alice")]) == []
    assert [item["outcome"] for item in analyzer.outcomes] == [AuthorizationOutcome.DECIDED.value]


def test_duplicate_events_do_not_duplicate_the_outcome() -> None:
    analyzer = TaintAnalyzer(_policy(None), graph=_owned_graph())
    analyzer.analyze([_write_event(), _write_event()])
    assert len(analyzer.outcomes) == 1
    assert len(analyzer.inconclusive) == 0


# --------------------------------------------------------------------------- #
# B - per-law coverage and verdict invariants
# --------------------------------------------------------------------------- #


def test_all_relevant_checks_resolved_is_clean() -> None:
    result = _result(
        {"L2": LawCoverage(eligible=1, attempted=1, decided=1), "L3": LawCoverage(eligible=1, attempted=1, decided=1)}
    )
    assert result.verdict is Verdict.CLEAN


def test_a_proven_finding_keeps_findings_precedence() -> None:
    result = _result(
        {
            "L2": LawCoverage(eligible=1, attempted=1, inconclusive=1),
            "L3": LawCoverage(eligible=1, attempted=1, findings=1),
        },
        findings=1,
    )
    assert result.verdict is Verdict.FINDINGS


def test_an_unresolved_l3_check_is_not_clean() -> None:
    result = _result(
        {
            "L2": LawCoverage(eligible=1, attempted=1, decided=1),
            "L3": LawCoverage(eligible=1, attempted=1, inconclusive=1),
        }
    )
    assert result.verdict is Verdict.INCONCLUSIVE


def test_an_ambiguous_row_mapping_is_not_clean() -> None:
    result = _result({"L3": LawCoverage(eligible=1, attempted=1, inconclusive=1)})
    assert result.verdict is Verdict.INCONCLUSIVE


def test_candidate_ownership_is_not_clean() -> None:
    result = _result({"L3": LawCoverage(eligible=1, attempted=1, inconclusive=1)})
    assert result.verdict is Verdict.INCONCLUSIVE


def test_an_unresolved_identity_check_is_not_clean() -> None:
    result = _result({"L2": LawCoverage(eligible=1, attempted=1, inconclusive=1)})
    assert result.verdict is Verdict.INCONCLUSIVE


def test_grant_resolved_checks_are_clean() -> None:
    result = _result(
        {
            "L2": LawCoverage(eligible=1, attempted=1, allowed_by_grant=1),
            "L3": LawCoverage(eligible=1, attempted=1, allowed_by_grant=1),
        }
    )
    assert result.verdict is Verdict.CLEAN


def test_a_grant_plus_an_unresolved_write_is_not_clean() -> None:
    result = _result(
        {
            "L2": LawCoverage(eligible=1, attempted=1, allowed_by_grant=1),
            "L3": LawCoverage(eligible=1, attempted=1, inconclusive=1),
        }
    )
    assert result.verdict is Verdict.INCONCLUSIVE


def test_budget_exhaustion_is_not_clean() -> None:
    result = _result({"L3": LawCoverage(eligible=2, attempted=1, decided=1)}, budget_exhausted=True)
    assert result.verdict is Verdict.INCONCLUSIVE


def test_a_setup_error_is_error() -> None:
    result = _result({"L3": LawCoverage(eligible=1, attempted=1, decided=1)}, setup_error="bad contract")
    assert result.verdict is Verdict.ERROR


def test_an_execution_error_is_error() -> None:
    result = _result({"L3": LawCoverage(eligible=1, attempted=1, decided=1)}, error="RuntimeError: boom")
    assert result.verdict is Verdict.ERROR


def test_no_meaningful_security_coverage_is_inconclusive() -> None:
    result = _result({"L3": LawCoverage()}, meaningful=False)
    assert result.verdict is Verdict.INCONCLUSIVE


def test_mixed_resolved_and_unmapped_resources_are_not_clean() -> None:
    # Resource A: ownership and its checks resolved. Resource B: an observed
    # write whose database row cannot be mapped. Nothing is proven, and the
    # scan still may not claim to be clean.
    result = _result(
        {
            "L2": LawCoverage(eligible=1, attempted=1, decided=1),
            "L3": LawCoverage(eligible=2, attempted=2, decided=1, inconclusive=1),
        }
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.clean is False


def test_l2_and_l3_coverage_are_not_merged() -> None:
    result = _result(
        {
            "L2": LawCoverage(eligible=2, attempted=2, allowed_by_grant=2),
            "L3": LawCoverage(eligible=1, attempted=1, inconclusive=1),
        }
    )
    assert result.coverage.laws["L2"].allowed_by_grant == 2
    assert result.coverage.laws["L3"].inconclusive == 1
    assert result.verdict is Verdict.INCONCLUSIVE


def test_authorized_checks_are_counted_as_resolved_not_unresolved() -> None:
    result = _result({"L2": LawCoverage(eligible=1, attempted=1, allowed_by_grant=1)})
    assert result.coverage.resolved_checks == 1
    assert result.coverage.unresolved_checks == 0


# --------------------------------------------------------------------------- #
# C1/C4 - the real pipeline
# --------------------------------------------------------------------------- #


def test_pipeline_read_grant_allows_read_but_not_write() -> None:
    result = _scan("grant_write")
    assert result.law_types == ["L3"], (result.law_types, result.ownership.get("inconclusive_checks"))
    assert all(finding["law"] == "L3" for finding in result.findings)
    assert result.coverage.laws["L2"].findings == 0
    assert result.coverage.laws["L2"].allowed_by_grant >= 1
    assert result.coverage.laws["L3"].findings >= 1
    assert result.coverage.laws["L2"].inconclusive == 0


def test_pipeline_read_write_grant_is_clean() -> None:
    result = _scan("read_write_grant")
    assert result.finding_count == 0
    assert result.verdict is Verdict.CLEAN, (result.law_types, result.coverage.to_dict())
    assert result.coverage.laws["L2"].allowed_by_grant >= 1
    assert result.coverage.laws["L3"].allowed_by_grant >= 1
    assert result.coverage.unresolved_checks == 0


def test_pipeline_write_only_grant_still_reports_the_read() -> None:
    result = _scan("write_only_grant")
    assert result.law_types == ["L2"]
    assert result.coverage.laws["L2"].findings >= 1
    assert result.coverage.laws["L2"].allowed_by_grant == 0


@pytest.mark.parametrize("variant", ["creator_only", "observer_only"])
def test_pipeline_non_grant_columns_never_suppress(variant: str) -> None:
    result = _scan(variant)
    assert result.law_types == ["L2"]
    assert result.coverage.laws["L2"].allowed_by_grant == 0
    assert result.coverage.laws["L2"].findings >= 1


def test_pipeline_wrong_principal_fk_never_suppresses_the_finding() -> None:
    result = _scan("declared_creator")
    assert result.law_types == ["L2"]
    assert result.coverage.laws["L2"].findings >= 1


def test_pipeline_findings_are_not_duplicated() -> None:
    result = _scan("grant_write")
    l3 = [finding for finding in result.findings if finding["law"] == "L3"]
    assert l3
    assert len(l3) == len({(finding["principal"], finding["resource"]) for finding in l3})


def test_pipeline_direct_probe_and_analyzer_agree_on_a_write_grant() -> None:
    allowed = _scan("read_write_grant")
    assert allowed.finding_count == 0
    assert allowed.coverage.laws["L3"].allowed_by_grant >= 1

    denied = _scan("grant_write")
    assert denied.law_types == ["L3"]
    assert len([finding for finding in denied.findings if finding["law"] == "L3"]) == 1


def test_parallel_workers_keep_the_action_scope(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    result, laws = _run_twin(tmp_path, "grant_write", workers=2)
    assert result.exit_code == 0, result.output
    assert laws == ["L3"], result.output


def test_serial_and_parallel_agree_on_the_read_write_grant(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-token-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-token-bob")
    serial, serial_laws = _run_twin(tmp_path / "serial", "read_write_grant", workers=1)
    assert serial.exit_code == 0, serial.output
    assert serial_laws == []
