"""Phase V.2.3: ownership trust boundary and one final outcome per check.

Written failing-first against the pre-fix implementation. The audited defect
is that a CANDIDATE response-level owner survives learning in
``policy.resources``/``TrafficRecord.resource_owner`` and is then used as an
authoritative owner by ``_probe_read_authorization``. The second defect is an
outcome deduplication key that includes the outcome value, which allows one
logical check to hold contradictory outcomes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mizan.attribution import SqliteAttributor
from mizan.cli import main
from mizan.core import AuthorizationOutcome, LawCoverage, Principal, ScanCoverage, Verdict
from mizan.engine import Mizan, Target
from mizan.ownership import (
    Evidence,
    EvidenceState,
    OwnershipGraph,
    RelationshipContract,
    RelationshipType,
)
from mizan.taint import TaintAnalyzer, WriteEvent
from mizan.traffic import TrafficRecord
from mizan.validation import scan_application

ROOT = Path(__file__).resolve().parent.parent
MIXED = ROOT / "tests" / "fixtures" / "external_apps" / "mixed_ownership"
ADVERSARIAL = ROOT / "tests" / "fixtures" / "external_apps" / "adversarial_store"
SPEC = ADVERSARIAL / "openapi.json"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _learned_engine(workspace: Path) -> Mizan:
    contract = RelationshipContract.load(MIXED / "mizan-relationships.json", strict=True)
    engine = Mizan(
        Target(
            base_url="http://127.0.0.1:1",
            principals=[
                Principal("alice", ("user",), "alice-token"),
                Principal("bob", ("user",), "bob-token"),
            ],
        ),
        traffic_path=workspace / "traffic.jsonl",
        attributor=SqliteAttributor(workspace / "application.sqlite"),
        relationship_contract=contract,
    )
    # The saved traffic already contains the identity observations; do not
    # re-request them from a live application in this unit-level reconstruction.
    engine._identity_observations = lambda: []  # type: ignore[method-assign]
    return engine


def _empty_engine() -> Mizan:
    return Mizan(
        Target(
            base_url="http://127.0.0.1:1",
            principals=[
                Principal("alice", ("user",), "alice-token"),
                Principal("bob", ("user",), "bob-token"),
            ],
        )
    )


def _write_event(**overrides) -> WriteEvent:
    values = {
        "ts": 0.0,
        "request_id": "r1",
        "principal": "bob",
        "method": "PUT",
        "path": "/docs/d1",
        "table": "docs",
        "row_id": "1",
        "row_key": "d1",
        "columns": {"title": "changed"},
        "source_fields": {"title"},
    }
    values.update(overrides)
    return WriteEvent(**values)


def _graph_with_owner(state: EvidenceState, key: str = "documents:d1", owner: str = "alice") -> OwnershipGraph:
    graph = OwnershipGraph()
    graph.resource_rows[key] = ("docs", ("d1",))
    evidence = graph.add_evidence(Evidence(source="test", principal=owner, resource=key))
    graph.add_relationship(RelationshipType.OWNS, owner, key, state, [evidence])
    return graph


def _coverage_invariants(coverage: ScanCoverage) -> None:
    for law, counter in coverage.laws.items():
        assert counter.attempted <= counter.eligible, law
        assert counter.resolved == counter.decided + counter.allowed_by_grant + counter.findings, law
        assert counter.attempted == counter.resolved + counter.inconclusive, f"{law}: {counter}"
        assert counter.pending == max(0, counter.eligible - counter.attempted), law


def _variant_contract(tmp_path: Path, variant: str) -> Path:
    contract = RelationshipContract.load(ADVERSARIAL / "mizan-relationships.json", variant, strict=True)
    assert contract is not None
    data = {
        "version": contract.version,
        "identity": {"endpoint": contract.identity[0], "field": contract.identity[1]} if contract.identity else None,
        "ownership": {key: {"source": value[0], "column": value[1]} for key, value in contract.ownership.items()},
        "sharing": {
            table: {
                "resource_fk": value[0],
                "principal_fk": value[1],
                "semantics": value[2],
                "actions": sorted(value[4]),
            }
            for table, value in contract.sharing.items()
        },
    }
    path = tmp_path / f"contract-{variant}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _run_twin(tmp_path: Path, variant: str, workers: int):
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = tmp_path / "store.sqlite"
    proofs = tmp_path / "proofs"
    command = (
        f'"{Path(sys.executable).as_posix()}" "{(ADVERSARIAL / "app.py").as_posix()}"'
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
            "alice=cli-alice",
            "--token",
            "bob=cli-bob",
            "--out",
            str(proofs),
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
    if proofs.exists():
        for bundle in (path for path in proofs.iterdir() if path.is_dir()):
            for meta in bundle.glob("*.json"):
                data = json.loads(meta.read_text(encoding="utf-8"))
                if data.get("law"):
                    laws.add(str(data["law"]))
    return result, sorted(laws)


# --------------------------------------------------------------------------- #
# A/B/C - ownership trust boundary
# --------------------------------------------------------------------------- #


def test_candidate_owner_hint_is_neutralized_after_graph_construction(monkeypatch) -> None:
    from mizan.attribution import Column, DatabaseSchema, TableSchema
    from mizan.core import Resource

    engine = _empty_engine()
    record = TrafficRecord(
        method="GET",
        path="/docs/d1",
        status=200,
        principal="bob",
        resource_type="docs",
        resource_id="d1",
        resource_owner="alice",  # the unverified response-level hint
        response={"id": "d1", "owner_id": "alice"},
    )
    engine.traffic.records = [record]
    engine.policy.resources["docs:d1"] = Resource("docs", "d1", owner="alice")
    schema = DatabaseSchema(tables={"docs": TableSchema(name="docs", columns=(Column("id", primary_key=1),))})
    engine.attributor = type("A", (), {"schema": lambda self: schema, "rows": lambda self, name: []})()
    graph = _graph_with_owner(EvidenceState.CANDIDATE, key="docs:d1")
    monkeypatch.setattr("mizan.engine.build_ownership_graph", lambda **kwargs: graph)
    monkeypatch.setattr(engine, "_identity_observations", lambda: [])

    engine.learn()

    assert graph.owner_state("docs:d1") is EvidenceState.CANDIDATE
    assert graph.owner_of("docs:d1") is None
    resource = engine.policy.resource("docs:d1")
    assert resource is not None and resource.owner is None
    assert all(item.resource_owner is None for item in engine.traffic.records)


def test_candidate_owner_does_not_authorize_an_owner_control_request(monkeypatch) -> None:
    from mizan.attribution import Column, DatabaseSchema, TableSchema
    from mizan.core import Resource

    engine = _empty_engine()
    record = TrafficRecord(
        method="GET",
        path="/docs/d1",
        status=200,
        principal="bob",
        resource_type="docs",
        resource_id="d1",
        resource_owner="alice",
    )
    engine.traffic.records = [record]
    engine.policy.resources["docs:d1"] = Resource("docs", "d1", owner="alice")
    schema = DatabaseSchema(tables={"docs": TableSchema(name="docs", columns=(Column("id", primary_key=1),))})
    engine.attributor = type("A", (), {"schema": lambda self: schema, "rows": lambda self, name: []})()
    graph = _graph_with_owner(EvidenceState.CANDIDATE, key="docs:d1")
    monkeypatch.setattr("mizan.engine.build_ownership_graph", lambda **kwargs: graph)
    monkeypatch.setattr(engine, "_identity_observations", lambda: [])
    engine.learn()

    calls: list[tuple[str, str]] = []

    class Response:
        status_code = 200

        def json(self):
            return {}

    def recording(session, method, url, **kwargs):
        calls.append((str(session.headers.get("Authorization", "")), str(url)))
        return Response()

    engine._request = recording  # type: ignore[method-assign]
    engine._probe_read_authorization()
    assert not [call for call in calls if "alice-token" in call[0]], calls


def test_candidate_owner_produces_one_inconclusive_l2_check() -> None:
    result = scan_application(MIXED, variant="clean", budget=90)
    outcomes = [
        item
        for item in result.ownership["authorization_outcomes"]
        if item["resource"] == "candidate:item-b1" and item["law"] == "L2"
    ]
    assert len(outcomes) == 1, outcomes
    assert outcomes[0]["outcome"] == AuthorizationOutcome.INCONCLUSIVE.value
    assert all(finding["law"] != "L2" or finding["resource"] != "candidate:item-b1" for finding in result.findings)


def test_unknown_ownership_is_inconclusive_without_a_guessed_owner() -> None:
    result = scan_application(MIXED, variant="clean", budget=90)
    outcomes = [item for item in result.ownership["authorization_outcomes"] if item["resource"] == "unknown:item-c1"]
    assert outcomes
    assert all(item["outcome"] == AuthorizationOutcome.INCONCLUSIVE.value for item in outcomes)
    assert result.finding_count == 0


@pytest.mark.parametrize("state", [EvidenceState.CANDIDATE, EvidenceState.AMBIGUOUS, EvidenceState.CONTRADICTED])
def test_unconfirmed_ownership_never_produces_an_l3_finding(state: EvidenceState) -> None:
    from mizan.core import Policy

    policy = Policy()
    policy.principals["bob"] = Principal("bob", ("user",), "bob-token")
    analyzer = TaintAnalyzer(policy, graph=_graph_with_owner(state))
    assert analyzer.analyze([_write_event()]) == []
    assert analyzer.outcomes
    assert all(item["outcome"] == AuthorizationOutcome.INCONCLUSIVE.value for item in analyzer.outcomes)


# --------------------------------------------------------------------------- #
# D/E - genuine detection and grants
# --------------------------------------------------------------------------- #


def test_confirmed_ownership_still_detects_a_genuine_bola() -> None:
    result = scan_application(ADVERSARIAL, variant="read", budget=90)
    assert result.verdict is Verdict.FINDINGS
    assert "L2" in result.law_types
    assert any(finding["law"] == "L2" for finding in result.findings)
    assert result.coverage.laws["L2"].findings >= 1


def test_action_scoped_grants_remain_resolved() -> None:
    denied = scan_application(ADVERSARIAL, variant="grant_write", budget=90)
    assert denied.law_types == ["L3"]
    assert denied.coverage.laws["L2"].allowed_by_grant >= 1

    allowed = scan_application(ADVERSARIAL, variant="read_write_grant", budget=90)
    assert allowed.verdict is Verdict.CLEAN
    assert allowed.coverage.laws["L2"].allowed_by_grant >= 1
    assert allowed.coverage.laws["L3"].allowed_by_grant >= 1


# --------------------------------------------------------------------------- #
# F - one final outcome per logical check
# --------------------------------------------------------------------------- #


def test_a_logical_check_has_one_final_outcome_with_reconciliation() -> None:
    engine = _empty_engine()
    engine.eligible_by_law = {"L3": 1}
    engine._outcome("L3", "write", "docs:d1", "bob", AuthorizationOutcome.INCONCLUSIVE)
    engine._outcome("L3", "write", "docs:d1", "bob", AuthorizationOutcome.VIOLATION)
    engine._outcome("L3", "write", "docs:d1", "bob", AuthorizationOutcome.DECIDED)
    assert len(engine.outcomes) == 1
    assert engine.outcomes[0]["outcome"] == AuthorizationOutcome.VIOLATION.value
    coverage = engine.coverage()
    law = coverage.laws["L3"]
    assert law.attempted == law.findings == 1
    assert law.inconclusive == 0
    _coverage_invariants(coverage)


def test_an_inconclusive_reason_cannot_survive_a_resolved_outcome() -> None:
    engine = _empty_engine()
    engine.eligible_by_law = {"L2": 1}
    engine._inconclusive("L2", "docs:d1", "ownership unresolved", principal="bob")
    engine._outcome("L2", "read", "docs:d1", "bob", AuthorizationOutcome.DECIDED)
    assert len(engine.outcomes) == 1
    assert engine.outcomes[0]["outcome"] == AuthorizationOutcome.DECIDED.value
    assert engine.inconclusive_checks == []


def test_duplicate_observations_do_not_inflate_final_coverage() -> None:
    engine = _empty_engine()
    engine.eligible_by_law = {"L3": 1}
    for _ in range(4):
        engine._outcome("L3", "write", "docs:d1", "bob", AuthorizationOutcome.DECIDED)
    engine._inconclusive("L3", "docs:d1", "another reason", principal="bob")
    coverage = engine.coverage()
    assert coverage.laws["L3"].attempted == 1
    assert coverage.laws["L3"].decided == 1
    assert len(engine.inconclusive_checks) == 0
    _coverage_invariants(coverage)


def test_pipeline_coverage_partition_holds() -> None:
    for fixture, variant in ((MIXED, "clean"), (ADVERSARIAL, "read"), (ADVERSARIAL, "grant_write")):
        result = scan_application(fixture, variant=variant, budget=90)
        assert result.coverage.laws, (fixture.name, variant)
        _coverage_invariants(result.coverage)


def test_law_coverage_model_partition() -> None:
    counter = LawCoverage(eligible=3, attempted=2, decided=1, findings=1)
    assert counter.resolved == 2
    assert counter.pending == 1
    assert counter.resolved + counter.inconclusive == counter.attempted


# --------------------------------------------------------------------------- #
# G - serial/parallel consistency
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("variant,expected", [("read", ["L2"]), ("grant_write", ["L3"])])
def test_serial_and_parallel_agree(variant: str, expected: list[str], tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "cli-alice")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "cli-bob")
    serial, serial_laws = _run_twin(tmp_path / "serial", variant, workers=1)
    parallel, parallel_laws = _run_twin(tmp_path / "parallel", variant, workers=2)
    assert serial.exit_code == 0, serial.output
    assert parallel.exit_code == 0, parallel.output
    assert serial_laws == expected
    assert parallel_laws == expected


def test_external_target_status_is_not_misreported() -> None:
    # The optional external-target job must be labelled SKIPPED in the report.
    report = (ROOT / "PHASE_V2_3_SOUNDNESS_REPORT.md").read_text(encoding="utf-8")
    assert "SKIPPED" in report and "not PASSED" in report
