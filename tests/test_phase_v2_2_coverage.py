"""Phase V.2.2: unresolved ownership coverage and strict variant validation.

The tests are written against observable behaviour:

* the real validation pipeline on the mixed-ownership fixture;
* engine-produced ``LawCoverage`` counters and their invariants;
* strict/lenient relationship-contract variant parsing.

Before the fix, relevant unresolved resources vanish from L2/L3 eligibility,
and invalid non-object variant entries are silently discarded by strict
parsing. No test here weakens or replaces a Phase V.2.1 test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mizan.core import AuthorizationOutcome, LawCoverage, Principal, Verdict
from mizan.engine import Mizan, Target
from mizan.ownership import RelationshipContract, RelationshipContractError
from mizan.traffic import TrafficRecord
from mizan.validation import scan_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "mixed_ownership"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _scan(variant: str = "clean", budget: int = 90):
    return scan_application(APP, variant=variant, budget=budget)


def _contract(**variants) -> dict:
    return {"version": 1, "variants": dict(variants)}


def _engine(records: list[TrafficRecord], principals: list[Principal]) -> Mizan:
    engine = Mizan(Target(base_url="http://example.test", principals=principals))
    engine.traffic.records = records
    return engine


def _read_record(owner: str = "alice", path: str = "/confirmed/item-a1") -> TrafficRecord:
    return TrafficRecord(
        method="GET",
        path=path,
        status=200,
        principal="bob",
        resource_type="confirmed",
        resource_id="item-a1",
        resource_owner=owner,
        body=None,
        response={"item_ref": "item-a1", "label": "A"},
    )


# --------------------------------------------------------------------------- #
# Part D - strict variant validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_value",
    ["a string", ["list"], 7, True, None],
    ids=["string", "list", "number", "boolean", "null"],
)
def test_strict_variants_reject_non_object_values(bad_value) -> None:
    data = _contract(broken=bad_value)
    with pytest.raises(RelationshipContractError, match="variant"):
        RelationshipContract.from_dict(data, strict=True)


def test_strict_variants_reject_a_mixed_valid_and_invalid_set() -> None:
    data = _contract(good={"ownership": None}, bad="not-an-object")
    with pytest.raises(RelationshipContractError, match="variant"):
        RelationshipContract.from_dict(data, strict=True)


def test_strict_variants_reject_an_empty_name() -> None:
    with pytest.raises(RelationshipContractError, match="variant"):
        RelationshipContract.from_dict(_contract(**{"": {"ownership": None}}), strict=True)


def test_strict_variants_keep_valid_overrides() -> None:
    contract = RelationshipContract.from_dict(_contract(good={"ownership": None}), strict=True)
    assert "good" in contract.variants
    assert contract.for_variant("good", strict=True) is not None


def test_strict_variants_reject_an_invalid_action_inside_a_valid_object() -> None:
    data = _contract(
        good={
            "sharing": {
                "t": {
                    "resource_fk": "a",
                    "principal_fk": "b",
                    "semantics": "authorization_grant",
                    "actions": ["delete"],
                }
            }
        }
    )
    with pytest.raises(RelationshipContractError, match="delete"):
        contract = RelationshipContract.from_dict(data, strict=True)
        contract.for_variant("good", strict=True)


def test_strict_variants_reject_an_invalid_sharing_declaration() -> None:
    data = _contract(good={"sharing": "not-an-object"})
    with pytest.raises(RelationshipContractError, match="sharing"):
        contract = RelationshipContract.from_dict(data, strict=True)
        contract.for_variant("good", strict=True)


def test_lenient_mode_never_turns_an_invalid_variant_into_a_grant() -> None:
    data = _contract(
        broken={"sharing": {"t": {"resource_fk": "a", "principal_fk": "b", "semantics": "authorization_grant"}}}
    )
    contract = RelationshipContract.from_dict(data)  # lenient: missing actions
    assert contract.sharing == {}
    assert "broken" in contract.variants


# --------------------------------------------------------------------------- #
# Part A - relevance and exclusions (engine-level)
# --------------------------------------------------------------------------- #


def test_an_unresolved_read_resource_increases_l2_eligibility() -> None:
    engine = _engine(
        [_read_record()],
        [Principal("alice", ("user",), "a"), Principal("bob", ("user",), "b")],
    )
    assert engine._eligible_probe_targets()["L2"] >= 1


def test_a_candidate_read_resource_increases_l2_eligibility() -> None:
    from mizan.ownership import Evidence, EvidenceState, OwnershipGraph, RelationshipType

    record = _read_record()
    record.resource_owner = None  # ownership is only a candidate in the graph
    engine = _engine(
        [record],
        [Principal("alice", ("user",), "a"), Principal("bob", ("user",), "b")],
    )
    graph = OwnershipGraph()
    graph.resource_rows["confirmed:item-a1"] = ("confirmed_items", ("item-a1",))
    evidence = graph.add_evidence(Evidence(source="foreign_key", principal="alice", resource="confirmed:item-a1"))
    graph.add_relationship(RelationshipType.OWNS, "alice", "confirmed:item-a1", EvidenceState.CANDIDATE, [evidence])
    engine.graph = graph
    assert engine._eligible_probe_targets()["L2"] >= 1


def test_an_unresolved_write_resource_increases_l3_eligibility() -> None:
    from mizan.ownership import OwnershipGraph

    record = TrafficRecord(
        method="PUT",
        path="/unknown/item-c1",
        status=200,
        principal="bob",
        resource_type="unknown",
        resource_id="item-c1",
        body={"label": "changed"},
    )
    engine = _engine(
        [record],
        [Principal("alice", ("user",), "a"), Principal("bob", ("user",), "b")],
    )
    graph = OwnershipGraph()
    graph.resource_rows["unknown:item-c1"] = ("unknown_items", ("item-c1",))
    engine.graph = graph
    assert engine._eligible_probe_targets()["L3"] >= 1


def test_health_and_login_do_not_create_ownership_checks() -> None:
    records = [
        TrafficRecord(method="GET", path="/health", status=200, principal="bob"),
        TrafficRecord(method="POST", path="/login", status=200, principal="bob", body={"username": "bob"}),
    ]
    engine = _engine(records, [Principal("alice", ("user",), "a"), Principal("bob", ("user",), "b")])
    eligible = engine._eligible_probe_targets()
    assert eligible["L2"] == 0
    assert eligible["L3"] == 0


def test_duplicate_traffic_does_not_inflate_eligible_counts() -> None:
    engine = _engine(
        [_read_record(), _read_record(), _read_record()],
        [Principal("alice", ("user",), "a"), Principal("bob", ("user",), "b")],
    )
    eligible = engine._eligible_probe_targets()
    assert eligible["L2"] == 1


def test_a_privileged_identity_is_not_an_eligible_attacker() -> None:
    engine = _engine(
        [_read_record()],
        [Principal("alice", ("user",), "a"), Principal("admin", ("admin",), "adm")],
    )
    assert engine._eligible_probe_targets()["L2"] == 0


# --------------------------------------------------------------------------- #
# Parts A/B/C - real pipeline and coverage invariants
# --------------------------------------------------------------------------- #


def test_mixed_pipeline_keeps_unresolved_ownership_visible() -> None:
    result = _scan()
    laws = result.coverage.laws
    assert result.verdict is Verdict.INCONCLUSIVE, (result.law_types, result.coverage.to_dict())
    assert result.finding_count == 0
    assert laws["L2"].eligible >= 2
    assert laws["L3"].eligible >= 2
    assert laws["L2"].inconclusive >= 1
    assert laws["L3"].inconclusive >= 1
    assert laws["L2"].findings == 0
    assert laws["L3"].findings == 0
    assert any(
        "candidate" in item["reason"].lower() or "ownership" in item["reason"].lower()
        for item in result.ownership["inconclusive_checks"]
    )


def test_mixed_pipeline_finding_keeps_findings_precedence() -> None:
    result = _scan("finding")
    assert result.verdict is Verdict.FINDINGS
    assert result.law_types == ["L3"]
    assert result.coverage.laws["L3"].findings >= 1
    # The unresolved resources remain visible even though a finding won.
    assert result.coverage.laws["L2"].inconclusive >= 1
    assert result.coverage.laws["L3"].inconclusive >= 1


def test_engine_coverage_invariants_hold() -> None:
    result = _scan()
    for law, coverage in result.coverage.laws.items():
        assert coverage.attempted <= coverage.eligible, law
        assert coverage.resolved <= coverage.attempted, law
        assert coverage.inconclusive <= coverage.attempted, law
        assert coverage.pending == max(0, coverage.eligible - coverage.attempted), law
        assert coverage.resolved == coverage.decided + coverage.allowed_by_grant + coverage.findings, law


def test_l2_and_l3_are_not_merged_by_unresolved_checks() -> None:
    result = _scan()
    laws = result.coverage.laws
    assert set(laws) >= {"L2", "L3"}
    assert laws["L2"].inconclusive >= 1
    assert laws["L3"].inconclusive >= 1
    assert laws["L2"] is not laws["L3"]


def test_confirmed_grants_remain_resolved() -> None:
    from mizan.core import Policy
    from mizan.ownership import Evidence, EvidenceState, OwnershipGraph, RelationshipType
    from mizan.taint import TaintAnalyzer, WriteEvent

    policy = Policy()
    graph = OwnershipGraph()
    graph.resource_rows["t:1"] = ("t", ("1",))
    owner_evidence = graph.add_evidence(Evidence(source="declared", principal="alice", resource="t:1"))
    graph.add_relationship(RelationshipType.OWNS, "alice", "t:1", EvidenceState.CONFIRMED, [owner_evidence])
    grant_evidence = graph.add_evidence(Evidence(source="declared_grant", principal="bob", resource="t:1"))
    graph.add_relationship(
        RelationshipType.SHARED_WITH,
        "bob",
        "t:1",
        EvidenceState.CONFIRMED,
        [grant_evidence],
        actions=["write"],
    )
    policy.principals["bob"] = Principal("bob", ("user",), "bob-token")
    event = WriteEvent(
        ts=0.0,
        request_id="r",
        principal="bob",
        method="PUT",
        path="/x",
        table="t",
        row_id="1",
        row_key="1",
        columns={"a": 1},
        source_fields={"a"},
    )
    analyzer = TaintAnalyzer(policy, graph=graph)
    assert analyzer.analyze([event]) == []
    assert [item["outcome"] for item in analyzer.outcomes] == [AuthorizationOutcome.ALLOWED_BY_GRANT.value]
    assert analyzer.inconclusive == []


def test_verdict_matrix_pending_and_mixed_still_hold() -> None:
    from mizan.core import ScanCoverage, Verdict
    from mizan.validation import ValidationResult

    def result(laws: dict[str, LawCoverage], findings: int = 0) -> ValidationResult:
        return ValidationResult(
            application="test",
            variant="test",
            finding_count=findings,
            coverage=ScanCoverage(
                learning_operations=1, resources_discovered=1, probe_candidates=2, probes_executed=1, laws=laws
            ),
        )

    assert result({"L3": LawCoverage(eligible=1, attempted=0)}).verdict is Verdict.INCONCLUSIVE
    assert (
        result(
            {
                "L2": LawCoverage(eligible=1, attempted=1, decided=1),
                "L3": LawCoverage(eligible=1, attempted=1, inconclusive=1),
            }
        ).verdict
        is Verdict.INCONCLUSIVE
    )
    assert (
        result(
            {
                "L2": LawCoverage(eligible=1, attempted=1, inconclusive=1),
                "L3": LawCoverage(eligible=1, attempted=1, findings=1),
            },
            findings=1,
        ).verdict
        is Verdict.FINDINGS
    )
