"""L4/L6 execution-state separation and backend consistency."""

from __future__ import annotations

from mizan.core import LawCoverage, LawExecutionState, ScanCoverage
from mizan.engine import Mizan, Target
from mizan.ownership import RelationshipContract


def _contract(with_l4: bool, with_l6: bool) -> RelationshipContract:
    data: dict = {"version": 1}
    if with_l4:
        data["authority"] = {
            "fields": [
                {
                    "resource_type": "users",
                    "field": "role",
                    "source": "trusted_contract",
                    "confidence": "confirmed",
                }
            ]
        }
    if with_l6:
        data["cardinality"] = [
            {
                "resource_type": "items",
                "bound": 2,
                "scope": "principal",
                "unit": "objects",
                "source": "trusted_contract",
                "enforcement": "reject_beyond",
            }
        ]
    return RelationshipContract.from_dict(data, strict=True)


def test_l6_is_not_a_probe_without_an_explicit_invariant() -> None:
    engine = Mizan(Target(base_url="http://localhost", principals=[]))
    assert "L6" not in engine.probe_names()
    coverage = engine.coverage()
    assert coverage.law_state("L6") is LawExecutionState.UNSUPPORTED


def test_l6_is_a_probe_only_with_a_declared_invariant() -> None:
    engine = Mizan(Target(base_url="http://localhost", principals=[]), relationship_contract=_contract(False, True))
    assert "L6" in engine.probe_names()
    coverage = engine.coverage()
    assert coverage.laws["L6"].supported is True
    assert coverage.laws["L6"].skipped is False


def test_l4_policy_probe_requires_a_trusted_declaration() -> None:
    plain = Mizan(Target(base_url="http://localhost", principals=[]))
    with_policy = Mizan(
        Target(base_url="http://localhost", principals=[]), relationship_contract=_contract(True, False)
    )
    assert plain._probe_authority_creation != with_policy._probe_authority_creation_policy
    assert with_policy._law_policy_enabled is True


def test_an_inconclusive_law_is_not_reported_as_executed() -> None:
    coverage = ScanCoverage(
        laws={
            "L4": LawCoverage(eligible=1, attempted=1, executed=1, inconclusive=1),
            "L6": LawCoverage(eligible=1, attempted=1, executed=1, findings=1),
        }
    )
    assert coverage.law_state("L4") is LawExecutionState.INCONCLUSIVE
    assert coverage.law_state("L6") is LawExecutionState.EXECUTED
    assert coverage.executed_laws == ["L6"]
