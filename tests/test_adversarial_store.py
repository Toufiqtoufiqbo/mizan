"""Adversarial Phase V.1 fixture driven through the real scan pipeline.

Every test asserts both the outcome and the *explanation*: a result is not
acceptable merely because the law types happen to match.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mizan.core import Verdict
from mizan.validation import scan_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "adversarial_store"

CASES = {
    "clean": (Verdict.CLEAN, ()),
    "read": (Verdict.FINDINGS, ("L2",)),
    "write": (Verdict.FINDINGS, ("L3",)),
    "grant": (Verdict.CLEAN, ()),
    "creator_only": (Verdict.FINDINGS, ("L2",)),
    "observer_only": (Verdict.FINDINGS, ("L2",)),
    "declared_creator": (Verdict.FINDINGS, ("L2",)),
    "provenance": (Verdict.INCONCLUSIVE, ()),
    "ambiguous_identity": (Verdict.INCONCLUSIVE, ()),
}


@pytest.mark.parametrize("variant,expected", sorted(CASES.items()))
def test_adversarial_scenarios(variant: str, expected: tuple[Verdict, tuple[str, ...]]) -> None:
    verdict, laws = expected
    result = scan_application(APP, variant=variant, budget=90)
    assert result.error is None, result.error
    assert result.setup_error is None, result.setup_error
    assert result.verdict is verdict, f"{variant}: {result.verdict.value}"
    assert tuple(result.law_types) == laws, f"{variant}: {result.law_types}"


def test_an_undeclared_watcher_does_not_suppress_a_real_l2() -> None:
    result = scan_application(APP, variant="read", budget=90)
    assert "L2" in result.law_types
    assert result.ownership["by_state"]["CANDIDATE"] >= 1  # the watcher row stayed a candidate
    assert not result.ownership["inconclusive_checks"] or all(
        "sharing" not in item.get("reason", "") for item in result.ownership["inconclusive_checks"]
    )
    for finding in result.findings:
        evidence = finding.get("evidence") or {}
        assert "ownership_evidence" in evidence
        assert evidence.get("owner") != finding.get("principal")


def test_a_declared_grant_explains_legitimate_access() -> None:
    result = scan_application(APP, variant="grant", budget=90)
    assert result.finding_count == 0
    assert result.ownership["by_state"]["CONFIRMED"] > 0
    assert result.ownership["sources"].get("declared_grant", 0) >= 1


def test_a_creator_column_never_becomes_a_grant() -> None:
    """The creator row is provenance: access through it stays a real finding."""
    result = scan_application(APP, variant="creator_only", budget=90)
    assert result.law_types == ["L2"]
    assert result.ownership["sources"].get("declared_grant", 0) == 0
    assert any(finding["principal"] == "bob" and finding["law"] == "L2" for finding in result.findings)


def test_an_observer_column_never_becomes_a_grant() -> None:
    result = scan_application(APP, variant="observer_only", budget=90)
    assert result.law_types == ["L2"]
    assert result.ownership["sources"].get("declared_grant", 0) == 0


def test_a_contract_naming_the_wrong_principal_fk_does_not_suppress_l2() -> None:
    """The declared creator column is not the column the application authorizes on."""
    result = scan_application(APP, variant="declared_creator", budget=90)
    assert result.law_types == ["L2"]
    for finding in result.findings:
        assert finding["principal"] == "bob"


def test_provenance_only_ownership_is_inconclusive() -> None:
    result = scan_application(APP, variant="provenance", budget=90)
    assert result.finding_count == 0
    assert result.coverage.resources_discovered > 0
    assert result.coverage.resources_owned == 0
    assert result.ownership["by_state"]["CANDIDATE"] > 0
    assert result.ownership["confirmed_ownership_edges"] == 0
    assert any("ownership" in reason for reason in result.ownership["inconclusive"].values())


def test_ambiguous_identity_evidence_is_not_promoted() -> None:
    result = scan_application(APP, variant="ambiguous_identity", budget=90)
    assert result.finding_count == 0
    assert result.coverage.resources_owned == 0
    assert result.ownership["confirmed_ownership_edges"] == 0
    assert any("anchor" in reason or "identity" in reason for reason in result.ownership["inconclusive"].values())


def test_l3_reports_the_explicit_resource_mapping() -> None:
    result = scan_application(APP, variant="write", budget=90)
    findings = [finding for finding in result.findings if finding.get("law") == "L3"]
    assert findings
    for finding in findings:
        mapping = (finding.get("evidence") or {}).get("resource_mapping") or {}
        assert mapping.get("database_table")
        assert mapping.get("database_key")
        assert mapping.get("api_resource")
        assert json.dumps(mapping)  # serializable for proof bundles


def test_no_raw_token_enters_the_adversarial_findings() -> None:
    from mizan.tokens import principal_from_placeholder

    result = scan_application(APP, variant="read", budget=90)
    for finding in result.findings:
        for step in finding.get("steps", []):
            authorization = (step.get("headers") or {}).get("Authorization")
            if authorization:
                assert authorization.startswith("Bearer ")
                assert principal_from_placeholder(authorization[len("Bearer ") :]) is not None
    assert "MIZAN_SECRET" not in json.dumps(result.findings)
