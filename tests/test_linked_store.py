"""The nonstandard-ownership fixture, driven through the real scan pipeline.

This application exposes no ``owner_id``/``user_id`` field. Ownership must be
discovered from the declared database relationships and a repeatable identity
anchor. A clean result here is evidence of relationship discovery, not of a
fixture-specific lookup.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mizan.core import Verdict
from mizan.validation import scan_application, validate_finding

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "linked_store"

CASES = {
    "clean": (Verdict.CLEAN, ()),
    "read": (Verdict.FINDINGS, ("L2",)),
    "write": (Verdict.FINDINGS, ("L3",)),
    "both": (Verdict.FINDINGS, ("L2", "L3")),
    # An explicit grant is not an ownership breach.
    "collaborator": (Verdict.CLEAN, ()),
    # Two candidate identities: no owner may be fabricated.
    "ambiguous": (Verdict.INCONCLUSIVE, ()),
}


@pytest.mark.parametrize("variant,expected", sorted(CASES.items()))
def test_the_six_ownership_scenarios(variant: str, expected: tuple[Verdict, tuple[str, ...]]) -> None:
    verdict, laws = expected
    result = scan_application(APP, variant=variant, budget=90)
    assert result.error is None, result.error
    assert result.setup_error is None, result.setup_error
    assert result.verdict is verdict, f"{variant}: {result.verdict.value} ({result.error or result.setup_error})"
    assert tuple(result.law_types) == laws, f"{variant}: {result.law_types}"


@pytest.mark.parametrize("variant,law", [("read", "L2"), ("write", "L3"), ("both", "L2"), ("both", "L3")])
def test_findings_are_structurally_valid_and_replayable(variant: str, law: str) -> None:
    result = scan_application(APP, variant=variant, budget=90)
    findings = [finding for finding in result.findings if finding.get("law") == law]
    assert findings, f"{variant}: no {law} finding"
    for finding in findings:
        assert validate_finding(finding) == [], validate_finding(finding)
        evidence = finding.get("evidence") or {}
        # Ownership evidence is referenced by id, not by a copied token.
        assert isinstance(evidence.get("ownership_evidence"), list)
        assert all(isinstance(item, str) for item in evidence["ownership_evidence"])


def test_the_collaborator_case_has_no_l2_finding() -> None:
    result = scan_application(APP, variant="collaborator", budget=90)
    assert "L2" not in result.law_types
    assert "L3" not in result.law_types
    # The scan did reach the resources - this is a clean result, not an empty one.
    assert result.coverage.resources_discovered > 0
    assert result.coverage.probes_executed > 0


def test_the_ambiguous_case_has_no_confirmed_owner() -> None:
    result = scan_application(APP, variant="ambiguous", budget=90)
    assert result.coverage.resources_discovered > 0
    assert result.coverage.resources_owned == 0
    assert result.finding_count == 0
    assert result.verdict is Verdict.INCONCLUSIVE


def test_no_raw_token_enters_the_findings() -> None:
    result = scan_application(APP, variant="both", budget=90)
    # Every Authorization header in a proof step must be a placeholder that
    # replay can resolve - never a token the application actually issued.
    from mizan.tokens import principal_from_placeholder

    found_header = False
    for finding in result.findings:
        for step in finding.get("steps", []):
            authorization = (step.get("headers") or {}).get("Authorization")
            if not authorization:
                continue
            found_header = True
            assert authorization.startswith("Bearer ")
            assert principal_from_placeholder(authorization[len("Bearer ") :]) is not None
    assert found_header
    assert "MIZAN_SECRET" not in json.dumps(result.findings)


def test_the_real_cli_validates_all_six_variants() -> None:
    """`mizan validate` drives the fixture through the real CLI and proxy."""
    from click.testing import CliRunner

    from mizan.cli import main

    result = CliRunner().invoke(main, ["validate", str(APP), "--budget", "90"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    for variant in CASES:
        assert f"{variant}:" in result.output
    assert "ambiguous:" in result.output
