"""Deterministic tests for truthful per-law execution coverage."""

from __future__ import annotations

from types import SimpleNamespace

from mizan.cli import postgres_backend_status
from mizan.core import LawCoverage, LawExecutionState, ScanCoverage


def test_every_state_has_a_distinct_documented_value() -> None:
    values = [state.value for state in LawExecutionState]
    assert len(values) == len(set(values))
    assert set(values) == {
        "unsupported",
        "supported_not_exercised",
        "eligible",
        "attempted",
        "executed",
        "inconclusive",
        "skipped",
    }


def test_unsupported_and_not_exercised_are_distinct() -> None:
    assert LawCoverage(supported=False).state is LawExecutionState.UNSUPPORTED
    assert LawCoverage(supported=True).state is LawExecutionState.SUPPORTED_NOT_EXERCISED


def test_eligible_is_not_executed() -> None:
    coverage = LawCoverage(eligible=3)
    assert coverage.state is LawExecutionState.ELIGIBLE
    assert coverage.executed == 0


def test_attempted_without_probe_requests_is_not_executed() -> None:
    coverage = LawCoverage(eligible=1, attempted=1, inconclusive=1)
    assert coverage.state is LawExecutionState.INCONCLUSIVE


def test_a_failed_or_inconclusive_probe_is_not_a_successful_execution() -> None:
    coverage = LawCoverage(eligible=1, attempted=1, executed=1, inconclusive=1)
    assert coverage.state is LawExecutionState.INCONCLUSIVE
    assert coverage.state is not LawExecutionState.EXECUTED


def test_a_decided_probe_is_executed() -> None:
    coverage = LawCoverage(eligible=2, attempted=2, executed=2, decided=2)
    assert coverage.state is LawExecutionState.EXECUTED
    assert coverage.to_dict()["state"] == "executed"


def test_skipped_law_is_not_counted_as_executed() -> None:
    coverage = LawCoverage(skipped=True, supported=False, executed=0)
    assert coverage.state is LawExecutionState.SKIPPED
    assert coverage.to_dict()["executed"] == 0


def test_scan_coverage_exposes_only_really_executed_laws() -> None:
    coverage = ScanCoverage(
        laws={
            "L2": LawCoverage(eligible=1, attempted=1, executed=1, decided=1),
            "L3": LawCoverage(eligible=1, attempted=1, executed=0, inconclusive=1),
            "L6": LawCoverage(skipped=True, supported=False),
            "L7": LawCoverage(supported=False),
        }
    )
    assert coverage.executed_laws == ["L2"]
    assert coverage.law_state("L3") is LawExecutionState.INCONCLUSIVE
    assert coverage.law_state("L6") is LawExecutionState.SKIPPED
    assert coverage.law_state("L9") is LawExecutionState.UNSUPPORTED
    assert coverage.to_dict()["executed_laws"] == ["L2"]


def test_cli_status_cannot_hardcode_a_law_into_laws_executed() -> None:
    coverage = ScanCoverage(
        laws={
            "L1": LawCoverage(eligible=1, attempted=1, executed=1, decided=1),
            "L2": LawCoverage(eligible=2, attempted=2, executed=2, findings=1, decided=1),
            "L3": LawCoverage(eligible=1),
        }
    )
    engine = SimpleNamespace(
        coverage=lambda: coverage,
        probe_candidates=4,
        probes_executed=3,
        requests=12,
        _attributed_events=[object()],
        inconclusive_checks=[],
    )
    finding = SimpleNamespace(law="L5")
    status = postgres_backend_status(engine, [finding], 2)
    assert status["laws_executed"] == ["L1", "L2"]
    assert status["laws_by_status"]["L3"] == "eligible"
    assert "L5" not in status["laws_by_status"] or status["laws_by_status"]["L5"] != "executed"
    assert status["laws_unsupported"] == []


def test_cli_status_reports_unsupported_and_skipped_laws() -> None:
    coverage = ScanCoverage(
        laws={
            "L6": LawCoverage(skipped=True, supported=False),
            "L7": LawCoverage(supported=False),
        }
    )
    engine = SimpleNamespace(
        coverage=lambda: coverage,
        probe_candidates=0,
        probes_executed=0,
        requests=0,
        _attributed_events=[],
        inconclusive_checks=[],
    )
    status = postgres_backend_status(engine, [], 1)
    assert status["laws_unsupported"] == ["L7"]
    assert status["laws_skipped"] == ["L6"]
    assert status["laws_executed"] == []
