"""The cross-framework benchmark itself.

The benchmark runs the same scenarios against two independently implemented
applications and measures what Mīzān found. These tests cover the parts that
can be checked without running the whole matrix - the aggregation, the report
and the consistency checker - plus one live scenario, so a broken harness
cannot pass silently.

The full benchmark is a separate command:

    python -m benchmarks.cross_framework.run --repetitions 3
    python -m benchmarks.cross_framework.check benchmarks/cross_framework/results/results.json
"""

from __future__ import annotations

import json

import pytest

from benchmarks.cross_framework.check import check_results
from benchmarks.cross_framework.report import aggregate, render_json, render_markdown, tree_digest
from benchmarks.cross_framework.runner import generate_credentials, run_scenario
from benchmarks.cross_framework.scenarios import EXPECTED, FRAMEWORKS, VARIANTS


def _scenario(**overrides) -> dict:
    """A scenario as the benchmark reports it."""
    scenario = {
        "framework": "fastapi",
        "variant": "clean",
        "repetition": 1,
        "outcome": "expected",
        "expected_findings": [],
        "observed_findings": [],
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": None,
        "recall": None,
        "requests": {"bootstrap": 2, "learning": 9, "attack": 3, "total": 14, "budget": 60},
        "budget_exhausted": False,
        "wall_clock_seconds": 1.5,
        "peak_memory_bytes": 1024,
        "peak_memory_note": "measured",
        "setup_errors": [],
        "errors": [],
        "missing_identities": [],
        "reproduction": {"attempted": 0, "succeeded": 0, "requests": 0, "failures": []},
        "evidence_complete": True,
    }
    scenario.update(overrides)
    return scenario


# --------------------------------------------------------------------------- #
# The scenarios
# --------------------------------------------------------------------------- #


def test_the_expected_matrix_is_the_one_the_mission_asks_for() -> None:
    assert EXPECTED == {"clean": (), "read": ("L2",), "write": ("L3",), "both": ("L2", "L3")}
    assert VARIANTS == ("clean", "read", "write", "both")


def test_both_frameworks_are_registered() -> None:
    assert set(FRAMEWORKS) == {"fastapi", "express"}
    for name, framework in FRAMEWORKS.items():
        assert framework.directory.exists(), f"the {name} fixture is missing"
        assert framework.launch.command, f"the {name} launch specification is empty"


def test_the_credentials_are_unique_and_never_reused() -> None:
    first = generate_credentials()
    second = generate_credentials()
    assert set(first) == set(second) == {"alice", "bob", "root"}
    assert first != second, "two runs received the same credentials"
    for password in first.values():
        assert len(password) >= 16


def test_the_tree_digest_is_stable_and_sensitive() -> None:
    directory = FRAMEWORKS["fastapi"].directory
    assert tree_digest([directory]) == tree_digest([directory])
    assert tree_digest([directory]) != tree_digest([FRAMEWORKS["express"].directory])


# --------------------------------------------------------------------------- #
# The aggregation
# --------------------------------------------------------------------------- #


def test_the_aggregation_keeps_the_raw_counts() -> None:
    scenarios = [
        _scenario(variant="clean"),
        _scenario(
            variant="read",
            expected_findings=["L2"],
            observed_findings=["L2"],
            true_positives=1,
            recall=1.0,
            reproduction={"attempted": 1, "succeeded": 1, "requests": 1, "failures": []},
        ),
    ]
    totals = aggregate(scenarios)
    assert totals["scenarios"] == 2
    assert totals["scenarios_expected"] == 2
    assert totals["true_positives"] == 1
    assert totals["false_positives"] == 0
    assert totals["false_negatives"] == 0
    assert totals["precision"] == 1.0
    assert totals["recall"] == 1.0
    assert totals["reproduction_attempted"] == 1
    assert totals["reproduction_succeeded"] == 1


def test_a_ratio_without_a_denominator_is_undefined_not_zero() -> None:
    totals = aggregate([_scenario()])
    assert totals["precision"] is None
    assert totals["recall"] is None


def test_the_report_shows_the_counts_behind_every_percentage() -> None:
    results = {
        "repetitions": 1,
        "budget": 60,
        "environment": {
            "platform": "test",
            "processor": "test",
            "cpu_count": 1,
            "memory_bytes": None,
            "python": "3.12.10",
            "node": "v24.20.0",
            "sqlite": "3.45.0",
            "fastapi": "0.162.4",
            "uvicorn": "0.54.0",
            "mizan_commit": None,
            "mizan_commit_note": "git is not installed on this machine",
            "mizan_tree_digest": "deadbeef",
            "fixture_digests": {"fastapi": "cafe", "express": "babe"},
        },
        "scenarios": [_scenario()],
        "totals": aggregate([_scenario()]),
    }
    markdown = render_markdown(results)
    assert "| FastAPI | clean |" in markdown or "| fastapi | clean |" in markdown
    assert "n/a" in markdown, "a ratio without a denominator must be shown as undefined"
    assert "deadbeef" in markdown
    assert "git is not installed" in markdown
    # The JSON must round-trip.
    assert json.loads(render_json(results))["scenarios"][0]["variant"] == "clean"


# --------------------------------------------------------------------------- #
# The consistency checker
# --------------------------------------------------------------------------- #


def _results(scenarios: list[dict]) -> dict:
    return {
        "repetitions": 1,
        "budget": 60,
        "frameworks": ["fastapi"],
        "variants": ["clean"],
        "scenarios": scenarios,
        "totals": aggregate(scenarios),
    }


def test_the_checker_accepts_a_consistent_result() -> None:
    assert check_results(_results([_scenario()])) == []


def test_the_checker_rejects_a_missing_finding() -> None:
    scenario = _scenario(
        variant="read",
        expected_findings=["L2"],
        observed_findings=[],
        true_positives=0,
        false_negatives=1,
        outcome="unexpected",
    )
    problems = check_results(_results([scenario]))
    assert any("expected ['L2'], observed []" in problem for problem in problems)


def test_the_checker_rejects_an_unexpected_finding() -> None:
    scenario = _scenario(
        variant="clean",
        expected_findings=[],
        observed_findings=["L2"],
        true_positives=0,
        false_positives=1,
        outcome="unexpected",
    )
    problems = check_results(_results([scenario]))
    assert any("observed ['L2']" in problem for problem in problems)


def test_the_checker_rejects_an_exhausted_budget() -> None:
    problems = check_results(_results([_scenario(budget_exhausted=True)]))
    assert any("budget was exhausted" in problem for problem in problems)


def test_the_checker_rejects_a_finding_that_cannot_be_reproduced() -> None:
    scenario = _scenario(
        variant="read",
        expected_findings=["L2"],
        observed_findings=["L2"],
        true_positives=1,
        reproduction={"attempted": 1, "succeeded": 0, "requests": 1, "failures": [{"reason": "no"}]},
    )
    problems = check_results(_results([scenario]))
    assert any("could not be reproduced" in problem for problem in problems)


def test_the_checker_rejects_a_setup_error() -> None:
    problems = check_results(_results([_scenario(setup_errors=["could not authenticate: bob"])]))
    assert any("setup error" in problem for problem in problems)


def test_the_checker_rejects_an_empty_result() -> None:
    assert check_results({"scenarios": []}) == ["the result contains no scenario at all"]


# --------------------------------------------------------------------------- #
# One live scenario
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("framework", ["fastapi"])
def test_one_scenario_runs_end_to_end(framework: str) -> None:
    """The harness must work, including the replay - not only in theory."""
    scenario = run_scenario(FRAMEWORKS[framework], "read", 1, budget=60)
    assert scenario["errors"] == []
    assert scenario["setup_errors"] == []
    assert scenario["outcome"] == "expected", scenario
    assert scenario["observed_findings"] == ["L2"]
    assert scenario["true_positives"] == 1
    assert scenario["false_positives"] == 0
    assert scenario["false_negatives"] == 0
    assert scenario["requests"]["total"] > 0
    assert scenario["requests"]["bootstrap"] == 2
    assert scenario["budget_exhausted"] is False
    assert scenario["evidence_complete"] is True
    assert scenario["reproduction"]["attempted"] == 1
    assert scenario["reproduction"]["succeeded"] == 1, scenario["reproduction"]
    assert scenario["peak_memory_bytes"] is not None
