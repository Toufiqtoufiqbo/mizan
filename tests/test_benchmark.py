"""Tests for the AuthzBugs benchmark.

The benchmark is the measurement instrument of the whole project, so it gets
its own tests: every bug kind must be detected, and every patched application
must stay silent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mizan.benchmark import BUGS, build_suite, describe, run_application, run_suite
from mizan.benchmark.apps import AppSpec


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    return tmp_path


def test_suite_shape() -> None:
    suite = build_suite(50, controls=5)
    assert suite.size == 50
    assert len(suite.controls) == 5
    counts: dict[str, int] = {}
    for spec in suite.applications:
        assert len(spec.bugs) == 1
        counts[spec.bugs[0]] = counts.get(spec.bugs[0], 0) + 1
    assert set(counts) == set(BUGS)
    assert all(count == 10 for count in counts.values()), "every kind must appear equally often"
    assert "AuthzBugs-50" in describe(suite)


@pytest.mark.parametrize("kind", sorted(BUGS))
def test_every_bug_kind_is_detected(kind: str, workspace: Path) -> None:
    spec = AppSpec(name=f"case-{kind}", bugs=(kind,), users=("alice", "bob", "carol"), orders=6)
    result = run_application(spec, workspace)
    assert result.missing == (), f"{kind} was not detected (found {result.detected})"
    assert result.unexpected == (), f"{kind} produced unrelated findings {result.unexpected}"


def test_patched_applications_are_silent(workspace: Path) -> None:
    spec = AppSpec(name="case-clean", bugs=(), users=("alice", "bob", "carol"), orders=6)
    result = run_application(spec, workspace, patched=True)
    assert result.detected == (), f"the patched application produced findings: {result.findings}"


def test_report_metrics() -> None:
    suite = build_suite(5, controls=1)
    report = run_suite(suite)
    assert report.total_expected == 5
    assert report.detection_rate == 1.0
    assert report.false_positives == 0
    assert report.unexpected_in_buggy_apps == 0
    payload = report.to_dict()
    assert payload["metrics"]["detection_rate"] == 1.0
    assert "detection rate" in report.to_markdown()
