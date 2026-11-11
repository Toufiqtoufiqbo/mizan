"""The guided search against the benchmark.

The search must find the same breaches as the fixed probes, and it must not
need more requests to do it.
"""

from __future__ import annotations

import pytest

from mizan.benchmark.evaluate import compare_modes


@pytest.fixture(scope="module")
def comparison(tmp_path_factory) -> dict:
    workspace = tmp_path_factory.mktemp("compare")
    return compare_modes(5, workspace=workspace)


def test_the_search_finds_every_breach(comparison: dict) -> None:
    assert comparison["applications"] == 5
    assert comparison["guided"]["detected"] == comparison["probes"]["detected"], (
        "the guided search found fewer breaches than the fixed probes"
    )


def test_the_search_needs_no_more_requests(comparison: dict) -> None:
    assert comparison["guided"]["average_requests"] <= comparison["probes"]["average_requests"], (
        "the guided search used more requests than the fixed probes"
    )


def test_the_search_does_not_invent_breaches(comparison: dict) -> None:
    for row in comparison["rows"]:
        assert set(row["guided"]["laws"]) == set(row["expected"]), (
            f"{row['application']}: the search reported {row['guided']['laws']}"
        )
