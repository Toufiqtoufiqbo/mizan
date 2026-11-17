"""Independent checker for the PostgreSQL ownership benchmark."""

from __future__ import annotations

from typing import Any


def check(results: dict[str, Any]) -> list[str]:
    """Return every deviation; an empty list means all scenarios matched."""
    problems: list[str] = []
    scenarios = results.get("scenarios", [])
    if not scenarios:
        return ["the benchmark produced no scenarios"]
    for scenario in scenarios:
        name = scenario["name"]
        expected = scenario["expected"]
        observed = scenario["observed"]
        for metric in ("findings", "inconclusive", "grant"):
            if observed.get(metric) != expected.get(metric):
                problems.append(f"{name}: {metric} expected {expected.get(metric)}, observed {observed.get(metric)}")
        if observed.get("status") == "skipped":
            problems.append(f"{name}: a skipped scenario cannot be counted as passed")
    return problems
