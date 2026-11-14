"""Check a benchmark result against the expected matrix.

The benchmark is only worth something if its result can be checked by
something that did not produce it. This module is that check: it reads a
``results.json`` and says what is wrong with it, if anything.

    python -m benchmarks.cross_framework.check benchmarks/cross_framework/results/results.json
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def check_results(results: dict[str, Any]) -> list[str]:
    """The problems in a result set. An empty list means it is consistent."""
    problems: list[str] = []

    scenarios = results.get("scenarios") or []
    if not scenarios:
        return ["the result contains no scenario at all"]

    repetitions = results.get("repetitions") or 0
    frameworks = results.get("frameworks") or []
    variants = results.get("variants") or []
    if repetitions < 1:
        problems.append("the result claims zero repetitions")
    if not frameworks:
        problems.append("the result names no framework")
    if not variants:
        problems.append("the result names no variant")

    seen = Counter((item["framework"], item["variant"], item["repetition"]) for item in scenarios)
    for framework in frameworks:
        for variant in variants:
            for repetition in range(1, repetitions + 1):
                key = (framework, variant, repetition)
                count = seen.get(key, 0)
                if count != 1:
                    problems.append(f"{framework}/{variant}/repetition {repetition} ran {count} times, expected once")

    for item in scenarios:
        label = f"{item['framework']}/{item['variant']}/repetition {item['repetition']}"
        expected = sorted(item.get("expected_findings") or [])
        observed = sorted(item.get("observed_findings") or [])
        if expected != observed:
            problems.append(f"{label}: expected {expected}, observed {observed}")
        if item.get("outcome") != "expected":
            problems.append(f"{label}: the outcome is {item.get('outcome')!r}")
        if item.get("setup_errors"):
            problems.append(f"{label}: a setup error - {item['setup_errors']}")
        if item.get("errors"):
            problems.append(f"{label}: a scan error - {item['errors']}")
        if item.get("budget_exhausted"):
            problems.append(f"{label}: the request budget was exhausted, so the scan is incomplete")
        if item.get("missing_identities"):
            problems.append(f"{label}: the identities {item['missing_identities']} could not authenticate")
        if not item.get("evidence_complete", True):
            problems.append(f"{label}: a finding does not carry its evidence")
        reproduction = item.get("reproduction") or {}
        attempted = reproduction.get("attempted", 0)
        succeeded = reproduction.get("succeeded", 0)
        if attempted != succeeded:
            problems.append(f"{label}: {attempted - succeeded} of {attempted} findings could not be reproduced")
        expected_findings = len(expected)
        if attempted != expected_findings:
            problems.append(f"{label}: {attempted} findings were replayed, expected {expected_findings}")

    totals = results.get("totals") or {}
    if totals:
        if totals.get("scenarios_expected") != totals.get("scenarios"):
            problems.append(
                f"the totals say {totals.get('scenarios_expected')} of {totals.get('scenarios')} "
                "scenarios matched the expectation"
            )
        if totals.get("false_positives"):
            problems.append(f"{totals['false_positives']} false positives were reported")
        if totals.get("false_negatives"):
            problems.append(f"{totals['false_negatives']} false negatives were reported")
    return problems


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("usage: python -m benchmarks.cross_framework.check <results.json>", file=sys.stderr)
        return 2
    path = Path(argv[0])
    if not path.exists():
        print(f"the result file {path} does not exist", file=sys.stderr)
        return 2
    results = json.loads(path.read_text(encoding="utf-8"))
    problems = check_results(results)
    if problems:
        print(f"{len(problems)} problems:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    totals = results.get("totals") or {}
    print(
        "the result is consistent: "
        f"{totals.get('scenarios_expected')}/{totals.get('scenarios')} scenarios as expected, "
        f"{totals.get('reproduction_succeeded')}/{totals.get('reproduction_attempted')} findings reproduced"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
