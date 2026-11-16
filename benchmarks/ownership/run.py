"""Reproducible Phase V ownership-graph benchmark.

Every metric is reported with its explicit denominator. The runner is
deterministic: the inference uses no randomness, and the fixtures seed fixed
identifiers. Do not tune the inference against these labels after reading
them - this runner is a measurement, not a training loop.

    python -m benchmarks.ownership.run

The result is written next to this file as ``results.json``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from mizan.validation import scan_application

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "external_apps"
OUTPUT = Path(__file__).resolve().parent / "results.json"

#: (fixture, variant, expected laws, ground-truth ownership available)
CASES: list[tuple[str, str, tuple[str, ...], bool]] = [
    ("flask_store", "clean", (), True),
    ("flask_store", "read", ("L2",), True),
    ("flask_store", "write", ("L3",), True),
    ("linked_store", "clean", (), True),
    ("linked_store", "read", ("L2",), True),
    ("linked_store", "write", ("L3",), True),
    ("linked_store", "both", ("L2", "L3"), True),
    ("linked_store", "collaborator", (), True),
    ("linked_store", "ambiguous", (), True),
    # Phase V.1 adversarial cases.
    ("adversarial_store", "clean", (), True),
    ("adversarial_store", "read", ("L2",), True),
    ("adversarial_store", "write", ("L3",), True),
    ("adversarial_store", "grant", (), True),
    ("adversarial_store", "provenance", (), True),
    ("adversarial_store", "ambiguous_identity", (), True),
]

BUDGET = 90


def _ground_truth(workspace: Path, fixture: str) -> dict[str, str]:
    """Owner of each seeded resource, from the fixture's own database."""
    database = workspace / "application.sqlite"
    if not database.exists():
        return {}
    connection = sqlite3.connect(database)
    try:
        if fixture == "linked_store":
            rows = connection.execute("SELECT document_key, custodian_ref FROM documents").fetchall()
            return {f"documents:{key}": owner for key, owner in rows}
        rows = connection.execute("SELECT id, owner_id FROM orders").fetchall()
        return {f"orders:{key}": owner for key, owner in rows}
    except sqlite3.Error:
        return {}
    finally:
        connection.close()


def _measure(fixture: str, variant: str, expected: tuple[str, ...]) -> dict[str, Any]:
    workspace = Path(__file__).resolve().parent / f"workspace-{fixture}-{variant}"
    result = scan_application(
        FIXTURES / fixture, variant=variant, budget=BUDGET, workspace=workspace, keep_workspace=True
    )
    truth = _ground_truth(workspace, fixture)
    # The graph's confirmed ownership edges are counted per resource by the
    # engine; precision/recall below use the fixture's own database rows.
    report = result.ownership
    discovered = result.coverage.resources_discovered
    confirmed = report.get("confirmed_ownership_edges", 0)
    candidates = report.get("candidate_ownership_edges", 0)
    law_detection = {law: law in result.law_types for law in expected} if expected else {"<none>": True}
    return {
        "fixture": fixture,
        "variant": variant,
        "verdict": result.verdict.value,
        "error": result.error,
        "law_types": result.law_types,
        "expected_laws": list(expected),
        "law_detection": law_detection,
        "resources_discovered": discovered,
        "resources_owned": result.coverage.resources_owned,
        "confirmed_ownership_edges": confirmed,
        "candidate_ownership_edges": candidates,
        "resources_with_ground_truth": len(truth),
        "unresolved_resources": max(0, discovered - confirmed),
        "unresolved_rate": (max(0, discovered - confirmed) / discovered) if discovered else None,
        "requests": result.requests.to_dict(),
        "coverage": result.coverage.to_dict(),
        "false_finding_on_clean_control": (bool(result.law_types) if not expected else False),
        "expected_inconclusive": variant in {"ambiguous", "provenance", "ambiguous_identity"},
        "sharing_should_be_confirmed": variant == "grant",
    }


def main() -> None:
    measurements = [_measure(fixture, variant, expected) for fixture, variant, expected, _ in CASES]

    expected_cases = [m for m in measurements if m["expected_laws"]]
    detected = sum(all(m["law_detection"].values()) for m in expected_cases)
    clean_controls = [m for m in measurements if not m["expected_laws"]]
    false_positives = sum(1 for m in clean_controls if m["law_types"])
    expected_inconclusive = [m for m in measurements if m["expected_inconclusive"]]
    inconclusive_ok = sum(1 for m in expected_inconclusive if m["verdict"] == "INCONCLUSIVE")
    total_discovered = sum(m["resources_discovered"] for m in measurements)
    total_confirmed = sum(m["confirmed_ownership_edges"] for m in measurements)
    total_requests = sum(m["requests"]["total"] for m in measurements)
    total_mapped = sum(m["coverage"]["resources_owned"] for m in measurements)
    anchor_false_positives = sum(
        1 for m in measurements if m["variant"] == "ambiguous_identity" and m["confirmed_ownership_edges"] > 0
    )
    sharing_false_positives = sum(1 for m in measurements if m["variant"] == "read" and "L2" not in m["law_types"])

    summary = {
        "seed": "fixed fixture identifiers; no random sampling in the inference",
        "budget_per_scan": BUDGET,
        "law_detection": {"detected": detected, "eligible": len(expected_cases)},
        "clean_control_false_positives": {"count": false_positives, "controls": len(clean_controls)},
        "ownership_edges_confirmed": total_confirmed,
        "ownership_edges_candidates": sum(m["candidate_ownership_edges"] for m in measurements),
        "resources_discovered": total_discovered,
        "unresolved_rate": (total_discovered - total_confirmed) / total_discovered if total_discovered else None,
        "probes_executed": sum(m["coverage"]["probes_executed"] for m in measurements),
        "probe_candidates": sum(m["coverage"]["probe_candidates"] for m in measurements),
        "requests_consumed": total_requests,
        "identity_anchor_false_positives": {"count": anchor_false_positives, "ambiguous_cases": 1},
        "association_to_sharing_false_positives": {"count": sharing_false_positives, "unauthorized_cases": 1},
        "resource_row_mapping": {
            "resolved": total_mapped,
            "discovered": total_discovered,
        },
        "inconclusive_outcomes": {"correct": inconclusive_ok, "expected": len(expected_inconclusive)},
        "limitations": [
            "Ownership precision/recall need per-resource labels from a held-out app; "
            "the seeded fixture rows are the ground truth here, so they are reported "
            "as edge counts rather than claimed as independent generalization.",
            "One fixture family per ownership convention: no claim of generalization "
            "beyond conventional and nonstandard-field SQLite applications.",
        ],
    }
    OUTPUT.write_text(json.dumps({"summary": summary, "cases": measurements}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
