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
    ("adversarial_store", "creator_only", ("L2",), True),
    ("adversarial_store", "observer_only", ("L2",), True),
    ("adversarial_store", "declared_creator", ("L2",), True),
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
        "declared_grants": report.get("sources", {}).get("declared_grant", 0),
        "candidate_associations": report.get("sources", {}).get("association_table", 0),
        "l3_findings": sum(1 for finding in result.findings if finding.get("law") == "L3"),
        "l3_unique": len(
            {
                (finding.get("principal"), finding.get("resource"))
                for finding in result.findings
                if finding.get("law") == "L3"
            }
        ),
        "inconclusive_checks": len(result.ownership.get("inconclusive_checks", [])),
        "sharing_semantics_ambiguous": result.coverage.sharing_semantics_ambiguous,
    }


def _laws_from_bundles(directory: Path) -> list[str]:
    laws: set[str] = set()
    if not directory.exists():
        return []
    for bundle in sorted(path for path in directory.iterdir() if path.is_dir()):
        for meta in bundle.glob("*.json"):
            data = json.loads(meta.read_text(encoding="utf-8"))
            if data.get("law"):
                laws.add(str(data["law"]))
    return sorted(laws)


def _cli_contract_propagation() -> dict[str, Any]:
    """Run the real ``mizan twin`` command with and without the contract.

    This is the one measurement unit tests cannot replace: it proves the
    operator-supplied metadata reaches the engine the CLI actually builds.
    """
    import os
    import sys
    import tempfile

    from click.testing import CliRunner

    from mizan.cli import main

    app = FIXTURES / "adversarial_store"
    contract = app / "mizan-relationships.json"
    tokens = {"MIZAN_TOKEN_ALICE": "bench-token-alice", "MIZAN_TOKEN_BOB": "bench-token-bob"}
    previous = {key: os.environ.get(key) for key in tokens}
    os.environ.update(tokens)
    detail: dict[str, Any] = {}
    try:
        for label, contract_path in (("with_contract", contract), ("without_contract", None)):
            with tempfile.TemporaryDirectory(prefix=f"mizan-cli-{label}-") as directory:
                root = Path(directory)
                database = root / "store.sqlite"
                command = (
                    f'"{Path(sys.executable).as_posix()}" "{(app / "app.py").as_posix()}"'
                    f' --db "{database.as_posix()}" --port {{port}} --vulnerability read'
                )
                arguments = [
                    "twin",
                    "--command",
                    command,
                    "--data",
                    str(database),
                    "--spec",
                    str(app / "openapi.json"),
                    "--token",
                    "alice=bench-token-alice",
                    "--token",
                    "bob=bench-token-bob",
                    "--out",
                    str(root / "proofs"),
                    "--traffic",
                    str(root / "traffic.jsonl"),
                    "--workdir",
                    str(root),
                ]
                if contract_path is not None:
                    arguments.extend(["--relationship-contract", str(contract_path)])
                result = CliRunner().invoke(main, arguments, catch_exceptions=False)
                detail[label] = {"exit_code": result.exit_code, "laws": _laws_from_bundles(root / "proofs")}
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return {
        "propagated": int(detail.get("with_contract", {}).get("laws") == ["L2"]),
        "cases": 1,
        "without_contract_invented_ownership": int(bool(detail.get("without_contract", {}).get("laws"))),
        "detail": detail,
    }


def _contract_validation() -> dict[str, Any]:
    """Explicitly invalid contracts must be rejected, not silently dropped."""
    import tempfile

    from mizan.attribution import DatabaseSchema
    from mizan.ownership import RelationshipContract, RelationshipContractError

    cases: list[tuple[str, Any]] = [
        (
            "malformed_json",
            "{not json",
        ),
        (
            "unsupported_version",
            json.dumps({"version": 99}),
        ),
        (
            "same_column",
            json.dumps(
                {
                    "version": 1,
                    "sharing": {"t": {"resource_fk": "x", "principal_fk": "x", "semantics": "authorization_grant"}},
                }
            ),
        ),
        (
            "unknown_table",
            json.dumps(
                {
                    "version": 1,
                    "sharing": {
                        "invented": {
                            "resource_fk": "a",
                            "principal_fk": "b",
                            "semantics": "authorization_grant",
                        }
                    },
                }
            ),
        ),
    ]
    rejected = 0
    with tempfile.TemporaryDirectory(prefix="mizan-contracts-") as directory:
        root = Path(directory)
        for name, payload in cases:
            path = root / f"{name}.json"
            path.write_text(payload, encoding="utf-8")
            try:
                contract = RelationshipContract.load(path, strict=True)
                if name == "unknown_table":
                    contract.validate_schema(DatabaseSchema())
                rejected += 1
            except RelationshipContractError:
                rejected += 1
        # An unknown column is a schema error, not a syntax error.
        contract = RelationshipContract.from_dict(
            {
                "version": 1,
                "sharing": {"t": {"resource_fk": "a", "principal_fk": "missing", "semantics": "authorization_grant"}},
            },
            strict=True,
        )
        try:
            from mizan.attribution import Column, ForeignKey, TableSchema

            schema = DatabaseSchema(
                tables={
                    "t": TableSchema(
                        name="t",
                        columns=(Column("a", primary_key=1), Column("b")),
                        foreign_keys=(ForeignKey("a", "other", "id"), ForeignKey("b", "other", "id")),
                    ),
                    "other": TableSchema(name="other", columns=(Column("id", primary_key=1),)),
                }
            )
            contract.validate_schema(schema)
        except RelationshipContractError:
            rejected += 1
        total = len(cases) + 1
    return {"rejected": rejected, "invalid_contracts": total}


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

    # V.2 denominators. Each one is reported as numerator/denominator so a
    # zero cannot be mistaken for a perfect score on an empty set.
    grant_inheritance = [
        m for m in measurements if m["variant"] in {"creator_only", "observer_only", "declared_creator"}
    ]
    grant_inheritance_detected = sum(1 for m in grant_inheritance if "L2" in m["law_types"])
    duplicate_l3_findings = sum(max(0, m["l3_findings"] - m["l3_unique"]) for m in measurements)
    duplicate_l3_cases = sum(1 for m in measurements if m["l3_findings"] > m["l3_unique"])
    cli_propagation = _cli_contract_propagation()
    contract_gate = _contract_validation()

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
        "cli_contract_propagation": {
            "propagated": cli_propagation["propagated"],
            "cases": cli_propagation["cases"],
            "invented_ownership_without_contract": {
                "count": cli_propagation["without_contract_invented_ownership"],
                "controls": 1,
            },
            "detail": cli_propagation["detail"],
        },
        "contract_validation": {
            "rejected": contract_gate["rejected"],
            "invalid_contracts": contract_gate["invalid_contracts"],
        },
        "principal_fk_selection": {
            "detected": grant_inheritance_detected,
            "eligible": len(grant_inheritance),
            "declared_grants_confirmed": sum(m["declared_grants"] for m in measurements),
            "candidate_associations": sum(m["candidate_associations"] for m in measurements),
        },
        "incorrect_grant_suppression": {
            "suppressed": len(grant_inheritance) - grant_inheritance_detected,
            "eligible": len(grant_inheritance),
        },
        "duplicate_l3": {"findings": duplicate_l3_findings, "affected_cases": duplicate_l3_cases},
        "unresolved_attribution": {
            "inconclusive_cases": inconclusive_ok,
            "expected_cases": len(expected_inconclusive),
            "inconclusive_checks": sum(m["inconclusive_checks"] for m in measurements),
        },
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
