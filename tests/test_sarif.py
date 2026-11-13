"""Tests for the SARIF 2.1.0 export."""

from __future__ import annotations

import json
from pathlib import Path

from mizan.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    export_sarif,
    rule_id,
    to_sarif,
    validate_sarif,
)


def _bundle(root: Path, name: str, payload: dict, evidence: dict | None = None) -> Path:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "replay.json").write_text(json.dumps(payload), encoding="utf-8")
    if evidence is not None:
        (directory / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    return directory


PAYLOAD = {
    "law": "L2",
    "law_name": "Read authorization (read-taint)",
    "title": "alice read an object owned by bob",
    "detail": "The object was returned to somebody who does not own it.",
    "severity": "high",
    "principal": "alice",
    "resource": "orders:o2",
    "action": "read",
    "steps": [
        {
            "method": "GET",
            "url": "http://127.0.0.1:8000/orders/o2",
            "headers": {},
            "body": None,
            "status": 200,
            "note": "the cross-identity read",
        }
    ],
}


def test_the_document_is_sarif_2_1_0(tmp_path: Path) -> None:
    _bundle(tmp_path, "L2-alice", PAYLOAD)
    result = to_sarif([tmp_path / "L2-alice"])
    document = result.document
    assert document["version"] == SARIF_VERSION
    assert document["$schema"] == SARIF_SCHEMA
    assert validate_sarif(document) == []


def test_a_finding_becomes_a_result(tmp_path: Path) -> None:
    _bundle(tmp_path, "L2-alice", PAYLOAD, {"owner": "bob", "attacker_status": 200})
    document = to_sarif([tmp_path / "L2-alice"]).document
    run = document["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == rule_id("L2") == "MIZAN-L2"
    assert result["level"] == "error"
    assert result["message"]["text"] == PAYLOAD["title"]
    assert result["properties"]["principal"] == "alice"
    assert result["properties"]["resource"] == "orders:o2"
    assert result["properties"]["evidence"]["owner"] == "bob"
    assert result["properties"]["httpMethod"] == "GET"
    assert result["properties"]["reproduction"][0]["method"] == "GET"
    assert result["partialFingerprints"]["mizanFindingId"]


def test_the_rule_carries_the_severity_and_the_description(tmp_path: Path) -> None:
    _bundle(tmp_path, "L2-alice", PAYLOAD)
    document = to_sarif([tmp_path / "L2-alice"]).document
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "MIZAN-L2"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["shortDescription"]["text"]
    assert rule["properties"]["tags"]


def test_the_identifier_is_stable_between_runs(tmp_path: Path) -> None:
    _bundle(tmp_path, "L2-alice", PAYLOAD)
    first = to_sarif([tmp_path / "L2-alice"]).document
    second = to_sarif([tmp_path / "L2-alice"]).document
    assert (
        first["runs"][0]["results"][0]["partialFingerprints"] == second["runs"][0]["results"][0]["partialFingerprints"]
    )


def test_no_source_locations_are_invented(tmp_path: Path) -> None:
    _bundle(tmp_path, "L2-alice", PAYLOAD)
    document = to_sarif([tmp_path / "L2-alice"]).document
    assert "locations" not in document["runs"][0]["results"][0]


def test_an_incomplete_bundle_is_a_warning_not_a_crash(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    result = to_sarif([tmp_path / "empty"])
    assert result.warnings
    assert result.results == 0
    assert validate_sarif(result.document) == []


def test_a_broken_bundle_is_a_warning_not_a_crash(tmp_path: Path) -> None:
    directory = tmp_path / "broken"
    directory.mkdir()
    (directory / "replay.json").write_text("{not json", encoding="utf-8")
    result = to_sarif([directory])
    assert result.warnings
    assert result.results == 0


def test_the_export_writes_valid_json(tmp_path: Path) -> None:
    _bundle(tmp_path, "L2-alice", PAYLOAD)
    out = tmp_path / "out" / "findings.sarif"
    result = export_sarif(tmp_path, out)
    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded == result.document
    assert validate_sarif(loaded) == []


def test_the_export_handles_several_laws(tmp_path: Path) -> None:
    _bundle(tmp_path, "L2", PAYLOAD)
    _bundle(tmp_path, "L4", {**PAYLOAD, "law": "L4", "severity": "critical", "title": "mass assignment"})
    document = to_sarif([tmp_path / "L2", tmp_path / "L4"]).document
    rules = {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    assert rules == {"MIZAN-L2", "MIZAN-L4"}
    assert len(document["runs"][0]["results"]) == 2
    assert validate_sarif(document) == []


def test_the_validator_catches_a_broken_document() -> None:
    problems = validate_sarif({"version": "1.0", "runs": []})
    assert problems
