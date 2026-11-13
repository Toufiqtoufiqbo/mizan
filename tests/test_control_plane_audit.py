"""The control plane and the SARIF export, audited.

Two things are checked here: that the control plane really keeps its promises
(ownership, path traversal, strict validation, the target rules), and that the
SARIF export does not leak anything it should not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mizan.sarif import RULES, export_sarif, rule_id, to_sarif, validate_sarif
from mizan.server import create_app, validate_target

# --------------------------------------------------------------------------- #
# The control plane
# --------------------------------------------------------------------------- #


def _app(root: Path, tokens: dict[str, str]):
    return create_app(
        root / "api.sqlite",
        users={name: (token, "user") for name, token in tokens.items()},
        bundle_root=root / "bundles",
    )


def test_the_bundle_endpoint_does_not_escape_its_root(tmp_path: Path) -> None:
    token = "token-alice"
    app = _app(tmp_path, {"alice": token})
    bundles = tmp_path / "bundles"
    (bundles / "scan-1").mkdir(parents=True)
    (bundles / "scan-1" / "replay.json").write_text('{"law": "L2"}', encoding="utf-8")
    secret = tmp_path / "secret.json"
    secret.write_text('{"law": "L9"}', encoding="utf-8")

    with TestClient(app) as client:
        response = client.get("/scans/scan-1/bundle", headers={"Authorization": f"Bearer {token}"})
        # The scan does not exist, so there is no bundle - and nothing else.
        assert response.status_code == 404

        traversal = client.get("/scans/..%2F..%2Fsecret/bundle", headers={"Authorization": f"Bearer {token}"})
        assert traversal.status_code in {404, 400}
        assert "L9" not in traversal.text


def test_the_bundle_of_another_user_is_not_served(tmp_path: Path) -> None:
    alice, bob = "token-alice", "token-bob"
    app = _app(tmp_path, {"alice": alice, "bob": bob})
    with TestClient(app) as client:
        created = client.post(
            "/scans",
            json={"target": "http://127.0.0.1:8000/openapi.json"},
            headers={"Authorization": f"Bearer {alice}"},
        )
        scan_id = created.json()["id"]
        bundles = tmp_path / "bundles" / scan_id
        bundles.mkdir(parents=True)
        (bundles / "replay.json").write_text('{"law": "L2"}', encoding="utf-8")

        assert client.get(f"/scans/{scan_id}/bundle", headers={"Authorization": f"Bearer {alice}"}).status_code == 200
        assert client.get(f"/scans/{scan_id}/bundle", headers={"Authorization": f"Bearer {bob}"}).status_code == 404


def test_an_unknown_field_in_a_finding_is_rejected(tmp_path: Path) -> None:
    token = "token-alice"
    app = _app(tmp_path, {"alice": token})
    with TestClient(app) as client:
        created = client.post(
            "/scans",
            json={"target": "http://127.0.0.1:8000/openapi.json"},
            headers={"Authorization": f"Bearer {token}"},
        )
        scan_id = created.json()["id"]
        response = client.post(
            f"/scans/{scan_id}/findings",
            json={
                "law": "L2",
                "title": "a finding",
                "severity": "high",
                "owner_id": "root",
                "id": "finding-1",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422, "unknown fields must be rejected"


def test_the_target_rules() -> None:
    for target in (
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        "http://user:pass@127.0.0.1:8000/openapi.json",
        "not-a-url",
        "http://[::1]:8000/openapi.json",
    ):
        with pytest.raises(Exception) as error:
            validate_target(target)
        assert "not allowed" in str(error.value) or "credentials" in str(error.value), target


def test_the_ipv6_form_is_understood(tmp_path: Path, monkeypatch) -> None:
    import mizan.server as server

    monkeypatch.setattr(server, "ALLOWED_TARGET_HOSTS", ("::1",))
    assert validate_target("http://[::1]:8000/openapi.json")


def test_a_queued_scan_is_not_claimed_to_be_running(tmp_path: Path) -> None:
    """The API must not pretend that it scans."""
    token = "token-alice"
    app = _app(tmp_path, {"alice": token})
    with TestClient(app) as client:
        created = client.post(
            "/scans",
            json={"target": "http://127.0.0.1:8000/openapi.json"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert created.status_code == 201
        assert created.json()["status"] == "queued"
        stored = client.get("/scans", headers={"Authorization": f"Bearer {token}"}).json()
        assert stored[0]["status"] == "queued"
        assert stored[0]["findings"] == 0


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #


def test_the_validator_is_structural_and_says_so() -> None:
    """The validator checks the structure, not the full schema."""
    from mizan import sarif

    assert "structure" in (sarif.validate_sarif.__doc__ or "").lower()
    assert sarif.validate_sarif({"version": "2.1.0", "runs": []})


def test_the_export_contains_no_secret(tmp_path: Path) -> None:
    bundle = tmp_path / "L2-alice"
    bundle.mkdir()
    (bundle / "replay.json").write_text(
        json.dumps(
            {
                "law": "L2",
                "title": "a finding",
                "severity": "high",
                "principal": "alice",
                "resource": "orders:o2",
                "action": "read",
                "steps": [
                    {
                        "method": "GET",
                        "url": "http://127.0.0.1:8000/orders/o2",
                        "headers": {"Authorization": "Bearer ${MIZAN_TOKEN_ALICE}"},
                        "body": None,
                        "status": 200,
                        "note": "",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "findings.sarif"
    export_sarif(tmp_path, out)
    text = out.read_text(encoding="utf-8")
    assert "MIZAN_TOKEN_ALICE" in text or "token" not in text.lower()
    assert "eyJ" not in text, "the export contains something that looks like a token"


def test_the_severity_mapping() -> None:
    from mizan.sarif import _rule

    assert _rule("L4", "critical")["defaultConfiguration"]["level"] == "error"
    assert _rule("L4", "high")["defaultConfiguration"]["level"] == "error"
    assert _rule("L2", "medium")["defaultConfiguration"]["level"] == "warning"
    assert _rule("L2", "low")["defaultConfiguration"]["level"] == "note"
    assert _rule("L2", "unknown-severity")["defaultConfiguration"]["level"] == "warning"


def test_the_rule_identifiers_are_stable() -> None:
    assert rule_id("L2") == "MIZAN-L2"
    assert rule_id("L4") == "MIZAN-L4"
    assert set(RULES) == {"L1", "L2", "L3", "L4", "L5", "L6", "L7"}


def test_multiple_results_and_missing_evidence(tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    (first / "replay.json").write_text(json.dumps({"law": "L2", "title": "a", "severity": "high"}), encoding="utf-8")
    (second / "replay.json").write_text(json.dumps({"law": "L4", "title": "b", "severity": "low"}), encoding="utf-8")
    document = to_sarif([first, second]).document
    assert len(document["runs"][0]["results"]) == 2
    assert validate_sarif(document) == []
    # A finding without evidence is still a finding - it simply has no evidence.
    result = next(r for r in document["runs"][0]["results"] if r["ruleId"] == "MIZAN-L4")
    assert "evidence" not in result["properties"]


def test_an_unknown_law_still_produces_a_rule(tmp_path: Path) -> None:
    bundle = tmp_path / "odd"
    bundle.mkdir()
    (bundle / "replay.json").write_text(json.dumps({"law": "L9", "title": "odd"}), encoding="utf-8")
    document = to_sarif([bundle]).document
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "MIZAN-L9"
    assert validate_sarif(document) == []
