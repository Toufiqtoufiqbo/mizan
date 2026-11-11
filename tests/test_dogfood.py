"""Mīzān scanning itself.

This is the project's own first user. The clean control plane must produce no
findings, and a deliberately weakened twin must produce one - otherwise the
check is not known to bite, and "no findings" means nothing.
"""

from __future__ import annotations

import pytest


@pytest.fixture(scope="module")
def self_check(tmp_path_factory):
    from mizan.dogfood import run_self_check

    workspace = tmp_path_factory.mktemp("selfscan")
    return run_self_check(workspace=workspace)


def test_the_clean_api_produces_no_findings(self_check) -> None:
    clean = self_check["clean"]
    assert clean["error"] is None, clean["error"]
    assert clean["laws"] == [], f"the clean API produced findings: {clean['findings']}"
    assert clean["requests"] > 0, "the scan did not send a single request"


def test_the_weakened_api_is_detected(self_check) -> None:
    weakened = self_check["weakened"]
    assert weakened["error"] is None, weakened["error"]
    assert "L2" in weakened["laws"], "the weakened API was not detected"
    finding = next(item for item in weakened["findings"] if item["law"] == "L2")
    # A finding must say who did what to which object.
    assert finding["principal"]
    assert finding["resource"]
    assert finding["steps"]


def test_the_self_check_passes(self_check) -> None:
    assert self_check["passed"] is True


def test_the_control_plane_scopes_reads_to_the_caller() -> None:
    """The API itself: another user's scan is a 404, not a 403."""
    import tempfile
    from pathlib import Path

    from mizan.server import create_app
    from mizan.tokens import make_token

    app = create_app(Path(tempfile.mkdtemp()) / "api.sqlite")
    from fastapi.testclient import TestClient

    alice = make_token("alice")
    bob = make_token("bob")
    with TestClient(app) as client:
        created = client.post(
            "/scans",
            json={"target": "http://127.0.0.1:8000/openapi.json"},
            headers={"Authorization": f"Bearer {alice}"},
        )
        assert created.status_code == 201
        scan_id = created.json()["id"]

        # Alice sees her own scan.
        assert client.get(f"/scans/{scan_id}", headers={"Authorization": f"Bearer {alice}"}).status_code == 200

        # Bob does not - and the answer does not reveal that it exists.
        denied = client.get(f"/scans/{scan_id}", headers={"Authorization": f"Bearer {bob}"})
        assert denied.status_code == 404
        assert "scan not found" in denied.json()["detail"]


def test_the_control_plane_refuses_a_mass_assignment() -> None:
    """A client cannot decide who owns a scan."""
    import tempfile
    from pathlib import Path

    from mizan.server import create_app
    from mizan.tokens import make_token

    app = create_app(Path(tempfile.mkdtemp()) / "api.sqlite")
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.post(
            "/scans",
            json={
                "target": "http://127.0.0.1:8000/openapi.json",
                "owner_id": "root",
                "status": "done",
                "findings": 99,
            },
            headers={"Authorization": f"Bearer {make_token('alice')}"},
        )
        assert response.status_code == 201
        stored = client.get("/scans", headers={"Authorization": f"Bearer {make_token('alice')}"}).json()
        assert stored[0]["owner_id"] == "alice"
        assert stored[0]["status"] == "queued"
        assert stored[0]["findings"] == 0


def test_the_control_plane_refuses_an_unknown_target() -> None:
    """The server does not become a scanner for arbitrary hosts."""
    import tempfile
    from pathlib import Path

    from mizan.server import create_app
    from mizan.tokens import make_token

    app = create_app(Path(tempfile.mkdtemp()) / "api.sqlite")
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.post(
            "/scans",
            json={"target": "http://169.254.169.254/latest/meta-data/"},
            headers={"Authorization": f"Bearer {make_token('alice')}"},
        )
        assert response.status_code == 400
        assert "not allowed" in response.json()["detail"]
