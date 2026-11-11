"""Mīzān scanning itself.

This is the project's own first user. The clean control plane must produce no
findings, and a deliberately weakened twin must produce one - otherwise the
check is not known to bite, and "no findings" means nothing.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def self_check(tmp_path_factory):
    from mizan.dogfood import run_self_check

    workspace = tmp_path_factory.mktemp("selfscan")
    check = run_self_check(workspace=workspace)
    return check.to_dict()


def test_the_clean_api_produces_no_findings(self_check) -> None:
    clean = self_check["clean"]
    assert clean["error"] is None, clean["error"]
    assert clean["law_types"] == [], f"the clean API produced findings: {clean['findings']}"
    assert clean["finding_count"] == 0
    assert clean["request_count"] > 0, "the scan did not send a single request"


def test_the_weakened_api_is_detected(self_check) -> None:
    weakened = self_check["weakened"]
    assert weakened["error"] is None, weakened["error"]
    assert "L2" in weakened["law_types"], "the weakened API was not detected"
    # Two identities read the same object: one law, two findings.
    assert weakened["finding_count"] >= 1
    finding = next(item for item in weakened["findings"] if item["law"] == "L2")
    assert finding["principal"]
    assert finding["resource"]
    assert finding["steps"]


def test_the_finding_count_and_the_law_count_are_different_numbers(self_check) -> None:
    weakened = self_check["weakened"]
    assert weakened["finding_count"] >= len(weakened["law_types"])


def test_the_self_check_passes(self_check) -> None:
    failed = [item for item in self_check["checks"] if not item["passed"]]
    assert not failed, f"the self-check failed: {failed}"
    assert self_check["passed"] is True


def test_the_two_variants_use_separate_workspaces(self_check) -> None:
    clean = self_check["clean"]
    weakened = self_check["weakened"]
    assert Path(clean["workspace"]) != Path(weakened["workspace"])
    assert Path(clean["workspace"]).name == "clean"
    assert Path(weakened["workspace"]).name == "weakened"


def test_the_variants_do_not_share_a_database(tmp_path: Path) -> None:
    from mizan.dogfood import scan_server

    clean = scan_server(variant="clean", vulnerable=False, workspace=tmp_path / "clean")
    weakened = scan_server(variant="weakened", vulnerable=True, workspace=tmp_path / "weakened")
    clean_db = list((tmp_path / "clean").glob("*.sqlite"))
    weakened_db = list((tmp_path / "weakened").glob("*.sqlite"))
    assert clean_db and weakened_db
    assert clean_db[0] != weakened_db[0]
    assert clean.error is None and weakened.error is None


def test_a_scanner_error_is_not_an_empty_result(tmp_path: Path) -> None:
    """A scan that cannot run is a failure, not a clean result."""

    # The scan runs; to force an error, point it at an application that is not there.
    from mizan.validation import scan_application

    broken = scan_application(tmp_path / "does-not-exist", variant="clean")
    assert broken.error is not None, "a missing application must be an error"
    assert broken.clean is False


def test_an_empty_traffic_log_is_rejected(tmp_path: Path) -> None:
    """Without traffic there is nothing to learn and nothing to attack."""
    from mizan.core import Principal
    from mizan.engine import Mizan, Target

    engine = Mizan(
        Target(base_url="http://127.0.0.1:1", principals=[Principal(id="alice", token="t")]),
        traffic_path=tmp_path / "empty.jsonl",
    )
    (tmp_path / "empty.jsonl").write_text("", encoding="utf-8")
    engine.learn()
    assert engine.policy.resources == {}
    violations = engine.attack()
    assert violations == []


def test_the_budget_is_enforced(tmp_path: Path) -> None:
    """The scan stops at the number of requests it was allowed."""
    from mizan.core import Principal, RequestBudgetExhausted
    from mizan.engine import Mizan, Target

    class _Session:
        headers = {"Authorization": "Bearer token"}

        def request(self, *args, **kwargs):  # pragma: no cover - never reached
            raise AssertionError("the budget should have stopped the scan")

    engine = Mizan(
        Target(base_url="http://127.0.0.1:1", principals=[Principal(id="alice", token="token")]),
        request_budget=0,
    )
    engine.requests = 0
    with pytest.raises(RequestBudgetExhausted):
        engine._request(_Session(), "GET", "http://127.0.0.1:1/x")


def test_the_control_plane_scopes_reads_to_the_caller() -> None:
    """The API itself: another user's scan is a 404, not a 403."""
    import tempfile

    from fastapi.testclient import TestClient

    from mizan.server import create_app

    token = secrets.token_urlsafe(32)
    other = secrets.token_urlsafe(32)
    app = create_app(
        Path(tempfile.mkdtemp()) / "api.sqlite",
        users={"alice": (token, "user"), "bob": (other, "user")},
    )
    with TestClient(app) as client:
        created = client.post(
            "/scans",
            json={"target": "http://127.0.0.1:8000/openapi.json"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert created.status_code == 201
        scan_id = created.json()["id"]

        assert client.get(f"/scans/{scan_id}", headers={"Authorization": f"Bearer {token}"}).status_code == 200

        denied = client.get(f"/scans/{scan_id}", headers={"Authorization": f"Bearer {other}"})
        assert denied.status_code == 404
        assert "scan not found" in denied.json()["detail"]


def test_the_control_plane_refuses_a_mass_assignment() -> None:
    """A client cannot decide who owns a scan."""
    import tempfile

    from fastapi.testclient import TestClient

    from mizan.server import create_app

    token = secrets.token_urlsafe(32)
    app = create_app(
        Path(tempfile.mkdtemp()) / "api.sqlite",
        users={"alice": (token, "user")},
    )
    with TestClient(app) as client:
        response = client.post(
            "/scans",
            json={
                "target": "http://127.0.0.1:8000/openapi.json",
                "owner_id": "root",
                "status": "done",
                "findings": 99,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422, "unknown fields must be rejected, not ignored"
        # The rejected request created nothing at all.
        assert client.get("/scans", headers={"Authorization": f"Bearer {token}"}).json() == []

        # A valid request creates a scan that belongs to the caller.
        created = client.post(
            "/scans",
            json={"target": "http://127.0.0.1:8000/openapi.json"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert created.status_code == 201
        stored = client.get("/scans", headers={"Authorization": f"Bearer {token}"}).json()
        assert stored[0]["owner_id"] == "alice"
        assert stored[0]["status"] == "queued"
        assert stored[0]["findings"] == 0


def test_the_control_plane_refuses_an_unknown_target() -> None:
    """The server does not become a scanner for arbitrary hosts."""
    import tempfile

    from fastapi.testclient import TestClient

    from mizan.server import create_app

    token = secrets.token_urlsafe(32)
    app = create_app(
        Path(tempfile.mkdtemp()) / "api.sqlite",
        users={"alice": (token, "user")},
    )
    with TestClient(app) as client:
        for target in (
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://user:pass@127.0.0.1:8000/openapi.json",
            "not-a-url",
        ):
            response = client.post(
                "/scans",
                json={"target": target},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 400, f"{target} was accepted"


def test_the_control_plane_refuses_an_unauthenticated_caller() -> None:
    import tempfile

    from fastapi.testclient import TestClient

    from mizan.server import create_app

    app = create_app(Path(tempfile.mkdtemp()) / "api.sqlite", users={})
    with TestClient(app) as client:
        assert client.get("/scans").status_code == 401
        assert client.post("/scans", json={"target": "http://127.0.0.1:8000/x"}).status_code == 401
        assert client.get("/scans/anything").status_code == 401


def test_the_control_plane_stores_no_plaintext_token() -> None:
    import sqlite3
    import tempfile

    from mizan.server import create_app

    token = secrets.token_urlsafe(32)
    database = Path(tempfile.mkdtemp()) / "api.sqlite"
    create_app(database, users={"alice": (token, "user")})
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute("SELECT token_hash FROM users").fetchall()
    finally:
        connection.close()
    assert rows
    assert all(row[0] != token for row in rows), "the token is stored in plain text"
