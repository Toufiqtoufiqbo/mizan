"""Fail-closed validation.

A scan that could not authenticate every expected identity has not tested
anything. It must be reported as a setup error - never as a clean result.
"""

from __future__ import annotations

from pathlib import Path

from mizan.validation import _authenticate, _login, scan_application, validate_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "flask_store"


def test_a_wrong_password_is_a_setup_error_not_a_clean_scan(tmp_path: Path) -> None:
    result = scan_application(
        APP,
        variant="clean",
        budget=60,
        credentials={"alice": ("alice", "wrong-password"), "bob": ("bob", "bob-secret")},
    )
    assert result.setup_error is not None, "a failed authentication was not reported"
    assert "alice" in result.setup_error
    assert result.missing_identities == ["alice"]
    assert result.clean is False, "a scan without its identities was called clean"
    assert result.finding_count == 0, "a failed setup was reported as a finding"


def test_a_missing_principal_fails_closed(tmp_path: Path) -> None:
    result = scan_application(
        APP,
        variant="clean",
        budget=60,
        credentials={"alice": ("alice", "alice-secret")},
    )
    assert result.setup_error is not None
    assert result.missing_identities == ["bob"]
    assert result.clean is False


def test_an_empty_token_response_is_refused() -> None:
    """A token that is not a non-empty string is not a token."""
    from mizan.twin import Twin, TwinSpec, script_command

    root = Path(__file__).parent / "fixtures" / "external_apps" / "flask_store"
    workspace = Path(__file__).parent.parent.parent / ".pytest-auth"
    workspace.mkdir(parents=True, exist_ok=True)
    twin = Twin(
        TwinSpec(
            command=script_command(root / "app.py", "--db", str(workspace / "a.sqlite"), "--port", "{port}"),
            workdir=workspace,
            data_paths=[workspace / "a.sqlite"],
            health_path="/health",
            health_timeout=60.0,
        ),
        workspace=workspace / "twin",
    )
    twin.start()
    try:
        assert _login(twin.base_url, "alice", "wrong") is None
        token = _login(twin.base_url, "alice", "alice-secret")
        assert token and token.strip(), "the application issued an empty token"
    finally:
        twin.stop()


def test_the_authentication_reports_every_missing_identity() -> None:
    tokens, missing = _authenticate(
        "http://127.0.0.1:1", {"alice": ("alice", "x"), "bob": ("bob", "y")}, ["alice", "bob", "root"]
    )
    assert tokens == {}, "an unreachable application produced tokens"
    assert missing == ["alice", "bob", "root"]


def test_an_incomplete_identity_map_is_not_a_clean_result() -> None:
    """The identity map must cover every principal the scan uses."""
    result = scan_application(APP, variant="read", budget=60)
    assert result.setup_error is None
    assert result.requests.total > 0
    # Every finding names a principal that was authenticated.
    for finding in result.findings:
        assert finding["principal"] in {"alice", "bob"}


def test_the_gate_reports_a_setup_error_as_a_failure() -> None:
    result = validate_application(
        APP,
        budget=30,
        expected={"clean": ()},
        credentials={"alice": ("alice", "wrong-password"), "bob": ("bob", "bob-secret")},
    )
    assert result["passed"] is False
    failures = [item for item in result["checks"] if not item["passed"]]
    assert failures, "the gate passed a scan that never authenticated"
    assert any("setup error" in item["check"] for item in failures)


def test_a_setup_error_is_not_counted_as_a_finding() -> None:
    result = scan_application(
        APP,
        variant="clean",
        budget=60,
        credentials={"alice": ("alice", "wrong"), "bob": ("bob", "wrong")},
    )
    assert result.setup_error is not None
    assert result.finding_count == 0
    assert result.findings == []
