"""The launch contract: how an independent application is started.

The validation harness must be able to start an application it did not write -
a Python one and a Node.js one - with the same code. That is what the launch
contract is for, and these tests pin its behaviour down.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mizan.validation import (
    LAUNCH_EXPRESS,
    LAUNCH_FASTAPI,
    LAUNCH_FLASK,
    LaunchSpec,
    build_command,
    environment_for,
    launch_for,
    resolve_launch,
    scan_application,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "external_apps"


# --------------------------------------------------------------------------- #
# The registry
# --------------------------------------------------------------------------- #


def test_the_registry_knows_the_three_fixtures() -> None:
    assert launch_for(FIXTURES / "flask_store") is LAUNCH_FLASK
    assert launch_for(FIXTURES / "fastapi_store") is LAUNCH_FASTAPI
    assert launch_for(FIXTURES / "express_store") is LAUNCH_EXPRESS


def test_an_unknown_application_gets_no_specification() -> None:
    """Nothing is guessed: an unknown directory falls back to the convention."""
    assert launch_for(FIXTURES / "something_else") is None


def test_an_explicit_specification_always_wins() -> None:
    custom = LaunchSpec(command=["custom"])
    assert resolve_launch(FIXTURES / "express_store", custom) is custom
    assert resolve_launch(FIXTURES / "express_store") is LAUNCH_EXPRESS
    assert resolve_launch(FIXTURES / "something_else") is None


# --------------------------------------------------------------------------- #
# The command
# --------------------------------------------------------------------------- #


def test_the_command_resolves_every_placeholder() -> None:
    command = build_command(
        LAUNCH_EXPRESS,
        FIXTURES / "express_store",
        Path("/tmp/store.sqlite"),
        "write",
    )
    assert command[0].lower().endswith("node.exe") or command[0] == "node"
    assert command[1].endswith("server.js")
    assert "--db" in command and str(Path("/tmp/store.sqlite")) in command
    assert command[-2:] == ["--vulnerability", "write"]
    assert command.count("--vulnerability") == 1, "the variant flag must not be sent twice"
    # `{port}` is the twin's placeholder: it picks a free port and replaces it.
    assert [part for part in command if "{" in part] == ["{port}"]


def test_the_command_of_the_python_fixture_uses_the_current_interpreter() -> None:
    command = build_command(
        LAUNCH_FASTAPI,
        FIXTURES / "fastapi_store",
        Path("/tmp/store.sqlite"),
        "clean",
    )
    assert command[1].endswith("app.py")
    assert command[-2:] == ["--vulnerability", "clean"]


# --------------------------------------------------------------------------- #
# The environment
# --------------------------------------------------------------------------- #


def test_the_launch_specification_wins_over_the_ambient_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit configuration beats whatever the shell happens to export."""
    monkeypatch.setenv("MIZAN_TEST_ALICE", "from-the-environment")
    launch = LAUNCH_FASTAPI.with_environment({"MIZAN_TEST_ALICE": "from-the-specification"})
    assert environment_for(launch)["MIZAN_TEST_ALICE"] == "from-the-specification"


def test_the_ambient_environment_is_used_when_the_specification_is_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIZAN_TEST_ALICE", "from-the-environment")
    assert environment_for(LAUNCH_FASTAPI)["MIZAN_TEST_ALICE"] == "from-the-environment"


def test_with_environment_returns_a_copy() -> None:
    original = LAUNCH_FASTAPI
    changed = original.with_environment({"A": "B"})
    assert changed is not original
    assert original.environment is None
    assert changed.environment == {"A": "B"}


# --------------------------------------------------------------------------- #
# The workspace
# --------------------------------------------------------------------------- #


def test_the_workspace_is_removed_by_default() -> None:
    result = scan_application(FIXTURES / "flask_store", variant="clean", budget=20)
    assert result.error is None, result.error
    assert result.workspace is None
    assert "workspace" in result.to_dict()


def test_the_workspace_can_be_kept_for_a_replay() -> None:
    import shutil

    result = scan_application(
        FIXTURES / "flask_store",
        variant="read",
        budget=60,
        keep_workspace=True,
    )
    try:
        assert result.error is None, result.error
        assert result.workspace, "the workspace was not recorded"
        workspace = Path(result.workspace)
        assert workspace.exists()
        assert (workspace / "application.sqlite").exists()
        assert (workspace / "traffic.jsonl").exists()
    finally:
        if result.workspace:
            shutil.rmtree(result.workspace, ignore_errors=True)


def test_the_observer_sees_the_running_application() -> None:
    seen: list[object] = []
    result = scan_application(
        FIXTURES / "flask_store",
        variant="clean",
        budget=20,
        observer=seen.append,
    )
    assert result.error is None, result.error
    assert len(seen) == 1
    twin = seen[0]
    assert hasattr(twin, "base_url")
    assert twin.base_url.startswith("http://127.0.0.1:")


def test_a_failing_observer_does_not_hide_the_result() -> None:
    def broken(_twin: object) -> None:
        raise RuntimeError("the observer is broken")

    result = scan_application(FIXTURES / "flask_store", variant="clean", budget=20, observer=broken)
    assert result.error is not None
    assert "the observer failed" in result.error


def test_the_process_is_stopped_even_when_the_scan_fails() -> None:
    """A failed scan must not leave an application running."""
    import subprocess

    before = len(subprocess.run(["tasklist"], capture_output=True, text=True).stdout.splitlines())
    result = scan_application(FIXTURES / "flask_store", variant="write", budget=60)
    # Scan should produce L3 findings (cross-user write vulnerability)
    assert "L3" in result.law_types, f"expected L3 law type, got {result.law_types}"
    after = len(subprocess.run(["tasklist"], capture_output=True, text=True).stdout.splitlines())
    assert after <= before, "the application was left running"


def test_the_environment_of_a_scan_reaches_the_application() -> None:
    """The launch specification's environment is what the application reads."""
    launch = LAUNCH_FASTAPI.with_environment({"MIZAN_TEST_ALICE": "a-temporary-secret"})
    result = scan_application(
        FIXTURES / "fastapi_store",
        variant="clean",
        budget=20,
        credentials={"alice": ("alice", "a-temporary-secret"), "bob": ("bob", "bob-secret")},
        launch=launch,
    )
    assert result.setup_error is None, result.setup_error
    assert result.missing_identities == []


def test_a_wrong_password_is_a_setup_error_not_a_clean_result() -> None:
    """The gate is fail-closed: a failed authentication is never a pass."""
    result = scan_application(
        FIXTURES / "flask_store",
        variant="clean",
        budget=20,
        credentials={"alice": ("alice", "wrong"), "bob": ("bob", "wrong")},
    )
    assert result.setup_error is not None
    assert result.clean is False
    assert os.environ.get("STORE_VULNERABLE") is None
