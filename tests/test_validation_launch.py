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


def _pid_alive(pid: int) -> bool:
    """Whether a specific process is still running - by identity, not by count."""
    import subprocess
    import sys

    if sys.platform == "win32":
        output = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in output
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # the process exists but belongs to someone else
    return True


def test_the_process_is_stopped_after_a_successful_scan() -> None:
    """A scan that finds something must still stop the application - by PID.

    Comparing operating-system-wide process counts proves nothing: any other
    process starting or stopping during the test changes the count. The
    identity of the launched process is what has to disappear.
    """
    pids: list[int] = []

    def observe(twin: object) -> None:
        # Capture the identity while the process is still running: Twin.stop()
        # clears its reference, so a PID read after the scan is always None.
        pids.append(twin.process.pid)  # type: ignore[attr-defined]

    result = scan_application(
        FIXTURES / "flask_store",
        variant="write",
        budget=60,
        observer=observe,
    )
    assert "L3" in result.law_types, f"expected L3 law type, got {result.law_types}"
    assert pids, "the observer never saw the application"
    assert _pid_alive(pids[0]) is False, f"the application process {pids[0]} was left running"


def test_the_process_is_stopped_even_when_the_scan_fails() -> None:
    """A scan whose observer raises must still stop the application - by PID."""
    pids: list[int] = []

    def broken(twin: object) -> None:
        # Record the identity first, then fail: the point is to prove that the
        # cleanup runs even when the scan itself did not.
        pids.append(twin.process.pid)  # type: ignore[attr-defined]
        raise RuntimeError("the observer is broken")

    result = scan_application(
        FIXTURES / "flask_store",
        variant="clean",
        budget=20,
        observer=broken,
    )
    # The scan failed, and the failure is reported.
    assert result.error is not None
    assert "the observer failed" in result.error
    # The application was stopped anyway.
    assert pids, "the observer never captured the application process"
    assert _pid_alive(pids[0]) is False, f"the application process {pids[0]} was left running after a failed scan"


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


# --------------------------------------------------------------------------- #
# Regression: the entry point comes from the specification, not from a guess
# --------------------------------------------------------------------------- #
#
# The first launch contract resolved the entry point by guessing a filename
# from the directory name ("express_store" -> server.js, everything else ->
# app.py) and *appended* the entry point when the guess did not match.  A
# Node.js application whose directory was not called ``express_store`` was
# started with the Python interpreter, and a Python fixture run from another
# working directory could not find its ``app.py`` at all - the process died
# with exit code 2 before the health check ever answered.  These tests pin the
# repaired behaviour: the ``{fixture}`` placeholder in the specification is the
# only source of the entry point.


def test_the_entry_point_is_resolved_against_the_fixture_directory() -> None:
    """The command must name the entry point by its absolute path."""
    command = build_command(LAUNCH_FLASK, FIXTURES / "flask_store", Path("db.sqlite"), "clean")
    assert command[1] == str(FIXTURES / "flask_store" / "app.py"), command
    assert Path(command[1]).is_absolute(), "a relative entry point breaks when the cwd changes"


def test_the_specification_does_not_guess_the_entry_point_from_the_directory() -> None:
    """An unknown directory must not silently get a Python entry point."""
    custom = LaunchSpec(command=["node", "{fixture}/server.js"])
    command = build_command(custom, FIXTURES / "something_else", Path("db.sqlite"), "clean")
    assert command[1] == str(FIXTURES / "something_else" / "server.js"), command


def test_the_launch_specification_carries_the_health_and_replay_contract() -> None:
    """Replay reopens the scan's database through the same specification.

    The cross-framework runner reads ``launch.database``, ``launch.health_path``
    and ``launch.health_timeout`` - fields the first specification did not
    carry, so every replay crashed before it started.
    """
    for name, launch in (
        ("fastapi", LAUNCH_FASTAPI),
        ("express", LAUNCH_EXPRESS),
        ("flask", LAUNCH_FLASK),
    ):
        assert launch.health_path == "/health", name
        assert launch.health_timeout > 0, name
        assert launch.database == "application.sqlite", name
        assert launch.spec_source is not None, name


def test_the_command_is_rebuilt_identically_for_the_replay() -> None:
    """Replay uses the same command the scan used - same executable, same entry point."""
    first = build_command(LAUNCH_EXPRESS, FIXTURES / "express_store", Path("db.sqlite"), "read")
    second = build_command(LAUNCH_EXPRESS, FIXTURES / "express_store", Path("db.sqlite"), "read")
    assert first == second
    assert Path(first[1]).name == "server.js"


def test_the_scan_and_the_replay_use_the_same_database_file() -> None:
    """The scan must write the database the replay reopens.

    The scan used to hardcode ``application.sqlite`` while the replay read
    ``launch.database``. The two names agreed by coincidence; a specification
    that named a different file would have made the replay open a database the
    scan never wrote - and the findings would silently fail to reproduce.
    """
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        result = scan_application(
            FIXTURES / "flask_store",
            variant="write",
            budget=60,
            workspace=workspace,
            keep_workspace=True,
        )
        try:
            assert result.error is None, result.error
            # The scan wrote the database the launch contract names.
            assert (workspace / LAUNCH_FLASK.database).exists(), sorted(path.name for path in workspace.iterdir())
            # And it is a real SQLite database, not a stand-in.
            header = (workspace / LAUNCH_FLASK.database).read_bytes()[:16]
            assert header.startswith(b"SQLite format 3"), header
        finally:
            shutil.rmtree(workspace, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Regression: the OpenAPI source
# --------------------------------------------------------------------------- #


def test_an_openapi_document_served_over_http_is_resolved() -> None:
    """A document that only exists at runtime is fetched, parsed and validated."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from mizan.validation import SpecSource, resolve_spec

    document = {"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {"/health": {"get": {}}}}
    payload = json.dumps(document).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the http.server API
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:  # keep the test output quiet
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        resolved = resolve_spec(
            SpecSource.from_url("/openapi.json"),
            fixture_dir=None,
            base_url=f"http://127.0.0.1:{server.server_port}",
        )
    finally:
        server.shutdown()
        server.server_close()
    assert resolved["openapi"].startswith("3.")
    assert resolved["paths"], "a document without paths teaches the engine nothing"


def test_a_missing_openapi_document_is_a_setup_error_never_a_clean_result() -> None:
    """The old behaviour returned a setup error for a missing file - keep it, from the source."""
    import pytest as _pytest

    from mizan.validation import SpecResolutionError, SpecSource, resolve_spec

    with _pytest.raises(SpecResolutionError):
        resolve_spec(
            SpecSource.from_file("{fixture}/openapi.json"),
            fixture_dir=FIXTURES / "fastapi_store",
            base_url="http://127.0.0.1:9",
        )


def test_an_unreachable_openapi_endpoint_is_a_setup_error() -> None:
    """A server that never exposes its document must fail the setup, loudly."""
    import pytest as _pytest

    from mizan.validation import SpecResolutionError, SpecSource, resolve_spec

    with _pytest.raises(SpecResolutionError):
        resolve_spec(
            SpecSource.from_url("/openapi.json", timeout=1.0),
            fixture_dir=None,
            base_url="http://127.0.0.1:9",
        )


def test_an_invalid_openapi_document_is_a_setup_error(tmp_path: Path) -> None:
    """Not every JSON document is an OpenAPI document."""
    import pytest as _pytest

    from mizan.validation import SpecResolutionError, SpecSource, resolve_spec

    invalid = tmp_path / "openapi.json"
    invalid.write_text('{"not": "openapi"}', encoding="utf-8")
    with _pytest.raises(SpecResolutionError):
        resolve_spec(SpecSource.from_file(str(invalid)))

    broken = tmp_path / "broken.json"
    broken.write_text("{not json at all", encoding="utf-8")
    with _pytest.raises(SpecResolutionError):
        resolve_spec(SpecSource.from_file(str(broken)))


# --------------------------------------------------------------------------- #
# Regression: request accounting
# --------------------------------------------------------------------------- #


def test_bootstrap_accounts_for_the_requests_actually_made() -> None:
    """The accounting counts sent requests, not the identities that were planned.

    The first implementation set ``bootstrap = len(required)`` before any login
    was attempted, so a scan whose credentials were never sent still reported
    two bootstrap requests.
    """
    from mizan.validation import _authenticate

    _tokens, _missing, attempted = _authenticate("http://127.0.0.1:1", {}, ["alice", "bob", "root"])
    assert attempted == 0, "credentials that were never configured must not be counted"


def test_a_budget_smaller_than_the_bootstrap_cannot_run_a_scan() -> None:
    """A budget the setup alone consumes must be reported as exhausted.

    The bootstrap (authentication) is setup traffic and runs before the budget
    gates the learning and attack phases. When it consumes the whole budget,
    the learning phase gets zero requests, the attack phase never starts, and
    the result says so instead of passing as a clean scan.
    """
    result = scan_application(
        FIXTURES / "flask_store",
        variant="clean",
        budget=1,
        credentials={"alice": ("alice", "alice-secret"), "bob": ("bob", "bob-secret")},
    )
    assert result.requests.bootstrap == 2, result.requests.to_dict()
    assert result.requests.learning == 0, result.requests.to_dict()
    assert result.requests.attack == 0, result.requests.to_dict()
    assert result.requests.budget_exhausted is True, result.requests.to_dict()
    assert result.clean is False, "a scan that never learned and never attacked is not clean"
