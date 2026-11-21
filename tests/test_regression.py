"""Tests for the patch suggestions and the generated regression tests."""

from __future__ import annotations

import pytest

from mizan.core import Step, Violation
from mizan.patching import render, suggest
from mizan.regression import Attack, attack_succeeds, build_attack, render_test


def _violation(law: str = "L2") -> Violation:
    return Violation(
        law=law,
        title="alice read an object owned by bob",
        detail="the object was returned to somebody who does not own it",
        severity="high",
        principal="alice",
        resource="orders:o1",
        action="read",
        steps=[
            Step(
                method="GET",
                url="http://127.0.0.1:8000/orders/o1",
                headers={"Authorization": "Bearer token-alice"},
                status=200,
            )
        ],
    )


def test_patch_suggestion_exists_for_every_law() -> None:
    for law in ("L1", "L2", "L3", "L4", "L5"):
        suggestion = suggest(_violation(law))
        assert suggestion is not None, f"{law} has no suggestion"
        assert suggestion.diff.startswith("---")
        assert "where" in suggestion.to_dict()


def test_patch_render_mentions_the_regression_test() -> None:
    text = render(_violation("L3"))
    assert text is not None
    assert "regression test" in text


def test_regression_test_is_valid_python() -> None:
    source = render_test(_violation("L2"))
    compile(source, "test_mizan_l2.py", "exec")
    assert "def test_" in source
    assert "MIZAN_TOKEN_ALICE" in source
    assert "MIZAN_TARGET" in source


@pytest.mark.parametrize("law", ["L1", "L2", "L3", "L4", "L5"])
def test_regression_test_is_valid_python_for_every_law(law: str) -> None:
    compile(render_test(_violation(law)), f"test_mizan_{law.lower()}.py", "exec")


def test_regression_test_without_a_body_does_not_call_json_loads_on_none() -> None:
    violation = _violation("L2")
    violation.steps[0].body = None
    source = render_test(violation)
    compile(source, "test_mizan_l2.py", "exec")
    assert "BODY = None" in source
    assert "BODY = json.loads" not in source


def test_attack_is_built_from_the_first_step() -> None:
    attack = build_attack(_violation("L2"))
    assert attack is not None
    assert attack.method == "GET"
    assert attack.path == "/orders/o1"
    assert attack.token_var == "MIZAN_TOKEN_ALICE"
    assert attack.principal == "alice"


def test_attack_succeeds_against_a_vulnerable_target(workspace=None) -> None:
    import tempfile
    from pathlib import Path

    from mizan.benchmark.apps import BenchmarkApp, serve

    root = Path(tempfile.mkdtemp())
    app = BenchmarkApp(root / "db.sqlite", bugs=("idor_read",))
    server, port, _ = serve(app)
    try:
        attack = build_attack(_violation("L2"))
        assert attack is not None
        token = app.tokens()["alice"]
        # The attack reads somebody else's order - in the vulnerable app it works.
        assert attack_succeeds(attack, token, f"http://127.0.0.1:{port}") is False  # alice owns ord0
        other = Attack(
            law="L2",
            title="x",
            method="GET",
            path="/orders/ord1",
            token_var="MIZAN_TOKEN_ALICE",
            headers={"Authorization": "Bearer token"},
            body=None,
            expectation="rejected",
            principal="alice",
        )
        assert attack_succeeds(other, token, f"http://127.0.0.1:{port}") is True
    finally:
        server.shutdown()


def test_generated_test_fails_on_vulnerable_and_passes_on_fixed(tmp_path) -> None:
    """The generated pytest must behave like a real regression test."""
    import os
    import subprocess
    import sys

    from mizan.benchmark.apps import BenchmarkApp, serve

    test_file = tmp_path / "test_mizan_l4.py"

    # The child pytest must not depend on where it happens to be started: the
    # repository's own ini file would otherwise decide its rootdir, its
    # testpaths and its plugins. An isolated configuration makes the child's
    # behaviour the same everywhere.
    child_ini = tmp_path / "pytest.ini"
    child_ini.write_text("[pytest]\n", encoding="utf-8")

    def write_and_run(app, port) -> tuple[int, str]:
        violation = Violation(
            law="L4",
            title="alice created authority by writing `role`",
            detail="",
            severity="critical",
            principal="alice",
            resource="users:alice",
            action="write",
            steps=[
                Step(
                    method="PATCH",
                    url=f"http://127.0.0.1:{port}/users/me",
                    headers={"Authorization": f"Bearer {app.tokens()['alice']}"},
                    body={"role": "mizan-probe-role"},
                    status=200,
                )
            ],
        )
        test_file.write_text(render_test(violation), encoding="utf-8")
        env = dict(os.environ)
        env["MIZAN_TARGET"] = f"http://127.0.0.1:{port}"
        env["MIZAN_TOKEN_ALICE"] = app.tokens()["alice"]
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(test_file),
                "-q",
                "-p",
                "no:cacheprovider",
                "-c",
                str(child_ini),
                "--rootdir",
                str(tmp_path),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode, (result.stdout or "") + (result.stderr or "")

    vulnerable = BenchmarkApp(tmp_path / "vulnerable.sqlite", bugs=("mass_assignment",))
    server, port, _ = serve(vulnerable)
    try:
        code, output = write_and_run(vulnerable, port)
        # Pytest exit code 1 means "the tests ran and one of them failed".
        # Any other non-zero code means the harness itself broke - a usage
        # error, a collection error, no tests collected - and that must not be
        # mistaken for "the generated test correctly detected the bug".
        assert code == 1, (
            f"the generated test must FAIL while the vulnerability is present "
            f"(pytest exit code 1), got {code}:\n{output}"
        )
    finally:
        server.shutdown()

    fixed = BenchmarkApp(tmp_path / "fixed.sqlite", bugs=())
    server, port, _ = serve(fixed)
    try:
        code, output = write_and_run(fixed, port)
        assert code == 0, (
            f"the generated test must PASS once the vulnerability is fixed (pytest exit code 0), got {code}:\n{output}"
        )
    finally:
        server.shutdown()


def test_attack_is_blocked_by_the_fixed_application() -> None:
    import tempfile
    from pathlib import Path

    from mizan.benchmark.apps import BenchmarkApp, serve

    root = Path(tempfile.mkdtemp())
    app = BenchmarkApp(root / "db.sqlite", bugs=())
    server, port, _ = serve(app)
    try:
        attack = Attack(
            law="L2",
            title="x",
            method="GET",
            path="/orders/ord1",
            token_var="MIZAN_TOKEN_ALICE",
            headers={"Authorization": "Bearer token"},
            body=None,
            expectation="rejected",
            principal="alice",
        )
        assert attack_succeeds(attack, app.tokens()["alice"], f"http://127.0.0.1:{port}") is False
    finally:
        server.shutdown()
