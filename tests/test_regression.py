"""Tests for the patch suggestions and the generated regression tests."""

from __future__ import annotations

import tempfile

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


def test_regression_test_without_a_body_replays_it_as_no_body() -> None:
    violation = _violation("L2")
    violation.evidence = {"owner": "bob", "object": "orders:o1"}
    violation.steps[0].body = None
    source = render_test(violation)
    compile(source, "test_mizan_l2.py", "exec")
    assert 'json=step.get("body") or {}' in source
    assert "'body': None" in source


def test_generated_write_regression_uses_the_real_http_method() -> None:
    """A generated L3 regression must replay the recorded write method.

    The write branch of the renderer used a non-f-string template, producing
    a literal ``{ATTACK.METHOD}`` that urllib3 rejects as an invalid method.
    """
    violation = _violation("L3")
    violation.evidence = {
        "owner": "bob",
        "event": {"columns": {"label": "mizan-probe-x"}},
        "verification_path": "/items/o1",
    }
    violation.steps[0].method = "PUT"
    violation.steps[0].body = {"label": "mizan-probe-x"}
    attack = build_attack(violation)
    assert attack is not None and attack.method == "PUT"
    source = render_test(violation)
    compile(source, "test_mizan_l3.py", "exec")
    assert "'method': 'PUT'" in source
    assert "requests.request(method, url" in source
    assert "{ATTACK.METHOD}" not in source
    assert "{attack.method}" not in source


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
            owner="bob",
            object_id="ord1",
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
            evidence={
                "field": "role",
                "sentinel": "mizan-probe-role",
                "event": {"columns": {"role": "mizan-probe-role"}},
                "verification_path": "/me",
            },
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


def _jwt_for(subject: str) -> str:
    import base64
    import json

    payload = base64.urlsafe_b64encode(json.dumps({"sub": subject}).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


def test_secure_l1_authenticated_200_does_not_fail() -> None:
    """A valid authenticated 200 is not an authentication breach."""
    from mizan.benchmark.apps import BenchmarkApp, serve

    app = BenchmarkApp(tempfile.mkdtemp() + "/db.sqlite", bugs=())
    server, port, _ = serve(app)
    try:
        violation = Violation(
            law="L1",
            title="identity coherence",
            detail="",
            principal="alice",
            steps=[
                Step(
                    method="GET",
                    url=f"http://127.0.0.1:{port}/me",
                    headers={"Authorization": "Bearer token"},
                    status=200,
                )
            ],
            evidence={"token_subject": "alice"},
        )
        attack = build_attack(violation)
        assert attack is not None
        assert attack_succeeds(attack, app.tokens()["alice"], f"http://127.0.0.1:{port}") is False
    finally:
        server.shutdown()


def test_vulnerable_l2_is_detected_from_disclosed_object() -> None:
    from mizan.benchmark.apps import BenchmarkApp, serve

    app = BenchmarkApp(tempfile.mkdtemp() + "/db.sqlite", bugs=("idor_read",))
    server, port, _ = serve(app)
    try:
        violation = Violation(
            law="L2",
            title="cross identity read",
            detail="",
            principal="alice",
            resource="orders:ord1",
            evidence={"owner": "bob", "object": "orders:ord1"},
            steps=[
                Step(
                    method="GET",
                    url=f"http://127.0.0.1:{port}/orders/ord1",
                    headers={"Authorization": "Bearer token"},
                    status=200,
                )
            ],
        )
        attack = build_attack(violation)
        assert attack is not None and attack.supported
        assert attack_succeeds(attack, app.tokens()["alice"], f"http://127.0.0.1:{port}") is True
    finally:
        server.shutdown()


def test_blocked_l2_is_not_reported_as_vulnerable() -> None:
    from mizan.benchmark.apps import BenchmarkApp, serve

    app = BenchmarkApp(tempfile.mkdtemp() + "/db.sqlite", bugs=())
    server, port, _ = serve(app)
    try:
        attack = Attack(
            law="L2",
            title="blocked read",
            method="GET",
            path="/orders/ord1",
            token_var="MIZAN_TOKEN_ALICE",
            headers={},
            body=None,
            expectation="the caller does not receive an object owned by somebody else",
            principal="alice",
            owner="bob",
            object_id="ord1",
            steps=[{"method": "GET", "path": "/orders/ord1", "principal": "alice"}],
        )
        assert attack_succeeds(attack, app.tokens()["alice"], f"http://127.0.0.1:{port}") is False
    finally:
        server.shutdown()


def test_l4_preserves_the_original_http_method() -> None:
    violation = Violation(
        law="L4",
        title="authority creation",
        detail="",
        principal="alice",
        steps=[
            Step(
                method="POST",
                url="http://127.0.0.1:8000/users",
                headers={"Authorization": "Bearer token"},
                body={"role": "mizan-probe-role"},
                status=200,
            )
        ],
        evidence={
            "event": {"columns": {"role": "mizan-probe-role"}},
            "verification_path": "/me",
        },
    )
    attack = build_attack(violation)
    assert attack is not None
    assert attack.method == "POST"
    source = render_test(violation)
    assert "'method': 'POST'" in source
    assert "'method': 'PATCH'" not in source


def test_echoed_value_alone_cannot_prove_privileged_state_change() -> None:
    """Without state evidence a regression must be unsupported, not a fake pass."""
    violation = Violation(
        law="L4",
        title="authority creation",
        detail="",
        principal="alice",
        steps=[
            Step(
                method="PATCH",
                url="http://127.0.0.1:8000/users/me",
                headers={"Authorization": "Bearer token"},
                body={"role": "mizan-probe-role"},
                status=200,
            )
        ],
        evidence={"status": 200, "response_echo": "mizan-probe-role"},
    )
    attack = build_attack(violation)
    assert attack is not None
    assert attack.supported is False
    assert "state evidence" in attack.unsupported_reason or "verification" in attack.unsupported_reason
    source = render_test(violation)
    assert "SUPPORTED = False" in source
    assert "pytest.skip" in source


def test_persisted_privileged_state_change_is_detected() -> None:
    from mizan.benchmark.apps import BenchmarkApp, serve

    app = BenchmarkApp(tempfile.mkdtemp() + "/db.sqlite", bugs=("mass_assignment",))
    server, port, _ = serve(app)
    try:
        violation = Violation(
            law="L4",
            title="authority creation",
            detail="",
            principal="alice",
            steps=[
                Step(
                    method="PATCH",
                    url=f"http://127.0.0.1:{port}/users/me",
                    headers={"Authorization": "Bearer token"},
                    body={"role": "mizan-probe-role"},
                    status=200,
                )
            ],
            evidence={
                "event": {"columns": {"role": "mizan-probe-role"}},
                "verification_path": "/me",
            },
        )
        attack = build_attack(violation)
        assert attack is not None and attack.supported
        assert attack_succeeds(attack, app.tokens()["alice"], f"http://127.0.0.1:{port}") is True
    finally:
        server.shutdown()


def test_multi_step_proof_preserves_the_full_sequence() -> None:
    violation = Violation(
        law="L3",
        title="two step cross identity write",
        detail="",
        principal="alice",
        evidence={
            "owner": "bob",
            "event": {"columns": {"label": "mizan-probe-x"}},
            "verification_path": "/items/o1",
        },
        steps=[
            Step(method="POST", url="http://127.0.0.1:8000/login", headers={}, body={"username": "alice"}, status=200),
            Step(
                method="PUT",
                url="http://127.0.0.1:8000/items/o1",
                headers={"Authorization": "Bearer token"},
                body={"label": "mizan-probe-x"},
                status=200,
            ),
        ],
    )
    attack = build_attack(violation)
    assert attack is not None
    assert len(attack.steps) == 2
    assert [step["method"] for step in attack.steps] == ["POST", "PUT"]
    source = render_test(violation)
    assert "def _replay()" in source
    assert "for step in STEPS" in source
    assert "'method': 'POST'" in source and "'method': 'PUT'" in source


def test_insufficient_evidence_is_explicitly_unsupported() -> None:
    violation = Violation(
        law="L2",
        title="cross identity read",
        detail="",
        principal="alice",
        steps=[Step(method="GET", url="http://127.0.0.1:8000/orders/o1", headers={}, status=200)],
    )
    attack = build_attack(violation)
    assert attack is not None
    assert attack.supported is False
    assert attack.unsupported_reason
    source = render_test(violation)
    assert "SUPPORTED = False" in source
    assert "pytest.skip" in source


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
