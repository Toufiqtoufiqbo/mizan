"""Independent validation: Mīzān against an application that knows nothing about it.

The application in `tests/fixtures/external_apps/flask_store` has its own
authentication, its own database and its own OpenAPI document. It does not
import Mīzān, and Mīzān only reaches it through ordinary HTTP.

The test proves both directions:

* the **clean** variant must produce no finding at all;
* the **vulnerable** variant must produce the expected finding, with evidence
  that names the principal, the endpoint and the resource.

It is a controlled validation target. It is **not** a claim that an external
customer has adopted Mīzān.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mizan.validation import validate_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "flask_store"


@pytest.fixture(scope="module")
def validation(tmp_path_factory) -> dict:
    workspace = tmp_path_factory.mktemp("external")
    return validate_application(APP, workspace=workspace, expected_laws=("L2", "L3"))


def test_the_clean_application_is_clean(validation: dict) -> None:
    clean = validation["clean"]
    assert clean["error"] is None, clean["error"]
    assert clean["request_count"] > 0, "the scan sent no request at all"
    assert clean["finding_count"] == 0, f"the clean application produced findings: {clean['findings']}"


def test_the_vulnerable_application_is_detected(validation: dict) -> None:
    vulnerable = validation["vulnerable"]
    assert vulnerable["error"] is None, vulnerable["error"]
    assert vulnerable["request_count"] > 0
    assert "L2" in vulnerable["law_types"], f"the cross-user read was missed: {vulnerable}"
    assert "L3" in vulnerable["law_types"], f"the cross-user write was missed: {vulnerable}"


def test_every_finding_identifies_principal_endpoint_and_resource(validation: dict) -> None:
    vulnerable = validation["vulnerable"]
    assert vulnerable["findings"], "there is nothing to check"
    for finding in vulnerable["findings"]:
        assert finding["principal"], "a finding without a principal"
        assert finding["resource"], "a finding without a resource"
        steps = finding["steps"]
        assert steps, "a finding without reproduction steps"
        assert steps[0]["method"], "a reproduction step without a method"
        assert steps[0]["url"], "a reproduction step without an endpoint"
        assert finding["evidence"], "a finding without evidence"


def test_the_evidence_names_the_owner(validation: dict) -> None:
    vulnerable = validation["vulnerable"]
    owners = [
        finding.get("evidence", {}).get("owner")
        or finding.get("evidence", {}).get("row_owner")
        or finding.get("evidence", {}).get("event", {}).get("row_owner")
        for finding in vulnerable["findings"]
    ]
    assert any(owners), "no finding says who owns the affected object"


def test_every_check_of_the_validation_gate_passes(validation: dict) -> None:
    failed = [item for item in validation["checks"] if not item["passed"]]
    assert not failed, f"the validation gate failed: {failed}"
    assert validation["passed"] is True


def test_the_application_does_not_import_mizan() -> None:
    """The fixture must stay independent of Mizan."""
    import ast

    source = (APP / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not [name for name in imported if name.split(".")[0] == "mizan"], imported


def test_the_application_uses_its_own_authentication() -> None:
    """Its tokens are opaque and random - not Mizan's JWT-shaped ones."""
    import tempfile

    from mizan.twin import Twin, TwinSpec, script_command
    from mizan.validation import _login

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        twin = Twin(
            TwinSpec(
                command=script_command(APP / "app.py", "--db", str(root / "s.sqlite"), "--port", "{port}"),
                workdir=root,
                data_paths=[root / "s.sqlite"],
                health_path="/health",
                health_timeout=60.0,
            ),
            workspace=root / "twin",
        )
        twin.start()
        try:
            token = _login(twin.base_url, "alice", "alice-secret")
            assert token and "." not in token, "the application issues a JWT-shaped token"
            assert len(token) >= 20, "the token is too short to be random"
        finally:
            twin.stop()


def test_a_wrong_password_is_refused() -> None:
    """The application authenticates on its own terms."""
    import tempfile

    from mizan.twin import Twin, TwinSpec, script_command
    from mizan.validation import _login

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        twin = Twin(
            TwinSpec(
                command=script_command(APP / "app.py", "--db", str(root / "s.sqlite"), "--port", "{port}"),
                workdir=root,
                data_paths=[root / "s.sqlite"],
                health_path="/health",
                health_timeout=60.0,
            ),
            workspace=root / "twin",
        )
        twin.start()
        try:
            assert _login(twin.base_url, "alice", "wrong-password") is None
        finally:
            twin.stop()
