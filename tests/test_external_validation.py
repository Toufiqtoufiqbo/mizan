"""Independent validation: Mīzān against an application that knows nothing about it.

The application in `tests/fixtures/external_apps/flask_store` has its own
authentication, its own database and its own OpenAPI document. It does not
import Mīzān, and Mīzān only reaches it through ordinary HTTP.

The test proves both directions:

* the **clean** variant must produce no finding at all;
* the **read** variant must produce `L2` and nothing else;
* the **write** variant must produce `L3` and nothing else;
* the **both** variant must produce both.

It is a controlled validation target. It is **not** a claim that an external
customer has adopted Mīzān.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from mizan.validation import scan_application, validate_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "flask_store"


@pytest.fixture(scope="module")
def validation() -> dict:
    return validate_application(APP, budget=60)


def test_the_clean_application_is_clean(validation: dict) -> None:
    clean = validation["variants"]["clean"]
    assert clean["setup_error"] is None, clean["setup_error"]
    assert clean["error"] is None, clean["error"]
    assert clean["requests"]["total"] > 0, "the scan sent no request at all"
    assert clean["finding_count"] == 0, f"the clean application produced findings: {clean['findings']}"
    assert clean["law_types"] == []


def test_the_read_variant_produces_only_a_read_finding(validation: dict) -> None:
    read = validation["variants"]["read"]
    assert read["error"] is None, read["error"]
    assert "L2" in read["law_types"], f"the cross-user read was missed: {read}"
    assert "L3" not in read["law_types"], f"the read variant reported a write finding as well: {read['law_types']}"


def test_the_write_variant_produces_only_a_write_finding(validation: dict) -> None:
    write = validation["variants"]["write"]
    assert write["error"] is None, write["error"]
    assert "L3" in write["law_types"], f"the cross-user write was missed: {write}"
    assert "L2" not in write["law_types"], f"the write variant reported a read finding as well: {write['law_types']}"


def test_the_combined_variant_produces_both(validation: dict) -> None:
    both = validation["variants"]["both"]
    assert "L2" in both["law_types"]
    assert "L3" in both["law_types"]


def test_the_listing_stays_scoped_to_the_caller_in_every_variant() -> None:
    """The variants must not weaken the listing by accident."""
    from mizan.twin import Twin, TwinSpec, script_command
    from mizan.validation import _login

    for variant in ("clean", "read", "write", "both"):
        workspace = Path(__file__).parent.parent.parent / f".pytest-listing-{variant}"
        workspace.mkdir(parents=True, exist_ok=True)
        twin = Twin(
            TwinSpec(
                command=script_command(
                    APP / "app.py",
                    "--db",
                    str(workspace / "a.sqlite"),
                    "--port",
                    "{port}",
                    "--vulnerability",
                    variant,
                ),
                workdir=workspace,
                data_paths=[workspace / "a.sqlite"],
                health_path="/health",
                health_timeout=60.0,
            ),
            workspace=workspace / "twin",
        )
        twin.start()
        try:
            token = _login(twin.base_url, "alice", "alice-secret")
            assert token
            # Alice creates an order, bob creates one.
            for user in ("alice", "bob"):
                other = _login(twin.base_url, user, f"{user}-secret")
                assert other
                import requests

                session = requests.Session()
                session.headers["Authorization"] = f"Bearer {other}"
                session.post(f"{twin.base_url}/orders", json={"sku": "SKU-1", "quantity": 1}, timeout=10)
            import requests

            session = requests.Session()
            session.headers["Authorization"] = f"Bearer {token}"
            listing = session.get(f"{twin.base_url}/orders", timeout=10).json()
            owners = {order["owner_id"] for order in listing["orders"]}
            assert owners == {"alice"}, f"the listing leaked other orders in the {variant} variant: {owners}"
        finally:
            twin.stop()


def test_every_finding_identifies_principal_endpoint_and_resource(validation: dict) -> None:
    for variant, data in validation["variants"].items():
        for finding in data["findings"]:
            assert finding["principal"], f"{variant}: a finding without a principal"
            assert finding["resource"], f"{variant}: a finding without a resource"
            steps = finding["steps"]
            assert steps, f"{variant}: a finding without reproduction steps"
            assert steps[0]["method"], f"{variant}: a reproduction step without a method"
            assert steps[0]["url"], f"{variant}: a reproduction step without an endpoint"
            assert finding["evidence"], f"{variant}: a finding without evidence"


def test_the_evidence_names_the_owner(validation: dict) -> None:
    for variant, data in validation["variants"].items():
        for finding in data["findings"]:
            evidence = finding.get("evidence") or {}
            owner = evidence.get("owner") or evidence.get("row_owner") or (evidence.get("event") or {}).get("row_owner")
            assert owner, f"{variant}: no finding says who owns the affected object"
            assert owner != finding["principal"], f"{variant}: the attacker is reported as the owner"


def test_every_check_of_the_validation_gate_passes(validation: dict) -> None:
    failed = [item for item in validation["checks"] if not item["passed"]]
    assert not failed, f"the validation gate failed: {failed}"
    assert validation["passed"] is True


def test_the_application_does_not_import_mizan() -> None:
    """The fixture must stay independent of Mizan."""
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


def test_a_single_variant_can_be_scanned() -> None:
    """The harness can scan one variant on its own."""
    result = scan_application(APP, variant="write", budget=60)
    assert result.error is None
    assert result.setup_error is None
    assert "L3" in result.law_types
