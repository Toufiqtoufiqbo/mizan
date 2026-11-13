"""Mīzān against an independently implemented FastAPI application.

The application in `tests/fixtures/external_apps/fastapi_store` is the second
implementation of the behavioral contract in
`tests/fixtures/external_apps/contract/CONTRACT.md`. It has its own
authentication, its own SQLite database, its own authorization functions and its
own OpenAPI document, which FastAPI generates. It does not import Mīzān, and
Mīzān only reaches it through ordinary HTTP.

The tests prove both directions:

* the **clean** variant must produce no finding at all;
* the **read** variant must produce `L2` and nothing else;
* the **write** variant must produce `L3` and nothing else;
* the **both** variant must produce both.

Before Mīzān is involved, the tests also check each variant at the HTTP level,
so a variant that is weaker in an unrelated way cannot hide behind a scan.

It is a controlled validation target. It is **not** a claim that an external
customer has adopted Mīzān.
"""

from __future__ import annotations

import ast
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import requests

from mizan.twin import Twin, TwinSpec, script_command
from mizan.validation import LAUNCH_FASTAPI, _login, scan_application, validate_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "fastapi_store"

READ_VIOLATIONS = {"read", "both"}
WRITE_VIOLATIONS = {"write", "both"}
ALL_VARIANTS = ("clean", "read", "write", "both")


@contextmanager
def _application(variant: str) -> Iterator[str]:
    """Run one variant of the application and yield its base URL."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "store.sqlite"
        twin = Twin(
            TwinSpec(
                command=script_command(
                    APP / "app.py",
                    "--db",
                    str(database),
                    "--port",
                    "{port}",
                    "--vulnerability",
                    variant,
                ),
                workdir=root,
                data_paths=[database],
                health_path="/health",
                health_timeout=60.0,
            ),
            workspace=root / "twin",
        )
        twin.start()
        try:
            yield twin.base_url
        finally:
            twin.stop()


def _session(base_url: str, username: str, password: str) -> requests.Session:
    """A session authenticated as one principal."""
    token = _login(base_url, username, password)
    assert token, f"the application refused {username}"
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    return session


def _create_order(session: requests.Session, base_url: str, sku: str = "SKU-1") -> str:
    response = session.post(f"{base_url}/orders", json={"sku": sku, "quantity": 1}, timeout=10)
    assert response.status_code == 201, response.text
    return response.json()["id"]


@pytest.fixture(scope="module")
def validation() -> dict:
    return validate_application(APP, budget=60, launch=LAUNCH_FASTAPI)


# --------------------------------------------------------------------------- #
# The detection matrix
# --------------------------------------------------------------------------- #


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


def test_every_check_of_the_validation_gate_passes(validation: dict) -> None:
    failed = [item for item in validation["checks"] if not item["passed"]]
    assert not failed, f"the validation gate failed: {failed}"
    assert validation["passed"] is True


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


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


def test_the_reproduction_step_matches_the_transmitted_request(validation: dict) -> None:
    """The step must name the method that was actually sent, not the recorded one."""
    for variant, data in validation["variants"].items():
        for finding in data["findings"]:
            step = finding["steps"][0]
            if finding["law"] == "L2":
                assert step["method"] == "GET", f"{variant}: the read finding claims {step['method']}"
            if finding["law"] == "L3":
                assert step["method"] in {"POST", "PUT", "PATCH"}, f"{variant}: {step['method']}"


def test_a_single_variant_can_be_scanned() -> None:
    result = scan_application(APP, variant="write", budget=60, launch=LAUNCH_FASTAPI)
    assert result.error is None
    assert result.setup_error is None
    assert "L3" in result.law_types


# --------------------------------------------------------------------------- #
# Each variant, at the HTTP level - before Mīzān is involved
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("variant", ALL_VARIANTS)
def test_a_principal_can_read_and_write_their_own_order(variant: str) -> None:
    with _application(variant) as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        order_id = _create_order(alice, base_url, "SKU-ALICE")
        assert alice.get(f"{base_url}/orders/{order_id}", timeout=10).status_code == 200
        response = alice.put(f"{base_url}/orders/{order_id}", json={"status": "cancelled"}, timeout=10)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "cancelled"


@pytest.mark.parametrize("variant", ALL_VARIANTS)
def test_a_cross_user_read_follows_the_variant(variant: str) -> None:
    with _application(variant) as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        bob = _session(base_url, "bob", "bob-secret")
        order_id = _create_order(alice, base_url, "SKU-ALICE")
        response = bob.get(f"{base_url}/orders/{order_id}", timeout=10)
        if variant in READ_VIOLATIONS:
            assert response.status_code == 200, f"{variant}: the read weakness was not present"
            assert response.json()["owner_id"] == "alice"
        else:
            assert response.status_code != 200, f"{variant}: the clean read check was weakened"
            assert response.status_code in {401, 403, 404}


@pytest.mark.parametrize("variant", ALL_VARIANTS)
def test_a_cross_user_write_follows_the_variant(variant: str) -> None:
    with _application(variant) as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        bob = _session(base_url, "bob", "bob-secret")
        order_id = _create_order(alice, base_url, "SKU-ALICE")
        response = bob.put(f"{base_url}/orders/{order_id}", json={"status": "shipped"}, timeout=10)
        if variant in WRITE_VIOLATIONS:
            assert response.status_code == 200, f"{variant}: the write weakness was not present"
        else:
            assert response.status_code != 200, f"{variant}: the clean write check was weakened"
            assert response.status_code in {401, 403, 404}
        # Alice's order is only changed when the write weakness is present.
        stored = alice.get(f"{base_url}/orders/{order_id}", timeout=10).json()
        assert stored["status"] == ("shipped" if variant in WRITE_VIOLATIONS else "created")


@pytest.mark.parametrize("variant", ALL_VARIANTS)
def test_the_listing_stays_scoped_to_the_caller(variant: str) -> None:
    with _application(variant) as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        bob = _session(base_url, "bob", "bob-secret")
        _create_order(alice, base_url, "SKU-ALICE")
        _create_order(bob, base_url, "SKU-BOB")
        for session, expected in ((alice, "alice"), (bob, "bob")):
            listing = session.get(f"{base_url}/orders", timeout=10).json()
            owners = {order["owner_id"] for order in listing["orders"]}
            assert owners == {expected}, f"{variant}: the listing leaked other orders: {owners}"


# --------------------------------------------------------------------------- #
# Negative controls
# --------------------------------------------------------------------------- #


def test_an_invalid_token_is_rejected() -> None:
    with _application("clean") as base_url:
        session = requests.Session()
        session.headers["Authorization"] = "Bearer not-a-real-token"
        response = session.get(f"{base_url}/me", timeout=10)
        assert response.status_code == 401, response.text


def test_a_missing_token_is_rejected() -> None:
    with _application("clean") as base_url:
        response = requests.get(f"{base_url}/me", timeout=10)
        assert response.status_code == 401, response.text


def test_a_wrong_password_is_refused() -> None:
    with _application("clean") as base_url:
        assert _login(base_url, "alice", "wrong-password") is None


def test_a_malformed_body_is_refused_without_a_finding() -> None:
    """A validation error is not an authorization finding."""
    with _application("clean") as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        for payload in ({"sku": ""}, {"sku": "SKU-1", "quantity": 0}, {"quantity": 1}, "not-an-object"):
            response = alice.post(f"{base_url}/orders", json=payload, timeout=10)
            assert response.status_code in {400, 422}, (payload, response.status_code, response.text)


def test_a_malformed_update_body_is_refused() -> None:
    with _application("clean") as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        order_id = _create_order(alice, base_url)
        response = alice.put(f"{base_url}/orders/{order_id}", json={}, timeout=10)
        assert response.status_code in {400, 422}, response.text


def test_an_unknown_order_is_reported_as_not_found() -> None:
    with _application("clean") as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        assert alice.get(f"{base_url}/orders/ord-does-not-exist", timeout=10).status_code == 404


# --------------------------------------------------------------------------- #
# Independence
# --------------------------------------------------------------------------- #


def test_the_application_does_not_import_mizan() -> None:
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
    """Its tokens are opaque and random - not Mīzān's JWT-shaped ones."""
    with _application("clean") as base_url:
        token = _login(base_url, "alice", "alice-secret")
        assert token and "." not in token, "the application issues a JWT-shaped token"
        assert len(token) >= 20, "the token is too short to be random"


def test_the_application_generates_its_own_openapi_document() -> None:
    """The document is FastAPI's own, and it describes the actual routes."""
    with _application("clean") as base_url:
        document = requests.get(f"{base_url}/openapi.json", timeout=10).json()
        assert document["openapi"].startswith("3.")
        paths = document["paths"]
        assert paths["/login"]["post"] and paths["/me"]["get"]
        assert paths["/orders"]["get"] and paths["/orders"]["post"]
        assert "order_id" in {parameter["name"] for parameter in paths["/orders/{order_id}"]["get"]["parameters"]}
        body = paths["/orders"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        assert body.get("properties") or body.get("$ref")


def test_the_fixture_uses_the_shared_contract_not_a_copy_of_the_flask_app() -> None:
    """The two fixtures must be independent implementations, not a rename."""
    fastapi_source = (APP / "app.py").read_text(encoding="utf-8")
    flask_source = (
        Path(__file__).resolve().parent / "fixtures" / "external_apps" / "flask_store" / "app.py"
    ).read_text(encoding="utf-8")
    assert "from flask" not in fastapi_source
    assert "from fastapi" in fastapi_source
    assert "flask" not in fastapi_source.lower()
    assert len({fastapi_source, flask_source}) == 2
