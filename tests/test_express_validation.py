"""Mīzān against an independently implemented Express application.

The application in `tests/fixtures/external_apps/express_store` is the third
implementation of the behavioral contract in
`tests/fixtures/external_apps/contract/CONTRACT.md`. It is a real Node.js
service: its own authentication, its own SQLite database (through Node's
built-in `node:sqlite`), its own authorization functions and its own committed
OpenAPI document. It does not import Mīzān, and Mīzān only reaches it through
ordinary HTTP.

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

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import requests

from mizan.twin import Twin, TwinSpec
from mizan.validation import LAUNCH_EXPRESS, _login, scan_application, validate_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "express_store"

READ_VIOLATIONS = {"read", "both"}
WRITE_VIOLATIONS = {"write", "both"}
ALL_VARIANTS = ("clean", "read", "write", "both")


def _node() -> str:
    """The Node.js interpreter, or a clear failure."""
    node = os.environ.get("MIZAN_NODE") or shutil.which("node")
    if not node:
        pytest.fail(
            "Node.js is not installed, so the Express fixture cannot run. "
            "Install it (winget install OpenJS.NodeJS.LTS) or set MIZAN_NODE."
        )
    return node


def _npm() -> str:
    """The npm executable, or a clear failure."""
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        pytest.fail("npm is not installed, so the Express dependencies cannot be installed.")
    return npm


def _ensure_dependencies() -> None:
    """Install the pinned dependencies from the lockfile, when they are missing.

    The installation is reproducible: ``npm ci`` installs exactly what
    ``package-lock.json`` pins, and never touches it.
    """
    if (APP / "node_modules" / "express").exists():
        return
    completed = subprocess.run(
        [_npm(), "ci", "--no-audit", "--no-fund"],
        cwd=str(APP),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if completed.returncode != 0:
        pytest.fail(f"the Express dependencies could not be installed:\n{completed.stdout}\n{completed.stderr}")


@pytest.fixture(scope="module", autouse=True)
def dependencies() -> None:
    _ensure_dependencies()


@contextmanager
def _application(variant: str) -> Iterator[str]:
    """Run one variant of the application and yield its base URL."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "store.sqlite"
        twin = Twin(
            TwinSpec(
                command=[
                    _node(),
                    str(APP / "server.js"),
                    "--db",
                    str(database),
                    "--port",
                    "{port}",
                    "--vulnerability",
                    variant,
                ],
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
    return validate_application(APP, budget=60, launch=LAUNCH_EXPRESS)


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
    result = scan_application(APP, variant="write", budget=60, launch=LAUNCH_EXPRESS)
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
    """The fixture must stay independent of Mizan."""
    source = (APP / "server.js").read_text(encoding="utf-8")
    required = re.findall(r"""require\(\s*["']([^"']+)["']\s*\)""", source)
    assert required, "the scan found no requires at all - the check would be vacuous"
    assert not [name for name in required if name.split(".")[0] == "mizan"], required
    assert not [name for name in required if "mizan" in name.lower()], required


def test_the_application_depends_on_nothing_but_express_and_node() -> None:
    """No shared implementation, no framework helper borrowed from Mizan."""
    source = (APP / "server.js").read_text(encoding="utf-8")
    required = set(re.findall(r"""require\(\s*["']([^"']+)["']\s*\)""", source))
    assert required <= {"node:crypto", "node:sqlite", "express"}, required


def test_the_application_uses_its_own_authentication() -> None:
    """Its tokens are opaque and random - not Mīzān's JWT-shaped ones."""
    with _application("clean") as base_url:
        token = _login(base_url, "alice", "alice-secret")
        assert token and "." not in token, "the application issues a JWT-shaped token"
        assert len(token) >= 20, "the token is too short to be random"


def test_the_application_uses_its_own_storage() -> None:
    """It writes a real SQLite file, not a JSON stand-in."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "store.sqlite"
        twin = Twin(
            TwinSpec(
                command=[
                    _node(),
                    str(APP / "server.js"),
                    "--db",
                    str(database),
                    "--port",
                    "{port}",
                    "--vulnerability",
                    "clean",
                ],
                workdir=root,
                data_paths=[database],
                health_path="/health",
                health_timeout=60.0,
            ),
            workspace=root / "twin",
        )
        twin.start()
        try:
            alice = _session(twin.base_url, "alice", "alice-secret")
            _create_order(alice, twin.base_url)
        finally:
            twin.stop()
        assert database.exists(), "the application did not create its database"
        header = database.read_bytes()[:16]
        assert header.startswith(b"SQLite format 3"), header


def test_the_openapi_document_describes_the_actual_routes() -> None:
    """Every documented route must exist, and the parameters must match."""
    document = json.loads((APP / "openapi.json").read_text(encoding="utf-8"))
    assert document["openapi"].startswith("3.")
    paths = document["paths"]
    assert set(paths) == {"/health", "/login", "/me", "/orders", "/orders/{order_id}"}
    assert paths["/orders/{order_id}"]["get"]["parameters"][0]["name"] == "order_id"
    assert paths["/orders/{order_id}"]["put"]["parameters"][0]["name"] == "order_id"
    assert document["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"

    with _application("clean") as base_url:
        alice = _session(base_url, "alice", "alice-secret")
        order_id = _create_order(alice, base_url)
        assert requests.get(f"{base_url}/health", timeout=10).status_code == 200
        assert alice.get(f"{base_url}/me", timeout=10).status_code == 200
        assert alice.get(f"{base_url}/orders", timeout=10).status_code == 200
        assert alice.get(f"{base_url}/orders/{order_id}", timeout=10).status_code == 200
        assert alice.put(f"{base_url}/orders/{order_id}", json={"status": "created"}, timeout=10).status_code == 200


def test_the_dependencies_are_pinned_and_locked() -> None:
    """The installation must be reproducible."""
    manifest = json.loads((APP / "package.json").read_text(encoding="utf-8"))
    assert manifest["dependencies"]["express"] == "4.21.2"
    assert (APP / "package-lock.json").exists(), "the lockfile is missing"
    lock = json.loads((APP / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["packages"]["node_modules/express"]["version"] == "4.21.2"
