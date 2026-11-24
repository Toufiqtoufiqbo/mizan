"""L7 evidence must come from HTTP operations the fixture application performed."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import threading
import uuid
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from mizan.confidentiality import PostgresCacheProvider, PostgresQueueProvider, replay_l7
from mizan.core import Principal
from mizan.engine import Mizan, Target

FIXTURE = Path(__file__).parent / "fixtures" / "external_apps" / "l7_store" / "app.py"
TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}


@pytest.fixture(scope="module")
def dsn():
    value = os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if value:
        dsn_value = value if "connect_timeout" in value else value + "?connect_timeout=5"
    else:
        pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required")
        server = pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-l7-app-")), cleanup_mode="delete")
        dsn_value = server.get_uri()
    os.environ["MIZAN_PG_DSN"] = dsn_value
    os.environ["MIZAN_TOKEN_ALICE"] = TOKENS["alice"]
    os.environ["MIZAN_TOKEN_BOB"] = TOKENS["bob"]
    return dsn_value


@pytest.fixture
def app_server(dsn):
    spec = importlib.util.spec_from_file_location("l7_store_fixture", FIXTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _serve(app_module, variant):
    server = make_server("127.0.0.1", 0, app_module.create_app(variant, dsn=os.environ["MIZAN_PG_DSN"]))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _policy(category: str) -> dict:
    if category == "cache":
        return {
            "category": "cache",
            "resource": "items",
            "scope": "tenant-a",
            "classification": "private",
            "authorized_readers": ["alice"],
            "source": "trusted_contract",
            "confidence": "confirmed",
            "producer_path": "/artifacts",
            "consumer_path_template": "/artifacts/{id}",
            "consumer_method": "GET",
        }
    return {
        "category": "queue",
        "resource": "messages",
        "scope": "tenant-a",
        "classification": "private",
        "authorized_readers": ["alice"],
        "source": "trusted_contract",
        "confidence": "confirmed",
        "producer_path": "/messages",
        "consumer_path_template": "/messages/{id}/consume",
        "consumer_method": "POST",
    }


def _engine(dsn, port, category):
    provider = (
        PostgresCacheProvider(dsn, namespace=f"app-{uuid.uuid4().hex}")
        if category == "cache"
        else PostgresQueueProvider(dsn, namespace=f"app-{uuid.uuid4().hex}")
    )
    engine = Mizan(
        Target(
            base_url=f"http://127.0.0.1:{port}",
            principals=[Principal(id=name, token=token, roles=("user",)) for name, token in TOKENS.items()],
        ),
        confidentiality_providers=[provider],
        confidentiality_policies={category: _policy(category)},
    )
    return engine, provider


@pytest.mark.parametrize("category", ["cache", "queue"])
@pytest.mark.parametrize(
    ("variant", "expected_findings"),
    [("vulnerable", 1), ("secure", 0)],
)
def test_application_operations_decide_authorization(dsn, app_server, category, variant, expected_findings) -> None:
    server, thread = _serve(app_server, variant)
    engine, provider = _engine(dsn, server.server_port, category)
    try:
        violations = engine.attack(groups=["L7"])
        assert len(violations) == expected_findings
        evidence = violations[0].evidence if violations else engine.l7_evidence[0]
        integrity = evidence["payload_integrity"]
        assert integrity["owner_can_read"] is True, "secure mode must still allow the authorized producer"
        assert evidence["artifact"]["producer"] == "alice"
        assert evidence["observation"]["consumer"] == "bob"
        assert evidence["observation"]["source"] == "application_http_operation"
        if expected_findings:
            assert integrity["consumer_content_matches"] is True
            assert evidence["state"] == "confirmed_disclosure"
        else:
            assert integrity["consumer_content_matches"] is False
            assert evidence["state"] == "blocked"
        assert len(evidence["steps"]) == 3
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize("category", ["cache", "queue"])
def test_replay_reproduces_http_sequence(dsn, app_server, category, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", TOKENS["alice"])
    monkeypatch.setenv("MIZAN_TOKEN_BOB", TOKENS["bob"])
    vuln, vuln_thread = _serve(app_server, "vulnerable")
    secure, secure_thread = _serve(app_server, "secure")
    engine, provider = _engine(dsn, vuln.server_port, category)
    try:
        violations = engine.attack(groups=["L7"])
        assert violations, "the vulnerable fixture must be detected"
        evidence = violations[0].evidence
        still, state = replay_l7(evidence, f"http://127.0.0.1:{vuln.server_port}")
        assert still is True and state == "confirmed_disclosure"
        still_secure, secure_state = replay_l7(evidence, f"http://127.0.0.1:{secure.server_port}")
        assert still_secure is False and secure_state == "blocked"
    finally:
        provider.cleanup()
        vuln.shutdown()
        secure.shutdown()
        vuln_thread.join(timeout=5)
        secure_thread.join(timeout=5)


def test_missing_or_mismatched_evidence_never_confirms(dsn, app_server) -> None:
    server, thread = _serve(app_server, "vulnerable")
    engine, provider = _engine(dsn, server.server_port, "cache")
    try:
        violations = engine.attack(groups=["L7"])
        evidence = dict(violations[0].evidence)
        target = f"http://127.0.0.1:{server.server_port}"
        assert replay_l7({"steps": []}, target)[0] is False
        tampered = dict(evidence)
        tampered["payload_integrity"] = dict(evidence["payload_integrity"])
        tampered["payload_integrity"]["expected_digest"] = "wrong"
        assert replay_l7(tampered, target)[0] is False
        no_consumer = dict(evidence)
        no_consumer["observation"] = {}
        assert replay_l7(no_consumer, target)[0] is False
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


def test_regression_replays_application_flow(dsn, app_server, tmp_path) -> None:
    from mizan.regression import build_attack, render_test

    server, thread = _serve(app_server, "vulnerable")
    engine, provider = _engine(dsn, server.server_port, "cache")
    try:
        violations = engine.attack(groups=["L7"])
        assert violations
        attack = build_attack(violations[0])
        assert attack is not None and attack.supported
        source = render_test(violations[0])
        assert "replay_l7(EVIDENCE, TARGET)" in source
        assert "SUPPORTED = True" in source
        compiled = compile(source, "test_mizan_l7.py", "exec")
        assert compiled
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)
