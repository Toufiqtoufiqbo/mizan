"""L7 evidence must come from HTTP operations the fixture application performed."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import tempfile
import threading
import uuid
from pathlib import Path

import pytest
from flask import Flask, Response, jsonify, request
from werkzeug.serving import make_server

from mizan.confidentiality import (
    PostgresCacheProvider,
    PostgresQueueProvider,
    replay_l7,
    replay_outcome_is_inconclusive,
)
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


def _serve_flask(app):
    """Serve an already-built Flask app and remember every request it gets."""
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _policy(category: str, readers=("alice",)) -> dict:
    if category == "cache":
        return {
            "category": "cache",
            "resource": "items",
            "scope": "tenant-a",
            "classification": "private",
            "authorized_readers": list(readers),
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
        "authorized_readers": list(readers),
        "source": "trusted_contract",
        "confidence": "confirmed",
        "producer_path": "/messages",
        "consumer_path_template": "/messages/{id}/consume",
        "consumer_method": "POST",
    }


def _engine(dsn, port, category, principals=None, policy=None):
    provider = (
        PostgresCacheProvider(dsn, namespace=f"app-{uuid.uuid4().hex}")
        if category == "cache"
        else PostgresQueueProvider(dsn, namespace=f"app-{uuid.uuid4().hex}")
    )
    if principals is None:
        principals = [Principal(id=name, token=token, roles=("user",)) for name, token in TOKENS.items()]
    engine = Mizan(
        Target(
            base_url=f"http://127.0.0.1:{port}",
            principals=principals,
        ),
        confidentiality_providers=[provider],
        confidentiality_policies={category: policy or _policy(category)},
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
        assert "replay_outcome_is_inconclusive" in source
        assert "SUPPORTED = True" in source
        compiled = compile(source, "test_mizan_l7.py", "exec")
        assert compiled
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Identity selection follows the policy, never the order of the list
# --------------------------------------------------------------------------- #


def _principals(*names: str) -> list[Principal]:
    tokens = {**TOKENS, "carol": "twin-carol"}
    return [Principal(id=name, token=tokens[name], roles=("user",)) for name in names]


@pytest.mark.parametrize("order", [("alice", "bob"), ("bob", "alice")])
def test_principal_selection_follows_the_policy_not_the_list_order(dsn, app_server, order) -> None:
    """Reordering the identities must not change which role each one plays."""
    server, thread = _serve(app_server, "vulnerable")
    engine, provider = _engine(dsn, server.server_port, "cache", principals=_principals(*order))
    try:
        violations = engine.attack(groups=["L7"])
        assert len(violations) == 1
        evidence = violations[0].evidence
        # Alice is the authorized reader, so she is always the producer and Bob,
        # who is not authorized, is always the consumer.
        assert evidence["artifact"]["producer"] == "alice"
        assert evidence["observation"]["consumer"] == "bob"
        headers = [step["headers"]["Authorization"] for step in evidence["steps"]]
        assert headers == [
            "Bearer ${MIZAN_TOKEN_ALICE}",
            "Bearer ${MIZAN_TOKEN_ALICE}",
            "Bearer ${MIZAN_TOKEN_BOB}",
        ]
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


def test_multiple_authorized_readers_never_choose_an_unauthorized_producer(dsn, app_server) -> None:
    """Bob is listed first, but he is not an authorized reader: he cannot produce."""
    server, thread = _serve(app_server, "vulnerable")
    policy = _policy("cache", readers=("alice", "carol"))
    principals = _principals("bob", "alice", "carol")
    engine, provider = _engine(dsn, server.server_port, "cache", principals=principals, policy=policy)
    try:
        violations = engine.attack(groups=["L7"])
        assert len(violations) == 1, "an authorized producer must still be selected"
        evidence = violations[0].evidence
        assert evidence["artifact"]["producer"] in {"alice", "carol"}
        assert evidence["artifact"]["producer"] != "bob"
        assert evidence["observation"]["consumer"] == "bob"
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


def test_missing_unauthorized_consumer_is_inconclusive_without_http(dsn, app_server) -> None:
    server, thread = _serve(app_server, "vulnerable")
    engine, provider = _engine(dsn, server.server_port, "cache", principals=_principals("alice"))
    try:
        violations = engine.attack(groups=["L7"])
        assert violations == []
        assert engine.l7_evidence == []
        assert engine.requests == 0, "no HTTP request may run without a usable consumer"
        reasons = [item["reason"] for item in engine.inconclusive_checks if item["law"] == "L7"]
        assert any("unauthorized consumer" in reason for reason in reasons), reasons
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


def test_missing_authorized_producer_is_inconclusive_without_http(dsn, app_server) -> None:
    server, thread = _serve(app_server, "vulnerable")
    engine, provider = _engine(dsn, server.server_port, "cache", principals=_principals("bob"))
    try:
        violations = engine.attack(groups=["L7"])
        assert violations == []
        assert engine.l7_evidence == []
        assert engine.requests == 0, "no HTTP request may run without an authorized producer"
        reasons = [item["reason"] for item in engine.inconclusive_checks if item["law"] == "L7"]
        assert any("authorized producer" in reason for reason in reasons), reasons
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Replay: a failed producer write stops the sequence before any read
# --------------------------------------------------------------------------- #

ARTIFACT = "mizan-cache-replay-alice"
CONTENT = "mizan-v1-cache-replay-alice"
DIGEST = hashlib.sha256(CONTENT.encode()).hexdigest()


def _replay_evidence(base_url: str) -> dict:
    return {
        "law": "L7",
        "category": "cache",
        "provider": "postgres-cache-app-v1",
        "artifact": {
            "artifact_id": ARTIFACT,
            "producer": "alice",
            "scope": "tenant-a",
            "payload_digest": DIGEST,
        },
        "observation": {"artifact_id": ARTIFACT, "consumer": "bob", "observable": True},
        "policy": {
            "resource": "items",
            "scope": "tenant-a",
            "classification": "private",
            "authorized_readers": ["alice"],
            "source": "trusted_contract",
            "confidence": "confirmed",
        },
        "payload_integrity": {"expected_digest": DIGEST},
        "steps": [
            {
                "method": "POST",
                "url": base_url + "/artifacts",
                "headers": {"Authorization": "Bearer ${MIZAN_TOKEN_ALICE}"},
                "body": {"artifact_id": ARTIFACT, "content": CONTENT, "scope": "tenant-a"},
            },
            {
                "method": "GET",
                "url": f"{base_url}/artifacts/{ARTIFACT}",
                "headers": {"Authorization": "Bearer ${MIZAN_TOKEN_ALICE}"},
            },
            {
                "method": "GET",
                "url": f"{base_url}/artifacts/{ARTIFACT}",
                "headers": {"Authorization": "Bearer ${MIZAN_TOKEN_BOB}"},
            },
        ],
    }


def _scripted_target(producer, owner, consumer, calls):
    """A tiny HTTP target with scripted answers that records every request."""
    app = Flask("l7-replay-target")

    def reply(spec):
        status, body = spec
        if isinstance(body, str):
            return Response(body, status=status, mimetype="application/json")
        return jsonify(body), status

    @app.post("/artifacts")
    def produce():
        calls.append(("POST", "/artifacts"))
        return reply(producer)

    @app.get("/artifacts/<artifact_id>")
    def read(artifact_id: str):
        calls.append(("GET", f"/artifacts/{artifact_id}"))
        authorization = request.headers.get("Authorization", "")
        spec = owner if authorization.endswith(TOKENS["alice"]) else consumer
        return reply(spec)

    return app


def _replay_against(monkeypatch, producer, owner, consumer):
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", TOKENS["alice"])
    monkeypatch.setenv("MIZAN_TOKEN_BOB", TOKENS["bob"])
    calls: list[tuple[str, str]] = []
    server, thread = _serve_flask(_scripted_target(producer, owner, consumer, calls))
    target = f"http://127.0.0.1:{server.server_port}"
    try:
        result = replay_l7(_replay_evidence(target), target)
        return result, calls
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _producer_ok() -> tuple[int, dict]:
    return 201, {"artifact_id": ARTIFACT, "digest": DIGEST, "content": CONTENT}


def _owner_ok() -> tuple[int, dict]:
    return 200, {"artifact_id": ARTIFACT, "digest": DIGEST, "content": CONTENT}


def _consumer_ok() -> tuple[int, dict]:
    return 200, {"artifact_id": ARTIFACT, "digest": DIGEST, "content": CONTENT}


@pytest.mark.parametrize(
    ("producer", "expected_state"),
    [
        ((500, {"error": "boom"}), "producer_write_failed:500"),
        ((401, {"error": "unauthorized"}), "producer_write_failed:401"),
        ((403, {"error": "forbidden"}), "producer_write_failed:403"),
        ((200, "this is not json"), "producer_response_invalid_json"),
        ((201, {"artifact_id": "some-other-id", "digest": DIGEST}), "producer_artifact_id_mismatch"),
        ((201, {"artifact_id": ARTIFACT, "digest": "0" * 64}), "producer_digest_mismatch"),
    ],
)
def test_replay_stops_when_the_producer_write_cannot_be_trusted(monkeypatch, producer, expected_state) -> None:
    (still_vulnerable, state), calls = _replay_against(monkeypatch, producer, _owner_ok(), _consumer_ok())
    assert still_vulnerable is False
    assert state == expected_state
    assert replay_outcome_is_inconclusive(state) is True
    # No read is sent: an old record with the same id must not become evidence.
    assert calls == [("POST", "/artifacts")]


def test_stale_record_cannot_become_a_finding_after_a_failed_write(monkeypatch) -> None:
    """The target still holds the old artifact, but the new write failed."""
    stale = (200, {"artifact_id": ARTIFACT, "digest": DIGEST, "content": CONTENT})
    (still_vulnerable, state), calls = _replay_against(
        monkeypatch,
        (500, {"error": "write failed"}),
        stale,
        stale,
    )
    assert still_vulnerable is False
    assert state.startswith("producer_write_failed")
    assert not any(method == "GET" for method, _ in calls), calls


def test_replay_continues_after_a_verified_producer_write(monkeypatch) -> None:
    (still_vulnerable, state), calls = _replay_against(monkeypatch, _producer_ok(), _owner_ok(), _consumer_ok())
    assert still_vulnerable is True
    assert state == "confirmed_disclosure"
    assert calls == [
        ("POST", "/artifacts"),
        ("GET", f"/artifacts/{ARTIFACT}"),
        ("GET", f"/artifacts/{ARTIFACT}"),
    ]


def test_replay_reports_blocked_when_the_consumer_is_refused(monkeypatch) -> None:
    (still_vulnerable, state), calls = _replay_against(
        monkeypatch, _producer_ok(), _owner_ok(), (403, {"error": "forbidden"})
    )
    assert still_vulnerable is False
    assert state == "blocked"
    assert replay_outcome_is_inconclusive(state) is False
    assert len(calls) == 3, "the owner read must be attempted before the consumer one"


def test_replay_rejects_an_owner_read_with_the_wrong_digest(monkeypatch) -> None:
    wrong_owner = (200, {"artifact_id": ARTIFACT, "digest": "2" * 64, "content": "other"})
    (still_vulnerable, state), calls = _replay_against(monkeypatch, _producer_ok(), wrong_owner, _consumer_ok())
    assert still_vulnerable is False
    assert state == "authorized_read_digest_mismatch"
    assert replay_outcome_is_inconclusive(state) is True
    assert len(calls) == 2, "the consumer read must not run after an unverified owner read"


def test_replay_does_not_confirm_a_disclosure_when_the_content_differs(monkeypatch) -> None:
    different = (200, {"artifact_id": ARTIFACT, "digest": "1" * 64, "content": "other"})
    (still_vulnerable, state), _calls = _replay_against(monkeypatch, _producer_ok(), _owner_ok(), different)
    assert still_vulnerable is False
    assert state == "payload_mismatch"


def test_replay_fails_closed_when_the_owner_cannot_read(monkeypatch) -> None:
    """Blocking the authorized owner is not a fix."""
    (still_vulnerable, state), _calls = _replay_against(
        monkeypatch, _producer_ok(), (403, {"error": "forbidden"}), _consumer_ok()
    )
    assert still_vulnerable is False
    assert state == "authorized_read_failed"
    assert replay_outcome_is_inconclusive(state) is True
