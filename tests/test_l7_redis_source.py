"""L7 evidence from a real Redis-backed application that owns its operations."""

from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from mizan.confidentiality import (
    Artifact,
    EvidenceState,
    RedisCacheProvider,
    RedisQueueProvider,
    evaluate,
    replay_l7,
)
from mizan.core import Principal
from mizan.engine import Mizan, Target

FIXTURE = Path(__file__).parent / "fixtures" / "external_apps" / "l7_redis" / "app.py"
TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def redis_dsn():
    """A real Redis server: configured DSN, or a local redis-server binary."""
    import redis

    dsn = os.environ.get("MIZAN_TEST_REDIS_DSN")
    process = None
    if not dsn:
        executable = os.environ.get("MIZAN_REDIS_SERVER") or shutil.which("redis-server")
        if not executable:
            pytest.skip("a real Redis server is required (MIZAN_TEST_REDIS_DSN or MIZAN_REDIS_SERVER)")
        port = _free_port()
        process = subprocess.Popen(
            [
                executable,
                "--port",
                str(port),
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dsn = f"redis://127.0.0.1:{port}/0"
    client = redis.Redis.from_url(dsn, socket_connect_timeout=1)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if client.ping():
                break
        except Exception:
            time.sleep(0.1)
    else:
        if process is not None:
            process.terminate()
        pytest.skip("the Redis server did not become reachable")
    client.flushdb()
    try:
        yield dsn
    finally:
        client.flushdb()
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


@pytest.fixture
def app_module():
    spec = importlib.util.spec_from_file_location("l7_redis_fixture", FIXTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _serve(app_module, variant, dsn):
    server = make_server("127.0.0.1", 0, app_module.create_app(variant, dsn=dsn))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _policy(category: str) -> dict:
    return {
        "category": category,
        "resource": "items" if category == "cache" else "messages",
        "scope": "tenant-a",
        "classification": "private",
        "authorized_readers": ["alice"],
        "source": "trusted_contract",
        "confidence": "confirmed",
        "producer_path": "/artifacts" if category == "cache" else "/messages",
        "consumer_path_template": "/artifacts/{id}" if category == "cache" else "/messages/{id}/consume",
        "consumer_method": "GET" if category == "cache" else "POST",
    }


def _engine(dsn, port, category):
    provider = (
        RedisCacheProvider(dsn, namespace=f"redis-app-{uuid.uuid4().hex}")
        if category == "cache"
        else RedisQueueProvider(dsn, namespace=f"redis-app-{uuid.uuid4().hex}")
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


@pytest.mark.redis_integration
@pytest.mark.parametrize("category", ["cache", "queue"])
@pytest.mark.parametrize(("variant", "expected"), [("vulnerable", 1), ("secure", 0)])
def test_redis_application_operations_decide_authorization(redis_dsn, app_module, category, variant, expected) -> None:
    server, thread = _serve(app_module, variant, redis_dsn)
    engine, provider = _engine(redis_dsn, server.server_port, category)
    try:
        violations = engine.attack(groups=["L7"])
        assert len(violations) == expected
        evidence = violations[0].evidence if violations else engine.l7_evidence[0]
        assert evidence["provider"].startswith("redis-")
        assert evidence["artifact"]["producer"] == "alice"
        assert evidence["observation"]["consumer"] == "bob"
        assert evidence["observation"]["source"] == "application_http_operation"
        assert evidence["payload_integrity"]["owner_can_read"] is True
        assert evidence["events"], "the Redis application must have recorded its own operations"
        if expected:
            assert evidence["state"] == "confirmed_disclosure"
            assert evidence["payload_integrity"]["consumer_content_matches"] is True
        else:
            assert evidence["state"] == "blocked"
            assert evidence["payload_integrity"]["consumer_content_matches"] is False
    finally:
        provider.cleanup()
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.redis_integration
@pytest.mark.parametrize("category", ["cache", "queue"])
def test_redis_replay_reproduces_real_http(redis_dsn, app_module, category, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", TOKENS["alice"])
    monkeypatch.setenv("MIZAN_TOKEN_BOB", TOKENS["bob"])
    vulnerable, vulnerable_thread = _serve(app_module, "vulnerable", redis_dsn)
    secure, secure_thread = _serve(app_module, "secure", redis_dsn)
    engine, provider = _engine(redis_dsn, vulnerable.server_port, category)
    try:
        violations = engine.attack(groups=["L7"])
        assert violations
        evidence = violations[0].evidence
        target_vulnerable = f"http://127.0.0.1:{vulnerable.server_port}"
        assert replay_l7(evidence, target_vulnerable) == (True, "confirmed_disclosure")
        target_secure = f"http://127.0.0.1:{secure.server_port}"
        assert replay_l7(evidence, target_secure) == (False, "blocked")
    finally:
        provider.cleanup()
        vulnerable.shutdown()
        secure.shutdown()
        vulnerable_thread.join(timeout=5)
        secure_thread.join(timeout=5)


@pytest.mark.redis_integration
def test_redis_provider_is_read_only(redis_dsn, app_module) -> None:
    import redis

    server, thread = _serve(app_module, "vulnerable", redis_dsn)
    engine, provider = _engine(redis_dsn, server.server_port, "cache")
    client = redis.Redis.from_url(redis_dsn, decode_responses=True)
    try:
        engine.attack(groups=["L7"])
        before = client.xlen("mizan:l7:events")
        keys = sorted(key for key in client.scan_iter(match="mizan:l7:*"))
        with pytest.raises(LookupError):
            provider.write(Artifact("a", "alice", "tenant-a", "x", request_id="nope"))
        provider.observe("a", "bob", request_id="nope")
        provider.cleanup()
        assert provider.events() == []
        assert client.xlen("mizan:l7:events") == before
        assert sorted(key for key in client.scan_iter(match="mizan:l7:*")) == keys
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.redis_integration
def test_redis_missing_event_never_confirms(redis_dsn) -> None:
    provider = RedisCacheProvider(redis_dsn, namespace="missing-event")
    policy = _policy("cache")
    artifact = Artifact("absent-artifact", "alice", "tenant-a", "content", request_id="absent-request")
    from mizan.confidentiality import policy_from_dict

    result = evaluate(provider, artifact, "bob", policy_from_dict(policy), request_id="absent-observation")
    assert result.state not in {EvidenceState.CONFIRMED_DISCLOSURE, EvidenceState.AUTHORIZED_SHARING}
    observation = provider.observe("absent-artifact", "bob", request_id="absent-observation")
    assert observation.details.get("missing_event") is True
