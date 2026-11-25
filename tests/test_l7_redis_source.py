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
    policy_from_dict,
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


def _namespace() -> str:
    return os.environ.get("MIZAN_REDIS_NAMESPACE", "")


def _delete_namespace_keys(client, namespace: str) -> int:
    """Delete only the keys owned by this test session, never the whole DB."""
    deleted = 0
    for key in client.scan_iter(match=f"{namespace}:*", count=100):
        client.delete(key)
        deleted += 1
    return deleted


@pytest.fixture(scope="module")
def redis_dsn():
    """A real Redis server and a unique key namespace owned by this session."""
    import redis

    namespace = f"mizan:test:{uuid.uuid4().hex}-{os.getpid()}:l7"
    previous_namespace = os.environ.get("MIZAN_REDIS_NAMESPACE")
    os.environ["MIZAN_REDIS_NAMESPACE"] = namespace
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
    try:
        yield dsn
    finally:
        # Namespace-scoped cleanup only; no database-wide deletion commands.
        cleanup = redis.Redis.from_url(dsn, decode_responses=True)
        _delete_namespace_keys(cleanup, namespace)
        if previous_namespace is None:
            os.environ.pop("MIZAN_REDIS_NAMESPACE", None)
        else:
            os.environ["MIZAN_REDIS_NAMESPACE"] = previous_namespace
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
def test_redis_observation_does_not_mutate_the_stream(redis_dsn, app_module) -> None:
    import redis

    server, thread = _serve(app_module, "vulnerable", redis_dsn)
    engine, provider = _engine(redis_dsn, server.server_port, "cache")
    client = redis.Redis.from_url(redis_dsn, decode_responses=True)
    namespace = _namespace()
    try:
        engine.attack(groups=["L7"])
        stream = f"{namespace}:events"
        before_entries = client.xrange(stream)
        before_keys = sorted(client.scan_iter(match=f"{namespace}:*"))
        provider.observe("missing-artifact", "bob", request_id="missing-request")
        provider.cleanup()
        assert client.xrange(stream) == before_entries
        assert sorted(client.scan_iter(match=f"{namespace}:*")) == before_keys
        assert provider.events() == []
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.redis_integration
def test_redis_missing_event_never_confirms(redis_dsn) -> None:
    provider = RedisCacheProvider(redis_dsn, namespace="missing-event")
    artifact = Artifact("absent-artifact", "alice", "tenant-a", "content", request_id="absent-request")
    result = evaluate(provider, artifact, "bob", policy_from_dict(_policy("cache")), request_id="absent-observation")
    assert result.state not in {EvidenceState.CONFIRMED_DISCLOSURE, EvidenceState.AUTHORIZED_SHARING}
    observation = provider.observe("absent-artifact", "bob", request_id="absent-observation")
    assert observation.details.get("missing_event") is True


@pytest.mark.redis_integration
def test_external_key_survives_namespace_cleanup(redis_dsn) -> None:
    import redis

    client = redis.Redis.from_url(redis_dsn, decode_responses=True)
    namespace = _namespace()
    external = f"mizan:unrelated:{uuid.uuid4().hex}"
    owned = f"{namespace}:temporary:{uuid.uuid4().hex}"
    client.set(external, "keep-me")
    client.set(owned, "mizan-owned")
    try:
        assert _delete_namespace_keys(client, namespace) >= 1
        assert client.get(owned) is None
        assert client.get(external) == "keep-me"
    finally:
        client.delete(external)


@pytest.mark.redis_integration
def test_parallel_namespaces_are_isolated(redis_dsn) -> None:
    import redis

    client = redis.Redis.from_url(redis_dsn, decode_responses=True)
    first = f"mizan:test:{uuid.uuid4().hex}:l7"
    second = f"mizan:test:{uuid.uuid4().hex}:l7"
    client.set(f"{first}:artifact:x", "one")
    client.set(f"{second}:artifact:x", "two")
    try:
        assert _delete_namespace_keys(client, first) == 1
        assert client.get(f"{first}:artifact:x") is None
        assert client.get(f"{second}:artifact:x") == "two"
    finally:
        _delete_namespace_keys(client, second)


def test_no_database_wide_flush_commands() -> None:
    flush_db = "flush" + "db"
    flush_all = "flush" + "all"
    sources = [
        Path(__file__).read_text(encoding="utf-8"),
        FIXTURE.read_text(encoding="utf-8"),
        (Path(__file__).parents[1] / "src" / "mizan" / "confidentiality.py").read_text(encoding="utf-8"),
    ]
    for source in sources:
        lowered = source.lower()
        assert flush_db not in lowered
        assert flush_all not in lowered


@pytest.mark.redis_integration
def test_missing_ownership_fails_closed(redis_dsn, app_module) -> None:
    import redis
    import requests

    server, thread = _serve(app_module, "secure", redis_dsn)
    client = redis.Redis.from_url(redis_dsn, decode_responses=True)
    namespace = _namespace()
    artifact_id = f"ownerless-{uuid.uuid4().hex}"
    content = "ownerless-content"
    base_url = f"http://127.0.0.1:{server.server_port}"
    write_request = f"write-{uuid.uuid4().hex}"
    alice_request = f"alice-{uuid.uuid4().hex}"
    bob_request = f"bob-{uuid.uuid4().hex}"
    try:
        created = requests.post(
            base_url + "/artifacts",
            json={"artifact_id": artifact_id, "content": content, "scope": "tenant-a"},
            headers={"Authorization": f"Bearer {TOKENS['alice']}", "X-Mizan-Request-Id": write_request},
            timeout=10,
        )
        assert created.status_code == 201
        # Simulate lost ownership metadata without removing the content.
        client.delete(f"{namespace}:owner:{artifact_id}")
        headers_alice = {"Authorization": f"Bearer {TOKENS['alice']}", "X-Mizan-Request-Id": alice_request}
        headers_bob = {"Authorization": f"Bearer {TOKENS['bob']}", "X-Mizan-Request-Id": bob_request}
        alice = requests.get(f"{base_url}/artifacts/{artifact_id}", headers=headers_alice, timeout=10)
        bob = requests.get(f"{base_url}/artifacts/{artifact_id}", headers=headers_bob, timeout=10)
        assert alice.status_code == 403, "missing ownership must never promote the caller to owner"
        assert bob.status_code == 403
        provider = RedisCacheProvider(redis_dsn, namespace="missing-owner")
        artifact = Artifact(artifact_id, "alice", "tenant-a", content, request_id=write_request)
        result = evaluate(provider, artifact, "bob", policy_from_dict(_policy("cache")), request_id=bob_request)
        assert result.state is not EvidenceState.CONFIRMED_DISCLOSURE
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.redis_integration
def test_queue_visibility_is_non_destructive(redis_dsn, app_module) -> None:
    import redis
    import requests

    server, thread = _serve(app_module, "secure", redis_dsn)
    client = redis.Redis.from_url(redis_dsn, decode_responses=True)
    namespace = _namespace()
    message_id = f"visible-{uuid.uuid4().hex}"
    base_url = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": f"Bearer {TOKENS['alice']}"}
    try:
        published = requests.post(
            base_url + "/messages",
            json={"message_id": message_id, "content": "visible", "scope": "tenant-a", "intended_consumer": "alice"},
            headers=headers,
            timeout=10,
        )
        assert published.status_code == 201
        url = f"{base_url}/messages/{message_id}/consume"
        first = requests.post(url, headers=headers, timeout=10)
        second = requests.post(url, headers=headers, timeout=10)
        assert first.status_code == second.status_code == 200
        assert first.json()["digest"] == second.json()["digest"]
        assert client.llen(f"{namespace}:queue:{message_id}") == 1, "LRANGE is a visibility read"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_redis_is_an_optional_dependency() -> None:
    import tomllib

    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    assert "redis" in extras
    assert any(item.startswith("redis>=") for item in extras["redis"])
