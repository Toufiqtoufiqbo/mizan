"""Tests for the traffic recorder."""

from __future__ import annotations

import json
from pathlib import Path

from mizan.recorder import Recorder, principal_from_token
from mizan.traffic import TrafficLog


def _app(environ, start_response):
    payload = json.dumps({"id": "o1", "owner_id": "alice"}).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(payload)))])
    return [payload]


def test_principal_is_read_from_the_token(tmp_path: Path) -> None:
    from mizan.benchmark.apps import make_token

    token = make_token("alice")
    assert principal_from_token(token) == "alice"
    assert principal_from_token("opaque-token") is None
    assert principal_from_token(None) is None


def test_recorder_writes_a_traffic_log(tmp_path: Path) -> None:
    from mizan.benchmark.apps import make_token

    path = tmp_path / "traffic.jsonl"
    recorder = Recorder(_app, path)

    def run() -> None:
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/orders/o1",
            "CONTENT_LENGTH": "0",
            "HTTP_AUTHORIZATION": f"Bearer {make_token('alice')}",
            "wsgi.input": _Empty(),
        }
        recorder(environ, lambda *args, **kwargs: None)

    run()
    log = TrafficLog.load(path)
    assert len(log) == 1
    record = log.records[0]
    assert record.method == "GET"
    assert record.principal == "alice"
    assert record.template == "/orders/{id}"
    assert record.resource_type == "orders"
    assert record.resource_id == "o1"
    assert record.resource_owner == "alice"


def test_a_user_header_is_not_an_identity_by_default(tmp_path: Path) -> None:
    """An ``X-User-Id`` header alone is not a proof of identity.

    Any client can send it. It is believed only when the request came from
    an explicitly trusted proxy - and by default no proxy is trusted.
    """
    path = tmp_path / "traffic.jsonl"
    recorder = Recorder(_app, path)
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/orders/o1",
        "CONTENT_LENGTH": "0",
        "HTTP_X_USER_ID": "bob",
        "REMOTE_ADDR": "203.0.113.7",
        "wsgi.input": _Empty(),
    }
    recorder(environ, lambda *args, **kwargs: None)
    log = TrafficLog.load(path)
    assert log.records[0].principal is None


def test_a_trusted_proxy_may_assert_an_identity(tmp_path: Path) -> None:
    """With an explicit trusted range, the proxy's assertion is believed."""
    path = tmp_path / "traffic.jsonl"
    recorder = Recorder(_app, path, trusted_proxy_cidrs=["127.0.0.1/32", "10.10.0.0/24"])
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/orders/o1",
        "CONTENT_LENGTH": "0",
        "HTTP_X_USER_ID": "bob",
        "REMOTE_ADDR": "10.10.0.5",
        "wsgi.input": _Empty(),
    }
    recorder(environ, lambda *args, **kwargs: None)
    log = TrafficLog.load(path)
    assert log.records[0].principal == "bob"


def test_a_forwarding_header_never_proves_trust(tmp_path: Path) -> None:
    """``X-Forwarded-For`` is written by the client - it proves nothing."""
    path = tmp_path / "traffic.jsonl"
    recorder = Recorder(_app, path, trusted_proxy_cidrs=["127.0.0.1/32"])
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/orders/o1",
        "CONTENT_LENGTH": "0",
        "HTTP_X_USER_ID": "bob",
        "HTTP_X_FORWARDED_FOR": "127.0.0.1",
        "REMOTE_ADDR": "203.0.113.7",
        "wsgi.input": _Empty(),
    }
    recorder(environ, lambda *args, **kwargs: None)
    log = TrafficLog.load(path)
    assert log.records[0].principal is None


class _Empty:
    def read(self, size: int = 0) -> bytes:
        return b""
