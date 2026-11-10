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


def test_recorder_falls_back_to_a_user_header(tmp_path: Path) -> None:
    path = tmp_path / "traffic.jsonl"
    recorder = Recorder(_app, path)
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/orders/o1",
        "CONTENT_LENGTH": "0",
        "HTTP_X_USER_ID": "bob",
        "wsgi.input": _Empty(),
    }
    recorder(environ, lambda *args, **kwargs: None)
    log = TrafficLog.load(path)
    assert log.records[0].principal == "bob"


class _Empty:
    def read(self, size: int = 0) -> bytes:
        return b""
