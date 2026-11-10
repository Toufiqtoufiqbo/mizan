"""Record the traffic Mizan learns from.

Mizan needs two inputs: the traffic of a healthy application, and a ledger of
attributed database writes. This module produces the first one.

Two recorders are provided:

* :class:`Recorder` - a WSGI middleware. Wrap any Flask, Django or FastAPI
  application with it and every request/response is written to the traffic log.
* ``mitm_recorder.py`` - a mitmproxy addon for applications you cannot wrap,
  for example a service behind a gateway.

The traffic log is JSONL, one line per request::

    {"method": "GET", "path": "/orders/o1", "template": "/orders/{id}",
     "status": 200, "principal": "alice", "body": null,
     "response": {"id": "o1", "owner_id": "alice"}, ...}
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable

from mizan.identity import decode_token
from mizan.traffic import TrafficRecord, infer_resource, to_template


def principal_from_token(token: str | None) -> str | None:
    """The subject a bearer token claims, if it is readable."""
    if not token:
        return None
    claims = decode_token(token)
    if claims is None or claims.subject is None:
        return None
    return claims.subject


class Recorder:
    """WSGI middleware that writes a traffic log.

    >>> app = Recorder(app, "traffic.jsonl")
    """

    def __init__(
        self,
        app: Callable[..., Any],
        traffic_path: str | Path,
        *,
        principal_header: str = "HTTP_AUTHORIZATION",
        principal_header_prefix: str = "Bearer ",
        user_id_header: str | None = "HTTP_X_USER_ID",
    ) -> None:
        self.app = app
        self.path = Path(traffic_path)
        self.principal_header = principal_header
        self.principal_header_prefix = principal_header_prefix
        self.user_id_header = user_id_header
        self._lock = threading.Lock()

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        body = _read_body(environ)
        principal = self._principal(environ)
        captured: dict[str, Any] = {}

        def start_response_wrapper(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
            captured["status"] = int(str(status).split(" ")[0])
            captured["headers"] = headers
            return start_response(status, headers, exc_info)

        response = self.app(environ, start_response_wrapper)
        payload = _decode(response)
        record = TrafficRecord(
            method=method,
            path=path,
            template=to_template(path),
            status=captured.get("status", 0),
            principal=principal,
            body=body,
            response=payload,
            resource_type=infer_resource(payload, to_template(path))[0],
            resource_id=infer_resource(payload, to_template(path))[1],
            resource_owner=infer_resource(payload, to_template(path))[2],
        )
        self._write(record)
        return response

    # -- helpers ------------------------------------------------------------ #

    def _principal(self, environ: dict[str, Any]) -> str | None:
        header = environ.get(self.principal_header)
        if header and header.startswith(self.principal_header_prefix):
            subject = principal_from_token(header[len(self.principal_header_prefix) :].strip())
            if subject:
                return subject
        if self.user_id_header:
            value = environ.get(self.user_id_header)
            if value:
                return value
        return None

    def _write(self, record: TrafficRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")


def _read_body(environ: dict[str, Any]) -> Any:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if not length:
        return None
    raw = environ["wsgi.input"].read(length)
    try:
        return json.loads(raw)
    except Exception:
        return None


def _decode(response: Any) -> Any:
    body = b"".join(response) if not isinstance(response, (str, bytes)) else response
    if isinstance(body, bytes):
        try:
            return json.loads(body)
        except Exception:
            return None
    return None


MITM_ADDON = '''"""mitmproxy addon that writes a Mizan traffic log.

    mitmdump -s mitm_recorder.py --set mizan_traffic=traffic.jsonl
"""

import json
import os

from mizan.identity import decode_token

TRAFFIC = os.environ.get("MIZAN_TRAFFIC", "traffic.jsonl")


def response(flow):
    request = flow.request
    if request.method == "CONNECT":
        return
    principal = None
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        claims = decode_token(header[len("Bearer "):].strip())
        if claims:
            principal = claims.subject
    if principal is None:
        principal = request.headers.get("X-User-Id")
    template = flow.request.path.split("?")[0]
    record = {
        "method": request.method,
        "path": template,
        "template": template,
        "status": flow.response.status_code,
        "principal": principal,
        "body": request.get_text(strict=False) or None,
        "response": flow.response.get_text(strict=False) or None,
    }
    with open(TRAFFIC, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\\n")
'''
