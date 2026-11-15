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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mizan.identity import resolve_principal
from mizan.traffic import TrafficRecord, infer_resource, to_template


def principal_from_token(token: str | None, identity_map: dict[str, str] | None = None) -> str | None:
    """The identity behind a bearer token, if it can be attributed.

    Resolution order: an entry in ``identity_map`` (a ``{token: principal}``
    mapping) wins; a readable JWT yields its subject; anything else - notably
    an opaque token nobody configured - is unattributable and yields ``None``.
    No identity is ever invented here.
    """
    return resolve_principal(token, identity_map)


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
        identity_map: dict[str, str] | None = None,
    ) -> None:
        self.app = app
        self.path = Path(traffic_path)
        self.principal_header = principal_header
        self.principal_header_prefix = principal_header_prefix
        self.user_id_header = user_id_header
        #: ``{token value: principal id}`` for opaque tokens the operator
        #: identified in advance. Same meaning as on :class:`RecordingProxy`.
        self.identity_map = dict(identity_map or {})
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
            # A presented token decides the identity - or decides that there
            # is none. An unknown opaque token stays unknown: the user-id
            # header is never consulted to rescue an authentication attempt,
            # because a forged header must not attribute traffic to someone.
            return principal_from_token(header[len(self.principal_header_prefix) :].strip(), self.identity_map)
        if self.user_id_header:
            value = environ.get(self.user_id_header)
            if value:
                # Only reached when no Authorization header was presented.
                # This is the deployment's own signal about the caller, not
                # an authenticated identity, and it can never override one.
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

The identity map is read from MIZAN_IDENTITY_MAP as a JSON object mapping
*token values* to principal names - the same format the RecordingProxy uses,
and the shape the identity-map file resolves to. Only variable names and
principal names travel through configuration; the tokens come from the
environment or the traffic itself.
"""

import json
import os

from mizan.identity import decode_token

TRAFFIC = os.environ.get("MIZAN_TRAFFIC", "traffic.jsonl")


def _identity_map():
    raw = os.environ.get("MIZAN_IDENTITY_MAP", "")
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {str(token): str(principal) for token, principal in loaded.items()}


def _principal(headers, identity_map):
    """Same resolution rules as the WSGI recorder and the proxy."""
    header = headers.get("Authorization", "")
    if header.startswith("Bearer "):
        token = header[len("Bearer "):].strip()
        if token in identity_map:
            return identity_map[token]
        claims = decode_token(token)
        if claims and claims.subject:
            return claims.subject
        # An unknown opaque token stays unknown - the user-id header is
        # never consulted to rescue an authentication attempt.
        return None
    return headers.get("X-User-Id")


def response(flow):
    request = flow.request
    if request.method == "CONNECT":
        return
    principal = _principal(request.headers, _identity_map())
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
