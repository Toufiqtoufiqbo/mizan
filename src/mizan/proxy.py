"""A recording reverse proxy: the traffic log without touching the application.

Wrapping the application in a middleware is the easy way to record traffic, but
it only works for code you can modify. The twin often launches a third-party
service, and that service cannot be changed. So Mizan sits in front of it and
writes down what goes by.

    proxy = RecordingProxy("http://127.0.0.1:8000", "traffic.jsonl")
    proxy.start()          # -> http://127.0.0.1:<free port>
    ...                    # point the engine at the proxy
    proxy.stop()

The output is the same JSONL format the middleware recorder produces, so both
can be used interchangeably.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mizan.identity import decode_token
from mizan.traffic import TrafficRecord, infer_resource, to_template

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------- #

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        pass

    def _handle(self) -> None:
        proxy: RecordingProxy = self.server.proxy  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path

        headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_BY_HOP}
        url = proxy.upstream.rstrip("/") + path
        request = urllib.request.Request(url, data=body or None, headers=headers, method=self.command)

        status = 0
        response_headers: list[tuple[str, str]] = []
        payload = b""
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status = response.status
                response_headers = list(response.headers.items())
                payload = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = list(exc.headers.items()) if exc.headers else []
            payload = exc.read()
        except Exception as exc:
            status = 502
            payload = json.dumps({"error": str(exc)}).encode("utf-8")
            response_headers = [("Content-Type", "application/json")]

        proxy.record(
            method=self.command,
            path=path,
            status=status,
            headers=self.headers,
            body=body,
            payload=payload,
        )

        self.send_response(status)
        for key, value in response_headers:
            if key.lower() in HOP_BY_HOP:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    # -- verbs -------------------------------------------------------------- #

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()


#: The environment variable that tells the proxy which token belongs to whom.
#: A token that is not a JWT carries no readable identity, so the operator has
#: to say who it is - Mizan will not guess.
IDENTITY_MAP_ENV = "MIZAN_IDENTITY_MAP"


class RecordingProxy:
    """A proxy that writes the traffic log.

    The identity of a request comes from the token's claims when the token is
    a JWT, and from `identity_map` otherwise. Without an identity the traffic is
    still recorded, but the engine cannot say who owns what.
    """

    def __init__(
        self,
        upstream: str,
        traffic_path: str | Path,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        identity_map: dict[str, str] | None = None,
    ) -> None:
        self.upstream = upstream
        self.path = Path(traffic_path)
        self.host = host
        self.port = port
        self.identity_map = dict(identity_map or {})
        if not self.identity_map:
            self.identity_map = _identity_map_from_env()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        server = ThreadingHTTPServer((self.host, self.port), _Handler)
        server.daemon_threads = True
        server.proxy = self  # type: ignore[attr-defined]
        self._server = server
        self.port = int(server.server_address[1])
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> RecordingProxy:
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # -- recording ---------------------------------------------------------- #

    def record(
        self,
        *,
        method: str,
        path: str,
        status: int,
        headers: Any,
        body: bytes,
        payload: bytes,
    ) -> None:
        template = to_template(path.split("?")[0])
        response_json = _json(payload)
        resource_type, resource_id, resource_owner = infer_resource(response_json, template)
        record = TrafficRecord(
            method=method,
            path=path.split("?")[0],
            template=template,
            status=status,
            principal=_principal(headers, self.identity_map),
            body=_json(body),
            response=response_json,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_owner=resource_owner,
        )
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")


def _identity_map_from_env() -> dict[str, str]:
    """The identity map from the environment, if there is one."""
    import json
    import os

    raw = os.environ.get(IDENTITY_MAP_ENV)
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {str(token): str(principal) for token, principal in loaded.items()}


def _principal(headers: Any, identity_map: dict[str, str] | None = None) -> str | None:
    """The identity behind a request, as far as it can be told."""
    value = headers.get("Authorization") or headers.get("authorization")
    if value and value.startswith("Bearer "):
        token = value[len("Bearer ") :].strip()
        if identity_map and token in identity_map:
            return identity_map[token]
        claims = decode_token(token)
        if claims:
            return claims.subject
    fallback = headers.get("X-User-Id") or headers.get("x-user-id")
    return fallback if fallback else None


def _json(payload: bytes) -> Any:
    if not payload:
        return None
    try:
        return json.loads(payload)
    except Exception:
        try:
            return payload.decode("utf-8")[:2000]
        except Exception:
            return None
