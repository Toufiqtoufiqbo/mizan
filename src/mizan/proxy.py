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
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mizan.identity import IdentityMapError, TrustedProxies, resolve_identity
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
            peer=self.client_address[0],
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

#: The environment variable that names the reverse proxies whose asserted
#: identity Mizan may believe. A comma separated list of CIDR ranges; empty
#: by default, which means no proxy is trusted.
TRUSTED_PROXY_CIDRS_ENV = "MIZAN_TRUSTED_PROXY_CIDRS"


class RecordingProxy:
    """A proxy that writes the traffic log.

    The identity of a request comes from the token's claims when the token is
    a JWT, and from `identity_map` otherwise. Without an identity the traffic is
    still recorded, but the engine cannot say who owns what.

    ``X-User-Id`` is believed only when the immediate peer is an explicitly
    trusted proxy (see ``trusted_proxy_cidrs``). The default is to trust
    nobody: a header is not a proof of identity.
    """

    def __init__(
        self,
        upstream: str,
        traffic_path: str | Path,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        identity_map: dict[str, str] | None = None,
        trusted_proxy_cidrs: Sequence[str] | None = None,
    ) -> None:
        self.upstream = upstream
        self.path = Path(traffic_path)
        self.host = host
        self.port = port
        self.identity_map = dict(identity_map or {})
        if not self.identity_map:
            self.identity_map = _identity_map_from_env()
        if trusted_proxy_cidrs is None:
            self.trusted_proxies = _trusted_proxies_from_env()
        else:
            self.trusted_proxies = TrustedProxies.from_cidrs(trusted_proxy_cidrs)
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
        peer: str | None = None,
    ) -> None:
        template = to_template(path.split("?")[0])
        response_json = _json(payload)
        resource_type, resource_id, resource_owner = infer_resource(response_json, template)
        record = TrafficRecord(
            method=method,
            path=path.split("?")[0],
            template=template,
            status=status,
            principal=_principal(headers, self.identity_map, peer=peer, trusted_proxies=self.trusted_proxies),
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
    """The identity map from the environment, if there is one.

    ``MIZAN_IDENTITY_MAP`` is a JSON object mapping **token values** to
    principal names - the same shape :meth:`validation` passes to the proxy.
    Configuration travels as names, never as secrets in a file.

    Fail closed: a set-but-unparseable variable is an error, not an empty
    map - a silently dropped identity map would attribute nothing and could
    turn a misconfiguration into a quietly useless scan.
    """
    import json
    import os

    raw = os.environ.get(IDENTITY_MAP_ENV)
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except ValueError as exc:
        raise IdentityMapError(f"{IDENTITY_MAP_ENV} is not valid JSON: {exc.__class__.__name__}") from exc
    if not isinstance(loaded, dict):
        raise IdentityMapError(f"{IDENTITY_MAP_ENV} must be a JSON object mapping tokens to principal names")
    return {str(token): str(principal) for token, principal in loaded.items()}


def _trusted_proxies_from_env() -> TrustedProxies:
    """The trusted proxy ranges from the environment.

    ``MIZAN_TRUSTED_PROXY_CIDRS`` is a comma separated list of CIDR ranges.
    Unset means an empty allowlist - no proxy is trusted.

    Fail closed: a set-but-invalid value is an error, not an empty
    allowlist. Silently ignoring a broken range would either trust a proxy
    the operator did not intend, or - worse - look like a working
    configuration while trusting nobody.
    """
    import os

    raw = os.environ.get(TRUSTED_PROXY_CIDRS_ENV, "")
    cidrs = [part.strip() for part in raw.split(",") if part.strip()]
    return TrustedProxies.from_cidrs(cidrs)


def _principal(
    headers: Any,
    identity_map: dict[str, str] | None = None,
    *,
    peer: str | None = None,
    trusted_proxies: TrustedProxies | None = None,
) -> str | None:
    """The identity behind a request, as far as it can be told.

    One rule, shared with the WSGI recorder and the MITM addon:

    1. an Authorization header was presented - it alone decides. A ``Bearer``
       token resolves through the identity map, then through a readable JWT
       subject (extracted, never verified). Any other scheme - ``Basic``,
       empty, malformed - yields no identity and no fallback;
    2. no Authorization header - the ``X-User-Id`` header is believed only
       when the **immediate peer** (``peer``, the socket the request arrived
       on) is inside an explicitly trusted proxy range. A forwarding header
       is never used as proof of trust.
    """
    return resolve_identity(
        authorization=headers.get("Authorization"),
        user_id=headers.get("X-User-Id") or headers.get("x-user-id"),
        peer=peer,
        identity_map=identity_map,
        trusted_proxies=trusted_proxies,
    )


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
