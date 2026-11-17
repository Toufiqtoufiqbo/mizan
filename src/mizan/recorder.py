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
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from mizan.identity import TrustedProxies, resolve_identity, resolve_principal
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
        trusted_proxy_cidrs: Sequence[str] = (),
    ) -> None:
        self.app = app
        self.path = Path(traffic_path)
        self.principal_header = principal_header
        self.principal_header_prefix = principal_header_prefix
        self.user_id_header = user_id_header
        #: ``{token value: principal id}`` for opaque tokens the operator
        #: identified in advance. Same meaning as on :class:`RecordingProxy`.
        self.identity_map = dict(identity_map or {})
        #: The reverse proxies whose asserted identity may be believed.
        #: Empty by default: an ``X-User-Id`` header is not an identity
        #: unless the immediate peer is an explicitly trusted proxy.
        #: An invalid CIDR is rejected here, at initialisation.
        self.trusted_proxies = TrustedProxies.from_cidrs(trusted_proxy_cidrs)
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
        resource_type, resource_id, resource_owner = infer_resource(payload, to_template(path), path=path)
        record = TrafficRecord(
            method=method,
            path=path,
            template=to_template(path),
            status=captured.get("status", 0),
            principal=principal,
            body=body,
            response=payload,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_owner=resource_owner,
        )
        self._write(record)
        return response

    # -- helpers ------------------------------------------------------------ #

    def _principal(self, environ: dict[str, Any]) -> str | None:
        """The identity behind one request.

        The peer address is ``REMOTE_ADDR`` - the address the request
        arrived on. ``HTTP_X_FORWARDED_FOR`` is written by the client and is
        never consulted.
        """
        return resolve_identity(
            authorization=environ.get(self.principal_header),
            user_id=environ.get(self.user_id_header) if self.user_id_header else None,
            peer=environ.get("REMOTE_ADDR"),
            identity_map=self.identity_map,
            trusted_proxies=self.trusted_proxies,
            bearer_prefix=self.principal_header_prefix,
        )

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

A broken configuration is an error, never an empty configuration: an
identity map that cannot be parsed is loud, because a silently empty map
would attribute nothing and look like a quiet scan.

X-User-Id is only believed when the request came from an explicitly trusted
proxy. Configure the ranges with MIZAN_TRUSTED_PROXY_CIDRS, a comma separated
list of CIDR ranges (empty by default - no proxy is trusted). The trusted
proxy must strip any client-supplied X-User-Id and overwrite it with the
authenticated identity; Mizan compares the immediate peer address, never a
forwarding header the client could write.
"""

import json
import os

from mizan.identity import TrustedProxies, resolve_identity

TRAFFIC = os.environ.get("MIZAN_TRAFFIC", "traffic.jsonl")


def _identity_map():
    """The identity map from the environment, or an explicit failure."""
    raw = os.environ.get("MIZAN_IDENTITY_MAP", "")
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except ValueError as exc:
        raise ValueError(
            "MIZAN_IDENTITY_MAP is not valid JSON: " + exc.__class__.__name__
        ) from exc
    if not isinstance(loaded, dict):
        raise ValueError("MIZAN_IDENTITY_MAP must be a JSON object mapping tokens to principal names")
    return {str(token): str(principal) for token, principal in loaded.items()}


def _trusted_proxies():
    """The trusted proxy ranges from the environment, or an explicit failure."""
    raw = os.environ.get("MIZAN_TRUSTED_PROXY_CIDRS", "")
    cidrs = [part.strip() for part in raw.split(",") if part.strip()]
    return TrustedProxies.from_cidrs(cidrs)


def _peer(flow):
    """The immediate peer address, or None when it is unavailable."""
    try:
        peer = flow.client_conn.peername
    except AttributeError:
        return None
    if isinstance(peer, (tuple, list)) and peer:
        return str(peer[0])
    return None


def _principal(headers, identity_map, trusted_proxies, peer):
    """The same rules as the WSGI recorder and the proxy - one implementation."""
    return resolve_identity(
        authorization=headers.get("Authorization"),
        user_id=headers.get("X-User-Id"),
        peer=peer,
        identity_map=identity_map,
        trusted_proxies=trusted_proxies,
    )


#: Read once, at start-up: a broken configuration must not wait for the
#: first request to announce itself.
IDENTITY_MAP = _identity_map()
TRUSTED_PROXIES = _trusted_proxies()


def response(flow):
    request = flow.request
    if request.method == "CONNECT":
        return
    principal = _principal(request.headers, IDENTITY_MAP, TRUSTED_PROXIES, _peer(flow))
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
