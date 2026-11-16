"""The trusted identity boundary.

An identity must come from a configured token mapping, an explicitly
documented token claim, or a verified trusted upstream source. An arbitrary
HTTP header is not proof of identity.

This module runs one matrix against all three recording components - the
WSGI recorder, the recording proxy and the MITM addon - so that no component
can quietly develop its own, weaker, policy.

The rules the matrix pins:

* an ``Authorization`` header that is present decides on its own, even when
  it is empty, malformed, or uses an unsupported scheme - it never falls back
  to a header the caller controls;
* ``X-User-Id`` is believed only when the **immediate peer** is inside an
  explicitly configured trusted-proxy range;
* a forwarding header such as ``X-Forwarded-For`` is never proof of trust;
* a missing peer address fails closed;
* a broken configuration is an error, never an empty configuration.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

from mizan.identity import TrustedProxies, TrustedProxyError
from mizan.proxy import RecordingProxy
from mizan.proxy import _principal as proxy_principal
from mizan.recorder import MITM_ADDON, Recorder

#: The trusted ranges used by the matrix.
TRUSTED_CIDRS = ["10.10.0.0/24"]

#: A peer inside the trusted range.
TRUSTED_PEER = "10.10.0.5"

#: A peer outside every trusted range.
UNTRUSTED_PEER = "203.0.113.7"

#: The opaque tokens the operator configured.
IDENTITY_MAP = {"tok-a": "alice", "tok-b": "bob"}


def _jwt(subject: str) -> str:
    from mizan.benchmark.apps import make_token

    return make_token(subject)


@dataclass(frozen=True)
class Scenario:
    """One row of the matrix."""

    name: str
    authorization: str | None
    user_id: str | None
    peer: str | None
    expected: str | None
    extra_environ: dict = field(default_factory=dict)


SCENARIOS = [
    Scenario("no authorization and no user id", None, None, UNTRUSTED_PEER, None),
    Scenario("no authorization, untrusted peer, user id", None, "alice", UNTRUSTED_PEER, None),
    Scenario("no authorization, trusted peer, user id", None, "alice", TRUSTED_PEER, "alice"),
    Scenario("bearer with a mapped token", "Bearer tok-a", None, UNTRUSTED_PEER, "alice"),
    Scenario("bearer with an unknown opaque token", "Bearer tok-unknown", "alice", UNTRUSTED_PEER, None),
    Scenario("malformed authorization header", "Bearer", "alice", UNTRUSTED_PEER, None),
    Scenario("unsupported authorization scheme", "Basic dXNlcjpwYXNz", "alice", UNTRUSTED_PEER, None),
    Scenario("empty but present authorization header", "", "alice", UNTRUSTED_PEER, None),
    Scenario("jwt with a conflicting user id", f"Bearer {_jwt('alice')}", "bob", UNTRUSTED_PEER, "alice"),
    Scenario(
        "trusted peer spoofed through x-forwarded-for",
        None,
        "alice",
        UNTRUSTED_PEER,
        None,
        {"HTTP_X_FORWARDED_FOR": TRUSTED_PEER},
    ),
    Scenario("peer address unavailable", None, "alice", None, None),
]


# --------------------------------------------------------------------------- #
# helpers: one WSGI application and one header mapping
# --------------------------------------------------------------------------- #


class _Empty:
    def read(self, size: int = 0) -> bytes:
        return b""


def _wsgi_app(environ, start_response):
    payload = json.dumps({"id": "o1", "owner_id": "alice"}).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(payload)))])
    return [payload]


class _Headers:
    """Just enough of an HTTP header mapping for the proxy's resolver."""

    def __init__(self, values: dict) -> None:
        self._values = values

    def get(self, name: str, default: str | None = None) -> str | None:
        if name in self._values:
            return self._values[name]
        for key, value in self._values.items():
            if key.lower() == name.lower():
                return value
        return default


# --------------------------------------------------------------------------- #
# the matrix, component by component
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_the_wsgi_recorder_follows_the_matrix(tmp_path: Path, scenario: Scenario) -> None:
    from mizan.traffic import TrafficLog

    recorder = Recorder(
        _wsgi_app,
        tmp_path / "traffic.jsonl",
        identity_map=IDENTITY_MAP,
        trusted_proxy_cidrs=TRUSTED_CIDRS,
    )
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/orders/o1",
        "CONTENT_LENGTH": "0",
        "wsgi.input": _Empty(),
    }
    if scenario.peer is not None:
        environ["REMOTE_ADDR"] = scenario.peer
    if scenario.authorization is not None:
        environ["HTTP_AUTHORIZATION"] = scenario.authorization
    if scenario.user_id is not None:
        environ["HTTP_X_USER_ID"] = scenario.user_id
    environ.update(scenario.extra_environ)

    recorder(environ, lambda *args, **kwargs: None)
    assert TrafficLog.load(tmp_path / "traffic.jsonl").records[-1].principal == scenario.expected


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_the_recording_proxy_follows_the_matrix(scenario: Scenario) -> None:
    headers: dict = {}
    if scenario.authorization is not None:
        headers["Authorization"] = scenario.authorization
    if scenario.user_id is not None:
        headers["X-User-Id"] = scenario.user_id
    for name, value in scenario.extra_environ.items():
        headers[name.replace("HTTP_", "").replace("_", "-").title()] = value

    resolved = proxy_principal(
        _Headers(headers),
        IDENTITY_MAP,
        peer=scenario.peer,
        trusted_proxies=TrustedProxies.from_cidrs(TRUSTED_CIDRS),
    )
    assert resolved == scenario.expected


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_the_mitm_addon_follows_the_matrix(tmp_path: Path, scenario: Scenario, monkeypatch: pytest.MonkeyPatch) -> None:
    traffic = tmp_path / "traffic.jsonl"
    namespace = _load_addon(traffic, trusted_cidrs=TRUSTED_CIDRS, identity_map=IDENTITY_MAP, monkeypatch=monkeypatch)

    headers: dict = {}
    if scenario.authorization is not None:
        headers["Authorization"] = scenario.authorization
    if scenario.user_id is not None:
        headers["X-User-Id"] = scenario.user_id
    for name, value in scenario.extra_environ.items():
        headers[name.replace("HTTP_", "").replace("_", "-").title()] = value

    namespace["response"](_flow(headers, scenario.peer))
    records = [json.loads(line) for line in traffic.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["principal"] == scenario.expected


# --------------------------------------------------------------------------- #
# the addon, loaded the way mitmdump loads it
# --------------------------------------------------------------------------- #


def _load_addon(
    traffic: Path,
    *,
    trusted_cidrs: list[str] | None,
    identity_map: dict | None,
    identity_map_raw: str | None = None,
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    """Load the addon template with the given environment.

    The environment changes are undone by ``monkeypatch`` when the test
    ends, so one test never inherits another's configuration.
    """
    monkeypatch.setenv("MIZAN_TRAFFIC", str(traffic))
    monkeypatch.delenv("MIZAN_IDENTITY_MAP", raising=False)
    monkeypatch.delenv("MIZAN_TRUSTED_PROXY_CIDRS", raising=False)
    if identity_map_raw is not None:
        monkeypatch.setenv("MIZAN_IDENTITY_MAP", identity_map_raw)
    elif identity_map is not None:
        monkeypatch.setenv("MIZAN_IDENTITY_MAP", json.dumps(identity_map))
    if trusted_cidrs is not None:
        monkeypatch.setenv("MIZAN_TRUSTED_PROXY_CIDRS", ",".join(trusted_cidrs))
    namespace: dict = {"__name__": "mitm_recorder"}
    exec(compile(MITM_ADDON, "mitm_recorder.py", "exec"), namespace)  # noqa: S102 - Mizan's own template
    return namespace


def _flow(headers: dict, peer: str | None):
    """A minimal mitmproxy flow: request, response and the client connection."""

    class _Request:
        method = "GET"
        path = "/orders/o1"

        def __init__(self) -> None:
            self.headers = headers

        def get_text(self, strict: bool = False) -> str:
            return ""

    class _Response:
        status_code = 200

        def get_text(self, strict: bool = False) -> str:
            return json.dumps({"id": "o1", "owner_id": "alice"})

    class _Connection:
        def __init__(self) -> None:
            self.peername = (peer, 54321) if peer else None

    class _Flow:
        request = _Request()
        response = _Response()
        client_conn = _Connection()

    return _Flow()


# --------------------------------------------------------------------------- #
# configuration is validated, never guessed
# --------------------------------------------------------------------------- #


def test_the_default_trusts_nobody() -> None:
    assert TrustedProxies.from_cidrs(()).trusts("127.0.0.1") is False
    assert TrustedProxies.from_cidrs(None).trusts("127.0.0.1") is False


def test_an_invalid_cidr_is_rejected() -> None:
    with pytest.raises(TrustedProxyError) as excinfo:
        TrustedProxies.from_cidrs(["not-a-cidr"])
    assert "not-a-cidr" in str(excinfo.value)


def test_an_invalid_cidr_is_rejected_by_the_recorder(tmp_path: Path) -> None:
    with pytest.raises(TrustedProxyError):
        Recorder(_wsgi_app, tmp_path / "traffic.jsonl", trusted_proxy_cidrs=["10.10.0.0/99"])


def test_an_invalid_cidr_is_rejected_by_the_proxy(tmp_path: Path) -> None:
    with pytest.raises(TrustedProxyError):
        RecordingProxy("http://127.0.0.1:1", tmp_path / "traffic.jsonl", trusted_proxy_cidrs=["10.10.0.0/99"])


def test_an_invalid_cidr_in_the_environment_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIZAN_TRUSTED_PROXY_CIDRS", "10.10.0.0/99")
    with pytest.raises(TrustedProxyError):
        RecordingProxy("http://127.0.0.1:1", tmp_path / "traffic.jsonl")


def test_an_invalid_identity_map_in_the_environment_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MIZAN_IDENTITY_MAP", "{not json")
    with pytest.raises(ValueError):
        RecordingProxy("http://127.0.0.1:1", tmp_path / "traffic.jsonl")


def test_the_addon_refuses_a_broken_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken configuration is loud - the addon refuses to start."""
    with pytest.raises(ValueError):
        _load_addon(
            tmp_path / "traffic.jsonl",
            trusted_cidrs=["10.10.0.0/99"],
            identity_map=None,
            monkeypatch=monkeypatch,
        )
    with pytest.raises(ValueError):
        _load_addon(
            tmp_path / "traffic.jsonl",
            trusted_cidrs=None,
            identity_map=None,
            identity_map_raw="{not json",
            monkeypatch=monkeypatch,
        )
    with pytest.raises(ValueError):
        _load_addon(
            tmp_path / "traffic.jsonl",
            trusted_cidrs=None,
            identity_map=None,
            identity_map_raw=json.dumps(["not", "a", "mapping"]),
            monkeypatch=monkeypatch,
        )


def test_no_configuration_error_mentions_a_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    canary = "MIZAN_SECRET_CANARY_TRUSTED_2A7F"
    monkeypatch.setenv("MIZAN_IDENTITY_MAP", json.dumps({canary: "alice"}))
    monkeypatch.setenv("MIZAN_TRUSTED_PROXY_CIDRS", "not-a-cidr")
    with pytest.raises(TrustedProxyError) as excinfo:
        RecordingProxy("http://127.0.0.1:1", tmp_path / "traffic.jsonl")
    assert canary not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# end to end: the proxy uses the socket peer, not a header
# --------------------------------------------------------------------------- #


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass

    def do_GET(self) -> None:
        payload = json.dumps({"id": "o1", "owner_id": "alice"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def upstream() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_the_proxy_uses_the_socket_peer_address(tmp_path: Path, upstream: str) -> None:
    """The peer is the address the request arrived on - nothing else."""
    from mizan.traffic import TrafficLog

    traffic = tmp_path / "traffic.jsonl"
    # The proxy listens on 127.0.0.1, so the peer is 127.0.0.1.
    trusted = RecordingProxy(upstream, traffic, trusted_proxy_cidrs=["127.0.0.1/32"])
    trusted.start()
    try:
        requests.get(f"{trusted.base_url}/orders/o1", headers={"X-User-Id": "alice"}, timeout=10)
    finally:
        trusted.stop()
    assert TrafficLog.load(traffic).records[-1].principal == "alice"

    untrusted = RecordingProxy(upstream, traffic, trusted_proxy_cidrs=["10.10.0.0/24"])
    untrusted.start()
    try:
        requests.get(
            f"{untrusted.base_url}/orders/o1",
            headers={"X-User-Id": "alice", "X-Forwarded-For": "127.0.0.1"},
            timeout=10,
        )
    finally:
        untrusted.stop()
    assert TrafficLog.load(traffic).records[-1].principal is None


def test_a_remote_client_cannot_claim_another_users_identity(tmp_path: Path, upstream: str) -> None:
    """The headline attack: a header alone must never attribute traffic."""
    from mizan.traffic import TrafficLog

    traffic = tmp_path / "traffic.jsonl"
    proxy = RecordingProxy(upstream, traffic)
    proxy.start()
    try:
        requests.get(
            f"{proxy.base_url}/orders/o1",
            headers={"X-User-Id": "alice", "X-Forwarded-For": "10.10.0.5"},
            timeout=10,
        )
        requests.get(
            f"{proxy.base_url}/orders/o1",
            headers={"Authorization": "Bearer tok-unknown", "X-User-Id": "alice"},
            timeout=10,
        )
        requests.get(
            f"{proxy.base_url}/orders/o1",
            headers={"Authorization": "Basic dXNlcjpwYXNz", "X-User-Id": "alice"},
            timeout=10,
        )
    finally:
        proxy.stop()
    assert [record.principal for record in TrafficLog.load(traffic).records] == [None, None, None]
