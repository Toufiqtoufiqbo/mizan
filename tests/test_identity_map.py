"""Identity-map configuration and identity-resolution semantics.

The law *L1* needs an identity it can trust, or an admission that there is
none. These tests pin both halves:

* a broken or contradictory identity-map configuration is an error, never a
  silent partial load;
* an unattributable token stays unattributable - no recorder ever invents an
  identity, and a forged ``X-User-Id`` can never override an authentication
  attempt.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mizan.core import UNKNOWN_PRINCIPAL
from mizan.identity import (
    IdentityMapError,
    TrustedProxies,
    load_identity_map,
    parse_identity_map,
    resolve_identity_map,
    resolve_principal,
    validate_principal_id,
)
from mizan.proxy import _principal as proxy_principal
from mizan.recorder import Recorder, principal_from_token

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _config(**principals: dict) -> str:
    return json.dumps({"version": 1, "principals": principals})


_ALICE = {"token_env": "MIZAN_TOKEN_ALICE", "roles": ["user"]}
_BOB = {"token_env": "MIZAN_TOKEN_BOB", "roles": ["user"]}


class _Empty:
    def read(self, size: int = 0) -> bytes:
        return b""


def _wsgi_app(environ, start_response):
    payload = json.dumps({"id": "o1", "owner_id": "alice"}).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(payload)))])
    return [payload]


def _record_principals(tmp_path: Path, *environ_overrides: dict) -> list[str | None]:
    recorder = Recorder(_wsgi_app, tmp_path / "traffic.jsonl", identity_map=None)
    results = []
    for headers in environ_overrides:
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/orders/o1",
            "CONTENT_LENGTH": "0",
            "wsgi.input": _Empty(),
            **headers,
        }
        recorder(environ, lambda *args, **kwargs: None)
        from mizan.traffic import TrafficLog

        log = TrafficLog.load(tmp_path / "traffic.jsonl")
        results.append(log.records[-1].principal)
    return results


# --------------------------------------------------------------------------- #
# configuration parsing - every rejection the mission demands
# --------------------------------------------------------------------------- #


def test_a_valid_configuration_with_one_principal() -> None:
    config = parse_identity_map(_config(alice=_ALICE))
    assert config.version == 1
    assert config.principals == {"alice": "MIZAN_TOKEN_ALICE"}
    assert config.roles == {"alice": ("user",)}


def test_a_valid_configuration_with_several_principals() -> None:
    config = parse_identity_map(_config(alice=_ALICE, bob=_BOB))
    assert config.principals == {"alice": "MIZAN_TOKEN_ALICE", "bob": "MIZAN_TOKEN_BOB"}


def test_roles_are_optional() -> None:
    config = parse_identity_map(_config(alice={"token_env": "MIZAN_TOKEN_ALICE"}))
    assert config.roles == {"alice": ()}


@pytest.mark.parametrize(
    "raw",
    [
        "not json at all",
        "[]",
        '"a string"',
        "42",
        json.dumps({"principals": {"alice": _ALICE}}),  # version missing
        json.dumps({"version": 2, "principals": {"alice": _ALICE}}),  # unsupported version
        json.dumps({"version": True, "principals": {"alice": _ALICE}}),  # bool is not an int
        json.dumps({"version": 1}),  # principals missing
        json.dumps({"version": 1, "principals": {}}),  # principals empty
        json.dumps({"version": 1, "principals": {"alice": "MIZAN_TOKEN_ALICE"}}),  # definition not an object
        json.dumps({"version": 1, "principals": {"alice": {"roles": ["user"]}}}),  # token_env missing
        json.dumps({"version": 1, "principals": {"alice": {"token_env": ""}}}),  # token_env empty
        json.dumps({"version": 1, "principals": {"alice": {"token_env": "MY TOKEN"}}}),  # not a variable name
        json.dumps({"version": 1, "principals": {"alice": {"token_env": "1BAD"}}}),  # not a variable name
        json.dumps(
            {
                "version": 1,
                "principals": {
                    "alice": {"token_env": "MIZAN_TOKEN_SHARED"},
                    "bob": {"token_env": "MIZAN_TOKEN_SHARED"},
                },
            }
        ),  # duplicate token assignment
        json.dumps({"version": 1, "principals": {"alice": {"token_env": "MIZAN_TOKEN_ALICE", "roles": "user"}}}),
        json.dumps({"version": 1, "principals": {"alice": {"token_env": "MIZAN_TOKEN_ALICE", "roles": [""]}}}),
        json.dumps({"version": 1, "principals": {"alice": {"token_env": "MIZAN_TOKEN_ALICE", "roles": [3]}}}),
        json.dumps({"version": 1, "principals": {"": _ALICE}}),  # empty principal id
        json.dumps({"version": 1, "principals": {"unknown": _ALICE}}),  # reserved id
        json.dumps({"version": 1, "principals": {"has space": _ALICE}}),  # unusable id
        json.dumps({"version": 1, "principals": {"; drop table x": _ALICE}}),  # unusable id
        json.dumps({"version": 1, "principals": {"a" * 200: _ALICE}}),  # unusable id
    ],
)
def test_every_broken_configuration_is_rejected_with_an_error(raw: str) -> None:
    with pytest.raises(IdentityMapError):
        parse_identity_map(raw)


def test_the_duplicate_token_error_names_both_principals_and_never_a_token() -> None:
    raw = json.dumps(
        {
            "version": 1,
            "principals": {
                "alice": {"token_env": "MIZAN_TOKEN_SHARED"},
                "bob": {"token_env": "MIZAN_TOKEN_SHARED"},
            },
        }
    )
    with pytest.raises(IdentityMapError) as excinfo:
        parse_identity_map(raw)
    message = str(excinfo.value)
    assert "alice" in message and "bob" in message
    assert "MIZAN_TOKEN_SECRET_VALUE" not in message


def test_a_reserved_principal_id_cannot_shadow_the_unknown_identity() -> None:
    with pytest.raises(IdentityMapError):
        validate_principal_id("unknown")
    assert UNKNOWN_PRINCIPAL == "unknown"


def test_usable_principal_ids() -> None:
    for name in ("alice", "user-1", "svc:billing", "a_b.c", "A-1_2.3:4@5"):
        validate_principal_id(name)


def test_an_error_message_never_contains_a_token_value() -> None:
    with pytest.raises(IdentityMapError) as excinfo:
        parse_identity_map("{invalid")
    assert "MIZAN_SECRET" not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# resolution from the environment
# --------------------------------------------------------------------------- #


def test_resolve_identity_map_reads_tokens_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "token-alice-1")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "token-bob-2")
    principals, tokens = resolve_identity_map(parse_identity_map(_config(alice=_ALICE, bob=_BOB)))
    by_id = {principal.id: principal for principal in principals}
    assert by_id["alice"].roles == ("user",)
    assert by_id["alice"].token == "token-alice-1"
    assert tokens == {"token-alice-1": "alice", "token-bob-2": "bob"}


def test_a_missing_environment_variable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIZAN_TOKEN_ALICE", raising=False)
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "token-bob-2")
    with pytest.raises(IdentityMapError) as excinfo:
        resolve_identity_map(parse_identity_map(_config(alice=_ALICE, bob=_BOB)))
    message = str(excinfo.value)
    assert "MIZAN_TOKEN_ALICE" in message
    assert "token-bob-2" not in message  # a configured variable's value never leaks into an error


def test_an_empty_environment_variable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "")
    with pytest.raises(IdentityMapError) as excinfo:
        resolve_identity_map(parse_identity_map(_config(alice=_ALICE)))
    assert "empty" in str(excinfo.value)
    assert "MIZAN_TOKEN_ALICE" in str(excinfo.value)


def test_two_principals_resolving_to_one_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", "token-shared-3")
    monkeypatch.setenv("MIZAN_TOKEN_BOB", "token-shared-3")
    config = parse_identity_map(_config(alice=_ALICE, bob=_BOB))
    with pytest.raises(IdentityMapError) as excinfo:
        resolve_identity_map(config)
    assert "alice" in str(excinfo.value) and "bob" in str(excinfo.value)


def test_the_configuration_file_is_loaded_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "identity-map.json"
    path.write_text(_config(alice=_ALICE), encoding="utf-8")
    config = load_identity_map(path)
    assert config.principals == {"alice": "MIZAN_TOKEN_ALICE"}


def test_an_unreadable_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(IdentityMapError):
        load_identity_map(tmp_path / "missing.json")


# --------------------------------------------------------------------------- #
# the shared resolver: what a token can and cannot prove
# --------------------------------------------------------------------------- #


def _jwt(subject: str) -> str:
    from mizan.benchmark.apps import make_token

    return make_token(subject)


def test_a_mapped_opaque_token_resolves_to_its_principal() -> None:
    assert resolve_principal("opaque-alice", {"opaque-alice": "alice"}) == "alice"


def test_a_jwt_still_resolves_to_its_subject() -> None:
    assert resolve_principal(_jwt("alice"), None) == "alice"


def test_an_unknown_opaque_token_stays_unattributable() -> None:
    # Never a placeholder: "unknown" would flow into learning and become a
    # fake principal.
    assert resolve_principal("opaque-nobody", {"opaque-alice": "alice"}) is None
    assert resolve_principal("opaque-nobody", None) is None


def test_the_reserved_sentinel_is_not_a_resolvable_identity() -> None:
    assert resolve_principal("opaque-x", {"opaque-x": UNKNOWN_PRINCIPAL}) == UNKNOWN_PRINCIPAL  # only if configured


def test_recorder_level_resolver_keeps_the_pinned_semantics() -> None:
    assert principal_from_token(_jwt("alice")) == "alice"
    assert principal_from_token("opaque-token") is None
    assert principal_from_token(None) is None
    assert principal_from_token("opaque-token", {"opaque-token": "alice"}) == "alice"


# --------------------------------------------------------------------------- #
# behavioural: the WSGI recorder and the proxy agree
# --------------------------------------------------------------------------- #


def test_mapped_opaque_tokens_resolve_to_their_principals(tmp_path: Path) -> None:
    recorder = Recorder(_wsgi_app, tmp_path / "traffic.jsonl", identity_map={"tok-a": "alice", "tok-b": "bob"})
    for headers, expected in (
        ({"HTTP_AUTHORIZATION": "Bearer tok-a"}, "alice"),
        ({"HTTP_AUTHORIZATION": "Bearer tok-b"}, "bob"),
    ):
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/orders/o1",
            "CONTENT_LENGTH": "0",
            "wsgi.input": _Empty(),
            **headers,
        }
        recorder(environ, lambda *args, **kwargs: None)
        from mizan.traffic import TrafficLog

        assert TrafficLog.load(tmp_path / "traffic.jsonl").records[-1].principal == expected


def test_two_unattributed_tokens_are_never_conflated(tmp_path: Path) -> None:
    # Alice and Bob both send tokens nobody configured: each request stays
    # unattributable. They must not become one shared "unknown" user.
    recorder = Recorder(_wsgi_app, tmp_path / "traffic.jsonl")
    from mizan.traffic import TrafficLog

    for token in ("token-A-of-alice", "token-B-of-bob"):
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/orders/o1",
            "CONTENT_LENGTH": "0",
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "wsgi.input": _Empty(),
        }
        recorder(environ, lambda *args, **kwargs: None)
    principals = [record.principal for record in TrafficLog.load(tmp_path / "traffic.jsonl").records]
    assert principals == [None, None]
    assert UNKNOWN_PRINCIPAL not in principals


@pytest.mark.parametrize(
    "headers,expected",
    [
        # 1. alice's token with a forged user header: the token decides
        ({"HTTP_AUTHORIZATION": "Bearer tok-a", "HTTP_X_USER_ID": "bob"}, "alice"),
        # 2. bob's token with a forged user header: same rule
        ({"HTTP_AUTHORIZATION": "Bearer tok-b", "HTTP_X_USER_ID": "alice"}, "bob"),
        # 3. an unknown opaque token with a forged user header: stays unknown
        ({"HTTP_AUTHORIZATION": "Bearer tok-x", "HTTP_X_USER_ID": "alice"}, None),
        # 5. a readable JWT with a conflicting user header: the JWT wins
        ({"HTTP_AUTHORIZATION": f"Bearer {_jwt('alice')}", "HTTP_X_USER_ID": "bob"}, "alice"),
        # 6. an unsupported scheme with a forged user header: no identity
        ({"HTTP_AUTHORIZATION": "Basic dXNlcjpwYXNz", "HTTP_X_USER_ID": "alice"}, None),
        # 7. a malformed Authorization header with a forged user header: no identity
        ({"HTTP_AUTHORIZATION": "Bearer", "HTTP_X_USER_ID": "alice"}, None),
        # 4. no Authorization at all: an untrusted peer stays unattributed
        ({"HTTP_X_USER_ID": "alice"}, None),
        # no headers at all: nothing is attributed
        ({}, None),
    ],
)
def test_proxy_and_recorder_never_let_a_header_override_authentication(
    tmp_path: Path, headers: dict, expected: str | None
) -> None:
    """The same matrix, run against the proxy and the WSGI recorder."""
    identity_map = {"tok-a": "alice", "tok-b": "bob"}
    http_headers = {name.replace("HTTP_", "").replace("_", "-").title(): value for name, value in headers.items()}
    assert proxy_principal(_Headers(http_headers), identity_map, peer="203.0.113.7") == expected
    recorder = Recorder(_wsgi_app, tmp_path / "traffic.jsonl", identity_map=identity_map)
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/orders/o1",
        "CONTENT_LENGTH": "0",
        "REMOTE_ADDR": "203.0.113.7",
        "wsgi.input": _Empty(),
        **headers,
    }
    recorder(environ, lambda *args, **kwargs: None)
    from mizan.traffic import TrafficLog

    assert TrafficLog.load(tmp_path / "traffic.jsonl").records[-1].principal == expected


def test_only_a_trusted_peer_may_assert_an_identity(tmp_path: Path) -> None:
    """The proxy's assertion is believed only inside the trusted range."""
    identity_map = {"tok-a": "alice", "tok-b": "bob"}
    headers = _Headers({"X-User-Id": "alice"})
    trusted = TrustedProxies.from_cidrs(["10.10.0.0/24"])
    assert proxy_principal(headers, identity_map, peer="10.10.0.5", trusted_proxies=trusted) == "alice"
    assert proxy_principal(headers, identity_map, peer="203.0.113.7", trusted_proxies=trusted) is None
    assert proxy_principal(headers, identity_map, peer=None, trusted_proxies=trusted) is None

    recorder = Recorder(
        _wsgi_app, tmp_path / "traffic.jsonl", identity_map=identity_map, trusted_proxy_cidrs=["10.10.0.0/24"]
    )
    base = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/orders/o1",
        "CONTENT_LENGTH": "0",
        "HTTP_X_USER_ID": "alice",
        "wsgi.input": _Empty(),
    }
    recorder({**base, "REMOTE_ADDR": "10.10.0.5"}, lambda *args, **kwargs: None)
    recorder({**base, "REMOTE_ADDR": "203.0.113.7"}, lambda *args, **kwargs: None)
    from mizan.traffic import TrafficLog

    assert [record.principal for record in TrafficLog.load(tmp_path / "traffic.jsonl").records] == ["alice", None]


class _Headers:
    """Just enough of an HTTP header mapping for the proxy's resolver."""

    def __init__(self, values: dict) -> None:
        self._values = values

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._values.get(name, self._values.get(name.lower(), default))


# --------------------------------------------------------------------------- #
# the MITM addon follows the same rules
# --------------------------------------------------------------------------- #


def test_the_mitm_addon_resolves_identities_the_same_way(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The addon follows the same rules: a token decides, a header does not."""
    from mizan.recorder import MITM_ADDON

    traffic = tmp_path / "traffic.jsonl"
    monkeypatch.setenv("MIZAN_TRAFFIC", str(traffic))
    monkeypatch.setenv("MIZAN_IDENTITY_MAP", json.dumps({"tok-a": "alice"}))

    namespace: dict = {"__name__": "mitm_recorder"}
    exec(compile(MITM_ADDON, "mitm_recorder.py", "exec"), namespace)  # noqa: S102 - Mizan's own template

    def flow_with(token: str | None, user_id: str | None = None, peer: str | None = "203.0.113.7"):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        if user_id:
            headers["X-User-Id"] = user_id

        class _Request:
            method = "GET"
            path = "/orders/o1?ignored=1"

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

    namespace["response"](flow_with("tok-a"))
    namespace["response"](flow_with("tok-b", user_id="alice"))  # forged header on an unknown token
    namespace["response"](flow_with(None, user_id="bob"))  # no auth presented: an untrusted peer stays unknown

    records = [json.loads(line) for line in traffic.read_text(encoding="utf-8").splitlines()]
    assert [record["principal"] for record in records] == ["alice", None, None]


def test_the_mitm_addon_believes_a_trusted_proxy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With an explicit trusted range, the proxy's assertion is believed."""
    from mizan.recorder import MITM_ADDON

    traffic = tmp_path / "traffic.jsonl"
    monkeypatch.setenv("MIZAN_TRAFFIC", str(traffic))
    monkeypatch.setenv("MIZAN_TRUSTED_PROXY_CIDRS", "10.10.0.0/24")

    namespace: dict = {"__name__": "mitm_recorder"}
    exec(compile(MITM_ADDON, "mitm_recorder.py", "exec"), namespace)  # noqa: S102 - Mizan's own template

    class _Request:
        method = "GET"
        path = "/orders/o1"

        def __init__(self) -> None:
            self.headers = {"X-User-Id": "bob"}

        def get_text(self, strict: bool = False) -> str:
            return ""

    class _Response:
        status_code = 200

        def get_text(self, strict: bool = False) -> str:
            return json.dumps({"id": "o1", "owner_id": "alice"})

    class _Connection:
        def __init__(self, peer: str | None) -> None:
            self.peername = (peer, 54321) if peer else None

    class _Flow:
        request = _Request()
        response = _Response()

        def __init__(self, peer: str | None) -> None:
            self.client_conn = _Connection(peer)

    namespace["response"](_Flow("10.10.0.5"))  # inside the trusted range
    namespace["response"](_Flow("203.0.113.7"))  # outside it
    namespace["response"](_Flow(None))  # peer unknown: fail closed

    records = [json.loads(line) for line in traffic.read_text(encoding="utf-8").splitlines()]
    assert [record["principal"] for record in records] == ["bob", None, None]


def test_the_mitm_addon_refuses_a_broken_identity_map(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken identity map is loud - never silently empty."""
    from mizan.recorder import MITM_ADDON

    monkeypatch.setenv("MIZAN_TRAFFIC", str(tmp_path / "traffic.jsonl"))
    monkeypatch.setenv("MIZAN_IDENTITY_MAP", "{not json")

    with pytest.raises(ValueError) as excinfo:
        exec(compile(MITM_ADDON, "mitm_recorder.py", "exec"), {"__name__": "mitm_recorder"})  # noqa: S102
    assert "MIZAN_IDENTITY_MAP" in str(excinfo.value)


def test_the_mitm_addon_refuses_a_broken_trusted_proxy_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken trusted-proxy range is loud too."""
    from mizan.recorder import MITM_ADDON

    monkeypatch.setenv("MIZAN_TRAFFIC", str(tmp_path / "traffic.jsonl"))
    monkeypatch.setenv("MIZAN_TRUSTED_PROXY_CIDRS", "not-a-cidr")

    with pytest.raises(ValueError) as excinfo:
        exec(compile(MITM_ADDON, "mitm_recorder.py", "exec"), {"__name__": "mitm_recorder"})  # noqa: S102
    assert "not-a-cidr" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# the CLI refuses ambiguity and never leaks a token
# --------------------------------------------------------------------------- #


def _write_map(tmp_path: Path, content: str) -> str:
    path = tmp_path / "identity-map.json"
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_the_cli_rejects_token_and_identity_map_together(tmp_path: Path) -> None:
    from mizan.cli import main

    map_path = _write_map(tmp_path, _config(alice=_ALICE))
    result = CliRunner().invoke(
        main,
        ["twin", "--command", "true", "--identity-map", map_path, "--token", "alice=tok"],
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "not both" in result.output


def test_the_cli_fails_closed_on_a_broken_configuration(tmp_path: Path) -> None:
    from mizan.cli import main

    map_path = _write_map(tmp_path, "{invalid")
    result = CliRunner().invoke(main, ["twin", "--command", "true", "--identity-map", map_path], catch_exceptions=False)
    assert result.exit_code == 2
    assert "identity map error" in result.output


def test_the_cli_fails_closed_on_a_missing_environment_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mizan.cli import main

    monkeypatch.delenv("MIZAN_TOKEN_ALICE", raising=False)
    map_path = _write_map(tmp_path, _config(alice=_ALICE))
    result = CliRunner().invoke(main, ["twin", "--command", "true", "--identity-map", map_path], catch_exceptions=False)
    assert result.exit_code == 2
    assert "MIZAN_TOKEN_ALICE" in result.output


def test_the_cli_never_prints_a_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from mizan.cli import main

    canary = "MIZAN_SECRET_CANARY_CLI_4D9E"
    monkeypatch.setenv("MIZAN_TOKEN_ALICE", canary)
    monkeypatch.setenv("MIZAN_TOKEN_BOB", canary)  # forces the collision error
    map_path = _write_map(tmp_path, _config(alice=_ALICE, bob=_BOB))
    result = CliRunner().invoke(main, ["twin", "--command", "true", "--identity-map", map_path], catch_exceptions=False)
    assert result.exit_code == 2
    assert canary not in result.output
