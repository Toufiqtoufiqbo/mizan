"""Tests for the token resolver.

No real secret is needed: the resolver is tested with fake tokens.
"""

from __future__ import annotations

import pytest

from mizan.tokens import (
    MissingToken,
    TokenResolver,
    mask_authorization,
    placeholder_for,
    principal_from_placeholder,
    resolve_headers,
)


def test_tokens_are_read_from_a_json_variable() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKENS": '{"alice": "tok-1", "bob": "tok-2"}'})
    assert resolver.token_for("alice") == "tok-1"
    assert resolver.token_for("bob") == "tok-2"


def test_tokens_are_read_from_per_principal_variables() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKEN_ALICE": "tok-1", "MIZAN_TOKEN_BOB": "tok-2"})
    assert resolver.token_for("alice") == "tok-1"
    assert resolver.token_for("bob") == "tok-2"


def test_a_lookup_is_case_insensitive() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKEN_ALICE": "tok-1"})
    assert resolver.token_for("ALICE") == "tok-1"
    assert resolver.token_for("Alice") == "tok-1"
    assert resolver.token_for("alice") == "tok-1"


def test_the_json_wins_over_a_variable() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKENS": '{"alice": "json-token"}', "MIZAN_TOKEN_ALICE": "env-token"})
    assert resolver.token_for("alice") == "json-token"


def test_a_missing_token_raises_instead_of_silently_continuing() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKEN_ALICE": "tok-1"})
    assert resolver.token_for("carol") is None
    with pytest.raises(MissingToken):
        resolver.require("carol")
    assert resolver.require("alice") == "tok-1"


def test_a_malformed_json_variable_is_rejected() -> None:
    with pytest.raises(ValueError):
        TokenResolver.from_env({"MIZAN_TOKENS": "not json"})


def test_a_simple_name_equals_token_list_is_accepted() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKENS": "alice=tok-1,bob=tok-2"})
    assert resolver.token_for("alice") == "tok-1"
    assert resolver.token_for("bob") == "tok-2"


def test_the_principal_is_found_back_from_a_token() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKEN_ALICE": "tok-1"})
    assert resolver.principal_for("tok-1") == "alice"


def test_a_token_is_never_printed_whole() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKEN_ALICE": "super-secret-token-value"})
    assert resolver.masked("super-secret-token-value") == "super-...alue"
    assert resolver.masked(None) == "<none>"


# --------------------------------------------------------------------------- #
# Placeholders: the bundle never carries a secret
# --------------------------------------------------------------------------- #


def test_the_placeholder_round_trip() -> None:
    placeholder = placeholder_for("alice")
    assert placeholder == "${MIZAN_TOKEN_ALICE}"
    assert principal_from_placeholder(placeholder) == "alice"


def test_the_placeholder_is_upper_cased_and_normalized() -> None:
    assert placeholder_for("Alice") == "${MIZAN_TOKEN_ALICE}"
    assert placeholder_for("alice@example.com") == "${MIZAN_TOKEN_ALICE_EXAMPLE_COM}"


def test_an_authorization_header_is_masked() -> None:
    headers = {"Authorization": "Bearer super-secret", "X-User-Id": "alice"}
    masked = mask_authorization(headers, "alice")
    assert masked["Authorization"] == "Bearer ${MIZAN_TOKEN_ALICE}"
    assert masked["X-User-Id"] == "alice"
    assert "super-secret" not in str(masked)


def test_the_headers_are_filled_back_when_replaying() -> None:
    resolver = TokenResolver.from_env({"MIZAN_TOKEN_ALICE": "tok-1"})
    headers = resolve_headers({"Authorization": "Bearer ${MIZAN_TOKEN_ALICE}"}, resolver)
    assert headers["Authorization"] == "Bearer tok-1"


def test_a_placeholder_without_a_token_is_an_error() -> None:
    resolver = TokenResolver.from_env({})
    with pytest.raises(MissingToken):
        resolve_headers({"Authorization": "Bearer ${MIZAN_TOKEN_ALICE}"}, resolver)


def test_a_header_without_a_placeholder_is_left_alone() -> None:
    resolver = TokenResolver.from_env({})
    assert resolve_headers({"X-User-Id": "alice"}, resolver) == {"X-User-Id": "alice"}
