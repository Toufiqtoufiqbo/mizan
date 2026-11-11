"""Tokens, and how to find the right one for a principal.

Mizan never stores a secret. A proof bundle records *which* principal made the
request; the bearer token is looked up when the bundle is replayed, from the
environment:

* ``MIZAN_TOKENS`` - a JSON object, e.g. ``{"alice": "eyJ..."}``
* ``MIZAN_TOKEN_ALICE`` - one variable per principal (the name is upper-cased)

The lookup is case-insensitive, because principals arrive from many places:
a bundle may say ``alice``, a CI matrix may say ``ALICE``, and an environment
variable is upper-case by convention.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

#: A JSON object with ``principal -> token``.
TOKENS_ENV = "MIZAN_TOKENS"

#: The prefix of the per-principal variables.
TOKEN_PREFIX = "MIZAN_TOKEN_"


def encode_segment(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_token(subject: str, role: str = "user", *, signature: str = "mizan-signature") -> str:
    """A JWT-shaped token for a subject."""
    header = encode_segment({"alg": "HS256", "typ": "JWT"})
    payload = encode_segment({"sub": subject, "role": role})
    return f"{header}.{payload}.{signature}"


def subject_of_token(token: str) -> str | None:
    """The subject a token claims, without verifying it."""
    from mizan.identity import subject_of

    return subject_of(token)


#: How a token is written into a proof bundle: a placeholder, never the secret.
PLACEHOLDER_PREFIX = "${MIZAN_TOKEN_"
PLACEHOLDER_SUFFIX = "}"


def placeholder_for(principal: str | None) -> str:
    """The placeholder that stands in for a principal's token."""
    name = (principal or "unknown").strip().upper().replace("-", "_").replace(".", "_").replace("@", "_")
    return f"{PLACEHOLDER_PREFIX}{name}{PLACEHOLDER_SUFFIX}"


def principal_from_placeholder(value: str) -> str | None:
    """The principal a placeholder refers to."""
    if not value or not value.startswith(PLACEHOLDER_PREFIX) or not value.endswith(PLACEHOLDER_SUFFIX):
        return None
    return value[len(PLACEHOLDER_PREFIX) : -len(PLACEHOLDER_SUFFIX)].lower()


def mask_authorization(headers: Mapping[str, str] | None, principal: str | None) -> dict[str, str]:
    """Replace the bearer token in the headers with a placeholder.

    A proof bundle is meant to be shared - it goes into a ticket, a pull
    request, a report. A secret must not travel with it.
    """
    masked: dict[str, str] = {}
    for name, value in (headers or {}).items():
        if name.lower() == "authorization" and value.lower().startswith("bearer "):
            masked[name] = f"Bearer {placeholder_for(principal)}"
        else:
            masked[name] = value
    return masked


def resolve_headers(headers: Mapping[str, str] | None, resolver: TokenResolver) -> dict[str, str]:
    """Fill the placeholders in the headers with the real tokens."""
    resolved: dict[str, str] = {}
    for name, value in (headers or {}).items():
        principal = principal_from_placeholder(value.split(" ", 1)[-1].strip())
        if principal is not None:
            token = resolver.token_for(principal)
            if token is None:
                raise MissingToken(
                    f"the request needs the token of {principal!r}, but none is configured. "
                    f'Set {TOKENS_ENV}={{"{principal}": "..."}} or {TOKEN_PREFIX}{principal.upper()}.'
                )
            resolved[name] = f"Bearer {token}"
        else:
            resolved[name] = value
    return resolved


class MissingToken(LookupError):
    """Raised when a principal has no token."""


@dataclass
class TokenResolver:
    """Finds the bearer token of a principal."""

    tokens: dict[str, str] = field(default_factory=dict)

    # -- construction ------------------------------------------------------- #

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> TokenResolver:
        """Collect the tokens from the environment.

        ``MIZAN_TOKENS`` (JSON) and ``MIZAN_TOKEN_<NAME>`` are both read; the
        JSON wins when both define the same principal.
        """
        environ = os.environ if environ is None else environ
        tokens: dict[str, str] = {}
        raw = environ.get(TOKENS_ENV)
        if raw:
            parsed = _parse_tokens(raw)
            if parsed is None:
                raise ValueError(
                    f"{TOKENS_ENV} must be a JSON object with principal names as keys, "
                    f'for example \'{{"alice": "eyJ..."}}\''
                )
            tokens.update(parsed)
        for name, value in environ.items():
            if name.startswith(TOKEN_PREFIX) and len(name) > len(TOKEN_PREFIX):
                principal = name[len(TOKEN_PREFIX) :].lower()
                tokens.setdefault(principal, value)
        return cls(tokens=tokens)

    # -- lookup ------------------------------------------------------------- #

    def token_for(self, principal: str | None) -> str | None:
        """The token of a principal, if there is one."""
        if not principal:
            return None
        return self.tokens.get(principal.strip().lower())

    def require(self, principal: str | None) -> str:
        """The token of a principal, or a clear error.

        Silently continuing without a token would turn a security check into a
        no-op, so this raises instead.
        """
        token = self.token_for(principal)
        if not token:
            known = ", ".join(sorted(self.tokens)) or "none"
            raise MissingToken(
                f"no token for principal {principal!r}. "
                f'Set {TOKENS_ENV}={{"{principal}": "..."}} or {TOKEN_PREFIX}{principal.upper()}. '
                f"Known principals: {known}"
            )
        return token

    def principal_for(self, token: str | None) -> str | None:
        """The principal a token belongs to."""
        if not token:
            return None
        for principal, candidate in self.tokens.items():
            if candidate == token:
                return principal
        return subject_of_token(token)

    def masked(self, token: str | None) -> str:
        """A token that is safe to print."""
        if not token:
            return "<none>"
        return f"{token[:6]}...{token[-4:]}" if len(token) > 12 else "***"

    def __len__(self) -> int:
        return len(self.tokens)


def _parse_tokens(raw: str) -> dict[str, str] | None:
    """Parse the ``MIZAN_TOKENS`` value."""
    raw = raw.strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            loaded = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(loaded, dict):
            return None
        return {str(name).strip().lower(): str(value) for name, value in loaded.items() if value}
    # A simple `name=token` list, separated by commas or semicolons.
    result: dict[str, str] = {}
    for part in raw.replace(";", ",").split(","):
        name, separator, value = part.partition("=")
        name = name.strip().lower()
        value = value.strip()
        if separator and name and value:
            result[name] = value
    if result:
        return result
    raise ValueError(f"cannot read {TOKENS_ENV}: expected a JSON object or name=token pairs")
