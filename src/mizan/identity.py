"""Identity helpers: what does a token actually claim?

The law *L1 - authentication coherence* says: the identity the server acts as
must be the identity the client presented. To check that, Mizan needs to know
what the token claims - which, for JWTs, is readable without the secret.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

#: Claim names that carry the subject, in order of preference.
SUBJECT_CLAIMS = ("sub", "user_id", "uid", "principal", "userId", "identity")

#: Claim names that carry a role.
ROLE_CLAIMS = ("role", "roles", "scope", "scopes")


@dataclass(frozen=True)
class TokenClaims:
    """What a bearer token claims about its bearer."""

    subject: str | None
    roles: tuple[str, ...]
    algorithm: str | None
    raw: dict[str, Any]

    @property
    def unsigned(self) -> bool:
        """Whether the token claims to need no signature."""
        return (self.algorithm or "").lower() in {"none", "nones"}


def _decode_segment(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_token(token: str) -> TokenClaims | None:
    """Read the claims of a JWT-shaped bearer token.

    Returns ``None`` for opaque tokens - there is nothing to read, and Mizan
    must not guess.
    """
    if not token:
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_decode_segment(parts[0]))
        payload = json.loads(_decode_segment(parts[1]))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    subject = None
    for claim in SUBJECT_CLAIMS:
        value = payload.get(claim)
        if isinstance(value, (str, int)):
            subject = str(value)
            break
    roles: list[str] = []
    for claim in ROLE_CLAIMS:
        value = payload.get(claim)
        if isinstance(value, str):
            roles.append(value)
        elif isinstance(value, (list, tuple)):
            roles.extend(str(item) for item in value)
    algorithm = header.get("alg") if isinstance(header, dict) else None
    return TokenClaims(
        subject=subject,
        roles=tuple(roles),
        algorithm=str(algorithm) if algorithm is not None else None,
        raw=payload,
    )


def subject_of(token: str) -> str | None:
    """The subject a token claims, if it is readable."""
    claims = decode_token(token)
    return claims.subject if claims else None


def forge_unsigned(claims: TokenClaims, token: str) -> str | None:
    """Rebuild a token with ``alg: none`` and no signature.

    Used to check whether the server accepts a token that carries no proof.
    """

    def encode(data: dict[str, Any]) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    header = {"alg": "none", "typ": "JWT"}
    parts = token.split(".")
    payload_segment = parts[1] if len(parts) > 1 else ""
    try:
        payload = json.loads(_decode_segment(payload_segment))
    except (binascii.Error, ValueError):
        payload = claims.raw
    return f"{encode(header)}.{encode(payload)}."
