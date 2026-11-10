"""Tokens.

Mizan reads the claims of the tokens it sees, so the identities in the traffic
log are the identities the token claims. The helpers here produce JWT-shaped
tokens with a fake signature - enough for the identity to be visible, never
intended to be a real authentication mechanism.
"""

from __future__ import annotations

import base64
import json
from typing import Any


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
