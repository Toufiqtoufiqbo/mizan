"""Identity helpers: what does a token actually claim?

The law *L1 - authentication coherence* says: the identity the server acts as
must be the identity the client presented. To check that, Mizan needs to know
what the token claims - which, for JWTs, is readable without the secret.

For opaque tokens there is nothing to read, so the operator must say who each
token belongs to: that is the identity map. The configuration file holds only
*names of environment variables* - the tokens themselves are read from the
environment at run time and are never written to disk.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
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

    Note the semantics: this **decodes** the payload, it does not verify a
    signature. A subject read this way is what the token *claims*, not a
    cryptographically proven identity. Mizan never describes it as verified.
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


# --------------------------------------------------------------------------- #
# Identity maps for opaque authentication
# --------------------------------------------------------------------------- #


class IdentityMapError(ValueError):
    """An identity-map configuration is invalid.

    The message names the configuration problem only - a principal, an
    environment-variable name, or a schema field. It never contains a token
    value, because tokens are read from the environment and never passed
    around in errors.
    """


#: Principal ids that would collide with the engine's reserved meaning.
#: ``"unknown"`` is how Mizan marks *unattributable* activity; a configured
#: principal must not be able to claim it.
RESERVED_PRINCIPAL_IDS = frozenset({"unknown"})

#: A principal id: short, printable, and safe in JSON, YAML and shell contexts.
_PRINCIPAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")

#: An environment-variable name: what a POSIX-ish shell accepts.
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def validate_principal_id(name: str) -> None:
    """Raise :class:`IdentityMapError` unless *name* is a usable principal id.

    A usable id is 1-128 characters of ``[A-Za-z0-9_.:@-]`` starting with a
    letter or digit, and it must not collide with a reserved identity such as
    ``unknown``.
    """
    if not isinstance(name, str) or not _PRINCIPAL_ID_RE.match(name):
        raise IdentityMapError(
            f"invalid principal id {name!r}: expected 1-128 characters of "
            "[A-Za-z0-9_.:@-] starting with a letter or digit"
        )
    if name in RESERVED_PRINCIPAL_IDS:
        raise IdentityMapError(
            f"invalid principal id {name!r}: this identifier is reserved for "
            "unattributable activity and cannot be configured"
        )


@dataclass(frozen=True)
class IdentityMap:
    """A validated identity-map configuration for opaque authentication.

    ``principals`` maps a principal id to the *name* of the environment
    variable that holds its bearer token. ``roles`` maps the same principal
    id to its declared roles. No token value is ever stored here.
    """

    version: int
    principals: dict[str, str]
    roles: dict[str, tuple[str, ...]]


def parse_identity_map(raw: str) -> IdentityMap:
    """Parse and validate an identity-map JSON document.

    Raises :class:`IdentityMapError` on any invalid input - malformed JSON,
    an unsupported schema version, a bad principal definition, a duplicate
    token assignment, or a reserved principal id. Validation is fail-closed:
    a broken configuration is an error, never a silent partial load.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise IdentityMapError(f"invalid JSON in identity map: {exc.__class__.__name__}") from exc

    if not isinstance(data, dict):
        raise IdentityMapError("the identity map must be a JSON object")

    version = data.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise IdentityMapError('the identity map needs an integer "version" field')
    if version != 1:
        raise IdentityMapError(f"unsupported identity map schema version {version}; only version 1 is supported")

    raw_principals = data.get("principals")
    if not isinstance(raw_principals, dict) or not raw_principals:
        raise IdentityMapError('the identity map needs a non-empty "principals" object')

    principals: dict[str, str] = {}
    roles: dict[str, tuple[str, ...]] = {}
    seen_envs: dict[str, str] = {}

    for name, definition in raw_principals.items():
        validate_principal_id(name)
        if not isinstance(definition, dict):
            raise IdentityMapError(f'principal {name!r} must be an object with "token_env" and optional "roles"')

        token_env = definition.get("token_env")
        if not isinstance(token_env, str) or not token_env.strip():
            raise IdentityMapError(f'principal {name!r} needs a non-empty "token_env" environment-variable name')
        token_env = token_env.strip()
        if not _ENV_NAME_RE.match(token_env):
            raise IdentityMapError(
                f'principal {name!r} has an invalid "token_env" value {token_env!r}: '
                "expected an environment-variable name like MIZAN_TOKEN_ALICE"
            )
        if token_env in seen_envs:
            raise IdentityMapError(
                f"principals {seen_envs[token_env]!r} and {name!r} share the environment variable "
                f"{token_env!r}: one token must belong to exactly one principal"
            )
        seen_envs[token_env] = name

        raw_roles = definition.get("roles", [])
        if not isinstance(raw_roles, list):
            raise IdentityMapError(f'principal {name!r} has invalid "roles": expected a list of strings')
        for role in raw_roles:
            if not isinstance(role, str) or not role.strip():
                raise IdentityMapError(f"principal {name!r} has an invalid role: every role must be a non-empty string")

        principals[name] = token_env
        roles[name] = tuple(role.strip() for role in raw_roles)

    return IdentityMap(version=1, principals=principals, roles=roles)


def load_identity_map(path: str | Path) -> IdentityMap:
    """Load and validate an identity-map configuration file.

    The file contains environment-variable *names*, never tokens. Raises
    :class:`IdentityMapError` when the file cannot be read or is invalid.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise IdentityMapError(f"cannot read identity map file: {exc.__class__.__name__}") from exc
    return parse_identity_map(raw)


def resolve_identity_map(config: IdentityMap) -> tuple[list[Any], dict[str, str]]:
    """Turn a validated :class:`IdentityMap` into runtime identities.

    Reads every referenced environment variable *now* and returns:

    1. a list of :class:`mizan.core.Principal` instances (id, roles, token),
    2. a ``{token value: principal id}`` mapping for the recorders.

    Raises :class:`IdentityMapError` when an environment variable is missing
    or empty - naming the variable, never its value - and when two principals
    resolve to the same token. Nothing is written to disk.
    """
    from mizan.core import Principal

    missing: list[str] = []
    empty: list[str] = []
    for env in config.principals.values():
        value = os.environ.get(env)
        if value is None:
            missing.append(env)
        elif value == "":
            empty.append(env)
    if missing:
        raise IdentityMapError(f"identity map: environment variable(s) not set: {', '.join(sorted(missing))}")
    if empty:
        raise IdentityMapError(f"identity map: environment variable(s) are empty: {', '.join(sorted(empty))}")

    principals: list[Any] = []
    tokens: dict[str, str] = {}
    for name, env in config.principals.items():
        token = os.environ[env]
        if token in tokens:
            raise IdentityMapError(
                f"identity map: principals {tokens[token]!r} and {name!r} resolve to the same token: "
                "one token must belong to exactly one principal"
            )
        tokens[token] = name
        principals.append(Principal(id=name, roles=config.roles.get(name, ()), token=token))
    return principals, tokens


def resolve_principal(token: str | None, identity_map: dict[str, str] | None = None) -> str | None:
    """The shared identity resolution used by every recorder.

    Resolution order:

    1. the token is listed in ``identity_map`` (a ``{token: principal id}``
       mapping) - return the configured principal. Explicit configuration
       wins, because the operator said who this token belongs to;
    2. the token is a readable JWT - return its subject. This is the identity
       the token *claims*; it is extracted, not cryptographically verified;
    3. otherwise ``None`` - the traffic is still recorded, but it is
       unattributable and proves nothing about ownership.

    An unknown opaque token therefore stays unknown. This function never
    fabricates an identity and never returns a placeholder string, because a
    placeholder would flow into the engine's learning phase and become a
    fake principal.
    """
    if not token:
        return None
    if identity_map and token in identity_map:
        return identity_map[token]
    claims = decode_token(token)
    if claims is not None and claims.subject is not None:
        return claims.subject
    return None
