"""The Mīzān control plane - a small HTTP API around the engine.

Mīzān is a tool, but a tool that other systems call needs an API. This is
that API: it starts scans, lists the findings and hands out proof bundles.

It is also Mīzān's own first user. The API is deliberately ordinary - the kind
of service a security team would write - so that Mīzān can be pointed at it
with the twin, and any finding it reports is a real defect in this project.

    python -m mizan.server --port 8000

Security decisions worth stating:

* **Authentication** - opaque random tokens, stored as a hash. There is no
  default credential: the users are injected explicitly
  (``MIZAN_SERVER_USERS=alice=secret``). This is a *development* mechanism;
  it is not a production identity provider and it says so.
* **Authorisation** - every read and write is scoped to the caller. A scan that
  belongs to somebody else is a 404, not a 403: the existence of the object is
  itself information.
* **Mass assignment** - the request models are closed. A field the model does
  not declare is rejected, not ignored. There is no ``owner_id`` to set.
* **No SSRF** - a scan target is restricted to an allow-list of hosts and
  schemes. The server is the one making requests, so an unrestricted target
  would let a caller use it to reach services that are only reachable from here.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from fastapi import Depends, FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, ConfigDict, Field
except ImportError as exc:  # pragma: no cover - optional dependency
    raise SystemExit("the Mizan server needs FastAPI: pip install 'mizan[server]'") from exc

#: The hosts the server may scan. Anything else is refused.
ALLOWED_TARGET_HOSTS = tuple(
    host.strip().lower()
    for host in os.environ.get("MIZAN_ALLOWED_TARGETS", "127.0.0.1,localhost").split(",")
    if host.strip()
)

#: The schemes the server may scan.
ALLOWED_TARGET_SCHEMES = ("http", "https")

#: The ports the server may scan. Empty means "any port on an allowed host".
ALLOWED_TARGET_PORTS = tuple(
    int(port) for port in os.environ.get("MIZAN_ALLOWED_TARGET_PORTS", "").split(",") if port.strip().isdigit()
)

DEFAULT_DB = os.environ.get("MIZAN_SERVER_DB", "mizan-server.sqlite")

#: Where the proof bundles live.
DEFAULT_BUNDLE_ROOT = os.environ.get("MIZAN_BUNDLE_ROOT", "mizan-proofs")

#: The maximum size of a request body the server accepts.
MAX_BODY_BYTES = 64 * 1024


def hash_token(token: str) -> str:
    """The stored form of a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DevAuth:
    """Development authentication: opaque random tokens, stored as a hash.

    This exists so that the control plane can be exercised locally and in CI.
    It is **not** production authentication: the tokens never expire, there is
    no rotation, and the secret is a plain environment variable.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}

    def issue(self, user_id: str) -> str:
        """A new random token for a user. The value is returned once."""
        token = secrets.token_urlsafe(32)
        self._tokens[self._hash(token)] = user_id
        return token

    def user_for(self, token: str) -> str | None:
        return self._tokens.get(self._hash(token))

    @staticmethod
    def _hash(token: str) -> str:
        return hash_token(token)

    def forget(self) -> None:
        """Drop every token."""
        self._tokens.clear()


@dataclass
class Store:
    """A tiny SQLite store. It holds users, scans and findings."""

    path: Path

    def connect(self) -> sqlite3.Connection:
        # Autocommit: the migration manages its own transaction explicitly.
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> list[str]:
        """Bring an older database up to the current schema.

        The user table used to store the token itself. A database created by an
        older version still has that column and no ``token_hash``, and
        ``CREATE TABLE IF NOT EXISTS`` would not notice. The migration hashes the
        existing tokens, keeps the user ids and the roles, and leaves no
        plaintext token behind.

        It is idempotent: a second run finds the current schema and does
        nothing.
        """
        notes: list[str] = []
        connection = self.connect()
        try:
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
            if "token_hash" in columns:
                return notes
            if "token" not in columns:
                # Nothing to migrate: a fresh database.
                return notes
            rows = connection.execute("SELECT id, token, role FROM users").fetchall()
            connection.execute("BEGIN")
            try:
                connection.execute(
                    """
                    CREATE TABLE users_migrated (
                        id TEXT PRIMARY KEY,
                        token_hash TEXT UNIQUE NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user'
                    )
                    """
                )
                for row in rows:
                    connection.execute(
                        "INSERT INTO users_migrated (id, token_hash, role) VALUES (?, ?, ?)",
                        (row["id"], hash_token(row["token"]), row["role"]),
                    )
                connection.execute("DROP TABLE users")
                connection.execute("ALTER TABLE users_migrated RENAME TO users")
                connection.execute("COMMIT")
            except Exception as exc:
                connection.execute("ROLLBACK")
                raise RuntimeError(f"the user table could not be migrated safely: {exc}") from exc
            notes.append(f"migrated {len(rows)} user(s) from a plaintext token column")
        finally:
            connection.close()
        return notes

    def initialise(self) -> None:
        self.migrate()
        connection = self.connect()
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user'
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    spec TEXT,
                    mode TEXT NOT NULL DEFAULT 'probes',
                    status TEXT NOT NULL DEFAULT 'queued',
                    findings INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    law TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    resource TEXT,
                    evidence TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
        connection.close()

    def ensure_user(self, user_id: str, token: str, role: str = "user") -> None:
        """Add a user, keeping only the hash of the token."""
        connection = self.connect()
        with connection:
            connection.execute(
                "INSERT OR IGNORE INTO users (id, token_hash, role) VALUES (?, ?, ?)",
                (user_id, hash_token(token), role),
            )
        connection.close()

    def user_for_token(self, token: str) -> tuple[str, str] | None:
        connection = self.connect()
        try:
            row = connection.execute("SELECT id, role FROM users WHERE token_hash = ?", (hash_token(token),)).fetchone()
        finally:
            connection.close()
        return (row["id"], row["role"]) if row else None


class StrictModel(BaseModel):
    """A request model that rejects fields it does not know."""

    model_config = ConfigDict(extra="forbid")


class ScanRequest(StrictModel):
    """The body of a scan request.

    Only these fields exist. Anything else a client sends is rejected, so the
    client cannot decide who owns the scan or what state it starts in.
    """

    target: str = Field(
        min_length=1,
        max_length=500,
        examples=["http://127.0.0.1:8000/openapi.json"],
    )
    spec: str | None = Field(
        default=None,
        max_length=500,
        examples=["http://127.0.0.1:8000/openapi.json"],
    )
    mode: str = Field(default="probes", pattern="^(probes|guided)$")


class FindingRequest(StrictModel):
    """The body of a finding submission.

    The examples matter: a client (and Mizan's own learning phase) reads the
    specification to find out what a valid body looks like.
    """

    law: str = Field(min_length=1, max_length=20, pattern=r"^L[0-9]+$", examples=["L2"])
    title: str = Field(min_length=1, max_length=200, examples=["an example finding"])
    severity: str = Field(
        min_length=1,
        max_length=20,
        pattern=r"^(critical|high|medium|low|info)$",
        examples=["high"],
    )
    resource: str | None = Field(default=None, max_length=200)
    evidence: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    law: str
    title: str
    severity: str
    resource: str | None = None
    owner_id: str


class Scan(BaseModel):
    id: str
    owner_id: str
    target: str
    spec: str | None = None
    mode: str
    status: str
    findings: int
    created_at: float


def validate_target(target: str) -> str:
    """Check that a target may be scanned.

    The server makes the request, so the target has to be one the operator
    allowed: an allowed scheme, an allowed host, an allowed port, and no
    credentials hidden in the URL.
    """
    parts = urlsplit(target)
    if parts.scheme.lower() not in ALLOWED_TARGET_SCHEMES:
        raise HTTPException(status_code=400, detail=f"scheme is not allowed: {parts.scheme}")
    if not parts.hostname:
        raise HTTPException(status_code=400, detail="the target has no host")
    if parts.username or parts.password:
        raise HTTPException(status_code=400, detail="the target must not carry credentials")
    host = (parts.hostname or "").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host not in ALLOWED_TARGET_HOSTS:
        raise HTTPException(status_code=400, detail=f"target host is not allowed: {host}")
    if ALLOWED_TARGET_PORTS and (parts.port or 0) not in ALLOWED_TARGET_PORTS:
        raise HTTPException(status_code=400, detail=f"target port is not allowed: {parts.port}")
    return target


def create_app(
    db_path: str | Path = DEFAULT_DB,
    *,
    seed_users: bool = True,
    vulnerable: bool = False,
    bundle_root: str | Path = DEFAULT_BUNDLE_ROOT,
    users: dict[str, tuple[str, str]] | None = None,
) -> FastAPI:
    """Build the application.

    ``vulnerable=True`` removes the ownership check on one endpoint. It exists
    for one purpose: the self-scan runs against both variants, so the check is
    known to *bite* and not merely to stay silent.

    ``users`` maps a user id to ``(token, role)``. There is no default
    credential - the caller has to inject one.
    """
    store = Store(Path(db_path))
    store.initialise()
    if seed_users:
        # Two ordinary users and an administrator: a cross-identity read needs
        # two ordinary users, and an administrator must not be attacked.
        injected = users if users is not None else _users_from_environment()
        for user_id, (token, role) in injected.items():
            store.ensure_user(user_id, token, role)

    app = FastAPI(title="Mizan", version="0.2.2", description="Law-driven API security testing.")
    app.state.store = store
    app.state.bundle_root = Path(bundle_root)

    def current_user(request: Request) -> tuple[str, str]:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        identity = store.user_for_token(header[len("Bearer ") :].strip())
        if identity is None:
            raise HTTPException(status_code=401, detail="unknown token")
        return identity

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/scans", status_code=201)
    def create_scan(payload: ScanRequest, user: tuple[str, str] = Depends(current_user)) -> dict[str, Any]:
        owner_id, _role = user
        validate_target(payload.target)
        scan_id = f"scan-{int(time.time() * 1000):x}"
        connection = store.connect()
        with connection:
            connection.execute(
                "INSERT INTO scans (id, owner_id, target, spec, mode, status, findings, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                (scan_id, owner_id, payload.target, payload.spec, payload.mode, "queued", time.time()),
            )
        connection.close()
        return {"id": scan_id, "status": "queued"}

    @app.get("/scans")
    def list_scans(user: tuple[str, str] = Depends(current_user)) -> list[Scan]:
        owner_id, _role = user
        connection = store.connect()
        try:
            rows = connection.execute(
                "SELECT * FROM scans WHERE owner_id = ? ORDER BY created_at DESC", (owner_id,)
            ).fetchall()
        finally:
            connection.close()
        return [Scan(**dict(row)) for row in rows]

    @app.get("/scans/{scan_id}")
    def get_scan(scan_id: str, user: tuple[str, str] = Depends(current_user)) -> Scan:
        owner_id, _role = user
        connection = store.connect()
        try:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        finally:
            connection.close()
        if row is None or row["owner_id"] != owner_id:
            # 404, not 403: the existence of the scan is not the caller's business.
            raise HTTPException(status_code=404, detail="scan not found")
        return Scan(**dict(row))

    @app.get("/scans/{scan_id}/findings")
    def list_findings(scan_id: str, user: tuple[str, str] = Depends(current_user)) -> list[Finding]:
        owner_id, _role = user
        connection = store.connect()
        try:
            if vulnerable:
                rows = connection.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM findings WHERE scan_id = ? AND owner_id = ? ORDER BY id", (scan_id, owner_id)
                ).fetchall()
        finally:
            connection.close()
        return [
            Finding(
                id=row["id"],
                law=row["law"],
                title=row["title"],
                severity=row["severity"],
                resource=row["resource"],
                owner_id=row["owner_id"],
            )
            for row in rows
        ]

    @app.post("/scans/{scan_id}/findings", status_code=201)
    def record_finding(
        scan_id: str, payload: FindingRequest, user: tuple[str, str] = Depends(current_user)
    ) -> dict[str, str]:
        owner_id, _role = user
        connection = store.connect()
        try:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        finally:
            connection.close()
        if row is None or row["owner_id"] != owner_id:
            raise HTTPException(status_code=404, detail="scan not found")
        finding_id = f"finding-{int(time.time() * 1000):x}"
        connection = store.connect()
        with connection:
            connection.execute(
                "INSERT INTO findings (id, scan_id, owner_id, law, title, severity, resource, evidence)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    scan_id,
                    owner_id,
                    payload.law,
                    payload.title[:200],
                    payload.severity,
                    payload.resource,
                    json.dumps(payload.evidence)[:10000],
                ),
            )
            connection.execute("UPDATE scans SET findings = findings + 1 WHERE id = ?", (scan_id,))
        connection.close()
        return {"id": finding_id}

    @app.get("/scans/{scan_id}/bundle")
    def get_bundle(scan_id: str, user: tuple[str, str] = Depends(current_user)) -> JSONResponse:
        """The proof bundle of a scan, as it was written to disk."""
        owner_id, _role = user
        connection = store.connect()
        try:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        finally:
            connection.close()
        if row is None or row["owner_id"] != owner_id:
            raise HTTPException(status_code=404, detail="scan not found")
        # The path must stay inside the configured root: a scan id is not
        # allowed to walk out of it.
        root = Path(app.state.bundle_root).resolve()
        directory = (root / scan_id).resolve()
        if root != directory and root not in directory.parents:
            raise HTTPException(status_code=404, detail="no bundle for this scan")
        replay = directory / "replay.json"
        if not replay.exists() or not replay.is_file():
            raise HTTPException(status_code=404, detail="no bundle for this scan")
        return JSONResponse(json.loads(replay.read_text(encoding="utf-8")))

    return app


def _users_from_environment() -> dict[str, tuple[str, str]]:
    """The users to create, injected explicitly.

    ``MIZAN_SERVER_USERS=alice=secret,root=secret:admin``
    """
    raw = os.environ.get("MIZAN_SERVER_USERS", "")
    users: dict[str, tuple[str, str]] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, _, secret = entry.partition("=")
        role = "user"
        if ":" in secret:
            secret, _, role = secret.partition(":")
        if name and secret:
            users[name] = (secret, role)
    return users


def issue_tokens(users: dict[str, tuple[str, str]]) -> dict[str, str]:
    """A random token per user - for development and tests."""
    auth = DevAuth()
    return {name: auth.issue(name) for name in users}


def main() -> None:  # pragma: no cover - the entry point
    import argparse

    parser = argparse.ArgumentParser(description="Run the Mizan control plane")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--bundles", default=DEFAULT_BUNDLE_ROOT)
    parser.add_argument("--vulnerable", action="store_true", help="Disable the ownership check (self-test only).")
    arguments = parser.parse_args()

    import uvicorn

    uvicorn.run(
        create_app(arguments.db, vulnerable=arguments.vulnerable, bundle_root=arguments.bundles),
        host=arguments.host,
        port=arguments.port,
        log_level="warning",
    )


if __name__ == "__main__":  # pragma: no cover
    main()
