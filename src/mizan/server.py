"""The Mīzān control plane - a small HTTP API around the engine.

Mīzān is a tool, but a tool that other systems call needs an API. This is
that API: it starts scans, lists the findings and hands out proof bundles.

It is also Mīzān's own first user. The API is deliberately ordinary - the kind
of service a security team would write - so that Mīzān can be pointed at it
with the twin, and any finding it reports is a real defect in this project.

    python -m mizan.server --port 8000

The design decisions worth stating:

* **Authentication** - a bearer token per user. The identity comes from the
  token's ``sub`` claim, and every row belongs to exactly one user.
* **Authorisation** - every read and write is scoped to the caller. A scan
  that belongs to somebody else is a 404, not a 403: the existence of the
  object is itself information.
* **Mass assignment** - request bodies are declared models with a closed set
  of fields. A client cannot set ``owner_id`` because there is no such field.
* **No SSRF** - a scan target is restricted to what the operator allowed. The
  server is the one making requests, so an unrestricted target would let a
  caller use it to reach internal services.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mizan.tokens import make_token

try:
    from fastapi import Depends, FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - optional dependency
    raise SystemExit("the Mizan server needs FastAPI: pip install 'mizan[server]'") from exc

#: The targets the server may scan. Anything else is refused, so the server
#: cannot be used to reach services that are not reachable from here.
ALLOWED_TARGET_HOSTS = tuple(
    host.strip() for host in os.environ.get("MIZAN_ALLOWED_TARGETS", "127.0.0.1,localhost").split(",") if host.strip()
)

DEFAULT_DB = os.environ.get("MIZAN_SERVER_DB", "mizan-server.sqlite")


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #


@dataclass
class Store:
    """A tiny SQLite store. It holds users, scans and findings."""

    path: Path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def initialise(self) -> None:
        connection = self.connect()
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    token TEXT UNIQUE NOT NULL,
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
        connection = self.connect()
        with connection:
            connection.execute("INSERT OR IGNORE INTO users (id, token, role) VALUES (?, ?, ?)", (user_id, token, role))
        connection.close()

    def user_for_token(self, token: str) -> tuple[str, str] | None:
        connection = self.connect()
        try:
            row = connection.execute("SELECT id, role FROM users WHERE token = ?", (token,)).fetchone()
        finally:
            connection.close()
        return (row["id"], row["role"]) if row else None


# --------------------------------------------------------------------------- #
# API models
# --------------------------------------------------------------------------- #


class ScanRequest(BaseModel):
    """The body of a scan request.

    Only these fields exist. Anything else a client sends is ignored, so the
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


# --------------------------------------------------------------------------- #
# The application
# --------------------------------------------------------------------------- #


def create_app(db_path: str | Path = DEFAULT_DB, *, seed_users: bool = True, vulnerable: bool = False) -> FastAPI:
    """Build the application.

    ``vulnerable=True`` removes the ownership check on a single endpoint. It
    exists for one purpose: the self-scan runs against both variants, so the
    check is known to *bite* and not merely to stay silent.
    """
    store = Store(Path(db_path))
    store.initialise()
    if seed_users:
        # Two ordinary users and an administrator: a cross-identity read needs
        # two ordinary users, and an administrator must not be attacked.
        store.ensure_user("alice", make_token("alice", "user"))
        store.ensure_user("bob", make_token("bob", "user"))
        store.ensure_user("root", make_token("root", "admin"), role="admin")

    app = FastAPI(title="Mizan", version="0.2.1", description="Law-driven API security testing.")
    app.state.store = store

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
        host = _host_of(payload.target)
        if host not in ALLOWED_TARGET_HOSTS:
            # Without this the server would scan whatever a caller names,
            # including services that are only reachable from here.
            raise HTTPException(status_code=400, detail=f"target host is not allowed: {host}")
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
                severity=row["row_severity"] if "row_severity" in row.keys() else row["severity"],
                resource=row["resource"],
                owner_id=row["owner_id"],
            )
            for row in rows
        ]

    @app.post("/scans/{scan_id}/findings")
    def record_finding(
        scan_id: str, payload: dict[str, Any], user: tuple[str, str] = Depends(current_user)
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
                    str(payload.get("law", "unknown")),
                    str(payload.get("title", "untitled"))[:200],
                    str(payload.get("severity", "unknown"))[:20],
                    payload.get("resource"),
                    json.dumps(payload.get("evidence", {}))[:10000],
                ),
            )
            connection.execute("UPDATE scans SET findings = findings + 1 WHERE id = ?", (scan_id,))
        connection.close()
        return {"id": finding_id}

    @app.get("/scans/{scan_id}/bundle")
    def get_bundle(scan_id: str, user: tuple[str, str] = Depends(current_user)) -> JSONResponse:
        owner_id, _role = user
        connection = store.connect()
        try:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        finally:
            connection.close()
        if row is None or row["owner_id"] != owner_id:
            raise HTTPException(status_code=404, detail="scan not found")
        raise HTTPException(status_code=501, detail="bundles are served from the filesystem")

    return app


def _host_of(target: str) -> str:
    """The host of a target URL."""
    from urllib.parse import urlsplit

    return (urlsplit(target).hostname or "").lower()


def main() -> None:  # pragma: no cover - the entry point
    import argparse

    parser = argparse.ArgumentParser(description="Run the Mizan control plane")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--vulnerable", action="store_true", help="Disable the ownership check (self-test only).")
    arguments = parser.parse_args()

    import uvicorn

    uvicorn.run(
        create_app(arguments.db, vulnerable=arguments.vulnerable),
        host=arguments.host,
        port=arguments.port,
        log_level="warning",
    )


if __name__ == "__main__":  # pragma: no cover
    main()
