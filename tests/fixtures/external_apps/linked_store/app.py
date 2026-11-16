"""An independent store API whose ownership is deliberately hard to guess.

This application knows nothing about Mīzān: it imports no Mīzān module, has
its own authentication, its own database and its own OpenAPI document. It is
the Phase V reference target for *evidence-based* relationship discovery.

Unlike the other fixtures, there is no ``owner_id`` / ``user_id`` field
anywhere in its API. A document has a public ``document_key`` and a database
column ``custodian_ref`` that declares a foreign key to the caller's identity
record. To reason about ownership, a scanner must:

1. anchor each configured principal to its database identity record using
   repeated observations from several principals;
2. match a public document key to a row using declared primary-key metadata;
3. follow the declared foreign key, and corroborate it with independent
   evidence - a foreign key alone is not ownership.

The ``collaborator`` variant adds an explicit grant (a separate association
table). A collaborator may read a document they do not own; that is legitimate
access, not a cross-user read vulnerability.

Variants: clean, read, write, both, collaborator, ambiguous.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    identity_key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    identity_ref TEXT NOT NULL REFERENCES identities(identity_key),
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    document_key TEXT PRIMARY KEY,
    custodian_ref TEXT NOT NULL REFERENCES identities(identity_key),
    title TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft'
);
CREATE TABLE IF NOT EXISTS document_grants (
    document_key TEXT NOT NULL REFERENCES documents(document_key),
    identity_key TEXT NOT NULL REFERENCES identities(identity_key),
    PRIMARY KEY (document_key, identity_key)
);
"""

VARIANTS = ("clean", "read", "write", "both", "collaborator", "ambiguous")

USERS = (
    ("alice", "Alice", "alice-secret", "MIZAN_TOKEN_ALICE"),
    ("bob", "Bob", "bob-secret", "MIZAN_TOKEN_BOB"),
    ("root", "Root", "root-secret", "MIZAN_TOKEN_ROOT"),
)


def _hash(value: str) -> str:
    return hashlib.sha256(f"linked-store-salt:{value}".encode()).hexdigest()


def create_app(database: str | Path, *, vulnerability: str = "clean") -> Flask:
    """Build the application. An unknown variant is an error, never clean."""
    if vulnerability not in VARIANTS:
        raise ValueError(f"unknown variant {vulnerability!r}; expected one of {VARIANTS}")
    app = Flask(__name__)
    app.config["DATABASE"] = str(database)
    app.config["VULNERABILITY"] = vulnerability

    def connect() -> sqlite3.Connection:
        connection = sqlite3.connect(app.config["DATABASE"], timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def initialise() -> None:
        connection = connect()
        with connection:
            connection.executescript(SCHEMA)
            for key, name, password, env_name in USERS:
                connection.execute(
                    "INSERT OR IGNORE INTO identities (identity_key, display_name, secret_hash) VALUES (?, ?, ?)",
                    (key, name, _hash(password)),
                )
                deployed = os.environ.get(env_name)
                if deployed:
                    connection.execute(
                        "INSERT OR REPLACE INTO tokens (token, identity_ref, created_at) VALUES (?, ?, ?)",
                        (deployed, key, time.time()),
                    )
            # Every variant seeds one document per ordinary principal so the
            # scanner has two stable, differently-owned resources to compare.
            for key in ("alice", "bob"):
                document_key = f"doc-{key}-1"
                connection.execute(
                    "INSERT OR IGNORE INTO documents (document_key, custodian_ref, title, state) VALUES (?, ?, ?, ?)",
                    (document_key, key, f"Notes of {key.title()}", "draft"),
                )
            if vulnerability == "collaborator":
                # An explicit sharing grant: Bob may read Alice's document.
                connection.execute(
                    "INSERT OR IGNORE INTO document_grants (document_key, identity_key) VALUES (?, ?)",
                    ("doc-alice-1", "bob"),
                )
            if vulnerability == "ambiguous":
                # Each caller maps to TWO real identity records. No scanner may
                # claim a unique principal -> identity anchor from this.
                for key in ("alice", "bob"):
                    connection.execute(
                        "INSERT OR IGNORE INTO identities (identity_key, display_name, secret_hash) VALUES (?, ?, ?)",
                        (f"{key}-alt", f"{key.title()} Alt", _hash(f"{key}-alt-secret")),
                    )
        connection.close()

    initialise()

    def caller() -> str | None:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :].strip()
        connection = connect()
        try:
            row = connection.execute("SELECT identity_ref FROM tokens WHERE token = ?", (token,)).fetchone()
        finally:
            connection.close()
        return row["identity_ref"] if row else None

    def is_admin(identity: str) -> bool:
        return identity == "root"

    def has_grant(document_key: str, identity: str) -> bool:
        connection = connect()
        try:
            row = connection.execute(
                "SELECT 1 FROM document_grants WHERE document_key = ? AND identity_key = ?",
                (document_key, identity),
            ).fetchone()
        finally:
            connection.close()
        return row is not None

    def may_read(row: sqlite3.Row, identity: str) -> bool:
        variant = app.config["VULNERABILITY"]
        if variant in {"read", "both"}:
            return True
        return (
            row["custodian_ref"] == identity
            or is_admin(identity)
            or (variant == "collaborator" and has_grant(row["document_key"], identity))
        )

    def may_write(row: sqlite3.Row, identity: str) -> bool:
        if app.config["VULNERABILITY"] in {"write", "both"}:
            return True
        return row["custodian_ref"] == identity or is_admin(identity)

    def document_json(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "document_key": row["document_key"],
            "title": row["title"],
            "state": row["state"],
        }

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        username, password = body.get("username"), body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"error": "invalid credentials"}), 400
        connection = connect()
        try:
            row = connection.execute(
                "SELECT identity_key, secret_hash FROM identities WHERE identity_key = ?", (username,)
            ).fetchone()
        finally:
            connection.close()
        if row is None or row["secret_hash"] != _hash(password):
            return jsonify({"error": "invalid credentials"}), 401
        token = secrets.token_urlsafe(32)
        connection = connect()
        with connection:
            connection.execute(
                "INSERT INTO tokens (token, identity_ref, created_at) VALUES (?, ?, ?)",
                (token, username, time.time()),
            )
        connection.close()
        return jsonify({"token": token})

    @app.get("/session")
    def session():
        identity = caller()
        if identity is None:
            return jsonify({"error": "unauthorized"}), 401
        connection = connect()
        try:
            row = connection.execute(
                "SELECT identity_key, display_name FROM identities WHERE identity_key = ?", (identity,)
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return jsonify({"error": "unauthorized"}), 401
        document: dict[str, Any] = {
            "identity_key": row["identity_key"],
            "display_name": row["display_name"],
        }
        if app.config["VULNERABILITY"] == "ambiguous":
            # The declared identity field now names a *document*, not an
            # identity record. The anchor resolves to the wrong table, so no
            # ownership may be confirmed from it.
            document["identity_key"] = f"doc-{identity}-1"
            document["alternate_identity_key"] = identity
        return jsonify(document)

    @app.get("/documents")
    def list_documents():
        identity = caller()
        if identity is None:
            return jsonify({"error": "unauthorized"}), 401
        connection = connect()
        try:
            rows = connection.execute("SELECT * FROM documents ORDER BY document_key").fetchall()
        finally:
            connection.close()
        visible = [row for row in rows if may_read(row, identity) or is_admin(identity)]
        return jsonify([document_json(row) for row in visible])

    @app.post("/documents")
    def create_document():
        identity = caller()
        if identity is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        title = body.get("title")
        if not isinstance(title, str) or not title.strip():
            return jsonify({"error": "title is required"}), 400
        document_key = f"doc-{identity}-{secrets.token_hex(4)}"
        connection = connect()
        with connection:
            connection.execute(
                "INSERT INTO documents (document_key, custodian_ref, title, state) VALUES (?, ?, ?, ?)",
                (document_key, identity, title, "draft"),
            )
            row = connection.execute("SELECT * FROM documents WHERE document_key = ?", (document_key,)).fetchone()
        connection.close()
        return jsonify(document_json(row)), 201

    def find_document(document_key: str) -> sqlite3.Row | None:
        connection = connect()
        try:
            return connection.execute("SELECT * FROM documents WHERE document_key = ?", (document_key,)).fetchone()
        finally:
            connection.close()

    @app.get("/documents/<document_key>")
    def read_document(document_key: str):
        identity = caller()
        if identity is None:
            return jsonify({"error": "unauthorized"}), 401
        row = find_document(document_key)
        if row is None or not may_read(row, identity):
            return jsonify({"error": "not found"}), 404
        return jsonify(document_json(row))

    @app.put("/documents/<document_key>")
    def update_document(document_key: str):
        identity = caller()
        if identity is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        state = body.get("state")
        if not isinstance(state, str) or not state.strip():
            return jsonify({"error": "state is required"}), 400
        row = find_document(document_key)
        if row is None or not may_write(row, identity):
            return jsonify({"error": "not found"}), 404
        changed = f"{state}-{secrets.token_hex(3)}"
        connection = connect()
        with connection:
            connection.execute("UPDATE documents SET state = ? WHERE document_key = ?", (changed, document_key))
            updated = connection.execute("SELECT * FROM documents WHERE document_key = ?", (document_key,)).fetchone()
        connection.close()
        return jsonify(document_json(updated))

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="A nonstandard-ownership independent test application")
    parser.add_argument("--db", required=True)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--vulnerability", choices=VARIANTS, default="clean")
    arguments = parser.parse_args()
    Path(arguments.db).parent.mkdir(parents=True, exist_ok=True)
    create_app(arguments.db, vulnerability=arguments.vulnerability).run(
        host="127.0.0.1", port=arguments.port, threaded=True
    )


if __name__ == "__main__":
    main()
