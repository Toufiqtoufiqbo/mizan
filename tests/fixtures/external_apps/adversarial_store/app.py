"""An independent adversarial application for Phase V.1.

It knows nothing about Mīzān: no import, its own opaque tokens, its own
SQLite database and its own OpenAPI document. Every name is deliberately
nonstandard so the engine cannot rely on owner/user conventions.

Variants:
  clean             - owner-only access
  read              - cross-user read allowed, with an unrelated watcher row
  write             - cross-user write allowed
  grant             - an explicit access grant (declared in the contract)
  provenance        - the only principal FK records creation provenance
  ambiguous_identity- the declared identity field names an item, not a principal
"""

from __future__ import annotations

import argparse
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals_registry (
    p_key TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_tokens (
    opaque TEXT PRIMARY KEY,
    p_ref TEXT NOT NULL REFERENCES principals_registry(p_key),
    issued_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS inventory_items (
    item_ref TEXT PRIMARY KEY,
    originator_ref TEXT NOT NULL REFERENCES principals_registry(p_key),
    label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observer_links (
    item_ref TEXT NOT NULL REFERENCES inventory_items(item_ref),
    p_ref TEXT NOT NULL REFERENCES principals_registry(p_key),
    PRIMARY KEY (item_ref, p_ref)
);
CREATE TABLE IF NOT EXISTS access_grants (
    item_ref TEXT NOT NULL REFERENCES inventory_items(item_ref),
    p_ref TEXT NOT NULL REFERENCES principals_registry(p_key),
    PRIMARY KEY (item_ref, p_ref)
);
"""

VARIANTS = ("clean", "read", "write", "grant", "provenance", "ambiguous_identity")
USERS = (("alice", "Alice"), ("bob", "Bob"))


def create_app(database: str | Path, *, vulnerability: str = "clean") -> Flask:
    if vulnerability not in VARIANTS:
        raise ValueError(f"unknown variant {vulnerability!r}")
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
            for key, label in USERS:
                connection.execute(
                    "INSERT OR IGNORE INTO principals_registry (p_key, label, secret_hash) VALUES (?, ?, ?)",
                    (key, label, f"digest:{key}"),
                )
                import os

                deployed = os.environ.get(f"MIZAN_TOKEN_{key.upper()}")
                if deployed:
                    connection.execute(
                        "INSERT OR REPLACE INTO auth_tokens (opaque, p_ref, issued_at) VALUES (?, ?, ?)",
                        (deployed, key, time.time()),
                    )
            connection.execute(
                "INSERT OR IGNORE INTO inventory_items (item_ref, originator_ref, label) VALUES (?, ?, ?)",
                ("item-alice-1", "alice", "Alice's item"),
            )
            connection.execute(
                "INSERT OR IGNORE INTO inventory_items (item_ref, originator_ref, label) VALUES (?, ?, ?)",
                ("item-bob-1", "bob", "Bob's item"),
            )
            # A watcher row with no authorization semantics whatsoever.
            connection.execute(
                "INSERT OR IGNORE INTO observer_links (item_ref, p_ref) VALUES (?, ?)", ("item-alice-1", "bob")
            )
            if vulnerability == "grant":
                connection.execute(
                    "INSERT OR IGNORE INTO access_grants (item_ref, p_ref) VALUES (?, ?)", ("item-alice-1", "bob")
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
            row = connection.execute("SELECT p_ref FROM auth_tokens WHERE opaque = ?", (token,)).fetchone()
        finally:
            connection.close()
        return row["p_ref"] if row else None

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        key = body.get("principal") or body.get("username")
        secret = body.get("passcode") or body.get("password")
        if key not in {name for name, _ in USERS} or secret != f"{key}-secret":
            return jsonify({"error": "invalid"}), 401
        token = secrets.token_urlsafe(32)
        connection = connect()
        with connection:
            connection.execute(
                "INSERT INTO auth_tokens (opaque, p_ref, issued_at) VALUES (?, ?, ?)", (token, key, time.time())
            )
        connection.close()
        return jsonify({"token": token})

    @app.get("/whoami")
    def whoami():
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        document: dict[str, Any] = {"p_key": key, "label": f"Label of {key}"}
        if app.config["VULNERABILITY"] == "ambiguous_identity":
            # The contract's declared identity field now names an item.
            document["p_key"] = f"item-{key}-1"
        return jsonify(document)

    def item_json(row: sqlite3.Row) -> dict[str, Any]:
        return {"item_ref": row["item_ref"], "label": row["label"]}

    def find_item(item_ref: str) -> sqlite3.Row | None:
        connection = connect()
        try:
            return connection.execute("SELECT * FROM inventory_items WHERE item_ref = ?", (item_ref,)).fetchone()
        finally:
            connection.close()

    def may_read(row: sqlite3.Row, key: str) -> bool:
        variant = app.config["VULNERABILITY"]
        if variant == "read":
            return True
        if variant == "grant":
            connection = connect()
            try:
                grant = connection.execute(
                    "SELECT 1 FROM access_grants WHERE item_ref = ? AND p_ref = ?", (row["item_ref"], key)
                ).fetchone()
            finally:
                connection.close()
            return row["originator_ref"] == key or grant is not None
        return row["originator_ref"] == key

    @app.get("/assets")
    def list_assets():
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        connection = connect()
        try:
            rows = connection.execute("SELECT * FROM inventory_items ORDER BY item_ref").fetchall()
        finally:
            connection.close()
        return jsonify([item_json(row) for row in rows if may_read(row, key)])

    @app.post("/assets")
    def create_asset():
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        item_ref = f"item-{key}-{secrets.token_hex(3)}"
        connection = connect()
        with connection:
            connection.execute(
                "INSERT INTO inventory_items (item_ref, originator_ref, label) VALUES (?, ?, ?)",
                (item_ref, key, "Created"),
            )
            row = connection.execute("SELECT * FROM inventory_items WHERE item_ref = ?", (item_ref,)).fetchone()
        connection.close()
        return jsonify(item_json(row)), 201

    @app.get("/assets/<item_ref>")
    def read_asset(item_ref: str):
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        row = find_item(item_ref)
        if row is None or not may_read(row, key):
            return jsonify({"error": "not found"}), 404
        return jsonify(item_json(row))

    @app.put("/assets/<item_ref>")
    def update_asset(item_ref: str):
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        label = body.get("label")
        if not isinstance(label, str) or not label:
            return jsonify({"error": "label required"}), 400
        row = find_item(item_ref)
        if row is None:
            return jsonify({"error": "not found"}), 404
        if app.config["VULNERABILITY"] != "write" and row["originator_ref"] != key:
            return jsonify({"error": "not found"}), 404
        connection = connect()
        with connection:
            connection.execute("UPDATE inventory_items SET label = ? WHERE item_ref = ?", (label, item_ref))
            updated = connection.execute("SELECT * FROM inventory_items WHERE item_ref = ?", (item_ref,)).fetchone()
        connection.close()
        return jsonify(item_json(updated))

    return app


def main() -> None:
    parser = argparse.ArgumentParser()
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
