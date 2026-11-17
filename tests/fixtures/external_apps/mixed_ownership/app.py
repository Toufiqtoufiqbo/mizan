"""Independent fixture for Phase V.2.2 unresolved-ownership coverage.

Three resource kinds are exposed through separate collections:

* ``/confirmed/{item_ref}`` — the owner is declared in the relationship
  contract and corroborated by a declared foreign key (CONFIRMED).
* ``/candidate/{item_ref}`` — a foreign key names an anchored principal, but
  no contract declaration promotes it (CANDIDATE).
* ``/unknown/{item_ref}`` — the row has no ownership signal at all (UNKNOWN).

No identity-specific column name or endpoint is known to Mīzān in advance; the
application publishes them in its own ``mizan-relationships.json``. The app
itself is owner-only in the default variant, so no violation is proven there.

Variants:
  clean    - owner-only access everywhere
  finding  - a cross-identity write on the confirmed resource is allowed
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
    label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_tokens (
    opaque TEXT PRIMARY KEY,
    p_ref TEXT NOT NULL REFERENCES principals_registry(p_key),
    issued_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS confirmed_items (
    item_ref TEXT PRIMARY KEY,
    originator_ref TEXT REFERENCES principals_registry(p_key),
    label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidate_items (
    item_ref TEXT PRIMARY KEY,
    creator_ref TEXT REFERENCES principals_registry(p_key),
    label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS unknown_items (
    item_ref TEXT PRIMARY KEY,
    label TEXT NOT NULL
);
"""

VARIANTS = ("clean", "finding")
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
                    "INSERT OR IGNORE INTO principals_registry (p_key, label) VALUES (?, ?)", (key, label)
                )
                import os

                deployed = os.environ.get(f"MIZAN_TOKEN_{key.upper()}")
                if deployed:
                    connection.execute(
                        "INSERT OR REPLACE INTO auth_tokens (opaque, p_ref, issued_at) VALUES (?, ?, ?)",
                        (deployed, key, time.time()),
                    )
            connection.execute(
                "INSERT OR IGNORE INTO confirmed_items (item_ref, originator_ref, label) VALUES (?, ?, ?)",
                ("item-a1", "alice", "Confirmed A"),
            )
            connection.execute(
                "INSERT OR IGNORE INTO candidate_items (item_ref, creator_ref, label) VALUES (?, ?, ?)",
                ("item-b1", "alice", "Candidate B"),
            )
            connection.execute(
                "INSERT OR IGNORE INTO unknown_items (item_ref, label) VALUES (?, ?)",
                ("item-c1", "Unknown C"),
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
        return jsonify({"p_key": key, "label": f"Label of {key}"})

    def one(table: str, item_ref: str) -> sqlite3.Row | None:
        connection = connect()
        try:
            return connection.execute(f"SELECT * FROM {table} WHERE item_ref = ?", (item_ref,)).fetchone()
        finally:
            connection.close()

    def item_json(row: sqlite3.Row) -> dict[str, Any]:
        return {"item_ref": row["item_ref"], "label": row["label"]}

    def owns(row: sqlite3.Row, column: str, key: str) -> bool:
        return row[column] == key

    def may_read(table: str, row: sqlite3.Row, key: str) -> bool:
        if table == "confirmed_items":
            return owns(row, "originator_ref", key)
        if table == "candidate_items":
            return owns(row, "creator_ref", key)
        return True  # unknown_items is readable by anybody; writes stay ownerless

    def may_write(table: str, row: sqlite3.Row, key: str) -> bool:
        if table == "confirmed_items":
            if app.config["VULNERABILITY"] == "finding":
                return True
            return owns(row, "originator_ref", key)
        if table == "candidate_items":
            return owns(row, "creator_ref", key)
        # No ownership signal: writes are allowed by the application, but the
        # scan cannot decide an authorization law without a confirmed owner.
        return True

    def listing() -> Any:
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        # Publish every identifier through every catalogue so both identities
        # learn the full API surface; object-level access is still scoped in
        # ``detail()``/``update()``.
        connection = connect()
        try:
            rows = [
                item_json(row)
                for name in ("confirmed_items", "candidate_items", "unknown_items")
                for row in connection.execute(f"SELECT * FROM {name} ORDER BY item_ref").fetchall()
            ]
        finally:
            connection.close()
        return jsonify(rows)

    def detail(table: str, item_ref: str):
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        row = one(table, item_ref)
        if row is None or not may_read(table, row, key):
            return jsonify({"error": "not found"}), 404
        return jsonify(item_json(row))

    def update(table: str, item_ref: str):
        key = caller()
        if key is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        label = body.get("label")
        if not isinstance(label, str) or not label:
            return jsonify({"error": "label required"}), 400
        row = one(table, item_ref)
        if row is None or not may_write(table, row, key):
            return jsonify({"error": "not found"}), 404
        connection = connect()
        with connection:
            connection.execute(f"UPDATE {table} SET label = ? WHERE item_ref = ?", (label, item_ref))
            updated = connection.execute(f"SELECT * FROM {table} WHERE item_ref = ?", (item_ref,)).fetchone()
        connection.close()
        return jsonify(item_json(updated))

    @app.get("/confirmed")
    def list_confirmed():
        return listing()

    @app.get("/confirmed/<item_ref>")
    def read_confirmed(item_ref: str):
        return detail("confirmed_items", item_ref)

    @app.put("/confirmed/<item_ref>")
    def write_confirmed(item_ref: str):
        return update("confirmed_items", item_ref)

    @app.get("/candidate")
    def list_candidate():
        return listing()

    @app.get("/candidate/<item_ref>")
    def read_candidate(item_ref: str):
        return detail("candidate_items", item_ref)

    @app.put("/candidate/<item_ref>")
    def write_candidate(item_ref: str):
        return update("candidate_items", item_ref)

    @app.get("/unknown")
    def list_unknown():
        return listing()

    @app.get("/unknown/<item_ref>")
    def read_unknown(item_ref: str):
        return detail("unknown_items", item_ref)

    @app.put("/unknown/<item_ref>")
    def write_unknown(item_ref: str):
        return update("unknown_items", item_ref)

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
