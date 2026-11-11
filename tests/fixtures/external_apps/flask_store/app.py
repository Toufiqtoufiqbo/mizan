"""A standalone store API - an independent validation target for Mizan.

This application knows nothing about Mizan. It has:

* its own authentication - opaque random tokens in its own database, not JWTs;
* its own SQLite database;
* its own OpenAPI document (``openapi.json`` next to this file);
* its own rules about who may touch which order.

The only thing Mizan uses is ordinary HTTP, plus the database file for
attribution - the same way it would work against a real application.

Set ``STORE_VULNERABLE=1`` to remove the ownership checks. The vulnerable
variant is what proves that Mizan's detection works on an application it did
not write.
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

HERE = Path(__file__).resolve().parent
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    sku TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def create_app(database: str | Path, *, vulnerable: bool = False) -> Flask:
    """Build the store API."""
    app = Flask(__name__)
    app.config["DATABASE"] = str(database)
    app.config["VULNERABLE"] = vulnerable

    def connect() -> sqlite3.Connection:
        connection = sqlite3.connect(app.config["DATABASE"], timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def initialise() -> None:
        connection = connect()
        with connection:
            connection.executescript(SCHEMA)
            for user, password, role in (
                ("alice", "alice-secret", "user"),
                ("bob", "bob-secret", "user"),
                ("root", "root-secret", "admin"),
            ):
                salt = "store-salt"
                connection.execute(
                    "INSERT OR IGNORE INTO users (id, password_hash, role) VALUES (?, ?, ?)",
                    (user, hash_password(password, salt), role),
                )
        connection.close()

    initialise()

    def current_user() -> str | None:
        """The identity behind the bearer token."""
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :].strip()
        connection = connect()
        try:
            row = connection.execute("SELECT user_id FROM tokens WHERE token = ?", (token,)).fetchone()
        finally:
            connection.close()
        return row["user_id"] if row else None

    def is_admin(user_id: str) -> bool:
        connection = connect()
        try:
            row = connection.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        finally:
            connection.close()
        return bool(row) and row["role"] == "admin"

    def owns(order: sqlite3.Row, user_id: str) -> bool:
        """Whether the caller may touch this order.

        The vulnerable variant skips the check - that is the whole point of it.
        """
        if app.config["VULNERABLE"]:
            return True
        return order["owner_id"] == user_id or is_admin(user_id)

    def order_json(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "owner_id": row["owner_id"],
            "sku": row["sku"],
            "quantity": row["quantity"],
            "status": row["status"],
            "created_at": row["created_at"],
        }

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    # -- authentication --------------------------------------------------- #

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"error": "username and password are required"}), 400
        connection = connect()
        try:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (username,)).fetchone()
        finally:
            connection.close()
        if row is None or row["password_hash"] != hash_password(password, "store-salt"):
            return jsonify({"error": "invalid credentials"}), 401
        token = secrets.token_urlsafe(32)
        connection = connect()
        with connection:
            connection.execute(
                "INSERT INTO tokens (token, user_id, created_at) VALUES (?, ?, ?)",
                (token, username, time.time()),
            )
        connection.close()
        return jsonify({"token": token, "user_id": username})

    @app.get("/me")
    def me():
        user_id = current_user()
        if user_id is None:
            return jsonify({"error": "unauthenticated"}), 401
        connection = connect()
        try:
            row = connection.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        finally:
            connection.close()
        return jsonify({"id": row["id"], "role": row["role"], "owner_id": row["id"]})

    # -- orders ------------------------------------------------------------ #

    @app.post("/orders")
    def create_order():
        user_id = current_user()
        if user_id is None:
            return jsonify({"error": "unauthenticated"}), 401
        body = request.get_json(silent=True) or {}
        sku = body.get("sku")
        quantity = body.get("quantity", 1)
        if not isinstance(sku, str) or not sku:
            return jsonify({"error": "sku is required"}), 400
        if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity < 1:
            return jsonify({"error": "quantity must be a positive integer"}), 400
        order_id = f"ord-{secrets.token_hex(6)}"
        connection = connect()
        with connection:
            connection.execute(
                "INSERT INTO orders (id, owner_id, sku, quantity, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (order_id, user_id, sku, quantity, "created", time.time()),
            )
        connection.close()
        return jsonify(order_json(_fetch(order_id))), 201

    @app.get("/orders")
    def list_orders():
        user_id = current_user()
        if user_id is None:
            return jsonify({"error": "unauthenticated"}), 401
        connection = connect()
        try:
            if app.config["VULNERABLE"]:
                rows = connection.execute("SELECT * FROM orders ORDER BY created_at").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM orders WHERE owner_id = ? ORDER BY created_at", (user_id,)
                ).fetchall()
        finally:
            connection.close()
        return jsonify({"orders": [order_json(row) for row in rows]})

    @app.get("/orders/<order_id>")
    def read_order(order_id: str):
        user_id = current_user()
        if user_id is None:
            return jsonify({"error": "unauthenticated"}), 401
        row = _fetch(order_id)
        if row is None:
            return jsonify({"error": "order not found"}), 404
        if not owns(row, user_id):
            return jsonify({"error": "forbidden"}), 403
        return jsonify(order_json(row))

    @app.put("/orders/<order_id>")
    def update_order(order_id: str):
        user_id = current_user()
        if user_id is None:
            return jsonify({"error": "unauthenticated"}), 401
        row = _fetch(order_id)
        if row is None:
            return jsonify({"error": "order not found"}), 404
        if not owns(row, user_id):
            return jsonify({"error": "forbidden"}), 403
        body = request.get_json(silent=True) or {}
        status = body.get("status")
        if not isinstance(status, str) or not status:
            return jsonify({"error": "status is required"}), 400
        connection = connect()
        with connection:
            connection.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
        connection.close()
        return jsonify(order_json(_fetch(order_id)))

    @app.delete("/orders/<order_id>")
    def delete_order(order_id: str):
        user_id = current_user()
        if user_id is None:
            return jsonify({"error": "unauthenticated"}), 401
        row = _fetch(order_id)
        if row is None:
            return jsonify({"error": "order not found"}), 404
        if not owns(row, user_id):
            return jsonify({"error": "forbidden"}), 403
        connection = connect()
        with connection:
            connection.execute("DELETE FROM orders WHERE id = ?", (order_id,))
        connection.close()
        return jsonify({"deleted": order_id})

    def _fetch(order_id: str) -> sqlite3.Row | None:
        connection = connect()
        try:
            return connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        finally:
            connection.close()

    return app


def main() -> None:  # pragma: no cover - the entry point
    parser = argparse.ArgumentParser(description="Run the standalone store API")
    parser.add_argument("--db", default="store.sqlite")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    arguments = parser.parse_args()

    vulnerable = os.environ.get("STORE_VULNERABLE") == "1"
    application = create_app(arguments.db, vulnerable=vulnerable)
    application.run(host=arguments.host, port=arguments.port, threaded=True, debug=False)


if __name__ == "__main__":  # pragma: no cover
    main()
