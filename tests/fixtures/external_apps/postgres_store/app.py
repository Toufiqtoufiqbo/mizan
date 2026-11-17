"""Independent PostgreSQL fixture for Phase VI.

Knows nothing about Mīzān: no imports, no helper calls, no shared code. It owns
its authentication, its request context and its PostgreSQL schema. The scan
proxy only sends HTTP requests with an optional per-request correlation header.

Environment:
  MIZAN_PG_DSN     - a PostgreSQL the fixture may use (CI uses a disposable DB)
  MIZAN_PG_SCHEMA  - schema the fixture owns (default: pgstore)

Variants:
  clean            - owner-only reads and writes
  read             - any authenticated principal may read an item
  write            - any authenticated principal may write an item
  grant_read       - collaborator may read, never write
  grant_write      - collaborator may read AND write (unauthorized write)
  unknown          - item has no ownership signal at all
  composite        - items are identified by (tenant_ref, item_ref)
"""

from __future__ import annotations

import argparse
import os
import secrets
import time
from typing import Any

import psycopg
from flask import Flask, jsonify, request

USERS = (("alice", "Alice"), ("bob", "Bob"))
VARIANTS = (
    "clean",
    "read",
    "write",
    "grant_read",
    "grant_write",
    "unknown",
    "composite",
)


def _dsn() -> str:
    return os.environ.get("MIZAN_PG_DSN") or os.environ.get("MIZAN_TEST_POSTGRES_DSN") or ""


def _schema() -> str:
    return os.environ.get("MIZAN_PG_SCHEMA", "pgstore")


def _quote(name: str) -> str:
    if not name or "\x00" in name:
        raise ValueError("invalid identifier")
    return '"' + name.replace('"', '""') + '"'


def create_app(variant: str = "clean", *, dsn: str | None = None, schema: str | None = None) -> Flask:
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}")
    app = Flask(__name__)
    app.config["PG_DSN"] = dsn or _dsn()
    app.config["PG_SCHEMA"] = schema or _schema()
    app.config["VARIANT"] = variant

    def q(name: str) -> str:
        return f"{_quote(app.config['PG_SCHEMA'])}.{_quote(name)}"

    def connect() -> psycopg.Connection:
        return psycopg.connect(app.config["PG_DSN"] or None, connect_timeout=5)

    def context(connection: psycopg.Connection, principal: str | None) -> None:
        """Transaction-local identity and request correlation (never authorization)."""
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT set_config('application_name', %s, true)", (f"mizan:{principal}" if principal else "",)
            )
            correlation = request.headers.get("X-Mizan-Request-Id", "")
            cursor.execute("SELECT set_config('mizan.request_id', %s, true)", (correlation,))

    def initialise() -> None:
        connection = connect()
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {_quote(app.config['PG_SCHEMA'])}")
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {q("principals_registry")} (
                    p_key TEXT PRIMARY KEY, label TEXT NOT NULL)"""
            )
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {q("auth_tokens")} (
                    opaque TEXT PRIMARY KEY, p_ref TEXT NOT NULL REFERENCES {q("principals_registry")}(p_key),
                    issued_at REAL NOT NULL)"""
            )
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {q("inventory_items")} (
                    item_ref TEXT PRIMARY KEY, originator_ref TEXT REFERENCES {q("principals_registry")}(p_key),
                    label TEXT NOT NULL)"""
            )
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {q("item_relations")} (
                    link_ref TEXT PRIMARY KEY,
                    item_ref TEXT NOT NULL REFERENCES {q("inventory_items")}(item_ref),
                    creator_ref TEXT REFERENCES {q("principals_registry")}(p_key),
                    collaborator_ref TEXT REFERENCES {q("principals_registry")}(p_key),
                    observer_ref TEXT REFERENCES {q("principals_registry")}(p_key))"""
            )
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {q("pair_items")} (
                    tenant_ref TEXT NOT NULL, item_ref TEXT NOT NULL,
                    originator_ref TEXT REFERENCES {q("principals_registry")}(p_key),
                    label TEXT NOT NULL, PRIMARY KEY (tenant_ref, item_ref))"""
            )
            for key, label in USERS:
                cursor.execute(
                    f"INSERT INTO {q('principals_registry')} (p_key, label) VALUES (%s, %s) "
                    "ON CONFLICT (p_key) DO NOTHING",
                    (key, label),
                )
            env_token = os.environ.get("MIZAN_TOKEN_ALICE")
            if env_token:
                cursor.execute(
                    f"INSERT INTO {q('auth_tokens')} (opaque, p_ref, issued_at) VALUES (%s, %s, %s) "
                    "ON CONFLICT (opaque) DO UPDATE SET p_ref = EXCLUDED.p_ref",
                    (env_token, "alice", time.time()),
                )
            env_token = os.environ.get("MIZAN_TOKEN_BOB")
            if env_token:
                cursor.execute(
                    f"INSERT INTO {q('auth_tokens')} (opaque, p_ref, issued_at) VALUES (%s, %s, %s) "
                    "ON CONFLICT (opaque) DO UPDATE SET p_ref = EXCLUDED.p_ref",
                    (env_token, "bob", time.time()),
                )
            owner = None if variant == "unknown" else "alice"
            cursor.execute(
                f"INSERT INTO {q('inventory_items')} (item_ref, originator_ref, label) VALUES (%s, %s, %s) "
                "ON CONFLICT (item_ref) DO NOTHING",
                ("item-a1", owner, "Item A"),
            )
            cursor.execute(
                f"""INSERT INTO {q("item_relations")}
                    (link_ref, item_ref, creator_ref, collaborator_ref, observer_ref)
                    VALUES (%s, %s, %s, %s, %s) ON CONFLICT (link_ref) DO NOTHING""",
                ("link-1", "item-a1", "alice", "bob", None),
            )
            cursor.execute(
                f"INSERT INTO {q('pair_items')} (tenant_ref, item_ref, originator_ref, label) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (tenant_ref, item_ref) DO NOTHING",
                ("t1", "p1", "alice", "Composite A"),
            )
        connection.commit()
        connection.close()

    initialise()

    def caller() -> str | None:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :].strip()
        connection = connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT p_ref FROM {q('auth_tokens')} WHERE opaque = %s", (token,))
                row = cursor.fetchone()
            return str(row[0]) if row else None
        finally:
            connection.close()

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        key = body.get("username", body.get("principal"))
        secret = body.get("password", body.get("passcode"))
        if key not in dict(USERS) or secret != f"{key}-secret":
            return jsonify({"error": "invalid"}), 401
        token = secrets.token_urlsafe(32)
        connection = connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"INSERT INTO {q('auth_tokens')} (opaque, p_ref, issued_at) VALUES (%s,%s,%s)",
                    (token, key, time.time()),
                )
            connection.commit()
        finally:
            connection.close()
        return jsonify({"token": token})

    @app.get("/whoami")
    def whoami():
        key = caller()
        return jsonify({"p_key": key, "label": f"Label of {key}"}) if key else (jsonify({"error": "unauthorized"}), 401)

    def item_json(row: Any) -> dict[str, Any]:
        return {"item_ref": row[0], "label": row[1]}

    def load_item(item_ref: str):
        connection = connect()
        try:
            with connection.cursor() as cursor:
                context(connection, None)
                cursor.execute(
                    f"SELECT item_ref, label, originator_ref FROM {q('inventory_items')} WHERE item_ref = %s",
                    (item_ref,),
                )
                return cursor.fetchone()
        finally:
            connection.close()

    def may(key: str, row: Any, *, write: bool) -> bool:
        owner = row[2]
        if owner == key:
            return True
        mode = app.config["VARIANT"]
        if write:
            return mode == "write" or (mode == "grant_write" and key == "bob")
        return mode in {"read", "grant_read", "grant_write"} and key == "bob"

    @app.get("/items")
    def list_items():
        key = caller()
        if not key:
            return jsonify({"error": "unauthorized"}), 401
        connection = connect()
        try:
            with connection.cursor() as cursor:
                context(connection, key)
                cursor.execute(f"SELECT item_ref, label FROM {q('inventory_items')} ORDER BY item_ref")
                return jsonify([item_json(row) for row in cursor.fetchall()])
        finally:
            connection.close()

    @app.get("/items/<item_ref>")
    def read_item(item_ref: str):
        key = caller()
        row = load_item(item_ref)
        if not key or row is None or not may(key, row, write=False):
            return jsonify({"error": "not found"}), 404
        return jsonify(item_json(row))

    @app.put("/items/<item_ref>")
    def write_item(item_ref: str):
        key = caller()
        body = request.get_json(silent=True) or {}
        label = body.get("label")
        row = load_item(item_ref)
        if not key or row is None or not isinstance(label, str) or not may(key, row, write=True):
            return jsonify({"error": "not found"}), 404
        connection = connect()
        try:
            with connection.cursor() as cursor:
                context(connection, key)
                cursor.execute(f"UPDATE {q('inventory_items')} SET label = %s WHERE item_ref = %s", (label, item_ref))
            connection.commit()
        finally:
            connection.close()
        return jsonify({"item_ref": item_ref, "label": label})

    @app.get("/pairs")
    def list_pairs():
        key = caller()
        if not key:
            return jsonify({"error": "unauthorized"}), 401
        connection = connect()
        try:
            with connection.cursor() as cursor:
                context(connection, key)
                cursor.execute(
                    f"SELECT tenant_ref, item_ref, label FROM {q('pair_items')} ORDER BY tenant_ref, item_ref"
                )
                return jsonify(
                    [
                        {"tenant_ref": row[0], "item_ref": row[1], "id": f"{row[0]}:{row[1]}", "label": row[2]}
                        for row in cursor.fetchall()
                    ]
                )
        finally:
            connection.close()

    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--vulnerability", choices=VARIANTS, default="clean")
    parser.add_argument("--schema", default=None)
    args = parser.parse_args()
    create_app(args.vulnerability, schema=args.schema).run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
