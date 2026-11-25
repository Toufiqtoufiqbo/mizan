"""Independent L7 fixture application with real cache/queue HTTP operations.

The application owns the artifacts and records its own operations in
``l7_events`` with the inbound request id. Mīzān only reads those events as
evidence; it never writes them. Two variants: ``vulnerable`` lets Bob read
Alice's artifact/message, ``secure`` does not (while Alice still can).
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

import psycopg
from flask import Flask, jsonify, request

TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}


def _dsn() -> str:
    return os.environ.get("MIZAN_PG_DSN") or os.environ.get("MIZAN_TEST_POSTGRES_DSN") or ""


def _connect() -> psycopg.Connection:
    return psycopg.connect(_dsn(), autocommit=True, connect_timeout=5)


def create_app(variant: str = "secure", *, dsn: str | None = None) -> Flask:
    if variant not in {"vulnerable", "secure"}:
        raise ValueError(f"unknown L7 variant {variant!r}")
    app = Flask(__name__)
    app.config["VARIANT"] = variant
    app.config["DSN"] = dsn or _dsn()

    def connect() -> psycopg.Connection:
        return psycopg.connect(app.config["DSN"], autocommit=True, connect_timeout=5)

    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS l7_artifacts (
                    artifact_id TEXT PRIMARY KEY, producer TEXT NOT NULL,
                    scope TEXT NOT NULL, content TEXT NOT NULL, created_at REAL NOT NULL)"""
            )
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS l7_messages (
                    message_id TEXT PRIMARY KEY, producer TEXT NOT NULL,
                    intended_consumer TEXT NOT NULL, scope TEXT NOT NULL,
                    content TEXT NOT NULL, created_at REAL NOT NULL)"""
            )
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS l7_events (
                    id BIGSERIAL PRIMARY KEY, request_id TEXT NOT NULL, operation TEXT NOT NULL,
                    principal TEXT NOT NULL, artifact_id TEXT NOT NULL, scope TEXT NOT NULL,
                    digest TEXT NOT NULL, granted BOOLEAN NOT NULL, occurred_at REAL NOT NULL)"""
            )

    def caller() -> str | None:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[7:].strip()
        return next((name for name, value in TOKENS.items() if value == token), None)

    def record(
        cursor: Any,
        request_id: str,
        operation: str,
        principal: str,
        artifact_id: str,
        scope: str,
        digest: str,
        granted: bool,
    ) -> None:
        cursor.execute(
            """INSERT INTO l7_events
               (request_id, operation, principal, artifact_id, scope, digest, granted, occurred_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (request_id, operation, principal, artifact_id, scope, digest, granted, time.time()),
        )

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "variant": variant})

    @app.post("/artifacts")
    def write_artifact():
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        artifact_id, content = body.get("artifact_id"), body.get("content")
        if not isinstance(artifact_id, str) or not isinstance(content, str):
            return jsonify({"error": "invalid"}), 400
        request_id = request.headers.get("X-Mizan-Request-Id", "")
        digest = hashlib.sha256(content.encode()).hexdigest()
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO l7_artifacts (artifact_id, producer, scope, content, created_at)
                       VALUES (%s,%s,%s,%s,%s) ON CONFLICT (artifact_id) DO UPDATE
                       SET producer = EXCLUDED.producer, content = EXCLUDED.content""",
                    (artifact_id, principal, body.get("scope", "tenant-a"), content, time.time()),
                )
                record(
                    cursor,
                    request_id,
                    "cache_write",
                    principal,
                    artifact_id,
                    body.get("scope", "tenant-a"),
                    digest,
                    True,
                )
        return jsonify({"artifact_id": artifact_id, "digest": digest, "content": content}), 201

    @app.get("/artifacts/<artifact_id>")
    def read_artifact(artifact_id: str):
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        request_id = request.headers.get("X-Mizan-Request-Id", "")
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT producer, scope, content FROM l7_artifacts WHERE artifact_id = %s", (artifact_id,)
                )
                row = cursor.fetchone()
                if row is None:
                    return jsonify({"error": "not found"}), 404
                granted = principal == row[0] or variant == "vulnerable"
                digest = hashlib.sha256(str(row[2]).encode()).hexdigest()
                record(cursor, request_id, "cache_read", principal, artifact_id, row[1], digest, granted)
        if not granted:
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"artifact_id": artifact_id, "digest": digest, "content": row[2]})

    @app.post("/messages")
    def publish_message():
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        message_id, content = body.get("message_id"), body.get("content")
        intended = body.get("intended_consumer")
        if not all(isinstance(item, str) for item in (message_id, content, intended)):
            return jsonify({"error": "invalid"}), 400
        request_id = request.headers.get("X-Mizan-Request-Id", "")
        digest = hashlib.sha256(content.encode()).hexdigest()
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO l7_messages
                       (message_id, producer, intended_consumer, scope, content, created_at)
                       VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (message_id) DO UPDATE
                       SET producer = EXCLUDED.producer, content = EXCLUDED.content,
                           intended_consumer = EXCLUDED.intended_consumer""",
                    (message_id, principal, intended, body.get("scope", "tenant-a"), content, time.time()),
                )
                record(
                    cursor,
                    request_id,
                    "queue_publish",
                    principal,
                    message_id,
                    body.get("scope", "tenant-a"),
                    digest,
                    True,
                )
        return jsonify({"message_id": message_id, "digest": digest}), 201

    @app.post("/messages/<message_id>/consume")
    def consume_message(message_id: str):
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        request_id = request.headers.get("X-Mizan-Request-Id", "")
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT producer, intended_consumer, scope, content FROM l7_messages WHERE message_id = %s",
                    (message_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return jsonify({"error": "not found"}), 404
                granted = principal == row[1] or variant == "vulnerable"
                digest = hashlib.sha256(str(row[3]).encode()).hexdigest()
                record(cursor, request_id, "queue_consume", principal, message_id, row[2], digest, granted)
        if not granted:
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"message_id": message_id, "digest": digest, "content": row[3]})

    return app


if __name__ == "__main__":  # pragma: no cover - manual helper
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--variant", choices=("vulnerable", "secure"), default="secure")
    args = parser.parse_args()
    create_app(args.variant).run(host="127.0.0.1", port=args.port, threaded=True)
