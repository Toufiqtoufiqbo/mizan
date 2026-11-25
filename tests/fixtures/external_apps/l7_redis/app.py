"""Independent L7 fixture application backed by a real Redis server.

The application performs the cache and queue operations itself (``SET``/``GET``
and ``LPUSH``/``LINDEX``) and records its own operations in a Redis stream with
the inbound ``X-Mizan-Request-Id``. Mīzān only reads that stream with XRANGE;
it never writes content or events.

Two variants: ``vulnerable`` lets Bob read Alice's data, ``secure`` does not
while Alice still can.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

import redis
from flask import Flask, jsonify, request

TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}
EVENT_STREAM = "mizan:l7:events"


def create_app(variant: str = "secure", *, dsn: str | None = None) -> Flask:
    if variant not in {"vulnerable", "secure"}:
        raise ValueError(f"unknown L7 Redis variant {variant!r}")
    app = Flask(__name__)
    app.config["VARIANT"] = variant
    app.config["DSN"] = dsn or os.environ.get("MIZAN_TEST_REDIS_DSN") or ""

    def client() -> Any:
        return redis.Redis.from_url(app.config["DSN"], decode_responses=True, socket_connect_timeout=5)

    def caller() -> str | None:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[7:].strip()
        return next((name for name, value in TOKENS.items() if value == token), None)

    def record(
        connection: Any,
        request_id: str,
        operation: str,
        principal: str,
        artifact_id: str,
        scope: str,
        digest: str,
        granted: bool,
    ) -> None:
        connection.xadd(
            EVENT_STREAM,
            {
                "request_id": request_id,
                "operation": operation,
                "principal": principal,
                "artifact_id": artifact_id,
                "scope": scope,
                "digest": digest,
                "granted": "true" if granted else "false",
                "occurred_at": str(time.time()),
            },
        )

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "variant": variant, "backend": "redis"})

    @app.post("/artifacts")
    def write_artifact():
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        artifact_id, content = body.get("artifact_id"), body.get("content")
        if not isinstance(artifact_id, str) or not isinstance(content, str):
            return jsonify({"error": "invalid"}), 400
        scope = str(body.get("scope", "tenant-a"))
        digest = hashlib.sha256(content.encode()).hexdigest()
        connection = client()
        connection.set(f"mizan:l7:artifact:{artifact_id}", content)
        connection.set(f"mizan:l7:owner:{artifact_id}", principal)
        record(
            connection,
            request.headers.get("X-Mizan-Request-Id", ""),
            "cache_write",
            principal,
            artifact_id,
            scope,
            digest,
            True,
        )
        return jsonify({"artifact_id": artifact_id, "digest": digest, "content": content}), 201

    @app.get("/artifacts/<artifact_id>")
    def read_artifact(artifact_id: str):
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        connection = client()
        key = f"mizan:l7:artifact:{artifact_id}"
        stored = connection.get(key)
        if stored is None:
            return jsonify({"error": "not found"}), 404
        content = str(stored)
        owner = connection.get(f"mizan:l7:owner:{artifact_id}") or principal
        granted = principal == str(owner) or variant == "vulnerable"
        digest = hashlib.sha256(content.encode()).hexdigest()
        record(
            connection,
            request.headers.get("X-Mizan-Request-Id", ""),
            "cache_read",
            principal,
            artifact_id,
            "tenant-a",
            digest,
            bool(granted),
        )
        if not granted:
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"artifact_id": artifact_id, "digest": digest, "content": content})

    @app.post("/messages")
    def publish_message():
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        message_id, content, intended = (
            body.get("message_id"),
            body.get("content"),
            body.get("intended_consumer"),
        )
        if not all(isinstance(item, str) for item in (message_id, content, intended)):
            return jsonify({"error": "invalid"}), 400
        digest = hashlib.sha256(content.encode()).hexdigest()
        connection = client()
        connection.rpush(f"mizan:l7:queue:{message_id}", content)
        connection.set(f"mizan:l7:consumer:{message_id}", intended)
        record(
            connection,
            request.headers.get("X-Mizan-Request-Id", ""),
            "queue_publish",
            principal,
            message_id,
            str(body.get("scope", "tenant-a")),
            digest,
            True,
        )
        return jsonify({"message_id": message_id, "digest": digest}), 201

    @app.post("/messages/<message_id>/consume")
    def consume_message(message_id: str):
        principal = caller()
        if principal is None:
            return jsonify({"error": "unauthorized"}), 401
        connection = client()
        key = f"mizan:l7:queue:{message_id}"
        messages = connection.lrange(key, 0, 0)
        if not messages:
            return jsonify({"error": "not found"}), 404
        content = str(messages[0])
        intended = connection.get(f"mizan:l7:consumer:{message_id}")
        granted = principal == str(intended) or variant == "vulnerable"
        digest = hashlib.sha256(content.encode()).hexdigest()
        record(
            connection,
            request.headers.get("X-Mizan-Request-Id", ""),
            "queue_consume",
            principal,
            message_id,
            "tenant-a",
            digest,
            bool(granted),
        )
        if not granted:
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"message_id": message_id, "digest": digest, "content": content})

    return app


if __name__ == "__main__":  # pragma: no cover - manual helper
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--variant", choices=("vulnerable", "secure"), default="secure")
    args = parser.parse_args()
    create_app(args.variant).run(host="127.0.0.1", port=args.port, threaded=True)
