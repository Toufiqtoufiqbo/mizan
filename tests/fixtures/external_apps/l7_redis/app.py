"""Independent L7 fixture application backed by a real Redis server.

The application performs the queue-visibility and cache operations itself
(``LPUSH``/``LRANGE`` and ``SET``/``GET``) and records its own operations in a
Redis stream with the inbound ``X-Mizan-Request-Id``. Mīzān only reads that
stream with XRANGE; it never writes content or events.

Every key is prefixed by the test-owned namespace from
``MIZAN_REDIS_NAMESPACE``. There is no database-wide deletion anywhere here.

Two variants: ``vulnerable`` lets Bob read Alice's data, ``secure`` does not
while Alice still can. Missing ownership metadata never grants access in the
secure variant.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

import redis
from flask import Flask, jsonify, request

TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}


def create_app(variant: str = "secure", *, dsn: str | None = None, namespace: str | None = None) -> Flask:
    if variant not in {"vulnerable", "secure"}:
        raise ValueError(f"unknown L7 Redis variant {variant!r}")
    app = Flask(__name__)
    app.config["VARIANT"] = variant
    app.config["DSN"] = dsn or os.environ.get("MIZAN_TEST_REDIS_DSN") or ""
    prefix = namespace or os.environ.get("MIZAN_REDIS_NAMESPACE") or "mizan:l7"
    app.config["PREFIX"] = prefix

    def key(part: str) -> str:
        return f"{prefix}:{part}"

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
            key("events"),
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
        # Content and ownership are written together: content without an owner
        # is never a valid artifact.
        pipeline = connection.pipeline(transaction=True)
        pipeline.set(key(f"artifact:{artifact_id}"), content)
        pipeline.set(key(f"owner:{artifact_id}"), principal)
        pipeline.execute()
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
        stored = connection.get(key(f"artifact:{artifact_id}"))
        if stored is None:
            return jsonify({"error": "not found"}), 404
        content = str(stored)
        owner = connection.get(key(f"owner:{artifact_id}"))
        # Fail closed: never promote the caller to owner when metadata is gone.
        # Only the deliberately vulnerable variant ignores authorization.
        granted = variant == "vulnerable" or (owner is not None and principal == str(owner))
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
        pipeline = connection.pipeline(transaction=True)
        # LPUSH + LRANGE is a queue *visibility* read, not a destructive pop.
        pipeline.rpush(key(f"queue:{message_id}"), content)
        pipeline.set(key(f"consumer:{message_id}"), intended)
        pipeline.execute()
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
        messages = connection.lrange(key(f"queue:{message_id}"), 0, 0)
        if not messages:
            return jsonify({"error": "not found"}), 404
        content = str(messages[0])
        intended = connection.get(key(f"consumer:{message_id}"))
        granted = variant == "vulnerable" or (intended is not None and principal == str(intended))
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
