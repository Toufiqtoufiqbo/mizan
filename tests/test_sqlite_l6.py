"""Generic/SQLite L6: declared bounds verified from real database state."""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import uuid
from pathlib import Path

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from mizan.attribution import SqliteAttributor
from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.ownership import RelationshipContract
from mizan.tokens import make_token
from mizan.traffic import TrafficRecord

TOKENS = {"alice": make_token("alice"), "bob": make_token("bob")}


def _app(db: Path, secure: bool) -> Flask:
    app = Flask(__name__)

    def caller():
        from mizan.identity import decode_token

        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        claims = decode_token(header[7:])
        return claims.subject if claims else None

    @app.post("/items")
    def create_item():
        principal = caller()
        if not principal:
            return jsonify({"error": "unauthorized"}), 401
        connection = sqlite3.connect(db)
        count = connection.execute("SELECT count(*) FROM items WHERE owner_id = ?", (principal,)).fetchone()[0]
        if secure and count >= 2:
            connection.close()
            return jsonify({"error": "quota"}), 409
        item_id = f"item-{uuid.uuid4().hex[:8]}"
        connection.execute(
            "INSERT INTO items (item_ref, owner_id, label) VALUES (?,?,?)", (item_id, principal, "mizan")
        )
        connection.commit()
        connection.close()
        return jsonify({"item_ref": item_id, "label": "mizan", "owner_id": principal}), 201

    @app.post("/capabilities/<code>/consume")
    def consume(code: str):
        principal = caller()
        if not principal:
            return jsonify({"error": "unauthorized"}), 401
        connection = sqlite3.connect(db)
        row = connection.execute("SELECT owner_id, consumed_at FROM capabilities WHERE code = ?", (code,)).fetchone()
        if row is None or row[0] != principal:
            connection.close()
            return jsonify({"error": "not found"}), 404
        if row[1] is not None and secure:
            connection.close()
            return jsonify({"error": "already used"}), 409
        connection.execute("UPDATE capabilities SET consumed_at = ? WHERE code = ?", (time.time(), code))
        connection.commit()
        connection.close()
        return jsonify({"code": code, "consumed": True})

    return app


def _contract() -> RelationshipContract:
    return RelationshipContract.from_dict(
        {
            "version": 1,
            "identity": {"endpoint": "/whoami", "field": "id"},
            "ownership": {
                "items": {"source": "database_foreign_key", "column": "owner_id", "table": "items"},
                "capabilities": {
                    "source": "database_foreign_key",
                    "column": "owner_id",
                    "table": "capabilities",
                },
            },
            "cardinality": [
                {
                    "resource_type": "items",
                    "bound": 2,
                    "scope": "principal",
                    "unit": "objects",
                    "source": "trusted_contract",
                    "enforcement": "reject_beyond",
                    "table": "items",
                },
                {
                    "resource_type": "capabilities",
                    "bound": 1,
                    "scope": "principal",
                    "unit": "uses",
                    "source": "trusted_contract",
                    "enforcement": "single_use",
                    "table": "capabilities",
                },
            ],
        },
        strict=True,
    )


def _engine(port: int, db: Path) -> Mizan:
    engine = Mizan(
        Target(
            base_url=f"http://127.0.0.1:{port}",
            principals=[Principal(id=name, token=token, roles=("user",)) for name, token in TOKENS.items()],
        ),
        attributor=SqliteAttributor(db),
        relationship_contract=_contract(),
    )
    engine.traffic.records = [
        TrafficRecord(
            method="POST",
            path="/items",
            status=201,
            principal="alice",
            body={"label": "mizan"},
            response={"item_ref": "seed", "owner_id": "alice"},
            resource_type="items",
            resource_id="seed",
        ),
        TrafficRecord(
            method="POST",
            path="/capabilities/cap-alice/consume",
            status=200,
            principal="alice",
            response={"code": "cap-alice"},
            resource_type="capabilities",
            resource_id="cap-alice",
        ),
    ]
    engine.learn()
    return engine


@pytest.mark.parametrize("secure,expected", [(False, 1), (True, 0)])
def test_sqlite_l6_collection_bound(secure, expected) -> None:
    db = Path(tempfile.mkdtemp()) / "app.sqlite"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE items (item_ref TEXT PRIMARY KEY, owner_id TEXT, label TEXT)")
    connection.execute("CREATE TABLE capabilities (code TEXT PRIMARY KEY, owner_id TEXT, consumed_at REAL)")
    connection.execute("INSERT INTO items VALUES ('seed','alice','mizan')")
    connection.execute("INSERT INTO capabilities VALUES ('cap-alice','alice',NULL)")
    connection.commit()
    connection.close()
    server = make_server("127.0.0.1", 0, _app(db, secure))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        engine = _engine(server.server_port, db)
        violations = [item for item in engine.attack(groups=["L6"]) if item.law == "L6"]
        assert len(violations) >= expected
        if expected:
            assert any(item.evidence["invariant"]["enforcement"] == "reject_beyond" for item in violations)
        assert engine.executed_by_law.get("L6") == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)
