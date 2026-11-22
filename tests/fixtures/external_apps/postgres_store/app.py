"""Independent PostgreSQL fixture for Phase VI.

Knows nothing about Mīzān: no imports, no helper calls, no shared code. It owns
its authentication, its request context and its PostgreSQL schema. The scan
proxy only sends HTTP requests with an optional per-request correlation header.

Environment:
  MIZAN_PG_DSN          - a PostgreSQL the fixture may use (CI uses a disposable DB)
  MIZAN_PG_SCHEMA       - schema the fixture owns (default: pgstore)
  MIZAN_PG_POOL_SIZE    - reuse this many connections (default: 0, one per request)
  MIZAN_PG_POOL_LEAK    - if set, deliberately do not close pooled connections

The stable session identity is the ``application_name`` in the DSN. The person
a request acts for is the transaction-local setting ``mizan.principal``; the
two are deliberately separate.

Variants:
  clean            - owner-only reads and writes
  read             - any authenticated principal may read an item
  write            - any authenticated principal may write an item
  both             - any authenticated principal may read AND write an item
  grant_read       - collaborator may read, never write
  grant_write      - collaborator may read AND write (unauthorized write)
  unknown          - item has no ownership signal at all
  composite        - items are identified by (tenant_ref, item_ref)

Concurrency endpoint (independent of Mīzān):
  POST /__barrier   - block until ``parties`` requests have arrived. A test can
                      use it to prove that several worker processes were alive
                      at the same instant. It is deliberately absent from the
                      OpenAPI document so the learning phase never sees it.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import os
import queue
import secrets
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
from flask import Flask, jsonify, request

USERS = (("alice", "Alice"), ("bob", "Bob"))
VARIANTS = (
    "clean",
    "read",
    "write",
    "both",
    "grant_read",
    "grant_write",
    "unknown",
    "composite",
)

#: Independent request rendezvous used only by concurrency tests.
_BARRIERS: dict[str, tuple[threading.Barrier, int]] = {}
_BARRIER_LOCK = threading.Lock()


def _dsn() -> str:
    return os.environ.get("MIZAN_PG_DSN") or os.environ.get("MIZAN_TEST_POSTGRES_DSN") or ""


def _schema() -> str:
    return os.environ.get("MIZAN_PG_SCHEMA", "pgstore")


def _pool_size() -> int:
    try:
        return max(0, int(os.environ.get("MIZAN_PG_POOL_SIZE", "0") or 0))
    except ValueError:
        return 0


def _quote(name: str) -> str:
    if not name or "\x00" in name:
        raise ValueError("invalid identifier")
    return '"' + name.replace('"', '""') + '"'


class ConnectionPool:
    """A small, realistic pool: pre-created idle connections and reuse.

    ``shutdown`` is observable: after it returns, every connection the pool
    owned is closed. ``leak`` intentionally leaves them open so a test can
    prove that cleanup refuses to drop a database that still has sessions.
    """

    def __init__(self, dsn: str, size: int) -> None:
        self.dsn = dsn
        self.size = size
        self._lock = threading.Lock()
        self._idle: queue.LifoQueue[Any] = queue.LifoQueue()
        self._owned: list[Any] = []
        self._closed = False
        self.created = 0
        self.active = 0
        for _ in range(size):
            self._add(psycopg.connect(dsn, connect_timeout=5))

    def _add(self, connection: Any) -> None:
        self._owned.append(connection)
        self.created += 1
        self._idle.put(connection)

    def _new(self) -> Any:
        connection = psycopg.connect(self.dsn, connect_timeout=5)
        with self._lock:
            self._owned.append(connection)
            self.created += 1
        return connection

    @contextlib.contextmanager
    def connection(self) -> Iterator[Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("the connection pool is closed")
            self.active += 1
        connection = None
        try:
            try:
                connection = self._idle.get_nowait()
            except queue.Empty:
                connection = self._new()
            if connection.closed:
                connection = self._new()
            yield connection
        finally:
            if connection is not None and not connection.closed:
                # Never return a pooled connection inside a failed or open
                # transaction: SET LOCAL state must not leak to the next user.
                with contextlib.suppress(Exception):
                    connection.rollback()
                self._idle.put(connection)
            with self._lock:
                self.active -= 1

    def shutdown(self, *, leak: bool = False) -> list[Any]:
        with self._lock:
            self._closed = True
            owned = list(self._owned)
            self._owned.clear()
        if leak:
            return owned
        for connection in owned:
            with contextlib.suppress(Exception):
                connection.close()
        with contextlib.suppress(Exception):
            while True:
                self._idle.get_nowait()
        return []


def create_app(variant: str = "clean", *, dsn: str | None = None, schema: str | None = None) -> Flask:
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}")
    app = Flask(__name__)
    app.config["PG_DSN"] = dsn or _dsn()
    app.config["PG_SCHEMA"] = schema or _schema()
    app.config["VARIANT"] = variant
    app.config["POOL_SIZE"] = _pool_size()
    app.config["POOL_LEAK"] = bool(os.environ.get("MIZAN_PG_POOL_LEAK"))
    app.config["POOL"] = None
    app.config["LEAKED_CONNECTIONS"] = []

    def q(name: str) -> str:
        return f"{_quote(app.config['PG_SCHEMA'])}.{_quote(name)}"

    def direct() -> psycopg.Connection:
        return psycopg.connect(app.config["PG_DSN"] or None, connect_timeout=5)

    @contextlib.contextmanager
    def connect() -> Iterator[psycopg.Connection]:
        pool = app.config["POOL"]
        if pool is None:
            connection = direct()
            try:
                yield connection
            finally:
                connection.close()
            return
        with pool.connection() as connection:
            yield connection

    def context(connection: psycopg.Connection, principal: str | None) -> None:
        """Transaction-local identity and request correlation (never authorization)."""
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('mizan.principal', %s, true)", (principal or "",))
            correlation = request.headers.get("X-Mizan-Request-Id", "")
            cursor.execute("SELECT set_config('mizan.request_id', %s, true)", (correlation,))

    def initialise() -> None:
        with connect() as connection:
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
                        "ON CONFLICT (opaque) DO NOTHING",
                        (env_token, "alice", time.time()),
                    )
                env_token = os.environ.get("MIZAN_TOKEN_BOB")
                if env_token:
                    cursor.execute(
                        f"INSERT INTO {q('auth_tokens')} (opaque, p_ref, issued_at) VALUES (%s, %s, %s) "
                        "ON CONFLICT (opaque) DO NOTHING",
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

    initialise()

    if app.config["POOL_SIZE"]:
        pool = ConnectionPool(app.config["PG_DSN"], app.config["POOL_SIZE"])
        app.config["POOL"] = pool
        atexit.register(lambda: app.config["LEAKED_CONNECTIONS"].extend(pool.shutdown(leak=app.config["POOL_LEAK"])))

    def caller() -> str | None:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :].strip()
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT p_ref FROM {q('auth_tokens')} WHERE opaque = %s", (token,))
                row = cursor.fetchone()
            return str(row[0]) if row else None

    @app.get("/health")
    def health():
        pool = app.config["POOL"]
        return jsonify(
            {
                "status": "ok",
                "pool": None if pool is None else {"size": pool.size, "created": pool.created, "active": pool.active},
            }
        )

    @app.get("/pool")
    def pool_status():
        pool = app.config["POOL"]
        if pool is None:
            return jsonify({"enabled": False})
        return jsonify(
            {
                "enabled": True,
                "size": pool.size,
                "created": pool.created,
                "active": pool.active,
                "idle": pool._idle.qsize(),
                "closed": pool._closed,
                "leaked": len(app.config["LEAKED_CONNECTIONS"]),
                "leak": app.config["POOL_LEAK"],
            }
        )

    @app.post("/pool/shutdown")
    def pool_shutdown():
        pool = app.config["POOL"]
        if pool is None:
            return jsonify({"enabled": False})
        leak = bool(request.args.get("leak")) or app.config["POOL_LEAK"]
        app.config["LEAKED_CONNECTIONS"].extend(pool.shutdown(leak=leak))
        return jsonify({"enabled": True, "closed": pool._closed, "leak": leak})

    @app.post("/pool/release")
    def pool_release():
        leaked = app.config["LEAKED_CONNECTIONS"]
        count = len(leaked)
        for connection in leaked:
            with contextlib.suppress(Exception):
                connection.close()
        leaked.clear()
        return jsonify({"released": count})

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        key = body.get("username", body.get("principal"))
        secret = body.get("password", body.get("passcode"))
        if key not in dict(USERS) or secret != f"{key}-secret":
            return jsonify({"error": "invalid"}), 401
        token = secrets.token_urlsafe(32)
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"INSERT INTO {q('auth_tokens')} (opaque, p_ref, issued_at) VALUES (%s,%s,%s)",
                    (token, key, time.time()),
                )
            connection.commit()
        return jsonify({"token": token})

    @app.get("/whoami")
    def whoami():
        key = caller()
        return jsonify({"p_key": key, "label": f"Label of {key}"}) if key else (jsonify({"error": "unauthorized"}), 401)

    def item_json(row: Any) -> dict[str, Any]:
        # The owner is part of the application's real response, not a hint
        # injected by Mīzān. Learning therefore sees a genuine ownership signal.
        return {"item_ref": row[0], "label": row[1], "owner_id": row[2]}

    def load_item(item_ref: str):
        with connect() as connection:
            with connection.cursor() as cursor:
                context(connection, None)
                cursor.execute(
                    f"SELECT item_ref, label, originator_ref FROM {q('inventory_items')} WHERE item_ref = %s",
                    (item_ref,),
                )
                return cursor.fetchone()

    def may(key: str, row: Any, *, write: bool) -> bool:
        owner = row[2]
        if owner == key:
            return True
        mode = app.config["VARIANT"]
        if write:
            return mode in {"write", "both"} or (mode == "grant_write" and key == "bob")
        return mode in {"read", "both", "grant_read", "grant_write"} and key == "bob"

    @app.get("/items")
    def list_items():
        key = caller()
        if not key:
            return jsonify({"error": "unauthorized"}), 401
        with connect() as connection:
            with connection.cursor() as cursor:
                context(connection, key)
                cursor.execute(f"SELECT item_ref, label, originator_ref FROM {q('inventory_items')} ORDER BY item_ref")
                return jsonify([item_json(row) for row in cursor.fetchall()])

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
        with connect() as connection:
            with connection.cursor() as cursor:
                context(connection, key)
                cursor.execute(f"UPDATE {q('inventory_items')} SET label = %s WHERE item_ref = %s", (label, item_ref))
            connection.commit()
        return jsonify({"item_ref": item_ref, "label": label, "owner_id": row[2]})

    @app.post("/__barrier")
    def barrier():
        """Wait until ``parties`` requests have arrived (across processes).

        With ``MIZAN_FIXTURE_RENDEZVOUS_DIR`` set, arrival markers are files in
        that shared directory. This is how several independent worker processes
        can rendezvous; each one has its own interpreter and its own memory.
        Without it, the in-process barrier serves single-process callers.
        """
        body = request.get_json(silent=True) or {}
        key = str(body.get("id", "default"))
        parties = max(1, min(32, int(body.get("parties", 2))))
        timeout = max(0.1, min(60.0, float(body.get("timeout", 10.0))))
        directory = os.environ.get("MIZAN_FIXTURE_RENDEZVOUS_DIR")
        if directory:
            root = Path(directory) / key
            root.mkdir(parents=True, exist_ok=True)
            (root / f"{os.getpid()}-{threading.get_ident()}").write_text("arrived", encoding="utf-8")
            deadline = time.time() + timeout
            while time.time() < deadline:
                if len(list(root.glob("*"))) >= parties:
                    return jsonify({"id": key, "parties": parties, "mode": "filesystem"})
                time.sleep(0.05)
            return jsonify({"error": "barrier timeout", "id": key}), 408
        with _BARRIER_LOCK:
            entry = _BARRIERS.get(key)
            if entry is None or entry[1] != parties or entry[0].broken:
                entry = (threading.Barrier(parties), parties)
                _BARRIERS[key] = entry
        try:
            entry[0].wait(timeout=timeout)
        except threading.BrokenBarrierError:
            return jsonify({"error": "barrier timeout", "id": key}), 408
        return jsonify({"id": key, "parties": parties})

    @app.get("/pairs")
    def list_pairs():
        key = caller()
        if not key:
            return jsonify({"error": "unauthorized"}), 401
        with connect() as connection:
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
