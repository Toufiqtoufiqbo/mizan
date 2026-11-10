"""A deliberately vulnerable API used as Mizan's test bed.

The bugs are the ones Mizan is built to find:

* ``GET  /orders/{id}``      - no ownership check      (L2: IDOR read)
* ``PUT  /orders/{id}``      - no ownership check      (L3: IDOR write)
* ``PATCH /users/me``        - trusts the client body  (L4: mass assignment)
* ``POST /orders/{id}/approve`` - check-then-act        (L5: TOCTOU race)

It uses nothing but the standard library, so it runs anywhere.
"""

from __future__ import annotations

import json
import re
import socketserver
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from mizan.taint import WriteEvent
from mizan.traffic import TrafficRecord, infer_resource, to_template

SEED_USERS = [
    ("alice", "Alice", "user", "alice-secret"),
    ("bob", "Bob", "user", "bob-secret"),
    ("root", "Root", "admin", "root-secret"),
]
SEED_ORDERS = [
    ("o1", "alice", "pending", 100),
    ("o2", "bob", "pending", 200),
    ("o3", "alice", "pending", 300),
]
SEED_TOKENS = [
    ("tok-alice", "alice"),
    ("tok-bob", "bob"),
    ("tok-admin", "root"),
]

#: How long the approve handler pauses between the check and the write. A real
#: application has such a window whenever a database round-trip or an HTTP call
#: to another service sits between "is this allowed?" and "do it".
APPROVE_WINDOW_SECONDS = 0.05


class DemoApp:
    """The vulnerable application."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        ledger_path: str | Path | None = None,
        traffic_path: str | Path | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self.traffic_path = Path(traffic_path) if traffic_path else None
        self._lock = threading.Lock()
        self._request_counter = 0
        self._init_db()

    # -- database ---------------------------------------------------------- #

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        connection = self._connect()
        with connection:
            connection.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, role TEXT, password TEXT)")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, owner_id TEXT, status TEXT, amount INTEGER)"
            )
            connection.execute("CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, user_id TEXT)")
            for user in SEED_USERS:
                connection.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?)", user)
            for order in SEED_ORDERS:
                connection.execute("INSERT OR IGNORE INTO orders VALUES (?, ?, ?, ?)", order)
            for token in SEED_TOKENS:
                connection.execute("INSERT OR IGNORE INTO tokens VALUES (?, ?)", token)
        connection.close()

    # -- helpers ----------------------------------------------------------- #

    def _principal(self, environ: dict[str, Any]) -> str | None:
        header = environ.get("HTTP_AUTHORIZATION", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :].strip()
        connection = self._connect()
        try:
            row = connection.execute("SELECT user_id FROM tokens WHERE token = ?", (token,)).fetchone()
        finally:
            connection.close()
        return row["user_id"] if row else None

    def _next_request_id(self) -> str:
        with self._lock:
            self._request_counter += 1
            return f"req-{self._request_counter}"

    def _record_write(
        self,
        *,
        request_id: str,
        principal: str,
        method: str,
        path: str,
        table: str,
        row_id: str,
        columns: dict[str, Any],
        source_fields: set[str],
        row_owner: str | None,
        status: int = 200,
        body: Any = None,
    ) -> None:
        if self.ledger_path is None:
            return
        event = WriteEvent(
            ts=time.time(),
            request_id=request_id,
            principal=principal,
            method=method,
            path=path,
            table=table,
            row_id=row_id,
            columns=columns,
            source_fields=source_fields,
            row_owner=row_owner,
            status=status,
            method_args={"body": body},
        )
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.ledger_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def _record_traffic(
        self,
        *,
        method: str,
        path: str,
        status: int,
        principal: str | None,
        body: Any,
        response: Any,
    ) -> None:
        if self.traffic_path is None:
            return
        template = to_template(path)
        resource_type, resource_id, resource_owner = infer_resource(response, template)
        record = TrafficRecord(
            method=method,
            path=path,
            template=template,
            status=status,
            principal=principal,
            body=body,
            response=response,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_owner=resource_owner,
        )
        self.traffic_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.traffic_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

    # -- wsgi -------------------------------------------------------------- #

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        body = self._read_body(environ)
        principal = self._principal(environ)
        request_id = self._next_request_id()

        status, payload = self._route(method, path, body, principal, request_id)
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body_bytes)))]
        self._record_traffic(method=method, path=path, status=status, principal=principal, body=body, response=payload)
        start_response(f"{status} {status_text(status)}", headers)
        return [body_bytes]

    def _read_body(self, environ: dict[str, Any]) -> Any:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if not length:
            return None
        raw = environ["wsgi.input"].read(length)
        try:
            return json.loads(raw)
        except Exception:
            return None

    def _route(self, method: str, path: str, body: Any, principal: str | None, request_id: str) -> tuple[int, Any]:
        if method == "POST" and path == "/login":
            return self._login(body)
        if method == "GET" and path == "/me":
            if principal is None:
                return 401, {"error": "unauthenticated"}
            return 200, self._user_payload(principal)
        if method == "PATCH" and path == "/users/me":
            return self._patch_me(body, principal, request_id)
        order_match = re.match(r"^/orders/([^/]+)$", path)
        if order_match and method == "GET":
            return self._get_order(order_match.group(1))
        if order_match and method == "PUT":
            return self._put_order(order_match.group(1), body, principal, request_id)
        approve_match = re.match(r"^/orders/([^/]+)/approve$", path)
        if approve_match and method == "POST":
            return self._approve_order(approve_match.group(1), principal, request_id)
        return 404, {"error": "not found"}

    # -- handlers ---------------------------------------------------------- #

    def _login(self, body: Any) -> tuple[int, Any]:
        if not isinstance(body, dict):
            return 400, {"error": "invalid body"}
        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return 400, {"error": "invalid body"}
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT id FROM users WHERE id = ? AND password = ?",
                (username, password),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return 401, {"error": "invalid credentials"}
        token = next(token for token, user in SEED_TOKENS if user == row["id"])
        return 200, {"token": token, "user_id": row["id"]}

    def _user_payload(self, user_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute("SELECT id, name, role FROM users WHERE id = ?", (user_id,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return {}
        return {"id": row["id"], "name": row["name"], "role": row["role"], "owner_id": row["id"]}

    def _get_order(self, order_id: str) -> tuple[int, Any]:
        # BUG (L2): the owner is never checked.
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return 404, {"error": "not found"}
        return 200, {
            "id": row["id"],
            "owner_id": row["owner_id"],
            "status": row["status"],
            "amount": row["amount"],
        }

    def _put_order(self, order_id: str, body: Any, principal: str | None, request_id: str) -> tuple[int, Any]:
        # BUG (L3): the owner is never checked, so anybody may edit anybody's order.
        if principal is None:
            return 401, {"error": "unauthenticated"}
        if not isinstance(body, dict):
            return 400, {"error": "invalid body"}
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
            if row is None:
                return 404, {"error": "not found"}
            allowed = {"status", "amount"}
            columns = {
                key: value for key, value in body.items() if key in allowed and isinstance(value, (str, int, float))
            }
            with self._lock:
                connection.execute(
                    "UPDATE orders SET status = ?, amount = ? WHERE id = ?",
                    (columns.get("status", row["status"]), columns.get("amount", row["amount"]), order_id),
                )
                connection.commit()
        finally:
            connection.close()
        self._record_write(
            request_id=request_id,
            principal=principal,
            method="PUT",
            path=f"/orders/{order_id}",
            table="orders",
            row_id=order_id,
            columns=columns,
            source_fields=set(body.keys()),
            row_owner=row["owner_id"],
            body=body,
        )
        return 200, {"id": order_id, "status": columns.get("status", row["status"]), "owner_id": row["owner_id"]}

    def _patch_me(self, body: Any, principal: str | None, request_id: str) -> tuple[int, Any]:
        # BUG (L4): every field the client sends is written, including `role`.
        if principal is None:
            return 401, {"error": "unauthenticated"}
        if not isinstance(body, dict):
            return 400, {"error": "invalid body"}
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (principal,)).fetchone()
            if row is None:
                return 404, {"error": "not found"}
            columns = {
                key: value
                for key, value in body.items()
                if key in {"name", "email", "role"} and isinstance(value, (str, int, float))
            }
            with self._lock:
                connection.execute(
                    "UPDATE users SET name = ?, role = ? WHERE id = ?",
                    (columns.get("name", row["name"]), columns.get("role", row["role"]), principal),
                )
                connection.commit()
        finally:
            connection.close()
        self._record_write(
            request_id=request_id,
            principal=principal,
            method="PATCH",
            path="/users/me",
            table="users",
            row_id=principal,
            columns=columns,
            source_fields=set(body.keys()),
            row_owner=principal,
            body=body,
        )
        return 200, self._user_payload(principal)

    def _approve_order(self, order_id: str, principal: str | None, request_id: str) -> tuple[int, Any]:
        # BUG (L5): the check and the write are not atomic.
        if principal is None:
            return 401, {"error": "unauthenticated"}
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
            if row is None:
                return 404, {"error": "not found"}
            if row["status"] != "pending":
                return 409, {"error": "order is not pending"}
            # The window every check-then-act bug needs.
            time.sleep(APPROVE_WINDOW_SECONDS)
            with self._lock:
                connection.execute("UPDATE orders SET status = 'approved' WHERE id = ?", (order_id,))
                connection.commit()
        finally:
            connection.close()
        self._record_write(
            request_id=request_id,
            principal=principal,
            method="POST",
            path=f"/orders/{order_id}/approve",
            table="orders",
            row_id=order_id,
            columns={"status": "approved"},
            source_fields=set(),
            row_owner=row["owner_id"],
        )
        return 200, {"id": order_id, "status": "approved", "owner_id": row["owner_id"]}


def status_text(status: int) -> str:
    return {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        409: "Conflict",
        500: "Internal Server Error",
    }.get(status, "Unknown")


class ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
    """A threading server - otherwise two concurrent requests cannot overlap."""

    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        pass


def serve(app: DemoApp, host: str = "127.0.0.1", port: int = 0) -> tuple[WSGIServer, int, threading.Thread]:
    """Start the demo API in a background thread."""
    server = make_server(host, port, app, server_class=ThreadingWSGIServer, handler_class=_QuietHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port, thread
