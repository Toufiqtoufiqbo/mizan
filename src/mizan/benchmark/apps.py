"""The benchmark applications.

One application skeleton, one parameter per injected bug. The same skeleton
without any bug is the *patched* variant, and it must be silent: that is how
Mizan's false-positive rate is measured.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import socketserver

from mizan.taint import WriteEvent
from mizan.tokens import make_token
from mizan.traffic import TrafficRecord, infer_resource, to_template

#: How long the vulnerable approve handler pauses between the check and the
#: write. Every check-then-act bug needs such a window.
RACE_WINDOW_SECONDS = 0.05


@dataclass(frozen=True)
class Bug:
    """A vulnerability the benchmark can inject."""

    kind: str
    law: str
    title: str
    severity: str


BUGS: dict[str, Bug] = {
    "idor_read": Bug("idor_read", "L2", "an object is returned to somebody who does not own it", "high"),
    "idor_write": Bug("idor_write", "L3", "a write lands in a row owned by somebody else", "high"),
    "mass_assignment": Bug("mass_assignment", "L4", "the client can set the role of its own account", "critical"),
    "race": Bug("race", "L5", "two concurrent requests both apply the same transition", "high"),
    "confused_identity": Bug("confused_identity", "L1", "the server acts as a different identity than the token claims", "critical"),
}

#: Bugs that the current engine is expected to detect.
DETECTABLE = tuple(BUGS)


def _encode(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass
class AppSpec:
    """One benchmark application."""

    name: str
    bugs: tuple[str, ...]
    users: tuple[str, ...] = ("alice", "bob", "carol")
    orders: int = 3

    @property
    def expected_laws(self) -> tuple[str, ...]:
        return tuple(sorted({BUGS[bug].law for bug in self.bugs}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "bugs": list(self.bugs),
            "expected_laws": list(self.expected_laws),
            "users": list(self.users),
            "orders": self.orders,
        }


class BenchmarkApp:
    """The application under test.

    ``bugs`` selects the vulnerabilities to inject. An empty set produces the
    fully patched application.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        bugs: tuple[str, ...] | set[str] = (),
        users: tuple[str, ...] = ("alice", "bob", "carol"),
        orders: int = 3,
        traffic_path: str | Path | None = None,
        ledger_path: str | Path | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.bugs = set(bugs)
        self.users = users
        self.order_count = orders
        self.traffic_path = Path(traffic_path) if traffic_path else None
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self._lock = threading.Lock()
        self._counter = 0
        self._init_db()

    # -- helpers ----------------------------------------------------------- #

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        connection = self._connect()
        with connection:
            connection.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, role TEXT)")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, owner_id TEXT, status TEXT, amount INTEGER)"
            )
            connection.execute("CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, user_id TEXT)")
            for user in self.users:
                connection.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", (user, user.title(), "user"))
            connection.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", ("admin", "Admin", "admin"))
            for index in range(self.order_count):
                owner = self.users[index % len(self.users)]
                connection.execute(
                    "INSERT OR IGNORE INTO orders VALUES (?, ?, ?, ?)",
                    (f"ord{index}", owner, "pending", 100 * (index + 1)),
                )
            for user in (*self.users, "admin"):
                token = make_token(user, "admin" if user == "admin" else "user")
                connection.execute("INSERT OR IGNORE INTO tokens VALUES (?, ?)", (token, user))
        connection.close()

    def tokens(self) -> dict[str, str]:
        """Token per user, as the benchmark's clients know them."""
        result = {user: make_token(user, "admin" if user == "admin" else "user") for user in self.users}
        result["admin"] = make_token("admin", "admin")
        return result

    def _resolve(self, token: str) -> str | None:
        """The identity a token acts as - where the identity bug lives."""
        connection = self._connect()
        try:
            row = connection.execute("SELECT user_id FROM tokens WHERE token = ?", (token,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        user = row["user_id"]
        if "confused_identity" in self.bugs and user == "bob":
            # The account was merged, but the token still says "bob".
            return "carol"
        return user

    def _principal(self, environ: dict[str, Any]) -> str | None:
        header = environ.get("HTTP_AUTHORIZATION", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :].strip()
        return self._resolve(token)

    def _next_request_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"req-{self._counter}"

    def _record_write(self, **kwargs: Any) -> None:
        if self.ledger_path is None:
            return
        event = WriteEvent(
            ts=time.time(),
            request_id=kwargs["request_id"],
            principal=kwargs["principal"],
            method=kwargs["method"],
            path=kwargs["path"],
            table=kwargs["table"],
            row_id=kwargs["row_id"],
            columns=kwargs["columns"],
            source_fields=kwargs.get("source_fields", set()),
            row_owner=kwargs.get("row_owner"),
            status=kwargs.get("status", 200),
            method_args={"body": kwargs.get("body")},
        )
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.ledger_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def _record_traffic(self, **kwargs: Any) -> None:
        if self.traffic_path is None:
            return
        template = to_template(kwargs["path"])
        resource_type, resource_id, resource_owner = infer_resource(kwargs["response"], template)
        record = TrafficRecord(
            method=kwargs["method"],
            path=kwargs["path"],
            template=template,
            status=kwargs["status"],
            principal=kwargs["principal"],
            body=kwargs.get("body"),
            response=kwargs["response"],
            resource_type=resource_type,
            resource_id=resource_id,
            resource_owner=resource_owner,
        )
        self.traffic_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.traffic_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

    # -- wsgi --------------------------------------------------------------- #

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        body = self._read_body(environ)
        principal = self._principal(environ)
        request_id = self._next_request_id()
        status, payload = self._route(method, path, body, principal, request_id)
        raw = json.dumps(payload).encode("utf-8")
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(raw)))]
        self._record_traffic(
            method=method, path=path, status=status, principal=principal, body=body, response=payload
        )
        start_response(f"{status} {status_text(status)}", headers)
        return [raw]

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
        if method == "GET" and path == "/me":
            if principal is None:
                return 401, {"error": "unauthenticated"}
            return 200, self._user_payload(principal)
        if method == "PATCH" and path == "/users/me":
            return self._patch_me(body, principal, request_id)
        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "orders" and method == "GET":
            return self._get_order(parts[1], principal)
        if len(parts) == 2 and parts[0] == "orders" and method == "PUT":
            return self._put_order(parts[1], body, principal, request_id)
        if len(parts) == 3 and parts[0] == "orders" and parts[2] == "approve" and method == "POST":
            return self._approve_order(parts[1], principal, request_id)
        return 404, {"error": "not found"}

    # -- handlers ----------------------------------------------------------- #

    def _user_payload(self, user_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute("SELECT id, name, role FROM users WHERE id = ?", (user_id,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return {}
        return {"id": row["id"], "name": row["name"], "role": row["role"], "owner_id": row["id"]}

    def _get_order(self, order_id: str, principal: str | None) -> tuple[int, Any]:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return 404, {"error": "not found"}
        if "idor_read" not in self.bugs:
            # The fix: the owner (or an admin) may read the order.
            if principal is None:
                return 401, {"error": "unauthenticated"}
            if row["owner_id"] != principal and principal != "admin":
                return 403, {"error": "forbidden"}
        return 200, {
            "id": row["id"],
            "owner_id": row["owner_id"],
            "status": row["status"],
            "amount": row["amount"],
        }

    def _put_order(self, order_id: str, body: Any, principal: str | None, request_id: str) -> tuple[int, Any]:
        if principal is None:
            return 401, {"error": "unauthenticated"}
        if not isinstance(body, dict):
            return 400, {"error": "invalid body"}
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
            if row is None:
                return 404, {"error": "not found"}
            if "idor_write" not in self.bugs:
                # The fix: ownership is checked before the write.
                if row["owner_id"] != principal and principal != "admin":
                    return 403, {"error": "forbidden"}
            columns = {
                key: value
                for key, value in body.items()
                if key in {"status", "amount"} and isinstance(value, (str, int, float))
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
        if principal is None:
            return 401, {"error": "unauthenticated"}
        if not isinstance(body, dict):
            return 400, {"error": "invalid body"}
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (principal,)).fetchone()
            if row is None:
                return 404, {"error": "not found"}
            allowed = {"name"}
            if "mass_assignment" in self.bugs:
                # The bug: the client decides its own role.
                allowed.add("role")
            columns = {
                key: value for key, value in body.items() if key in allowed and isinstance(value, (str, int, float))
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
        if principal is None:
            return 401, {"error": "unauthenticated"}
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
            if row is None:
                return 404, {"error": "not found"}
            if row["owner_id"] != principal and principal != "admin":
                return 403, {"error": "forbidden"}
            if "race" in self.bugs:
                # The bug: the check and the write are not atomic.
                if row["status"] != "pending":
                    return 409, {"error": "order is not pending"}
                time.sleep(RACE_WINDOW_SECONDS)
                with self._lock:
                    connection.execute("UPDATE orders SET status = 'approved' WHERE id = ?", (order_id,))
                    connection.commit()
            else:
                # The fix: one atomic statement, and only one winner.
                with self._lock:
                    cursor = connection.execute(
                        "UPDATE orders SET status = 'approved' WHERE id = ? AND status = 'pending'",
                        (order_id,),
                    )
                    connection.commit()
                    if cursor.rowcount != 1:
                        return 409, {"error": "order is not pending"}
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
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        500: "Internal Server Error",
    }.get(status, "Unknown")


class ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        pass


def serve(app: BenchmarkApp, host: str = "127.0.0.1", port: int = 0) -> tuple[WSGIServer, int, threading.Thread]:
    """Start an application in a background thread."""
    server = make_server(host, port, app, server_class=ThreadingWSGIServer, handler_class=_QuietHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port, thread
