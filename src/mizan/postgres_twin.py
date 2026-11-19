"""Disposable PostgreSQL Twin lifecycle (Phase VI.2 hardened).

This module owns database creation, restoration, server-verified ownership and
cleanup for PostgreSQL attack experiments. The source database is never a
target and the code never falls back to a weaker execution path.

Lifecycle:

    CREATED → INITIALIZED → READY → RUNNING → RESTORING → VERIFIED → CLEANED

Any mandatory failure moves the object to ``FAILED`` and disables execution.

Security boundary
-----------------

A local JSON record never authorizes deletion. Every database this module
creates carries a server-side marker in its database comment (run id, kind,
worker id, source database, cluster identity, owner role and a random nonce).
Deletion requires the local record, the marker and the live catalog to agree.
All identifiers are composed with :mod:`psycopg.sql` (never interpolated).

The cluster identity comes from ``pg_control_system().system_identifier``. If
the role cannot read it, baseline preparation and cleanup fail closed instead
of trusting the local registry.
"""

from __future__ import annotations

import contextlib
import datetime
import decimal
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from mizan.twin import Twin, TwinSpec, free_port

#: A run id is the 12-hex-character prefix of a random UUID.
RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")

#: Worker ids are short, lowercase and shell-free.
WORKER_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

#: A nonce is 16 random bytes in hexadecimal.
NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")

#: Every generated database name starts with this prefix.
DATABASE_PREFIX = "mizan_v61"

#: The only kinds of database this module owns.
DATABASE_KINDS = ("seed", "worker")

#: The marker schema version written into the database comment.
MARKER_VERSION = 1

#: A client-controlled label for application sessions. It is NOT a credential:
#: no backend is terminated or trusted because it carries this value.
APP_SESSION_PREFIX = "mizan:"

#: Mīzān's own control connections never share the application identity.
CONTROL_SESSION_PREFIX = "mizan-control:"

#: A backend label is metadata, never a credential. Backends are never
#: terminated because of this label; they must disconnect on their own.
SESSION_DRAIN_SECONDS = 5.0
PREFLIGHT_SESSION_SECONDS = 1.0

#: Namespace for run-level advisory locks. Kept small so a 48-bit run id can
#: be combined into one signed 64-bit key (the two-integer form is 32-bit).
RUN_LOCK_NAMESPACE = 0x4D5A
RUN_LOCK_TIMEOUT_SECONDS = 10.0

#: Objects installed by ``PostgresAuditor`` and therefore excluded from the
#: application fingerprint (they are verified separately).
AUDIT_TABLE_NAME = "mizan_write_audit"
AUDIT_SEQUENCE_NAME = "mizan_write_audit_id_seq"
AUDIT_FUNCTION_NAME = "mizan_write_audit_fn"
AUDIT_INDEX_NAME = "mizan_write_audit_time_idx"
AUDIT_TRIGGER_PREFIX = "mizan_write_audit_trg_"


class TwinState(StrEnum):
    CREATED = "CREATED"
    INITIALIZED = "INITIALIZED"
    READY = "READY"
    RUNNING = "RUNNING"
    RESTORING = "RESTORING"
    VERIFIED = "VERIFIED"
    CLEANED = "CLEANED"
    FAILED = "FAILED"


_ALLOWED_TRANSITIONS: dict[TwinState, set[TwinState]] = {
    TwinState.CREATED: {TwinState.INITIALIZED, TwinState.CLEANED, TwinState.FAILED},
    TwinState.INITIALIZED: {TwinState.READY, TwinState.FAILED},
    TwinState.READY: {TwinState.RUNNING, TwinState.RESTORING, TwinState.CLEANED, TwinState.FAILED},
    TwinState.RUNNING: {TwinState.RESTORING, TwinState.CLEANED, TwinState.FAILED},
    TwinState.RESTORING: {TwinState.VERIFIED, TwinState.FAILED},
    TwinState.VERIFIED: {TwinState.READY, TwinState.CLEANED, TwinState.FAILED},
    TwinState.CLEANED: set(),
    TwinState.FAILED: {TwinState.CLEANED},
}


class TwinLifecycleError(RuntimeError):
    """An invalid or failed lifecycle transition."""


class SourceProtectionError(TwinLifecycleError):
    """An operation would target the source or an unowned database."""


class OwnershipError(SourceProtectionError):
    """Ownership evidence is missing, malformed or inconsistent."""


class BaselineVerificationError(TwinLifecycleError):
    """The restored database does not match the verified baseline."""


class CleanupError(TwinLifecycleError):
    """A destructive operation could not be performed safely."""


class CleanupPreflightError(OwnershipError):
    """Whole-run ownership preflight failed; zero databases may be deleted."""

    def __init__(self, reasons: list[str], *, categories: dict[str, str] | None = None) -> None:
        self.reasons = list(reasons)
        self.categories = dict(categories or {})
        super().__init__("cleanup preflight failed: " + "; ".join(self.reasons))


class PartialCleanupError(CleanupError):
    """Some databases were deleted before an operational failure stopped the run."""

    def __init__(self, cleaned: list[str], remaining: list[str], reasons: list[str]) -> None:
        self.cleaned = list(cleaned)
        self.remaining = list(remaining)
        self.reasons = list(reasons)
        super().__init__(
            f"partial cleanup: {len(self.cleaned)} deleted, {len(self.remaining)} remaining; " + "; ".join(self.reasons)
        )


class RunInterrupted(TwinLifecycleError):
    """A cancellation signal stopped the run before it completed."""


class CancellationToken:
    """Translate SIGINT/SIGTERM/SIGBREAK into a checked, catchable condition.

    The handler raises on delivery so a blocked subprocess or probe returns to
    the caller, which performs the same cleanup path as any other failure.
    """

    def __init__(self) -> None:
        self.signal_number: int | None = None
        self._previous: dict[int, Any] = {}

    def _handle(self, signum: int, _frame: Any) -> None:
        self.signal_number = int(signum)
        raise RunInterrupted(f"the run was interrupted by signal {signum}")

    def install(self) -> None:
        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            number = getattr(signal, name, None)
            if number is None:
                continue
            try:
                self._previous[number] = signal.getsignal(number)
                signal.signal(number, self._handle)
            except (ValueError, OSError):  # pragma: no cover - not the main thread
                continue

    def disarm(self) -> None:
        """Restore the previous handlers so cleanup cannot be interrupted twice."""
        for number, handler in self._previous.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(number, handler)
        self._previous.clear()

    def check(self) -> None:
        if self.signal_number is not None:
            raise RunInterrupted(f"the run was interrupted by signal {self.signal_number}")

    def __enter__(self) -> CancellationToken:
        self.install()
        return self

    def __exit__(self, *_exc_info: Any) -> None:
        self.disarm()


# --------------------------------------------------------------------------- #
# Secrets and identifiers
# --------------------------------------------------------------------------- #


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Remove DSN passwords and explicit secrets from a message."""
    out = str(text)
    for secret in secrets:
        if secret:
            out = out.replace(secret, "***")
    # postgresql://user:password@host -> postgresql://user:***@host
    out = re.sub(r"(postgres(?:ql)?://[^:/@\s]+:)[^@\s]+@", r"\1***@", out)
    return out


def generated_name(run_id: str, kind: str, worker_id: str = "") -> str:
    """A deterministic, unique name for a database owned by this run."""
    if kind not in DATABASE_KINDS:
        raise OwnershipError(f"unknown database kind {kind!r}")
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise OwnershipError("a run id must be 12 lowercase hexadecimal characters")
    if kind == "seed":
        if worker_id:
            raise OwnershipError("a seed database has no worker id")
        return f"{DATABASE_PREFIX}_{run_id}_seed"
    if not WORKER_ID_PATTERN.fullmatch(worker_id):
        raise OwnershipError(f"invalid worker id {worker_id!r}")
    return f"{DATABASE_PREFIX}_{run_id}_worker_{worker_id}"


def expected_seed_name(run_id: str) -> str:
    return generated_name(run_id, "seed")


def expected_worker_name(run_id: str, worker_id: str) -> str:
    return generated_name(run_id, "worker", worker_id)


def parse_generated_name(name: str) -> tuple[str, str, str] | None:
    """Return ``(run_id, kind, worker_id)`` for a generated name, else ``None``."""
    match = re.fullmatch(
        rf"{re.escape(DATABASE_PREFIX)}_([0-9a-f]{{12}})_(seed|worker)(?:_([a-z0-9][a-z0-9_-]{{0,31}}))?",
        str(name),
    )
    if not match:
        return None
    run_id, kind, worker_id = match.group(1), match.group(2), match.group(3) or ""
    if kind == "seed" and worker_id:
        return None
    if kind == "worker" and not worker_id:
        return None
    return run_id, kind, worker_id


def require_generated_name(name: str, *, run_id: str, kind: str, worker_id: str = "") -> None:
    """Fail unless ``name`` is exactly the generated name for this identity."""
    if name != generated_name(run_id, kind, worker_id):
        raise OwnershipError(f"database name {name!r} is not the expected generated name")


def app_session_identity(run_id: str, worker_id: str) -> str:
    return f"{APP_SESSION_PREFIX}{run_id}:{worker_id}"


def control_session_identity(run_id: str, worker_id: str) -> str:
    return f"{CONTROL_SESSION_PREFIX}{run_id}:{worker_id}"


# --------------------------------------------------------------------------- #
# Connection target: DSN parsing without leaking passwords
# --------------------------------------------------------------------------- #


def _conninfo(dsn: str) -> dict[str, str]:
    try:
        from psycopg.conninfo import conninfo_to_dict
    except ImportError as exc:  # pragma: no cover - psycopg is a dev dependency
        raise TwinLifecycleError("psycopg is required for PostgreSQL support") from exc
    try:
        return {key: str(value) for key, value in conninfo_to_dict(dsn).items() if value is not None}
    except Exception:
        raise SourceProtectionError("the DSN could not be parsed") from None


@dataclass(frozen=True)
class ConnectionTarget:
    """The non-secret parts of a DSN plus the password kept out of argv."""

    host: str
    port: str
    user: str
    dbname: str
    password: str
    query: tuple[tuple[str, str], ...] = ()

    @classmethod
    def parse(cls, dsn: str) -> ConnectionTarget:
        info = _conninfo(dsn)
        return cls(
            host=info.get("host", ""),
            port=info.get("port", ""),
            user=info.get("user", ""),
            dbname=info.get("dbname", ""),
            password=info.get("password", ""),
            query=tuple(
                sorted(
                    (key, value)
                    for key, value in info.items()
                    if key not in {"host", "port", "user", "dbname", "password", "application_name"}
                )
            ),
        )

    def dsn(
        self,
        database: str | None = None,
        *,
        application_name: str | None = None,
        include_password: bool = True,
    ) -> str:
        """A URL for ``psycopg`` with an optional database and application name."""
        query = dict(self.query)
        if application_name:
            query["application_name"] = application_name
        if self.password and include_password:
            userinfo = f"{quote(self.user, safe='')}:{quote(self.password, safe='')}"
        else:
            userinfo = quote(self.user, safe="")
        netloc = f"{userinfo}@{self.host}" if userinfo else self.host
        if self.port:
            netloc = f"{netloc}:{self.port}"
        path = "/" + quote(database or self.dbname, safe="")
        return urlunsplit(("postgresql", netloc, path, urlencode(sorted(query.items())), ""))

    def child_environment(self, *, database: str, passfile: str | None) -> dict[str, str]:
        """Environment for ``pg_dump``/``psql``: no password in argv or env."""
        env = dict(os.environ)
        for key in ("PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGPASSFILE"):
            env.pop(key, None)
        env["PGCONNECT_TIMEOUT"] = "10"
        if self.host:
            env["PGHOST"] = self.host
        if self.port:
            env["PGPORT"] = self.port
        if self.user:
            env["PGUSER"] = self.user
        env["PGDATABASE"] = database
        query = dict(self.query)
        for source, target in (
            ("sslmode", "PGSSLMODE"),
            ("sslrootcert", "PGSSLROOTCERT"),
            ("sslcert", "PGSSLCERT"),
            ("sslkey", "PGSSLKEY"),
            ("connect_timeout", "PGCONNECT_TIMEOUT"),
        ):
            if source in query:
                env[target] = query[source]
        if passfile:
            env["PGPASSFILE"] = passfile
        return env

    def password_line(self, database: str) -> str:
        """One ``pgpass`` line. Empty when the connection has no password."""
        if not self.password:
            return ""

        def escape(value: str) -> str:
            return value.replace("\\", "\\\\").replace(":", "\\:")

        return ":".join(
            escape(part) for part in (self.host or "localhost", self.port or "5432", database, self.user, self.password)
        )


def database_dsn(dsn: str, database: str, *, application_name: str | None = None) -> str:
    """Return the same connection URI with a different database name."""
    if "://" in dsn:
        parts = urlsplit(dsn)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        if application_name:
            query["application_name"] = application_name
        path = "/" + quote(database, safe="")
        return urlunsplit((parts.scheme, parts.netloc, path, urlencode(sorted(query.items())), parts.fragment))
    target = ConnectionTarget.parse(dsn)
    return target.dsn(database, application_name=application_name)


@contextlib.contextmanager
def password_file(target: ConnectionTarget, *, database: str, directory: Path) -> Iterator[str | None]:
    """A private ``PGPASSFILE`` that exists only for the child process."""
    line = target.password_line(database)
    if not line:
        yield None
        return
    handle, path = tempfile.mkstemp(prefix="mizan-pgpass-", dir=str(directory))
    try:
        os.close(handle)
        with open(path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(line + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - Windows ACLs are not chmod
            pass
        yield path
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


def find_tool(name: str) -> str | None:
    """Find a PostgreSQL client, including the one bundled with pgserver."""
    found = shutil.which(name)
    if found:
        return found
    try:
        import pgserver
    except ImportError:
        return None
    root = Path(pgserver.__file__).resolve().parent
    for candidate in sorted(root.rglob(f"{name}*")):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _connect(dsn: str):
    import psycopg

    return psycopg.connect(dsn, autocommit=True, connect_timeout=10)


def _admin(target: ConnectionTarget) -> Any:
    return _connect(target.dsn("postgres", include_password=True))


# --------------------------------------------------------------------------- #
# Cluster identity and server-side ownership markers
# --------------------------------------------------------------------------- #


def cluster_identity(connection: Any) -> str:
    """The stable identity of the PostgreSQL cluster.

    ``pg_control_system()`` is restricted. Without it the module cannot prove
    which cluster a database belongs to, so it fails closed and documents the
    missing privilege instead of trusting the local registry.
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            row = cursor.fetchone()
    except Exception:
        raise TwinLifecycleError(
            "cluster identity is unavailable: pg_control_system() requires a superuser "
            "or a role explicitly granted EXECUTE on it"
        ) from None
    if not row or not row[0]:
        raise TwinLifecycleError("the cluster did not return a system identifier")
    return str(row[0])


@dataclass(frozen=True)
class OwnershipMarker:
    """The server-side record written into a database comment."""

    version: int
    run_id: str
    kind: str
    worker_id: str
    source_database: str
    cluster_id: str
    owner_role: str
    nonce: str
    created_at: float

    def to_json(self) -> str:
        return json.dumps(
            {
                "v": self.version,
                "run_id": self.run_id,
                "kind": self.kind,
                "worker_id": self.worker_id,
                "source": self.source_database,
                "cluster": self.cluster_id,
                "owner": self.owner_role,
                "nonce": self.nonce,
                "created_at": self.created_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, text: str) -> OwnershipMarker:
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            raise OwnershipError("the database ownership marker is not valid JSON") from None
        if not isinstance(data, dict):
            raise OwnershipError("the database ownership marker is not an object")
        try:
            marker = cls(
                version=int(data["v"]),
                run_id=str(data["run_id"]),
                kind=str(data["kind"]),
                worker_id=str(data.get("worker_id", "")),
                source_database=str(data["source"]),
                cluster_id=str(data["cluster"]),
                owner_role=str(data["owner"]),
                nonce=str(data["nonce"]),
                created_at=float(data["created_at"]),
            )
        except (KeyError, TypeError, ValueError):
            raise OwnershipError("the database ownership marker is incomplete") from None
        if marker.version != MARKER_VERSION:
            raise OwnershipError(f"unsupported ownership marker version {marker.version}")
        return marker


def read_marker(connection: Any, database: str) -> OwnershipMarker | None:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = %s",
            (database,),
        )
        row = cursor.fetchone()
    if not row or not row[0]:
        return None
    return OwnershipMarker.from_json(str(row[0]))


def write_marker(connection: Any, database: str, marker: OwnershipMarker) -> None:
    from psycopg import sql

    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL("COMMENT ON DATABASE {} IS {}").format(sql.Identifier(database), sql.Literal(marker.to_json()))
        )


def drop_marker(connection: Any, database: str) -> None:
    from psycopg import sql

    with connection.cursor() as cursor:
        cursor.execute(sql.SQL("COMMENT ON DATABASE {} IS NULL").format(sql.Identifier(database)))


def database_owner(connection: Any, database: str) -> str | None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s", (database,))
        row = cursor.fetchone()
    return str(row[0]) if row else None


def database_oid(connection: Any, database: str) -> int | None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT oid FROM pg_database WHERE datname = %s", (database,))
        row = cursor.fetchone()
    return int(row[0]) if row else None


def database_exists(connection: Any, database: str) -> bool:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (database,))
        return cursor.fetchone() is not None


# --------------------------------------------------------------------------- #
# Canonical fingerprint
# --------------------------------------------------------------------------- #


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def _typed(value: Any) -> list[Any]:
    """A type-preserving canonical representation of one PostgreSQL value."""
    if value is None:
        return ["null", ""]
    if isinstance(value, bool):
        return ["bool", "true" if value else "false"]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        return ["float", repr(value)]
    if isinstance(value, decimal.Decimal):
        # Preserve the declared scale: numeric(10,2) 1.00 and numeric(10,0) 1
        # are different values of different types.
        return ["decimal", format(value, "f")]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return ["bytes", bytes(value).hex()]
    if isinstance(value, uuid.UUID):
        return ["uuid", str(value)]
    if isinstance(value, datetime.datetime):
        return ["datetime", value.isoformat()]
    if isinstance(value, datetime.date):
        return ["date", value.isoformat()]
    if isinstance(value, datetime.time):
        return ["time", value.isoformat()]
    if isinstance(value, datetime.timedelta):
        return ["interval", str(value.total_seconds())]
    if isinstance(value, (list, tuple)):
        return ["array", [_typed(item) for item in value]]
    if isinstance(value, dict):
        return ["json", _canonical_json(value)]
    return ["other", f"{type(value).__module__}.{type(value).__name__}:{value!r}"]


def _primary_key_columns(connection: Any, oid: int) -> list[str]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT a.attname
            FROM pg_index i
            CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
            JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
            WHERE i.indrelid = %s AND i.indisprimary
            ORDER BY k.ord
            """,
            (oid,),
        )
        return [str(row[0]) for row in cursor.fetchall()]


def _table_rows(connection: Any, schema: str, table: str, oid: int) -> list[list[list[Any]]]:
    from psycopg import sql

    table_id = sql.SQL("{}").format(sql.Identifier(schema, table))
    primary_key = _primary_key_columns(connection, oid)
    with connection.cursor() as cursor:
        if primary_key:
            order = sql.SQL(", ").join(sql.Identifier(column) for column in primary_key)
            cursor.execute(sql.SQL("SELECT * FROM {} ORDER BY {}").format(table_id, order))
        else:
            cursor.execute(sql.SQL("SELECT * FROM {}").format(table_id))
        encoded = [[_typed(value) for value in row] for row in cursor.fetchall()]
    if not primary_key:
        encoded.sort(key=_canonical_json)
    return encoded


def _sequence_state(connection: Any, schema: str, name: str) -> dict[str, Any]:
    from psycopg import sql

    state: dict[str, Any] = {}
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT start_value, min_value, max_value, increment_by, cycle, cache_size
            FROM pg_sequences WHERE schemaname = %s AND sequencename = %s
            """,
            (schema, name),
        )
        row = cursor.fetchone()
        if row is None:
            raise BaselineVerificationError(f"the sequence {schema}.{name} could not be read from pg_sequences")
        state["configuration"] = [_typed(value) for value in row]
        # A sequence's next value depends on both last_value and is_called.
        # A permission failure is not "no state": fail closed.
        cursor.execute(sql.SQL("SELECT last_value, is_called FROM {}").format(sql.Identifier(schema, name)))
        current = cursor.fetchone()
        if current is None:
            raise BaselineVerificationError(f"the sequence {schema}.{name} returned no state")
        state["last_value"] = [_typed(current[0])]
        state["is_called"] = [_typed(current[1])]
    return state


def _index_definition(connection: Any, oid: int) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT i.relname, pg_get_indexdef(ix.indexrelid), ix.indisunique, ix.indisprimary
            FROM pg_index ix
            JOIN pg_class i ON i.oid = ix.indexrelid
            WHERE ix.indrelid = %s
            ORDER BY i.relname
            """,
            (oid,),
        )
        return [
            {"name": str(row[0]), "definition": str(row[1]), "unique": bool(row[2]), "primary": bool(row[3])}
            for row in cursor.fetchall()
        ]


def _constraint_definition(connection: Any, oid: int) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT conname, contype, pg_get_constraintdef(oid)
            FROM pg_constraint WHERE conrelid = %s ORDER BY conname
            """,
            (oid,),
        )
        return [{"name": str(row[0]), "type": str(row[1]), "definition": str(row[2])} for row in cursor.fetchall()]


def _trigger_definition(connection: Any, oid: int, *, exclude_audit: bool) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT tgname, pg_get_triggerdef(oid), tgenabled
            FROM pg_trigger WHERE tgrelid = %s AND NOT tgisinternal ORDER BY tgname
            """,
            (oid,),
        )
        rows = cursor.fetchall()
    result = []
    for name, definition, enabled in rows:
        if exclude_audit and str(name).startswith(AUDIT_TRIGGER_PREFIX):
            continue
        result.append({"name": str(name), "definition": str(definition), "enabled": str(enabled)})
    return result


def _function_definitions(
    connection: Any,
    schemas: tuple[str, ...],
    *,
    exclude_audit: bool,
    audit_schema: str,
) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
                   pg_get_functiondef(p.oid), p.prosecdef
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = ANY(%s) AND p.prokind = 'f'
            ORDER BY n.nspname, p.proname, 3
            """,
            (list(schemas),),
        )
        rows = cursor.fetchall()
    result = []
    for schema, name, arguments, definition, security_definer in rows:
        if exclude_audit and str(schema) == audit_schema and str(name) == AUDIT_FUNCTION_NAME:
            continue
        try:
            rendered = str(definition)
        except Exception:  # pragma: no cover - unusual catalog objects
            rendered = ""
        result.append(
            {
                "schema": str(schema),
                "name": str(name),
                "arguments": str(arguments),
                "definition": rendered,
                "security_definer": bool(security_definer),
            }
        )
    return result


def database_fingerprint(
    connection: Any,
    schemas: tuple[str, ...] | list[str],
    *,
    exclude_audit: bool = True,
    audit_schema: str | None = None,
) -> str:
    """Canonical, deterministic digest of the allowlisted schemas.

    Covers tables, typed rows in canonical order, column metadata and defaults,
    identity definitions, primary/unique keys, indexes, constraints, triggers,
    functions and sequence state. Mīzān's own audit objects are excluded and
    verified separately. Cluster-wide objects (roles, tablespaces, extensions,
    user-defined types, publications) are outside this guarantee and are
    documented as such.
    """

    allowed = tuple(dict.fromkeys(str(name) for name in schemas))
    if not allowed:
        raise BaselineVerificationError("a fingerprint needs at least one allowed schema")
    audit = audit_schema if audit_schema is not None else allowed[0]

    document: dict[str, Any] = {"schemas": sorted(allowed), "tables": {}, "sequences": {}, "functions": {}}
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT n.nspname, c.relname, c.oid, c.relpersistence, c.relrowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY(%s) AND c.relkind IN ('r', 'p')
            ORDER BY n.nspname, c.relname
            """,
            (list(allowed),),
        )
        tables = cursor.fetchall()

    for schema, table, oid, persistence, row_security in tables:
        if exclude_audit and schema == audit and table == AUDIT_TABLE_NAME:
            continue
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT column_name, data_type, udt_name, is_nullable, column_default,
                       is_identity, identity_generation, is_generated, generation_expression
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
                ORDER BY ordinal_position
                """,
                (schema, table),
            )
            columns = [
                {
                    "name": str(row[0]),
                    "type": str(row[1]),
                    "udt": str(row[2]),
                    "nullable": str(row[3]),
                    "default": None if row[4] is None else str(row[4]),
                    "identity": str(row[5] or ""),
                    "identity_generation": None if row[6] is None else str(row[6]),
                    "generated": str(row[7] or ""),
                    "generation_expression": None if row[8] is None else str(row[8]),
                }
                for row in cursor.fetchall()
            ]
        indexes = _index_definition(connection, oid)
        if exclude_audit and schema == audit:
            indexes = [item for item in indexes if item["name"] not in {AUDIT_INDEX_NAME, AUDIT_TABLE_NAME + "_pkey"}]
        constraints = _constraint_definition(connection, oid)
        if exclude_audit and schema == audit:
            constraints = [item for item in constraints if item["name"] != AUDIT_TABLE_NAME + "_pkey"]
        document["tables"][f"{schema}.{table}"] = {
            "persistence": str(persistence),
            "row_security": bool(row_security),
            "columns": columns,
            "primary_key": _primary_key_columns(connection, oid),
            "indexes": indexes,
            "constraints": constraints,
            "triggers": _trigger_definition(connection, oid, exclude_audit=exclude_audit),
            "rows": _table_rows(connection, schema, table, oid),
        }

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT n.nspname, c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY(%s) AND c.relkind = 'S'
            ORDER BY n.nspname, c.relname
            """,
            (list(allowed),),
        )
        sequences = cursor.fetchall()
    for schema, name in sequences:
        if exclude_audit and schema == audit and name == AUDIT_SEQUENCE_NAME:
            continue
        document["sequences"][f"{schema}.{name}"] = _sequence_state(connection, schema, name)

    document["functions"] = _function_definitions(connection, allowed, exclude_audit=exclude_audit, audit_schema=audit)
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def audit_state(connection: Any, *, schemas: tuple[str, ...], audit_schema: str) -> dict[str, Any]:
    """The state of Mīzān's audit objects, verified as an explicit effect."""
    from mizan.postgres_audit import AUDIT_TABLE, PostgresAuditor

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND c.relname = %s
            """,
            (audit_schema, AUDIT_TABLE),
        )
        table = cursor.fetchone()
        columns: list[str] = []
        if table:
            cursor.execute(
                """
                SELECT column_name FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position
                """,
                (audit_schema, AUDIT_TABLE),
            )
            columns = [str(row[0]) for row in cursor.fetchall()]
        cursor.execute(
            """
            SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = %s AND p.proname = %s
            """,
            (audit_schema, AUDIT_FUNCTION_NAME),
        )
        function = cursor.fetchone() is not None

    auditor = PostgresAuditor(connection, audit_schema=audit_schema, schemas=schemas)
    triggers: list[list[str]] = []
    for schema, table in auditor.user_tables():
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT tgname FROM pg_trigger
                WHERE tgrelid = to_regclass(%s) AND NOT tgisinternal ORDER BY tgname
                """,
                (f'"{schema}"."{table}"',),
            )
            for (name,) in cursor.fetchall():
                if str(name).startswith(AUDIT_TRIGGER_PREFIX):
                    triggers.append([schema, table, str(name)])
    return {
        "table": table is not None,
        "columns": columns,
        "function": function,
        "triggers": sorted(triggers),
    }


def expected_audit_state(connection: Any, *, schemas: tuple[str, ...], audit_schema: str) -> dict[str, Any]:
    from mizan.postgres_audit import AUDIT_TABLE, PostgresAuditor

    auditor = PostgresAuditor(connection, audit_schema=audit_schema, schemas=schemas)
    columns = [
        "id",
        "occurred_at",
        "raw_principal",
        "request_id",
        "schema_name",
        "table_name",
        "row_id",
        "row_identity",
        "operation",
        "row_data",
        "old_row",
    ]
    triggers = sorted(
        [schema, table, auditor.trigger_name(table)]
        for schema, table in auditor.user_tables()
        if not (schema == audit_schema and table == AUDIT_TABLE)
    )
    return {"table": True, "columns": columns, "function": True, "triggers": triggers}


# --------------------------------------------------------------------------- #
# Ownership records and registry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class OwnershipRecord:
    """A durable local record of one database created by this run."""

    run_id: str
    worker_id: str
    database_name: str
    source_database: str
    seed_database: str
    state: TwinState
    created_at: float
    kind: str = "worker"
    cluster_id: str = ""
    owner_role: str = ""
    nonce: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "worker_id": self.worker_id,
            "database_name": self.database_name,
            "source_database": self.source_database,
            "seed_database": self.seed_database,
            "state": str(self.state),
            "created_at": self.created_at,
            "kind": self.kind,
            "cluster_id": self.cluster_id,
            "owner_role": self.owner_role,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OwnershipRecord:
        try:
            return cls(
                run_id=str(data["run_id"]),
                worker_id=str(data["worker_id"]),
                database_name=str(data["database_name"]),
                source_database=str(data["source_database"]),
                seed_database=str(data["seed_database"]),
                state=TwinState(str(data["state"])),
                created_at=float(data["created_at"]),
                kind=str(data.get("kind", "worker")),
                cluster_id=str(data.get("cluster_id", "")),
                owner_role=str(data.get("owner_role", "")),
                nonce=str(data.get("nonce", "")),
            )
        except (KeyError, TypeError, ValueError):
            raise OwnershipError("an ownership record is incomplete or malformed") from None


def validate_record(
    record: OwnershipRecord,
    *,
    run_id: str,
    source_database: str,
    cluster_id: str | None,
) -> None:
    """Strict identity validation before any destructive operation.

    ``cluster_id=None`` performs the structural checks without a server
    connection (used before connecting); a destructive operation always
    passes the live cluster identity.
    """
    if not RUN_ID_PATTERN.fullmatch(record.run_id):
        raise OwnershipError("an ownership record has an invalid run id")
    if record.run_id != run_id:
        raise OwnershipError("an ownership record belongs to a different run")
    if record.kind not in DATABASE_KINDS:
        raise OwnershipError("an ownership record has an unknown kind")
    if record.kind == "worker":
        if not WORKER_ID_PATTERN.fullmatch(record.worker_id):
            raise OwnershipError("an ownership record has an invalid worker id")
        expected = expected_worker_name(record.run_id, record.worker_id)
        if record.seed_database != expected_seed_name(record.run_id):
            raise OwnershipError("an ownership record names a different seed database")
        if record.database_name == record.seed_database:
            raise OwnershipError("a worker record cannot name the seed database")
    else:
        if record.worker_id:
            raise OwnershipError("a seed record cannot name a worker")
        expected = expected_seed_name(record.run_id)
        if record.seed_database != record.database_name:
            raise OwnershipError("a seed record must name itself as the seed")
    if record.database_name != expected:
        raise OwnershipError("an ownership record does not match its generated name")
    if parse_generated_name(record.database_name) is None:
        raise OwnershipError("a database name is not a generated Mīzān name")
    if record.source_database != source_database:
        raise OwnershipError("an ownership record names a different source database")
    if record.database_name == source_database:
        raise OwnershipError("a record cannot name the source database")
    if not record.cluster_id:
        raise OwnershipError("an ownership record has no cluster identity")
    if cluster_id is not None and record.cluster_id != cluster_id:
        raise OwnershipError("an ownership record belongs to a different PostgreSQL cluster")
    if not record.owner_role:
        raise OwnershipError("an ownership record has no owner role")
    if not NONCE_PATTERN.fullmatch(record.nonce):
        raise OwnershipError("an ownership record has an invalid ownership nonce")


class DatabaseRegistry:
    """Local records. A secondary record, never the authority for deletion."""

    def __init__(self, path: str | Path, *, lock_timeout: float = 10.0, stale_lock: float = 60.0) -> None:
        self.path = Path(path)
        self.lock_timeout = lock_timeout
        self.stale_lock = stale_lock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.is_symlink():
            raise OwnershipError("the ownership registry must not be a symbolic link")
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:  # pragma: no cover - Windows ACLs are not chmod
            pass

    # -- locking ------------------------------------------------------------ #

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        deadline = time.monotonic() + self.lock_timeout
        handle: int | None = None
        while handle is None:
            try:
                handle = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    age = time.time() - self.lock_path.stat().st_mtime
                except FileNotFoundError:
                    continue
                if age > self.stale_lock:
                    with contextlib.suppress(FileNotFoundError):
                        self.lock_path.unlink()
                    continue
                if time.monotonic() > deadline:
                    raise OwnershipError("the ownership registry is locked by another process")
                time.sleep(0.02)
        try:
            os.write(handle, str(os.getpid()).encode("ascii"))
            yield
        finally:
            os.close(handle)
            with contextlib.suppress(FileNotFoundError):
                self.lock_path.unlink()

    # -- reading and writing ------------------------------------------------ #

    def load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            raise OwnershipError("the ownership registry could not be read") from None
        if not text.strip():
            return {}
        try:
            data = json.loads(text)
        except ValueError:
            raise OwnershipError("the ownership registry is not valid JSON") from None
        if not isinstance(data, dict):
            raise OwnershipError("the ownership registry is not an object")
        return data

    def records(self) -> list[OwnershipRecord]:
        result: list[OwnershipRecord] = []
        for key, value in self.load().items():
            if not isinstance(value, dict):
                raise OwnershipError(f"the ownership registry entry {key!r} is not an object")
            record = OwnershipRecord.from_dict(value)
            if record.database_name != key:
                raise OwnershipError(f"the ownership registry key {key!r} does not match its record")
            result.append(record)
        return result

    def get(self, database_name: str) -> OwnershipRecord | None:
        value = self.load().get(database_name)
        return OwnershipRecord.from_dict(value) if value else None

    def _write(self, records: dict[str, dict[str, Any]]) -> None:
        payload = json.dumps(records, indent=2, sort_keys=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            with open(temporary, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(temporary, 0o600)
            except OSError:  # pragma: no cover
                pass
            os.replace(temporary, self.path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    def put(self, record: OwnershipRecord) -> None:
        with self._lock():
            records = self.load()
            records[record.database_name] = record.to_dict()
            self._write(records)

    def update_state(self, database_name: str, state: TwinState) -> None:
        with self._lock():
            records = self.load()
            entry = records.get(database_name)
            if entry is None:
                return
            entry["state"] = str(state)
            records[database_name] = entry
            self._write(records)

    def remove(self, database_name: str) -> None:
        with self._lock():
            records = self.load()
            if records.pop(database_name, None) is not None:
                self._write(records)


# --------------------------------------------------------------------------- #
# Verified destructive operations
# --------------------------------------------------------------------------- #


def _verify_database_ownership(
    connection: Any,
    *,
    record: OwnershipRecord,
    cluster_id: str,
    source_database: str,
) -> OwnershipMarker:
    """Prove that the live database matches the local record and its marker."""
    validate_record(record, run_id=record.run_id, source_database=source_database, cluster_id=cluster_id)
    marker = read_marker(connection, record.database_name)
    if marker is None:
        raise OwnershipError("the database has no server-side ownership marker")
    if marker.run_id != record.run_id:
        raise OwnershipError("the server marker names a different run")
    if marker.kind != record.kind or marker.worker_id != record.worker_id:
        raise OwnershipError("the server marker names a different worker")
    if marker.source_database != source_database:
        raise OwnershipError("the server marker names a different source database")
    if marker.cluster_id != cluster_id:
        raise OwnershipError("the server marker names a different cluster")
    if marker.nonce != record.nonce:
        raise OwnershipError("the server marker does not match the local ownership nonce")
    if marker.owner_role != record.owner_role:
        raise OwnershipError("the server marker names a different owner")
    actual_owner = database_owner(connection, record.database_name)
    if actual_owner != marker.owner_role:
        raise OwnershipError("the database owner does not match the ownership marker")
    return marker


def _remaining_sessions(connection: Any, database: str) -> list[tuple[int, str]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT pid, coalesce(application_name, '') FROM pg_stat_activity
            WHERE datname = %s AND pid <> pg_backend_pid()
            ORDER BY pid
            """,
            (database,),
        )
        return [(int(row[0]), str(row[1])) for row in cursor.fetchall()]


def _wait_for_no_sessions(
    connection: Any, database: str, *, timeout: float = SESSION_DRAIN_SECONDS
) -> list[tuple[int, str]]:
    """Give the owned process a short window to disconnect on its own.

    This never inspects or uses the clients' labels. A backend that is still
    present after the drain window is simply "unowned" and blocks the drop.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        remaining = _remaining_sessions(connection, database)
        if not remaining or time.monotonic() >= deadline:
            return remaining
        time.sleep(0.05)


@contextlib.contextmanager
def _run_cleanup_lock(connection: Any, run_id: str) -> Iterator[None]:
    """Coordinate concurrent cleanups of one run with a session-scoped lock.

    The lock is held on the cleanup connection and disappears when the process
    dies. It serializes Mīzān cleanups; it never grants deletion authority.
    """
    key = (RUN_LOCK_NAMESPACE << 48) + int(run_id, 16)
    acquired = False
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", (key,))
        acquired = bool(cursor.fetchone()[0])
    if not acquired:
        deadline = time.monotonic() + RUN_LOCK_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(0.05)
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_try_advisory_lock(%s)", (key,))
                acquired = bool(cursor.fetchone()[0])
            if acquired:
                break
    if not acquired:
        raise CleanupPreflightError(
            ["the run cleanup lock is held by another process"],
            categories={"cleanup_lock": "unavailable"},
        )
    try:
        yield
    finally:
        with contextlib.suppress(Exception):
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s)", (key,))


def verified_drop(
    admin: Any,
    registry: DatabaseRegistry,
    record: OwnershipRecord,
    *,
    cluster_id: str,
    source_database: str,
    session_timeout: float = SESSION_DRAIN_SECONDS,
) -> bool:
    """Drop one database only when every proof agrees. Returns whether it existed.

    A backend label is client-controlled and is never used to identify or
    terminate a session. The only safe signal is the absence of backends after
    the owned process was stopped; any remaining backend blocks the drop.
    """
    from psycopg import sql

    validate_record(
        record,
        run_id=record.run_id,
        source_database=source_database,
        cluster_id=cluster_id,
    )
    name = record.database_name
    if not database_exists(admin, name):
        registry.update_state(name, TwinState.CLEANED)
        return False
    stored = registry.get(name)
    if stored is None or stored != record:
        raise OwnershipError("the database to drop is not the record stored in the ownership registry")
    _verify_database_ownership(admin, record=record, cluster_id=cluster_id, source_database=source_database)
    remaining = _wait_for_no_sessions(admin, name, timeout=session_timeout)
    if remaining:
        raise CleanupError(f"refusing to drop {name!r}: {len(remaining)} session(s) are still connected")
    with admin.cursor() as cursor:
        cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
    registry.update_state(name, TwinState.CLEANED)
    return True


# --------------------------------------------------------------------------- #
# Source and immutable baseline
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ImmutableBaseline:
    run_id: str
    name: str
    dsn: str
    fingerprint: str
    archive: Path
    schemas: tuple[str, ...]
    source_database: str
    cluster_id: str
    owner_role: str
    nonce: str
    created_at: float

    def record(self) -> OwnershipRecord:
        return OwnershipRecord(
            run_id=self.run_id,
            worker_id="",
            database_name=self.name,
            source_database=self.source_database,
            seed_database=self.name,
            state=TwinState.INITIALIZED,
            created_at=self.created_at,
            kind="seed",
            cluster_id=self.cluster_id,
            owner_role=self.owner_role,
            nonce=self.nonce,
        )


class PostgresSource:
    """A read-only view of the source database, used to prepare a seed."""

    def __init__(self, dsn_env: str, *, schemas: tuple[str, ...] | list[str]) -> None:
        self.dsn_env = dsn_env
        self.dsn = os.environ.get(dsn_env, "")
        if not self.dsn:
            raise SourceProtectionError(f"environment variable {dsn_env} is not set")
        self.target = ConnectionTarget.parse(self.dsn)
        if not self.target.dbname:
            raise SourceProtectionError("the DSN does not name a source database")
        if parse_generated_name(self.target.dbname) is not None:
            raise SourceProtectionError("the source DSN points at a Mīzan-generated database")
        self.schemas = tuple(dict.fromkeys(str(name) for name in schemas))
        if not self.schemas:
            raise SourceProtectionError("at least one schema must be allowlisted")
        self.run_id = uuid.uuid4().hex[:12]
        self.seed_name = expected_seed_name(self.run_id)
        self._baseline: ImmutableBaseline | None = None
        self._cluster_id: str | None = None
        #: Failures that prevented a seed rollback; they block a "verified" run.
        self.rollback_errors: list[str] = []

    # -- identity ----------------------------------------------------------- #

    def source_name(self) -> str:
        return self.target.dbname

    def admin(self) -> Any:
        return _admin(self.target)

    def cluster_id(self, connection: Any | None = None) -> str:
        if self._cluster_id is None:
            own = connection is None
            handle = connection or self.admin()
            try:
                self._cluster_id = cluster_identity(handle)
            finally:
                if own:
                    handle.close()
        return self._cluster_id

    def redact(self, text: str) -> str:
        return redact(text, secrets=(self.target.password, self.dsn))

    # -- read-only inspection ---------------------------------------------- #

    def fingerprint(self, dsn: str | None = None) -> str:
        connection = _connect(dsn or self.dsn)
        try:
            return database_fingerprint(connection, self.schemas, audit_schema=self.schemas[0])
        finally:
            connection.close()

    def preflight(self) -> dict[str, Any]:
        """Validate tools, privileges and schema allowlist without writing."""
        dump_tool = find_tool("pg_dump")
        psql_tool = find_tool("psql")
        if not dump_tool or not psql_tool:
            raise TwinLifecycleError("pg_dump and psql are required to prepare a baseline")
        connection = self.admin()
        try:
            cluster = self.cluster_id(connection)
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT nspname FROM pg_namespace WHERE nspname = ANY(%s) ORDER BY nspname",
                    (list(self.schemas),),
                )
                present = {str(row[0]) for row in cursor.fetchall()}
        finally:
            connection.close()
        missing = sorted(set(self.schemas) - present)
        if missing:
            raise SourceProtectionError(f"the source is missing allowlisted schema(s): {', '.join(missing)}")
        return {
            "source_database": self.source_name(),
            "cluster_id": cluster,
            "schemas": list(self.schemas),
            "fingerprint": self.fingerprint(),
            "tools": {"pg_dump": dump_tool, "psql": psql_tool},
        }

    def assert_unchanged(self) -> None:
        if self._baseline is None:
            return
        if self.fingerprint() != self._baseline.fingerprint:
            raise SourceProtectionError("the source database changed during the run")

    # -- baseline ----------------------------------------------------------- #

    def _dump_command(self, dump_tool: str, archive: Path) -> list[str]:
        # Only the allowlisted schemas are dumped. Large objects and
        # database-wide publications/subscriptions are not schema objects, so
        # they are excluded instead of silently crossing the boundary.
        command = [
            dump_tool,
            "--format=plain",
            "--no-owner",
            "--no-privileges",
            "--no-blobs",
            "--no-publications",
            "--no-subscriptions",
        ]
        for schema in self.schemas:
            command.append(f"--schema={schema}")
        command.extend(["-f", str(archive)])
        return command

    def _restore_command(self, psql_tool: str, script: Path) -> list[str]:
        return [psql_tool, "-v", "ON_ERROR_STOP=1", "-q", "-f", str(script)]

    def _assert_allowlisted(self, connection: Any) -> None:
        """The restored seed must contain no relation outside the allowlist."""
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT n.nspname, c.relname
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname NOT LIKE 'pg_%%'
                  AND n.nspname <> 'information_schema'
                  AND n.nspname <> ALL(%s)
                  AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
                ORDER BY n.nspname, c.relname
                """,
                (list(self.schemas),),
            )
            extra = cursor.fetchall()
        if extra:
            names = ", ".join(f"{row[0]}.{row[1]}" for row in extra[:5])
            raise BaselineVerificationError(f"the seed contains objects outside the schema allowlist: {names}")

    def prepare_baseline(self, workspace: str | Path) -> ImmutableBaseline:
        """Create an immutable seed without modifying the source."""
        root = Path(workspace)
        root.mkdir(parents=True, exist_ok=True)
        tools = self.preflight()
        before = self.fingerprint()
        cluster = str(tools["cluster_id"])
        dump_tool = str(tools["tools"]["pg_dump"])
        psql_tool = str(tools["tools"]["psql"])
        archive = root / f"seed-{self.run_id}.sql"

        admin = self.admin()
        created_oid: int | None = None
        registry = DatabaseRegistry(root / "ownership.json")
        seed_record: OwnershipRecord | None = None
        try:
            with admin.cursor() as cursor:
                cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.seed_name,))
                if cursor.fetchone():
                    raise TwinLifecycleError("the generated seed name already exists")
            from psycopg import sql

            with admin.cursor() as cursor:
                cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.seed_name)))
            created_oid = database_oid(admin, self.seed_name)
            if created_oid is None:
                raise TwinLifecycleError("the created seed has no catalog OID")
            # CREATE DATABASE makes the connecting role the owner; the source
            # owner is not necessarily the role that can create databases.
            owner_role = database_owner(admin, self.seed_name) or self.target.user

            marker = OwnershipMarker(
                version=MARKER_VERSION,
                run_id=self.run_id,
                kind="seed",
                worker_id="",
                source_database=self.source_name(),
                cluster_id=cluster,
                owner_role=owner_role,
                nonce=secrets.token_hex(16),
                created_at=time.time(),
            )
            seed_record = OwnershipRecord(
                run_id=self.run_id,
                worker_id="",
                database_name=self.seed_name,
                source_database=self.source_name(),
                seed_database=self.seed_name,
                state=TwinState.INITIALIZED,
                created_at=marker.created_at,
                kind="seed",
                cluster_id=cluster,
                owner_role=owner_role,
                nonce=marker.nonce,
            )
            write_marker(admin, self.seed_name, marker)
            registry.put(seed_record)
        except Exception as exc:
            if created_oid is not None and seed_record is not None:
                self._rollback_seed(admin, seed_record, cluster, created_oid, registry)
            admin.close()
            raise TwinLifecycleError(self.redact(f"the seed could not be initialized: {exc}")) from None

        try:
            with password_file(self.target, database=self.source_name(), directory=root) as passfile:
                dump_env = self.target.child_environment(database=self.source_name(), passfile=passfile)
                try:
                    dumped = subprocess.run(
                        self._dump_command(dump_tool, archive),
                        capture_output=True,
                        text=True,
                        timeout=300,
                        env=dump_env,
                    )
                except Exception as exc:
                    raise TwinLifecycleError(self.redact(f"the source dump could not be executed: {exc}")) from None
            if dumped.returncode != 0:
                detail = self.redact((dumped.stderr or "").strip()[:500])
                raise TwinLifecycleError(f"the source dump failed: {detail}")

            # Session parameters emitted by a newer client are not schema or
            # data; drop only the ones the target server rejects.
            script = archive.read_text(encoding="utf-8")
            filtered = "\n".join(line for line in script.splitlines() if "transaction_timeout" not in line.lower())
            filtered_path = root / f"seed-{self.run_id}-filtered.sql"
            filtered_path.write_text(filtered + "\n", encoding="utf-8")

            with password_file(self.target, database=self.seed_name, directory=root) as passfile:
                restore_env = self.target.child_environment(database=self.seed_name, passfile=passfile)
                try:
                    restored = subprocess.run(
                        self._restore_command(psql_tool, filtered_path),
                        capture_output=True,
                        text=True,
                        timeout=300,
                        env=restore_env,
                    )
                except Exception as exc:
                    raise TwinLifecycleError(self.redact(f"the seed restore could not be executed: {exc}")) from None
            if restored.returncode != 0:
                detail = self.redact((restored.stderr or "").strip()[:500])
                raise TwinLifecycleError(f"the seed restore failed: {detail}")

            seed_connection = _connect(seed_connection_dsn(self.target, self.seed_name))
            try:
                self._assert_allowlisted(seed_connection)
                digest = database_fingerprint(seed_connection, self.schemas)
            finally:
                seed_connection.close()
            if digest != before:
                raise BaselineVerificationError("the seed does not match the source fingerprint")
            if self.fingerprint() != before:
                raise SourceProtectionError("the source changed while preparing the baseline")

            baseline = ImmutableBaseline(
                run_id=self.run_id,
                name=self.seed_name,
                dsn=seed_connection_dsn(self.target, self.seed_name),
                fingerprint=digest,
                archive=archive,
                schemas=self.schemas,
                source_database=self.source_name(),
                cluster_id=cluster,
                owner_role=owner_role,
                nonce=marker.nonce,
                created_at=marker.created_at,
            )
            self._baseline = baseline
            return baseline
        except Exception:
            if seed_record is not None and created_oid is not None:
                self._rollback_seed(admin, seed_record, cluster, created_oid, registry)
            raise
        finally:
            admin.close()

    def _rollback_seed(
        self,
        admin: Any,
        record: OwnershipRecord,
        cluster: str,
        oid: int,
        registry: DatabaseRegistry,
    ) -> None:
        """Remove a seed created by this call. Never touches anything else.

        The OID read immediately after ``CREATE DATABASE`` is the server-side
        evidence that this is the object this call created. When the comment
        could not be written, OID + owner + cluster + exact generated name are
        the complete evidence; a local record alone is never enough.
        """
        try:
            if not database_exists(admin, record.database_name):
                registry.remove(record.database_name)
                return
            if database_oid(admin, record.database_name) != oid:
                raise OwnershipError("the seed OID changed; refusing rollback")
            if self.cluster_id(admin) != cluster:
                raise OwnershipError("the cluster changed; refusing rollback")
            if database_owner(admin, record.database_name) != record.owner_role:
                raise OwnershipError("the seed owner changed; refusing rollback")
            marker = read_marker(admin, record.database_name)
            if marker is not None:
                _verify_database_ownership(
                    admin,
                    record=record,
                    cluster_id=cluster,
                    source_database=self.source_name(),
                )
            remaining = _remaining_sessions(admin, record.database_name)
            if remaining:
                raise CleanupError("the seed still has active sessions")
            from psycopg import sql

            with admin.cursor() as cursor:
                cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(record.database_name)))
            registry.remove(record.database_name)
        except Exception as exc:
            # Rollback failure must not mask the original error. The record and
            # marker stay behind so --cleanup-run can recover the database.
            self.rollback_errors.append(self.redact(f"{record.database_name}: {exc}"))
            return


def seed_connection_dsn(target: ConnectionTarget, database: str) -> str:
    return target.dsn(database)


# --------------------------------------------------------------------------- #
# Disposable worker database
# --------------------------------------------------------------------------- #


@dataclass
class DisposableDatabase:
    """One owned, disposable database cloned from the immutable baseline."""

    source: PostgresSource
    baseline: ImmutableBaseline
    registry: DatabaseRegistry
    worker_id: str
    state: TwinState = TwinState.CREATED
    record: OwnershipRecord | None = field(default=None)
    connection: Any | None = field(default=None, repr=False)
    expected_fingerprint: str | None = field(default=None)

    @property
    def name(self) -> str:
        return expected_worker_name(self.source.run_id, self.worker_id)

    @property
    def dsn(self) -> str:
        return self.source.target.dsn(self.name)

    @property
    def control_dsn(self) -> str:
        return self.source.target.dsn(
            self.name, application_name=control_session_identity(self.source.run_id, self.worker_id)
        )

    @property
    def application_dsn(self) -> str:
        return self.source.target.dsn(
            self.name, application_name=app_session_identity(self.source.run_id, self.worker_id)
        )

    def _transition(self, target: TwinState) -> None:
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise TwinLifecycleError(f"invalid transition {self.state} -> {target}")
        self.state = target

    def create(self) -> OwnershipRecord:
        """Clone the seed into a uniquely named, owned database."""
        from psycopg import sql

        admin = self.source.admin()
        cluster = ""
        created_oid: int | None = None
        owner_role = ""
        try:
            cluster = self.source.cluster_id(admin)
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                    (self.baseline.name,),
                )
                if cursor.fetchone()[0]:
                    raise TwinLifecycleError("the immutable seed still has active sessions")
                cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.name,))
                if cursor.fetchone():
                    raise TwinLifecycleError("the generated worker database already exists")
            with admin.cursor() as cursor:
                cursor.execute(
                    sql.SQL("CREATE DATABASE {} TEMPLATE {}").format(
                        sql.Identifier(self.name), sql.Identifier(self.baseline.name)
                    )
                )
            created_oid = database_oid(admin, self.name)
            if created_oid is None:
                raise TwinLifecycleError("the created worker database has no catalog OID")
            owner_role = database_owner(admin, self.name) or self.source.target.user
            marker = OwnershipMarker(
                version=MARKER_VERSION,
                run_id=self.source.run_id,
                kind="worker",
                worker_id=self.worker_id,
                source_database=self.source.source_name(),
                cluster_id=cluster,
                owner_role=owner_role,
                nonce=secrets.token_hex(16),
                created_at=time.time(),
            )
            write_marker(admin, self.name, marker)
            self.record = OwnershipRecord(
                run_id=self.source.run_id,
                worker_id=self.worker_id,
                database_name=self.name,
                source_database=self.source.source_name(),
                seed_database=self.baseline.name,
                state=TwinState.INITIALIZED,
                created_at=marker.created_at,
                kind="worker",
                cluster_id=cluster,
                owner_role=owner_role,
                nonce=marker.nonce,
            )
            self.registry.put(self.record)
        except Exception:
            # If the database was created but its marker/record was not, the
            # OID captured right after CREATE DATABASE is the server-side
            # evidence that this exact object is ours. Never leave it untracked.
            if created_oid is not None:
                self._rollback_created(admin, oid=created_oid, owner_role=owner_role, cluster=cluster)
            admin.close()
            raise
        admin.close()
        self._transition(TwinState.INITIALIZED)
        self.expected_fingerprint = self.baseline.fingerprint
        self.verify(expect_audit=False)
        self._transition(TwinState.READY)
        return self.record

    def _rollback_created(self, admin: Any, *, oid: int, owner_role: str, cluster: str) -> None:
        """Drop a worker database this call created but could not register."""
        from psycopg import sql

        try:
            if not database_exists(admin, self.name):
                return
            if database_oid(admin, self.name) != oid:
                raise OwnershipError("the worker OID changed; refusing rollback")
            if self.source.cluster_id(admin) != cluster:
                raise OwnershipError("the cluster changed; refusing rollback")
            if owner_role and database_owner(admin, self.name) != owner_role:
                raise OwnershipError("the worker owner changed; refusing rollback")
            if _remaining_sessions(admin, self.name):
                raise CleanupError("the worker database still has active sessions")
            with admin.cursor() as cursor:
                cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(self.name)))
            self.registry.remove(self.name)
        except Exception as exc:
            self.source.rollback_errors.append(self.source.redact(f"{self.name}: {exc}"))

    def verify(self, *, expect_audit: bool = False) -> str:
        """Verify ownership, the canonical baseline and (optionally) audit objects."""
        record = self.record or self.registry.get(self.name)
        if record is None:
            raise OwnershipError("no valid ownership record for this worker database")
        admin = self.source.admin()
        try:
            cluster = self.source.cluster_id(admin)
            _verify_database_ownership(
                admin,
                record=record,
                cluster_id=cluster,
                source_database=self.source.source_name(),
            )
        finally:
            if admin is not None:
                admin.close()
        expected = self.expected_fingerprint or self.baseline.fingerprint
        digest = self.source.fingerprint(self.dsn)
        if digest != expected:
            raise BaselineVerificationError("the worker database does not match the baseline")
        if expect_audit:
            connection = self.connect()
            actual = audit_state(connection, schemas=self.baseline.schemas, audit_schema=self.baseline.schemas[0])
            expected_state = expected_audit_state(
                connection, schemas=self.baseline.schemas, audit_schema=self.baseline.schemas[0]
            )
            if actual != expected_state:
                raise BaselineVerificationError("the audit infrastructure does not match the expected state")
        self.record = record
        return digest

    def connect(self) -> Any:
        if self.connection is None or self.connection.closed:
            self.connection = _connect(self.control_dsn)
        return self.connection

    def close(self) -> None:
        if self.connection is not None and not self.connection.closed:
            self.connection.close()
        self.connection = None

    def drop(self) -> bool:
        """Verified, idempotent deletion of this worker database."""
        self.close()
        record = self.record or self.registry.get(self.name)
        if record is None:
            raise OwnershipError("refusing to drop a database without a local ownership record")
        admin = self.source.admin()
        try:
            cluster = self.source.cluster_id(admin)
            existed = verified_drop(
                admin,
                self.registry,
                record,
                cluster_id=cluster,
                source_database=self.source.source_name(),
            )
        finally:
            admin.close()
        if self.state is not TwinState.CLEANED:
            self._transition(TwinState.CLEANED)
        return existed


# --------------------------------------------------------------------------- #
# Twin: one disposable database plus one application process
# --------------------------------------------------------------------------- #


class PostgresTwin:
    """One disposable worker database plus its application process."""

    def __init__(
        self,
        source: PostgresSource,
        baseline: ImmutableBaseline,
        registry: DatabaseRegistry,
        worker_id: str,
        *,
        command: list[str],
        workdir: str | Path,
        env: dict[str, str] | None = None,
        health_path: str = "/health",
        health_timeout: float = 30.0,
        variant: str = "clean",
        pool_size: int = 0,
    ) -> None:
        self.source = source
        self.baseline = baseline
        self.worker_id = worker_id
        if not WORKER_ID_PATTERN.fullmatch(worker_id):
            raise TwinLifecycleError(f"invalid worker id {worker_id!r}")
        self.database = DisposableDatabase(source, baseline, registry, worker_id)
        self.state = TwinState.CREATED
        self.variant = variant
        self.cleanup_errors: list[str] = []
        self._twin: Twin | None = None
        self._app_env = dict(env or {})
        self._command = list(command)
        self._workdir = str(workdir)
        self._health_path = health_path
        self._health_timeout = health_timeout
        self._pool_size = max(0, int(pool_size))
        self._port = free_port()

    def _transition(self, target: TwinState) -> None:
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise TwinLifecycleError(f"invalid twin transition {self.state} -> {target}")
        self.state = target

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def snapshot_files(self) -> list[Path]:
        # Database identity replaces file snapshots; no copied files are used.
        return []

    # -- application process ------------------------------------------------ #

    def _launch_application(self) -> None:
        env = dict(self._app_env)
        env.update(
            {
                "MIZAN_PG_DSN": self.database.application_dsn,
                "MIZAN_PG_SCHEMA": ",".join(self.baseline.schemas),
                "MIZAN_PG_POOL_SIZE": str(self._pool_size),
            }
        )
        env.setdefault("MIZAN_VARIANT", self.variant)
        spec = TwinSpec(
            command=[part.replace("{port}", str(self._port)) for part in self._command],
            workdir=Path(self._workdir),
            env=env,
            port=self._port,
            health_path=self._health_path,
            health_timeout=self._health_timeout,
            data_paths=[],
        )
        self._twin = Twin(spec, workspace=Path(self._workdir) / f"twin-{self.worker_id}")
        self._twin.start()

    def _install_audit(self) -> None:
        from mizan.postgres_audit import PostgresAuditor

        auditor = PostgresAuditor(
            self.database.connect(),
            audit_schema=self.baseline.schemas[0],
            schemas=self.baseline.schemas,
        )
        auditor.install()

    def _stop_application(self, *, strict: bool) -> None:
        """Stop and reap the application; failure is never swallowed when strict."""
        errors: list[str] = []
        if self._twin is not None:
            twin = self._twin
            process = twin.process
            try:
                twin.stop()
            except Exception as exc:
                errors.append(self.source.redact(f"the application stop failed: {exc}"))
            errors.extend(twin.cleanup_errors)
            twin.cleanup_errors.clear()
            if process is not None and process.poll() is None:
                # Twin.stop kills after its grace period; make the exit
                # observable instead of trusting that the kill succeeded.
                deadline = time.monotonic() + 15.0
                while process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
            if process is not None and process.poll() is None:
                errors.append("the application process is still running after stop")
                with contextlib.suppress(Exception):
                    process.kill()
                    process.wait(timeout=5)
            self._twin = None
        self.database.close()
        if errors:
            self.cleanup_errors.extend(errors)
            if strict:
                raise TwinLifecycleError("; ".join(errors))

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> str:
        try:
            return self._start()
        except Exception:
            # A process may have been launched before the health check failed.
            # Reap it here; leaving it running would make a later drop race.
            self._stop_application(strict=False)
            if self.state is not TwinState.FAILED:
                self._transition(TwinState.FAILED)
            raise

    def _start(self) -> str:
        if self.state is TwinState.CREATED:
            self.database.create()
            self._transition(TwinState.INITIALIZED)
        if self.state in {TwinState.INITIALIZED, TwinState.VERIFIED, TwinState.READY}:
            # Verify the immutable baseline and the explicitly expected audit
            # objects before the application can write anything.
            self._install_audit()
            self.database.verify(expect_audit=True)
            self._launch_application()
            self._transition(TwinState.READY)
        else:
            raise TwinLifecycleError(f"cannot start a twin in state {self.state}")
        return self.base_url

    def restore(self) -> None:
        """Deterministically reset the worker database and application."""
        if self.state is TwinState.CREATED:
            self._transition(TwinState.FAILED)
            raise TwinLifecycleError("cannot restore a twin that never started")
        self._transition(TwinState.RESTORING)
        try:
            self._stop_application(strict=True)
            self.database.close()
            self.database.drop()
            self.database = DisposableDatabase(self.source, self.baseline, self.database.registry, self.worker_id)
            self.database.create()
            self._install_audit()
            self.database.verify(expect_audit=True)
            self._launch_application()
            self._transition(TwinState.VERIFIED)
            self.source.assert_unchanged()
            self._transition(TwinState.READY)
        except Exception:
            if self.state is not TwinState.FAILED:
                self._transition(TwinState.FAILED)
            raise

    def stop(self, *, strict: bool = False) -> None:
        self._stop_application(strict=strict)

    def cleanup(self) -> None:
        """Idempotent cleanup; never touches unrelated databases or sessions."""
        if self.state is TwinState.CLEANED:
            return
        try:
            self._stop_application(strict=True)
            self.database.drop()
            self.source.assert_unchanged()
            self._transition(TwinState.CLEANED)
        except Exception:
            if self.state is not TwinState.FAILED:
                self._transition(TwinState.FAILED)
            raise


# --------------------------------------------------------------------------- #
# Run-level cleanup
# --------------------------------------------------------------------------- #


def cleanup_run(dsn_env: str, workspace: str | Path, run_id: str) -> list[str]:
    """Clean one run in two phases: whole-run preflight, then sequential drops.

    DISCOVER → VALIDATE_ALL → BUILD_PLAN → RECHECK → DELETE → VERIFY_COMPLETE.
    PostgreSQL cannot drop several databases in one transaction, so a failure
    after the first deletion is reported as ``PartialCleanupError`` with the
    exact completed and remaining databases. No record, marker or session is
    trusted enough to authorize a drop on its own.
    """
    if not RUN_ID_PATTERN.fullmatch(str(run_id)):
        raise OwnershipError("a run id must be 12 lowercase hexadecimal characters")
    registry = DatabaseRegistry(Path(workspace) / "ownership.json")
    records = [record for record in registry.records() if record.run_id == run_id]
    if not records:
        return []
    names = [record.database_name for record in records]
    if len(names) != len(set(names)):
        raise CleanupPreflightError(
            ["the run contains duplicate or inconsistent database records"],
            categories={"registry": "duplicate entry"},
        )
    dsn = os.environ.get(dsn_env, "")
    if not dsn:
        raise SourceProtectionError(f"environment variable {dsn_env} is not set")
    target = ConnectionTarget.parse(dsn)
    if not target.dbname:
        raise SourceProtectionError("the DSN does not name a source database")
    if parse_generated_name(target.dbname) is not None:
        raise SourceProtectionError("the cleanup DSN points at a Mizan-generated database")
    # Structural checks run before a connection is opened, so a record that
    # names the source (or a malformed name) is rejected without touching SQL.
    for record in records:
        validate_record(
            record,
            run_id=run_id,
            source_database=target.dbname,
            cluster_id=None,
        )
    admin = _admin(target)
    try:
        with _run_cleanup_lock(admin, run_id):
            cluster = cluster_identity(admin)
            source_database = target.dbname
            reasons: list[str] = []
            categories: dict[str, str] = {}

            # DISCOVER + VALIDATE_ALL: nothing is dropped until every existing
            # database has passed every server-side check.
            for record in records:
                try:
                    validate_record(record, run_id=run_id, source_database=source_database, cluster_id=cluster)
                except Exception as exc:
                    reasons.append(f"{record.database_name}: {exc}")
                    categories[record.database_name] = "invalid local record"

            plan: list[OwnershipRecord] = []
            for record in records:
                name = record.database_name
                if not database_exists(admin, name):
                    if record.state is not TwinState.CLEANED:
                        reasons.append(f"{name}: the database is missing but its record is not CLEANED")
                        categories[name] = "missing inconsistent"
                    continue
                if name in categories:
                    continue
                try:
                    _verify_database_ownership(
                        admin, record=record, cluster_id=cluster, source_database=source_database
                    )
                except Exception as exc:
                    reasons.append(f"{name}: {exc}")
                    categories[name] = "invalid marker"
                    continue
                if _wait_for_no_sessions(admin, name, timeout=PREFLIGHT_SESSION_SECONDS):
                    reasons.append(f"{name}: a session is still connected")
                    categories[name] = "active session"
                    continue
                plan.append(record)

            if reasons:
                raise CleanupPreflightError(reasons, categories=categories)

            # BUILD_PLAN: workers before the seed; only fully validated names.
            ordered = sorted(plan, key=lambda record: (record.kind != "worker", record.worker_id))
            remaining = [record.database_name for record in ordered]
            cleaned: list[str] = []
            try:
                for record in ordered:
                    # RECHECK: a valid preflight never authorizes a later drop.
                    existed = verified_drop(
                        admin,
                        registry,
                        record,
                        cluster_id=cluster,
                        source_database=source_database,
                    )
                    if existed:
                        cleaned.append(record.database_name)
                    if record.database_name in remaining:
                        remaining.remove(record.database_name)
            except Exception as exc:
                detail = redact(str(exc), secrets=(target.password, target.dsn()))
                raise PartialCleanupError(cleaned, remaining, [detail]) from None

            # VERIFY_COMPLETE: never report CLEANED for an incomplete run.
            survived = [record.database_name for record in ordered if database_exists(admin, record.database_name)]
            if survived:
                raise PartialCleanupError(cleaned, survived, ["a validated database survived deletion"])
            return cleaned
    finally:
        admin.close()


# --------------------------------------------------------------------------- #
# Probe execution
# --------------------------------------------------------------------------- #


def run_l2_l3_probes(
    twin: PostgresTwin,
    *,
    schemas: tuple[str, ...],
    tokens: dict[str, str],
    contract_path: str | Path | None = None,
    groups: tuple[str, ...] = ("L2", "L3"),
    cancel: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Execute real L2/L3 probes against one disposable worker twin."""
    from mizan.core import Principal
    from mizan.engine import Mizan, Target
    from mizan.ownership import RelationshipContract
    from mizan.postgres_attribution import PostgresAttributor
    from mizan.traffic import TrafficRecord

    principals = [Principal(id=name, roles=("user",), token=token) for name, token in sorted(tokens.items())]
    owner = "alice"
    records: list[TrafficRecord] = []
    for name in tokens:
        records.append(
            TrafficRecord(
                method="GET",
                path="/whoami",
                status=200,
                principal=name,
                response={"p_key": name, "label": name},
            )
        )
    records.append(
        TrafficRecord(
            method="GET",
            path="/items",
            status=200,
            principal=owner,
            response=[{"item_ref": "item-a1", "label": "Item A"}],
        )
    )
    for name in tokens:
        records.append(
            TrafficRecord(
                method="GET",
                path="/items/item-a1",
                status=200,
                principal=name,
                template="/items/{item_ref}",
                resource_type="items",
                resource_id="item-a1",
                response={"item_ref": "item-a1", "label": "Item A"},
            )
        )
        records.append(
            TrafficRecord(
                method="PUT",
                path="/items/item-a1",
                status=200,
                principal=name,
                template="/items/{item_ref}",
                resource_type="items",
                resource_id="item-a1",
                body={"label": "Probe"},
                response={"item_ref": "item-a1", "label": "Probe"},
            )
        )
    contract = None
    if contract_path:
        contract = RelationshipContract.load(contract_path, strict=True)
    provider = PostgresAttributor(twin.database.connect(), schemas=schemas, audit_schema=schemas[0])
    engine = Mizan(
        Target(base_url=twin.base_url, principals=principals),
        attributor=provider,
        twin=twin,
        relationship_contract=contract,
        request_budget=60,
    )
    engine.traffic.records = records
    engine.learn()
    findings = []
    for group in groups:
        if cancel is not None:
            cancel()
        findings.extend(engine.attack_groups([group]))
    return {
        "law_types": sorted({finding.law for finding in findings}),
        "findings": [
            {"law": finding.law, "principal": finding.principal, "resource": finding.resource} for finding in findings
        ],
        "coverage": engine.coverage().to_dict(),
        "outcomes": list(engine.outcomes),
    }
