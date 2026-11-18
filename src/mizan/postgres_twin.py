"""Disposable PostgreSQL Twin lifecycle.

This module owns database creation, restoration, ownership records and cleanup
for PostgreSQL attack experiments. It never uses the source database as a
target and never falls back to a weaker execution path.

The lifecycle is explicit:

    CREATED → INITIALIZED → READY → RUNNING → RESTORING → VERIFIED → CLEANED

Any mandatory failure moves the object to ``FAILED`` and disables execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from mizan.twin import Twin, TwinSpec, free_port


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


class BaselineVerificationError(TwinLifecycleError):
    """The restored database does not match the verified baseline."""


@dataclass(frozen=True)
class OwnershipRecord:
    """Durable proof that a database belongs to this Mīzān run."""

    run_id: str
    worker_id: str
    database_name: str
    source_database: str
    seed_database: str
    state: TwinState
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "worker_id": self.worker_id,
            "database_name": self.database_name,
            "source_database": self.source_database,
            "seed_database": self.seed_database,
            "state": str(self.state),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OwnershipRecord:
        return cls(
            run_id=str(data["run_id"]),
            worker_id=str(data["worker_id"]),
            database_name=str(data["database_name"]),
            source_database=str(data["source_database"]),
            seed_database=str(data["seed_database"]),
            state=TwinState(str(data["state"])),
            created_at=float(data["created_at"]),
        )


def generated_name(run_id: str, kind: str, worker_id: str = "") -> str:
    """A deterministic, unique name for a database owned by this run."""
    suffix = f"_{worker_id}" if worker_id else ""
    return f"mizan_v61_{run_id}_{kind}{suffix}"


def database_dsn(dsn: str, database: str) -> str:
    """Return the same connection URI with a different database name."""
    parts = urlsplit(dsn)
    path = "/" + quote(database, safe="")
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


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
    binaries = sorted(root.rglob(f"{name}*"))
    for candidate in binaries:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _admin_dsn(dsn: str) -> str:
    return database_dsn(dsn, "postgres")


def _connect(dsn: str):
    import psycopg

    return psycopg.connect(dsn, autocommit=True, connect_timeout=10)


def database_fingerprint(connection: Any, schemas: tuple[str, ...]) -> str:
    """Canonical, deterministic digest of schema and data.

    Row counts alone are insufficient: the digest includes canonical row
    identities, column/type metadata, keys, indexes, constraints and sequences.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.relname, c.oid, n.nspname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY(%s) AND c.relkind IN ('r','p')
            ORDER BY n.nspname, c.relname
            """,
            (list(schemas),),
        )
        tables = cursor.fetchall()
        document: dict[str, Any] = {"tables": {}, "sequences": {}}
        for name, oid, table_schema in tables:
            cursor.execute(
                """
                SELECT column_name, data_type, is_nullable, ordinal_position
                FROM information_schema.columns
                WHERE table_schema = ANY(%s) AND table_name = %s
                ORDER BY ordinal_position
                """,
                (list(schemas), name),
            )
            columns = [list(row) for row in cursor.fetchall()]
            cursor.execute(
                """
                SELECT i.relname, ix.indisunique, ix.indisprimary,
                       array_agg(a.attname ORDER BY k.ord)
                FROM pg_index ix
                JOIN pg_class i ON i.oid = ix.indexrelid
                CROSS JOIN LATERAL unnest(ix.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                JOIN pg_attribute a ON a.attrelid = ix.indrelid AND a.attnum = k.attnum
                WHERE ix.indrelid = %s
                GROUP BY i.relname, ix.indisunique, ix.indisprimary
                ORDER BY i.relname
                """,
                (oid,),
            )
            indexes = [[row[0], bool(row[1]), bool(row[2]), list(row[3])] for row in cursor.fetchall()]
            cursor.execute(
                """
                SELECT conname, contype, pg_get_constraintdef(oid)
                FROM pg_constraint WHERE conrelid = %s ORDER BY conname
                """,
                (oid,),
            )
            constraints = [[row[0], str(row[1]), str(row[2])] for row in cursor.fetchall()]
            qualified = f"{table_schema}.{name}"
            cursor.execute(f'SELECT * FROM "{table_schema}"."{name.replace(chr(34), chr(34) * 2)}" ORDER BY 1')
            column_names = [description[0] for description in cursor.description]
            rows = []
            for row in cursor.fetchall():
                rows.append([str(value) if value is not None else None for value in row])
            document["tables"][qualified] = {
                "columns": columns,
                "indexes": indexes,
                "constraints": constraints,
                "column_names": column_names,
                "rows": rows,
                "row_count": len(rows),
            }
        cursor.execute(
            """
            SELECT sequence_schema, sequence_name
            FROM information_schema.sequences WHERE sequence_schema = ANY(%s)
            ORDER BY sequence_schema, sequence_name
            """,
            (list(schemas),),
        )
        for schema, name in cursor.fetchall():
            try:
                cursor.execute(f'SELECT last_value FROM "{schema}"."{name}"')
                value = cursor.fetchone()[0]
            except Exception:
                value = None
            document["sequences"][f"{schema}.{name}"] = str(value)
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


class PostgresSource:
    """Read-only view of the source database, used only to prepare a seed."""

    def __init__(self, dsn_env: str, *, schemas: tuple[str, ...] | list[str]) -> None:
        self.dsn_env = dsn_env
        self.dsn = os.environ.get(dsn_env, "")
        if not self.dsn:
            raise SourceProtectionError(f"environment variable {dsn_env} is not set")
        self.schemas = tuple(dict.fromkeys(schemas))
        if not self.schemas:
            raise SourceProtectionError("at least one schema must be allowlisted")
        self.run_id = uuid.uuid4().hex[:12]
        self.seed_name = generated_name(self.run_id, "seed")
        self._baseline: ImmutableBaseline | None = None

    def admin(self):
        return _connect(_admin_dsn(self.dsn))

    def source_name(self) -> str:
        return urlsplit(self.dsn).path.lstrip("/") or "postgres"

    def fingerprint(self, dsn: str | None = None) -> str:
        connection = _connect(dsn or self.dsn)
        try:
            return database_fingerprint(connection, self.schemas)
        finally:
            connection.close()

    def prepare_baseline(self, workspace: str | Path) -> ImmutableBaseline:
        """Create an immutable seed without modifying the source."""
        before = self.fingerprint()
        dump_tool = find_tool("pg_dump")
        restore_tool = find_tool("pg_restore")
        if not dump_tool or not restore_tool:
            raise TwinLifecycleError("pg_dump and pg_restore are required to prepare a baseline")
        root = Path(workspace)
        root.mkdir(parents=True, exist_ok=True)
        archive = root / f"seed-{self.run_id}.dump"
        result = subprocess.run(
            [dump_tool, "-Fc", "--no-owner", "--no-privileges", "-f", str(archive), self.dsn],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise TwinLifecycleError("the source dump failed")
        admin = self.admin()
        try:
            with admin.cursor() as cursor:
                cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.seed_name,))
                if cursor.fetchone():
                    raise TwinLifecycleError("the generated seed name already exists")
                cursor.execute(f'CREATE DATABASE "{self.seed_name}"')
        finally:
            admin.close()
        try:
            restored = subprocess.run(
                [
                    restore_tool,
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                    "-d",
                    database_dsn(self.dsn, self.seed_name),
                    str(archive),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except Exception:
            self._drop_seed()
            raise
        if restored.returncode != 0:
            detail = restored.stderr.strip()[:500].replace(self.dsn, "<redacted>")
            self._drop_seed()
            raise TwinLifecycleError(f"the seed restore failed: {detail}")
        digest = self.fingerprint(database_dsn(self.dsn, self.seed_name))
        if digest != before:
            raise BaselineVerificationError("the seed does not match the source fingerprint")
        if self.fingerprint() != before:
            raise SourceProtectionError("the source changed while preparing the baseline")
        baseline = ImmutableBaseline(
            run_id=self.run_id,
            name=self.seed_name,
            dsn=database_dsn(self.dsn, self.seed_name),
            fingerprint=digest,
            archive=archive,
            schemas=self.schemas,
        )
        self._baseline = baseline
        return baseline

    def _drop_seed(self) -> None:
        admin = self.admin()
        try:
            with admin.cursor() as cursor:
                cursor.execute(f'DROP DATABASE IF EXISTS "{self.seed_name}"')
        finally:
            admin.close()

    def assert_unchanged(self) -> None:
        if self._baseline is None:
            return
        if self.fingerprint() != self._baseline.fingerprint:
            raise SourceProtectionError("the source database changed during the run")


@dataclass(frozen=True)
class ImmutableBaseline:
    run_id: str
    name: str
    dsn: str
    fingerprint: str
    archive: Path
    schemas: tuple[str, ...]


class DatabaseRegistry:
    """Durable ownership records for databases created by the current run."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, records: dict[str, dict[str, Any]]) -> None:
        self.path.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")

    def put(self, record: OwnershipRecord) -> None:
        records = self.load()
        records[record.database_name] = record.to_dict()
        self.save(records)

    def get(self, database_name: str) -> OwnershipRecord | None:
        value = self.load().get(database_name)
        return OwnershipRecord.from_dict(value) if value else None


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
        return generated_name(self.source.run_id, "worker", self.worker_id)

    @property
    def dsn(self) -> str:
        return database_dsn(self.source.dsn, self.name)

    def _transition(self, target: TwinState) -> None:
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise TwinLifecycleError(f"invalid transition {self.state} -> {target}")
        self.state = target

    def create(self) -> OwnershipRecord:
        """Clone the seed into a uniquely named, owned database."""
        admin = self.source.admin()
        try:
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
                cursor.execute(f'CREATE DATABASE "{self.name}" TEMPLATE "{self.baseline.name}"')
        finally:
            admin.close()
        self.record = OwnershipRecord(
            run_id=self.source.run_id,
            worker_id=self.worker_id,
            database_name=self.name,
            source_database=self.source.source_name(),
            seed_database=self.baseline.name,
            state=TwinState.INITIALIZED,
            created_at=time.time(),
        )
        self.registry.put(self.record)
        self._transition(TwinState.INITIALIZED)
        self.verify()
        self._transition(TwinState.READY)
        return self.record

    def verify(self) -> str:
        """Verify the database fingerprint and ownership before use."""
        record = self.record or self.registry.get(self.name)
        if record is None or record.run_id != self.source.run_id or record.worker_id != self.worker_id:
            raise SourceProtectionError("no valid ownership record for this worker database")
        if record.database_name != self.name or record.source_database == self.name:
            raise SourceProtectionError("the ownership record names the wrong database")
        expected = self.expected_fingerprint or self.baseline.fingerprint
        digest = self.source.fingerprint(self.dsn)
        if digest != expected:
            raise BaselineVerificationError("the worker database does not match the baseline")
        return digest

    def connect(self) -> Any:
        if self.connection is None or self.connection.closed:
            self.connection = _connect(self.dsn)
        return self.connection

    def close(self) -> None:
        if self.connection is not None and not self.connection.closed:
            self.connection.close()
        self.connection = None

    def _assert_drop_allowed(self) -> OwnershipRecord:
        record = self.record or self.registry.get(self.name)
        if record is None or record.run_id != self.source.run_id:
            raise SourceProtectionError("refusing to drop a database without a matching run ownership record")
        if record.database_name != self.name:
            raise SourceProtectionError("refusing to drop a database whose record has a different name")
        if record.source_database == self.name or record.seed_database == self.name:
            raise SourceProtectionError("refusing to drop the source or seed database")
        if record.state in {TwinState.CLEANED, TwinState.FAILED} and self.state is not TwinState.FAILED:
            raise TwinLifecycleError("the database is already cleaned")
        return record

    def drop(self) -> None:
        """Idempotently drop only this run's worker database."""
        self.close()
        admin = self.source.admin()
        try:
            with admin.cursor() as cursor:
                cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.name,))
                if not cursor.fetchone():
                    self._transition(TwinState.CLEANED)
                    return
                self._assert_drop_allowed()
                # Terminate only sessions owned by this run and this worker.
                cursor.execute(
                    """
                    SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                    WHERE datname = %s
                      AND application_name LIKE %s
                      AND pid <> pg_backend_pid()
                    """,
                    (self.name, f"mizan:{self.source.run_id}:{self.worker_id}%"),
                )
                cursor.execute(f'DROP DATABASE IF EXISTS "{self.name}"')
        finally:
            admin.close()
        if self.record is not None:
            self.record = OwnershipRecord(**{**self.record.to_dict(), "state": TwinState.CLEANED})
            self.registry.put(self.record)
        self._transition(TwinState.CLEANED)


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
    ) -> None:
        self.source = source
        self.baseline = baseline
        self.worker_id = worker_id
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

    def start(self) -> str:
        try:
            return self._start()
        except Exception:
            if self.state is not TwinState.FAILED:
                self._transition(TwinState.FAILED)
            raise

    def _start(self) -> str:
        if self.state is TwinState.CREATED:
            self.database.create()
            self._transition(TwinState.INITIALIZED)
        if self.state in {TwinState.INITIALIZED, TwinState.VERIFIED, TwinState.READY}:
            env = dict(self._app_env)
            env.update(
                {
                    "MIZAN_PG_DSN": self.database.dsn,
                    "MIZAN_PG_SCHEMA": ",".join(self.baseline.schemas),
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
            from mizan.postgres_audit import PostgresAuditor

            auditor = PostgresAuditor(
                self.database.connect(), audit_schema=self.baseline.schemas[0], schemas=self.baseline.schemas
            )
            auditor.install()
            self.database.expected_fingerprint = self.source.fingerprint(self.database.dsn)
            self.database.verify()
            self._transition(TwinState.READY)
        else:
            raise TwinLifecycleError(f"cannot start a twin in state {self.state}")
        return self.base_url

    def restore(self) -> None:
        """Deterministically reset the worker database and application."""
        self._transition(TwinState.RESTORING)
        try:
            if self._twin is not None:
                self._twin.stop()
                self._twin = None
            self.database.close()
            self.database.drop()
            self.database = DisposableDatabase(self.source, self.baseline, self.database.registry, self.worker_id)
            self.database.create()
            self._transition(TwinState.VERIFIED)
            self.start()
            self.source.assert_unchanged()
        except Exception:
            self._transition(TwinState.FAILED)
            raise

    def stop(self) -> None:
        if self._twin is not None:
            try:
                self._twin.stop()
            except Exception as exc:
                self.cleanup_errors.append(str(exc))
            self._twin = None
        self.database.close()

    def cleanup(self) -> None:
        """Idempotent cleanup; never touches unrelated databases."""
        self.stop()
        if self.state in {TwinState.CLEANED}:
            return
        try:
            self.database.drop()
            self._transition(TwinState.CLEANED)
            self.source.assert_unchanged()
        except Exception:
            if self.state is not TwinState.FAILED:
                self._transition(TwinState.FAILED)
            raise


def cleanup_run(dsn_env: str, workspace: str | Path, run_id: str) -> list[str]:
    """Clean every database owned by a recorded run; never guess by prefix."""
    source = PostgresSource(dsn_env, schemas=("pg_catalog",))
    registry = DatabaseRegistry(Path(workspace) / "ownership.json")
    cleaned: list[str] = []
    for name, value in registry.load().items():
        record = OwnershipRecord.from_dict(value)
        if record.run_id != run_id:
            continue
        if record.database_name != name or record.source_database == name or record.seed_database == name:
            raise SourceProtectionError("refusing cleanup with an invalid ownership record")
        admin = source.admin()
        try:
            with admin.cursor() as cursor:
                cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
                if cursor.fetchone():
                    cursor.execute(f'DROP DATABASE IF EXISTS "{name}"')
            cleaned.append(name)
        finally:
            admin.close()
    return cleaned


def run_l2_l3_probes(
    twin: PostgresTwin,
    *,
    schemas: tuple[str, ...],
    tokens: dict[str, str],
    contract_path: str | Path | None = None,
    groups: tuple[str, ...] = ("L2", "L3"),
) -> dict[str, Any]:
    """Execute real L2/L3 probes against one disposable worker twin.

    The traffic records describe the fixture's observable API; the ownership
    graph and attribution still come from the live disposable database.
    """
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
    findings = engine.attack_groups(list(groups))
    return {
        "law_types": sorted({finding.law for finding in findings}),
        "findings": [
            {"law": finding.law, "principal": finding.principal, "resource": finding.resource} for finding in findings
        ],
        "coverage": engine.coverage().to_dict(),
        "outcomes": list(engine.outcomes),
    }
