"""PostgreSQL engine integration tests for the generic Mīzān engine."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

from mizan.postgres_twin import (
    DatabaseRegistry,
    PostgresSource,
    cleanup_run,
    run_l2_l3_probes,
)

FIXTURE = Path(__file__).parent / "fixtures" / "external_apps" / "postgres_store"
DSN_ENV = "MIZAN_VII_TEST_DSN"


def _dsn() -> str:
    value = os.environ.get(DSN_ENV) or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if value:
        return value if "connect_timeout" in value else value + "?connect_timeout=5"
    pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required")
    return pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-vii-pg-")), cleanup_mode="delete").get_uri()


def _admin(dsn: str):
    import psycopg

    return psycopg.connect(dsn, autocommit=True)


def _database_exists(dsn: str, name: str) -> bool:
    admin = _admin(dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            return cursor.fetchone() is not None
    finally:
        admin.close()


@pytest.fixture(scope="module")
def dsn():
    dsn = _dsn()
    os.environ[DSN_ENV] = dsn
    import importlib.util

    spec = importlib.util.spec_from_file_location("pgstore_engine", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
    os.environ["MIZAN_TOKEN_ALICE"] = "twin-alice"
    os.environ["MIZAN_TOKEN_BOB"] = "twin-bob"
    try:
        module.create_app("clean", dsn=dsn, schema="pgstore")
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return dsn


@pytest.fixture
def source(dsn):
    return PostgresSource(DSN_ENV, schemas=("pgstore",))


def _run_worker(instance, workspace, variant="write"):
    from mizan.postgres_engine import PostgresRun

    traffic = workspace / f"traffic-{variant}-{Path(workspace).name.split('-')[-1]}.jsonl"
    run = PostgresRun(
        instance,
        instance.prepare_baseline(workspace),
        DatabaseRegistry(workspace / "ownership.json"),
        workspace,
        [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}", "--vulnerability", variant],
        tokens={"alice": "twin-alice", "bob": "twin-bob"},
        traffic_path=traffic,
        pool_size=2,
    )
    return run, run.start_worker("w0")


@pytest.mark.postgres_integration
def test_mizan_engine_l3_with_postgres_attributor(source, dsn) -> None:
    instance = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-vii-l3-"))
    run, twin = _run_worker(instance, workspace, variant="write")
    try:
        result = run_l2_l3_probes(
            twin,
            schemas=("pgstore",),
            tokens={"alice": "twin-alice", "bob": "twin-bob"},
            contract_path=FIXTURE / "mizan-relationships.json",
        )
        assert result["law_types"] == ["L3"]
        assert result["coverage"]["laws"]["L3"]["findings"] >= 1
        instance.assert_unchanged()
    finally:
        twin.cleanup()
        cleanup_run(DSN_ENV, workspace, instance.run_id)
    assert not _database_exists(dsn, twin.database.name)
    assert not _database_exists(dsn, instance.seed_name)


@pytest.mark.postgres_integration
def test_mizan_engine_parallel_workers_are_isolated(source, dsn) -> None:
    from mizan.postgres_engine import PostgresRun

    instance = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-vii-parallel-"))

    run = PostgresRun(
        instance,
        instance.prepare_baseline(workspace),
        DatabaseRegistry(workspace / "ownership.json"),
        workspace,
        [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}", "--vulnerability", "clean"],
        tokens={"alice": "twin-alice", "bob": "twin-bob"},
        traffic_path=workspace / "traffic-parallel.jsonl",
        pool_size=2,
    )
    twins = []
    try:
        twins = [run.start_worker("w0"), run.start_worker("w1")]
        assert twins[0].database.name != twins[1].database.name
        assert twins[0].database.dsn != twins[1].database.dsn
        assert run.worker_traffic_path(twins[0]) != run.worker_traffic_path(twins[1])

        admin = _admin(twins[0].database.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT oid FROM pg_database WHERE datname = ANY(%s)", ([twin.database.name for twin in twins],)
                )
                oids = [int(row[0]) for row in cursor.fetchall()]
            assert len(oids) == 2 and len(set(oids)) == 2
        finally:
            admin.close()
        assert twins[0]._twin.process.pid != twins[1]._twin.process.pid
        admin = _admin(twins[0].database.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute('CREATE TABLE "pgstore"."worker_isolation_probe" (id TEXT PRIMARY KEY)')
        finally:
            admin.close()
        assert instance.fingerprint(twins[0].database.dsn) != instance.fingerprint(twins[1].database.dsn)
        other = instance.fingerprint(twins[1].database.dsn)
        twins[0].restore()
        assert instance.fingerprint(twins[1].database.dsn) == other
    finally:
        for twin in reversed(twins):
            twin.cleanup()
        cleanup_run(DSN_ENV, workspace, instance.run_id)
    assert not any(_database_exists(dsn, twin.database.name) for twin in twins)


@pytest.mark.postgres_integration
def test_mizan_twin_cli_uses_postgres_backend_safely(source, dsn) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    instance = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-vii-cli-"))

    out = workspace / "out"
    result = CliRunner().invoke(
        main,
        [
            "twin",
            "--backend",
            "postgres",
            "--command",
            f'"{sys.executable}" "{FIXTURE / "app.py"}" --port {{port}} --vulnerability clean',
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--allow-disposable",
            "--workers",
            "2",
            "--spec",
            str(FIXTURE / "openapi.json"),
            "--token",
            "alice=twin-alice",
            "--token",
            "bob=twin-bob",
            "--workdir",
            str(workspace),
            "--out",
            str(out),
        ],
    )
    if result.exit_code != 0:
        raise AssertionError(f"{result.output}\nEXC={result.exception!r}\nSTDERR={result.stderr}")
    instance.assert_unchanged()
    assert "cleanup: " in result.output


@pytest.mark.postgres_integration
def test_postgres_engine_source_and_cleanup_are_verified(source, dsn) -> None:
    instance = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-vii-source-"))

    run, twin = _run_worker(instance, workspace, variant="clean")
    try:
        baseline_fingerprint = instance.fingerprint()
        twin.restore()
        assert instance.fingerprint() == baseline_fingerprint
        instance.assert_unchanged()
    finally:
        twin.cleanup()
        cleaned = cleanup_run(DSN_ENV, workspace, instance.run_id)
    assert cleaned
    assert not _database_exists(dsn, twin.database.name)
    assert not _database_exists(dsn, instance.seed_name)
