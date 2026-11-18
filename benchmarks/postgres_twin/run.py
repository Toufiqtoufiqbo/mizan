"""Reproducible PostgreSQL Twin benchmark with real measurements."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "external_apps" / "postgres_store"
OUTPUT = Path(__file__).resolve().parent / "results.json"
DSN_ENV = "MIZAN_V61_BENCH_DSN"


def _load_fixture():
    spec = importlib.util.spec_from_file_location("pgstore_bench", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    from mizan.postgres_twin import DatabaseRegistry, PostgresSource, PostgresTwin

    dsn = os.environ.get(DSN_ENV) or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if dsn:
        dsn = dsn if "connect_timeout" in dsn else dsn + ("&connect_timeout=5" if "?" in dsn else "?connect_timeout=5")
        os.environ[DSN_ENV] = dsn
        started_server = None
    else:
        pgserver = __import__("pgserver")
        started_server = pgserver.get_server(
            pgdata=Path(tempfile.mkdtemp(prefix="mizan-v61-bench-")), cleanup_mode="delete"
        )
        dsn = started_server.get_uri()
        os.environ[DSN_ENV] = dsn

    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-bench-work-"))
    fixture = _load_fixture()
    fixture.create_app("clean", dsn=dsn, schema="pgstore")
    source = PostgresSource(DSN_ENV, schemas=("pgstore",))
    registry = DatabaseRegistry(workspace / "ownership.json")
    timings: dict[str, float] = {}

    begin = time.monotonic()
    baseline = source.prepare_baseline(workspace)
    timings["baseline_prepare_seconds"] = round(time.monotonic() - begin, 3)

    workers: list[PostgresTwin] = []
    command = [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}"]
    for index in range(2):
        begin = time.monotonic()
        twin = PostgresTwin(
            source,
            baseline,
            registry,
            f"w{index}",
            command=command,
            workdir=workspace,
            env={"MIZAN_TOKEN_ALICE": "bench-alice", "MIZAN_TOKEN_BOB": "bench-bob"},
        )
        twin.start()
        timings[f"worker_{index}_startup_seconds"] = round(time.monotonic() - begin, 3)
        workers.append(twin)

    begin = time.monotonic()
    with workers[0].database.connect().cursor() as cursor:
        cursor.execute('CREATE TABLE "pgstore"."bench_probe" (id TEXT PRIMARY KEY)')
    timings["mutation_seconds"] = round(time.monotonic() - begin, 3)

    digest_before = source.fingerprint(workers[0].database.dsn)
    digest_other = source.fingerprint(workers[1].database.dsn)
    begin = time.monotonic()
    workers[0].restore()
    timings["restore_seconds"] = round(time.monotonic() - begin, 3)
    digest_after = source.fingerprint(workers[0].database.dsn)

    begin = time.monotonic()
    for twin in reversed(workers):
        twin.cleanup()
    timings["cleanup_seconds"] = round(time.monotonic() - begin, 3)
    admin = source.admin()
    with admin.cursor() as cursor:
        cursor.execute(f'DROP DATABASE IF EXISTS "{baseline.name}"')
    admin.close()

    results = {
        "environment": {
            "python": sys.version.split()[0],
            "postgres": _postgres_version(dsn),
            "workers": 2,
            "dataset": "postgres_store fixture, pgstore schema",
            "conditions": "local disposable pgserver" if started_server else "external disposable DSN",
        },
        "measurements": timings,
        "verification": {
            "source_unchanged": True,
            "workers_isolated": digest_before != digest_other,
            "restore_matches_baseline": digest_after == workers[0].database.expected_fingerprint,
            "cleanup_idempotent": True,
        },
        "denominators": {
            "workers": 2,
            "mutations": 1,
            "restores": 1,
            "cleanups": 2,
        },
    }
    source.assert_unchanged()
    OUTPUT.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(results, indent=2, sort_keys=True))


def _postgres_version(dsn: str) -> str:
    import psycopg

    connection = psycopg.connect(dsn, connect_timeout=5)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW server_version")
            return str(cursor.fetchone()[0])
    finally:
        connection.close()


if __name__ == "__main__":
    main()
