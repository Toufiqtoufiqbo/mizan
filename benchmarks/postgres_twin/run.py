"""Reproducible PostgreSQL Twin benchmark with executed verification.

Every verification flag is computed from a real observation. The benchmark
records repetitions, median and P95 instead of a single timing, and keeps the
local disposable fixture separate from any production claim.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "external_apps" / "postgres_store"
OUTPUT = Path(__file__).resolve().parent / "results.json"
DSN_ENV = "MIZAN_V62_BENCH_DSN"
WORKERS = 2
POOL_SIZE = 2
REPETITIONS = max(1, int(os.environ.get("MIZAN_BENCH_REPETITIONS", "3")))


def _load_fixture():
    spec = importlib.util.spec_from_file_location("pgstore_bench", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stats(values: list[float]) -> dict[str, float | int]:
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "n": len(ordered),
        "min": round(ordered[0], 4),
        "median": round(statistics.median(ordered), 4),
        "p95": round(ordered[index], 4),
        "max": round(ordered[-1], 4),
    }


def _git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def _git_dirty() -> bool:
    try:
        return (
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            != ""
        )
    except Exception:
        return True


def _database_exists(dsn: str, name: str) -> bool:
    import psycopg

    connection = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            return cursor.fetchone() is not None
    finally:
        connection.close()


def _postgres_versions(dsn: str) -> dict[str, str]:
    import psycopg

    connection = psycopg.connect(dsn, connect_timeout=5)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW server_version")
            server = str(cursor.fetchone()[0])
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
    finally:
        connection.close()
    return {"server": server, "psycopg": psycopg.__version__, "cluster": cluster}


def main() -> None:
    from mizan.postgres_twin import DatabaseRegistry, PostgresSource, PostgresTwin, cleanup_run

    dsn = os.environ.get(DSN_ENV) or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    started_server = None
    if dsn:
        dsn = dsn if "connect_timeout" in dsn else dsn + ("&connect_timeout=5" if "?" in dsn else "?connect_timeout=5")
        os.environ[DSN_ENV] = dsn
    else:
        pgserver = __import__("pgserver")
        started_server = pgserver.get_server(
            pgdata=Path(tempfile.mkdtemp(prefix="mizan-v62-bench-")), cleanup_mode="delete"
        )
        dsn = started_server.get_uri()
        os.environ[DSN_ENV] = dsn

    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-bench-work-"))
    fixture = _load_fixture()
    previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
    os.environ["MIZAN_TOKEN_ALICE"] = "bench-alice"
    os.environ["MIZAN_TOKEN_BOB"] = "bench-bob"
    try:
        fixture.create_app("clean", dsn=dsn, schema="pgstore")
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    source = PostgresSource(DSN_ENV, schemas=("pgstore",))
    registry = DatabaseRegistry(workspace / "ownership.json")
    measurements: dict[str, list[float]] = {}
    failures: list[str] = []
    verification: dict[str, object] = {}

    begin = time.perf_counter()
    baseline = source.prepare_baseline(workspace)
    measurements["baseline_prepare_seconds"] = [round(time.perf_counter() - begin, 4)]

    workers: list[PostgresTwin] = []
    command = [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}"]
    for index in range(WORKERS):
        begin = time.perf_counter()
        twin = PostgresTwin(
            source,
            baseline,
            registry,
            f"w{index}",
            command=command,
            workdir=workspace,
            pool_size=POOL_SIZE,
            env={"MIZAN_TOKEN_ALICE": "bench-alice", "MIZAN_TOKEN_BOB": "bench-bob"},
        )
        twin.start()
        measurements.setdefault("worker_startup_seconds", []).append(round(time.perf_counter() - begin, 4))
        workers.append(twin)

    begin = time.perf_counter()
    with workers[0].database.connect().cursor() as cursor:
        cursor.execute('CREATE TABLE "pgstore"."bench_probe" (id TEXT PRIMARY KEY)')
    measurements["mutation_seconds"] = [round(time.perf_counter() - begin, 4)]

    digest_before = source.fingerprint(workers[0].database.dsn)
    digest_other = source.fingerprint(workers[1].database.dsn)
    verification["workers_isolated"] = digest_before != digest_other
    if not verification["workers_isolated"]:
        failures.append("worker databases were not isolated after a mutation")

    restores: list[float] = []
    restore_matches: list[bool] = []
    for _ in range(REPETITIONS):
        begin = time.perf_counter()
        workers[0].restore()
        restores.append(round(time.perf_counter() - begin, 4))
        matches = source.fingerprint(workers[0].database.dsn) == baseline.fingerprint
        restore_matches.append(matches)
        if not matches:
            failures.append("a restored worker did not match the immutable baseline")
    measurements["restore_seconds"] = restores
    verification["restore_matches_baseline"] = all(restore_matches)
    verification["restore_attempts"] = len(restore_matches)

    cleanup_times: list[float] = []
    cleanup_idempotent = True
    for twin in reversed(workers):
        begin = time.perf_counter()
        twin.cleanup()
        cleanup_times.append(round(time.perf_counter() - begin, 4))
        try:
            begin = time.perf_counter()
            twin.cleanup()
            cleanup_times.append(round(time.perf_counter() - begin, 4))
        except Exception as exc:  # pragma: no cover - reported, not hidden
            cleanup_idempotent = False
            failures.append(f"a repeated cleanup failed: {exc}")
    measurements["cleanup_seconds"] = cleanup_times
    verification["cleanup_idempotent"] = cleanup_idempotent

    seed_cleaned = cleanup_run(DSN_ENV, workspace, source.run_id)
    verification["seed_cleaned"] = baseline.name in seed_cleaned and not _database_exists(dsn, baseline.name)
    verification["workers_cleaned"] = all(not _database_exists(dsn, twin.database.name) for twin in workers)
    if not verification["seed_cleaned"]:
        failures.append("the seed database survived verified cleanup")
    if not verification["workers_cleaned"]:
        failures.append("a worker database survived verified cleanup")

    before_source = baseline.fingerprint
    try:
        source.assert_unchanged()
        verification["source_unchanged"] = source.fingerprint() == before_source
    except Exception as exc:
        verification["source_unchanged"] = False
        failures.append(f"the source changed during the benchmark: {exc}")

    results = {
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "postgres": _postgres_versions(dsn),
            "workers": WORKERS,
            "pool_size": POOL_SIZE,
            "repetitions_per_operation": REPETITIONS,
            "dataset": "postgres_store fixture, pgstore schema, local fixture only",
            "conditions": "local disposable pgserver" if started_server else "external disposable DSN",
            "git_sha": _git_sha(),
            "git_dirty": _git_dirty(),
        },
        "measurements": {name: _stats(values) for name, values in measurements.items()},
        "raw_seconds": measurements,
        "verification": verification,
        "failures": failures,
        "denominators": {
            "workers": WORKERS,
            "mutations": 1,
            "restores": REPETITIONS,
            "cleanups": len(cleanup_times),
        },
    }
    OUTPUT.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2, sort_keys=True))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
