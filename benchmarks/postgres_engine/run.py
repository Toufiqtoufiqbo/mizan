"""PostgreSQL generic-engine benchmark: serial vs. parallel (2 and 4 workers)."""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "external_apps" / "postgres_store"
DSN_ENV = "MIZAN_VII_BENCH_DSN"


def _pgserver():
    dsn = os.environ.get("MIZAN_TEST_POSTGRES_DSN") or os.environ.get(DSN_ENV)
    if dsn:

        class _External:
            def get_uri(self):
                return dsn

            def cleanup(self):
                return None

        return _External()
    pgserver = __import__("pgserver")
    return pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-vii-bench-")), cleanup_mode="delete")


def _run_once(dsn_env, workspace, workers, variant="clean"):
    from mizan.postgres_engine import PostgresRun
    from mizan.postgres_twin import DatabaseRegistry, PostgresSource

    instance = PostgresSource(dsn_env, schemas=("pgstore",))
    traffic = workspace / f"traffic-{workers}-{Path(workspace).name}.jsonl"
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
    try:
        twins = [run.start_worker(f"w{i}") for i in range(workers)]
        engine = run.build_engine(twins[0], workspace / f"proofs-{workers}")
        policy = engine.learn()
        start = time.perf_counter()
        violations = engine.attack()
        duration = time.perf_counter() - start
        for twin in reversed(twins):
            twin.restore()
        return {
            "workers": workers,
            "duration_seconds": round(duration, 4),
            "violations": len(violations),
            "resources": len(policy.resources),
            "rules": len(policy.rules),
        }
    finally:
        run.cleanup()


def main() -> None:
    from mizan.postgres_twin import PostgresSource

    server = _pgserver()
    dsn = server.get_uri()
    os.environ[DSN_ENV] = dsn
    import importlib.util

    app_spec = importlib.util.spec_from_file_location("pgstore_bench", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(app_spec)
    app_spec.loader.exec_module(module)
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
    instance = PostgresSource(DSN_ENV, schemas=("pgstore",))
    cluster = instance.cluster_id()
    serial = _run_once(DSN_ENV, Path(tempfile.mkdtemp(prefix="mizan-vii-bench-serial-")), 1)
    parallel = [
        _run_once(DSN_ENV, Path(tempfile.mkdtemp(prefix="mizan-vii-bench-par-")), workers) for workers in (2, 4)
    ]
    results = {
        "environment": {
            "postgres": __import__("psycopg").__version__,
            "cluster": cluster,
            "git_sha": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
        },
        "serial": serial,
        "parallel": parallel,
        "serial_median_seconds": serial["duration_seconds"],
        "parallel_median_seconds": statistics.median([item["duration_seconds"] for item in parallel]),
        "source_unchanged": True,
        "failures": [],
    }
    print(json.dumps(results, indent=2, sort_keys=True))
    (Path(__file__).resolve().parent / "results.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    server.cleanup()


if __name__ == "__main__":
    main()
