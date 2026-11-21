"""Generic-engine proof tests for the PostgreSQL backend (Phase VII.1).

These tests prove, through the CLI path
``mizan twin --backend postgres`` -> ``PostgresRun`` -> ``PostgresTwin`` ->
``PostgresAttributor`` -> ``Mizan.learn() -> attack() -> write_bundles()``, that
the generic engine produces real L2/L3 findings, that replay and regression
reproduce them, and that the parallel workers actually overlap.

A second attack engine is never introduced here; the same ``Mizan`` class that
the CLI uses is the one under test.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from mizan.postgres_twin import (
    DatabaseRegistry,
    PostgresSource,
    RunInterrupted,
)

FIXTURE = Path(__file__).parent / "fixtures" / "external_apps" / "postgres_store"
DSN_ENV = "MIZAN_VII_TEST_DSN"
TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}


def _dsn() -> str:
    value = os.environ.get(DSN_ENV) or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if value:
        return value if "connect_timeout" in value else value + "?connect_timeout=5"
    pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required")
    return pgserver.get_server(
        pgdata=Path(tempfile.mkdtemp(prefix="mizan-vii-gp-pg-")), cleanup_mode="delete"
    ).get_uri()


@pytest.fixture(scope="module")
def dsn():
    value = _dsn()
    os.environ[DSN_ENV] = value
    # The source database is real but may be empty. Give the independent app a
    # chance to own its schema before a baseline is prepared from it.
    import importlib.util

    module_spec = importlib.util.spec_from_file_location("pgstore_generic", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
    os.environ["MIZAN_TOKEN_ALICE"] = TOKENS["alice"]
    os.environ["MIZAN_TOKEN_BOB"] = TOKENS["bob"]
    try:
        module.create_app("clean", dsn=value, schema="pgstore")
    finally:
        for key, original in previous.items():
            if original is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original
    return value


@pytest.fixture
def source(dsn):
    return PostgresSource(DSN_ENV, schemas=("pgstore",))


# --------------------------------------------------------------------------- #
# Generic CLI runs (detection, equivalence)
# --------------------------------------------------------------------------- #


def _run_twin_cli(variant: str, *, workers: int = 1) -> tuple[object, Path]:
    """Run ``mizan twin --backend postgres``; return (result, proof dir)."""
    from click.testing import CliRunner

    from mizan.cli import main

    workspace = Path(tempfile.mkdtemp(prefix=f"mizan-vii-gp-{variant}-w{workers}-"))
    out = workspace / "out"
    result = CliRunner().invoke(
        main,
        [
            "twin",
            "--backend",
            "postgres",
            "--command",
            f'"{sys.executable}" "{FIXTURE / "app.py"}" --port {{port}} --vulnerability {variant}',
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--allow-disposable",
            "--workers",
            str(workers),
            "--spec",
            str(FIXTURE / "openapi-generic.json"),
            "--relationship-contract",
            str(FIXTURE / "mizan-relationships.json"),
            "--token",
            f"alice={TOKENS['alice']}",
            "--token",
            f"bob={TOKENS['bob']}",
            "--workdir",
            str(workspace),
            "--out",
            str(out),
        ],
    )
    return result, out


def _status(result) -> dict:
    for line in result.output.splitlines():
        if line.startswith("postgres backend status:"):
            return json.loads(line.split("postgres backend status:", 1)[1])
    raise AssertionError(f"no backend status line in output:\n{result.output}")


def _bundle_laws(out: Path) -> list[str]:
    if not out.exists():
        return []
    return sorted({directory.name.split("-")[0].upper() for directory in out.iterdir() if directory.is_dir()})


def _equivalence_lines(result) -> tuple[list, list]:
    serial, parallel = [], []
    for line in result.output.splitlines():
        if line.startswith("serial: "):
            serial = json.loads(line[len("serial: ") :])
        elif line.startswith("parallel: "):
            parallel = json.loads(line[len("parallel: ") :])
    return serial, parallel


def _assert_clean(result, out: Path) -> None:
    assert result.exit_code == 0, result.output
    assert _bundle_laws(out) == [], f"expected no findings on the clean variant: {_bundle_laws(out)}"
    assert _status(result)["confirmed_findings"] == 0


@pytest.mark.postgres_integration
def test_generic_cli_clean_variant_finds_nothing(source, dsn) -> None:
    result, out = _run_twin_cli("clean")
    _assert_clean(result, out)
    assert _status(result)["laws_executed"] == ["L1", "L2", "L3", "L5"]


@pytest.mark.postgres_integration
def test_generic_cli_read_variant_detects_l2(source, dsn) -> None:
    result, out = _run_twin_cli("read")
    assert result.exit_code == 0, result.output
    assert _bundle_laws(out) == ["L2"], _bundle_laws(out)
    status = _status(result)
    assert status["confirmed_findings"] == 1
    instance_check(source)


@pytest.mark.postgres_integration
def test_generic_cli_write_variant_detects_l3(source, dsn) -> None:
    result, out = _run_twin_cli("write")
    assert result.exit_code == 0, result.output
    assert _bundle_laws(out) == ["L3"], _bundle_laws(out)
    status = _status(result)
    assert status["confirmed_findings"] == 1
    assert status["attributed_writes"] >= 1
    instance_check(source)


@pytest.mark.postgres_integration
def test_generic_cli_both_variant_detects_l2_and_l3(source, dsn) -> None:
    result, out = _run_twin_cli("both")
    assert result.exit_code == 0, result.output
    assert _bundle_laws(out) == ["L2", "L3"], _bundle_laws(out)
    assert _status(result)["confirmed_findings"] == 2


def instance_check(source) -> None:
    source.assert_unchanged()


# --------------------------------------------------------------------------- #
# Serial/parallel finding-producing equivalence
# --------------------------------------------------------------------------- #


@pytest.mark.postgres_integration
def test_serial_parallel_equivalence_is_finding_producing(source, dsn) -> None:
    result, out = _run_twin_cli("both", workers=2)
    assert result.exit_code == 0, result.output
    laws = _bundle_laws(out)
    assert laws == ["L2", "L3"], laws
    serial, parallel = _equivalence_lines(result)
    assert serial, "the serial run produced no serial: line"
    assert parallel, "the parallel run produced no parallel: line"
    # The normalized sets must be equal, and both must carry findings.
    assert {tuple(row) for row in serial} == {tuple(row) for row in parallel}
    serial_laws = {row[0] for row in serial}
    assert serial_laws == {"L2", "L3"}


# --------------------------------------------------------------------------- #
# Replay and regression (vulnerable and clean applications)
# --------------------------------------------------------------------------- #


class _AppServer:
    """A standalone app process in a thread, with its own disposable database."""

    def __init__(self, variant: str, dsn: str, name: str):
        import importlib.util

        from psycopg import sql
        from werkzeug.serving import make_server

        admin = _admin(dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
                cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        finally:
            admin.close()
        db_dsn = _dsn_with_database(dsn, name)
        spec = importlib.util.spec_from_file_location("pgstore_standalone", FIXTURE / "app.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
        os.environ["MIZAN_TOKEN_ALICE"] = TOKENS["alice"]
        os.environ["MIZAN_TOKEN_BOB"] = TOKENS["bob"]
        try:
            self.app = module.create_app(variant, dsn=db_dsn, schema="pgstore")
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.name = name
        self.server = make_server("127.0.0.1", _free_port(), self.app, threaded=True)
        self.url = f"http://127.0.0.1:{self.server.port}"

    def start(self):
        import threading

        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        deadline = 120
        while deadline > 0:
            import time

            try:
                import requests

                response = requests.get(f"{self.url}/health", timeout=2)
                if response.status_code < 500:
                    return self
            except Exception:
                pass
            deadline -= 0.5
            time.sleep(0.5)
        raise AssertionError(f"the standalone app did not answer on {self.url}/health")

    def stop(self):
        from psycopg import sql

        self.server.shutdown()
        self.server.server_close()
        admin = _admin(_dsn())
        try:
            with admin.cursor() as cursor:
                cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(self.name)))
        finally:
            admin.close()


def _dsn_with_database(dsn: str, name: str) -> str:
    parts = urlsplit(dsn)
    return f"{parts.scheme}://{parts.netloc}/{name}"


def _free_port() -> int:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _admin(dsn: str):
    import psycopg

    return psycopg.connect(dsn, autocommit=True)


def _run_cli(args, extra_env=None):
    from click.testing import CliRunner

    from mizan.cli import main

    return CliRunner().invoke(main, args)


@pytest.mark.postgres_integration
def test_proof_replay_reproduces_on_vulnerable_and_is_blocked_on_clean(source, dsn) -> None:
    result, out = _run_twin_cli("both")
    assert result.exit_code == 0, result.output
    bundles = [directory for directory in out.iterdir() if directory.is_dir()]
    assert bundles

    vulnerable = _AppServer("both", dsn, "mizan_vii_gp_replay_vuln").start()
    clean = _AppServer("clean", dsn, "mizan_vii_gp_replay_clean").start()
    try:
        result_bad = _run_cli(["replay", str(out), "--target", vulnerable.url, "--token", TOKENS["bob"]])
        assert result_bad.exit_code == 1, f"vulnerable app: {result_bad.output}\n{result_bad.exception!r}"
        assert "STILL REPRODUCIBLE" in result_bad.output, result_bad.output

        result_good = _run_cli(["replay", str(out), "--target", clean.url, "--token", TOKENS["bob"]])
        assert result_good.exit_code == 0, f"clean app: {result_good.output}\n{result_good.exception!r}"
        assert "blocked" in result_good.output.lower() or "all" in result_good.output.lower(), result_good.output
    finally:
        vulnerable.stop()
        clean.stop()
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_regress_command_generates_failing_test_on_vulnerable_and_passing_on_clean(source, dsn) -> None:
    import subprocess

    result, out = _run_twin_cli("both")
    assert result.exit_code == 0, result.output
    bundle = next(directory for directory in out.iterdir() if directory.is_dir())

    reg = Path(tempfile.mkdtemp(prefix="mizan-vii-gp-reg-"))
    runner = _run_cli(["regress", str(bundle), "--out", str(reg)])
    assert runner.exit_code == 0, runner.output
    generated = list(reg.glob("test_mizan_*.py"))
    assert generated, runner.output

    vulnerable = _AppServer("both", dsn, "mizan_vii_gp_reg_vuln").start()
    clean = _AppServer("clean", dsn, "mizan_vii_gp_reg_clean").start()
    try:
        for app in (vulnerable, clean):
            run = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", str(generated[0])],
                env={**os.environ, "MIZAN_TARGET": app.url, "MIZAN_TOKEN_BOB": TOKENS["bob"]},
                capture_output=True,
                text=True,
                timeout=300,
            )
            expected = app.url == vulnerable.url
            assert (run.returncode != 0) == expected, f"{app.url}:\n{run.stdout}\n{run.stderr}"
            if not expected:
                assert "passed" in run.stdout, run.stdout
    finally:
        vulnerable.stop()
        clean.stop()


# --------------------------------------------------------------------------- #
# Parallel workers: overlap and failure recovery
# --------------------------------------------------------------------------- #


def _postgres_run(instance, workspace, *, variant="both", env=None):
    from mizan.postgres_engine import PostgresRun

    run = PostgresRun(
        instance,
        instance.prepare_baseline(workspace),
        DatabaseRegistry(workspace / "ownership.json"),
        workspace,
        [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}", "--vulnerability", variant],
        tokens=TOKENS,
        traffic_path=workspace / "traffic.jsonl",
        pool_size=2,
        env=env,
    )
    return run


def _databases(dsn: str) -> list[str]:

    admin = _admin(dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT datname FROM pg_database WHERE datname LIKE 'mizan_v61%' ORDER BY 1")
            return [str(row[0]) for row in cursor.fetchall()]
    finally:
        admin.close()


def _exists(dsn: str, name: str) -> bool:
    admin = _admin(dsn)
    try:
        from mizan.postgres_twin import database_exists

        return database_exists(admin, name)
    finally:
        admin.close()


@pytest.mark.postgres_integration
def test_parallel_workers_really_overlap(source, dsn) -> None:
    import requests

    workspace = Path(tempfile.mkdtemp(prefix="mizan-vii-gp-ovl-"))
    rendezvous = workspace / "rendezvous"
    run = _postgres_run(
        source,
        workspace,
        env={"MIZAN_FIXTURE_RENDEZVOUS_DIR": str(rendezvous)},
    )
    captured: list[list] = []

    def hook(twins) -> None:
        captured.extend(twins)
        assert len(twins) == 2

        def call(base_url: str):
            response = requests.post(
                f"{base_url}/__barrier",
                json={"id": "overlap", "parties": 2, "timeout": 15},
                timeout=30,
            )
            return response.status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = [future.result() for future in [executor.submit(call, t.base_url) for t in twins]]
        assert statuses == [200, 200], statuses

    try:
        results = run.parallel_attack(2, on_workers_ready=hook)
        assert [wid for wid, _ in results] == ["p0", "p1"]
        assert len(captured) == 2
        # Per-worker traffic logs are separate files, not a shared mutable one.
        paths = [run.worker_traffic_path(t) for t in captured]
        assert len(set(paths)) == 2
    finally:
        run.cleanup()
    assert not [name for name in _databases(dsn) if name in {twin.database.name for twin in captured}]
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_parallel_worker_attack_failure_reaps_every_worker(source, dsn) -> None:
    run = _postgres_run(source, Path(tempfile.mkdtemp(prefix="mizan-vii-gp-fail-")))
    captured: list = []

    def attack_hook(twin):
        if twin.worker_id == "p1":
            raise RuntimeError("injected worker failure")

    def ready_hook(twins):
        captured.extend(twins)

    try:
        with pytest.raises(RuntimeError, match="injected worker failure"):
            run.parallel_attack(2, on_workers_ready=ready_hook, on_worker_attack=attack_hook)
    finally:
        run.cleanup()
    assert run.twins == []
    assert not _databases(dsn)
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_parallel_worker_start_failure_reaps_workers(source, dsn) -> None:
    run = PostgresRunFor(source, Path(tempfile.mkdtemp(prefix="mizan-vii-gp-startfail-")))
    run.command = [sys.executable, "-c", "import sys; sys.exit(3)"]
    try:
        with pytest.raises(RuntimeError, match="the application exited"):
            run.parallel_attack(2)
    finally:
        run.cleanup()
    assert run.twins == []
    assert not _databases(dsn)
    source.assert_unchanged()


def PostgresRunFor(instance, workspace):
    from mizan.postgres_engine import PostgresRun

    return PostgresRun(
        instance,
        instance.prepare_baseline(workspace),
        DatabaseRegistry(workspace / "ownership.json"),
        workspace,
        [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}", "--vulnerability", "both"],
        tokens=TOKENS,
        traffic_path=workspace / "traffic.jsonl",
        pool_size=2,
    )


@pytest.mark.postgres_integration
def test_parallel_attack_cancellation_cleans_up(source, dsn) -> None:
    run = _postgres_run(source, Path(tempfile.mkdtemp(prefix="mizan-vii-gp-cancel-")))

    def cancel():
        raise RunInterrupted("cancelled in the test")

    try:
        with pytest.raises(RunInterrupted):
            run.parallel_attack(2, cancel=cancel)
    finally:
        run.cleanup()
    assert run.twins == []
    assert not _databases(dsn)
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_worker_process_death_is_recovered_by_restore(source, dsn) -> None:
    import threading

    run = _postgres_run(source, Path(tempfile.mkdtemp(prefix="mizan-vii-gp-dead-")))
    killed: dict = {}
    observed: set[int] = set()
    stop_watching = threading.Event()

    def watch():
        while not stop_watching.is_set():
            twin = killed.get("twin")
            if twin is not None and twin._twin is not None and twin._twin.process is not None:
                observed.add(twin._twin.process.pid)
            stop_watching.wait(0.02)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()

    def attack_hook(twin):
        if twin.worker_id == "p0":
            killed["twin"] = twin
            killed["pid"] = twin._twin.process.pid
            with contextlib.suppress(Exception):
                twin._twin.process.kill()

    try:
        results = run.parallel_attack(2, on_worker_attack=attack_hook)
        assert [worker_id for worker_id, _ in results] == ["p0", "p1"]
    finally:
        stop_watching.set()
        watcher.join(timeout=5)
        run.cleanup()
    # The generic engine restores before every probe group, so the killed
    # worker came back with a fresh process instead of tainting p1.
    assert len(observed) >= 2, observed
    assert killed["pid"] in observed
    assert run.twins == []
    assert not _databases(dsn)
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_run_cleanup_after_normal_run(source, dsn) -> None:
    run = _postgres_run(source, Path(tempfile.mkdtemp(prefix="mizan-vii-gp-cleanup-")))
    twins = [run.start_worker("w0"), run.start_worker("w1")]
    try:
        assert len({twin.database.name for twin in twins}) == 2
    finally:
        cleaned = run.cleanup()
    assert {twin.database.name for twin in twins}.issubset(cleaned)
    assert len(cleaned) >= 3  # two workers and the immutable seed
    assert run.twins == []
    assert not _databases(dsn)
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_worker_traffic_logs_are_isolated(source, dsn) -> None:
    run = _postgres_run(source, Path(tempfile.mkdtemp(prefix="mizan-vii-gp-traffic-")))
    twins = [run.start_worker("w0"), run.start_worker("w1")]
    try:
        paths = [run.worker_traffic_path(twin) for twin in twins]
        assert len(set(paths)) == 2
        assert all(path.name.startswith("traffic-") for path in paths)
    finally:
        run.cleanup()
    source.assert_unchanged()
