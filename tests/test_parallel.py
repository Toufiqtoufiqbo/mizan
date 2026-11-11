"""Tests for parallel probing and the CI replay gate."""

from __future__ import annotations

from pathlib import Path

import pytest
import requests

from mizan.attribution import SqliteAttributor
from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.parallel import TwinPool, run_parallel
from mizan.proxy import RecordingProxy
from mizan.tokens import make_token
from mizan.twin import Twin, TwinSpec, python_command

SPEC_PATH = Path(__file__).resolve().parents[1] / "src" / "mizan" / "demo" / "openapi.json"


def _spec(data_name: str = "seed.sqlite") -> TwinSpec:
    return TwinSpec(
        command=python_command("mizan.demo.server", "--db", "{data}/" + data_name, "--port", "{port}"),
        workdir=Path.cwd(),
        data_paths=[],
        health_path="/",
        health_timeout=30.0,
    )


def _seed(directory: Path) -> Path:
    """Create the demo database in a directory, by running the app once."""
    from mizan.demo.app import DemoApp

    database = directory / "demo.sqlite"
    DemoApp(database)
    return database


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    return tmp_path


def test_pool_gives_every_worker_its_own_copy(workspace: Path) -> None:
    from mizan.demo.app import DemoApp

    source = workspace / "seed.sqlite"
    DemoApp(source)

    pool = TwinPool(
        _spec(),
        workers=2,
        workspace=workspace / "pool",
        data_paths=[source],
    )
    pool.start()
    try:
        assert len(pool.workers) == 2
        databases = {worker.data_paths[0] for worker in pool.workers}
        assert len(databases) == 2, "the workers share their data"
        urls = {worker.base_url for worker in pool.workers}
        assert len(urls) == 2, "the workers share their port"
        for worker in pool.workers:
            response = requests.get(f"{worker.base_url}/me", timeout=10)
            assert response.status_code == 401
    finally:
        pool.stop()


def test_parallel_attack_finds_the_same_laws(workspace: Path) -> None:
    """Two isolated copies, the same findings as a single one."""
    from mizan.demo.app import DemoApp

    source = workspace / "seed.sqlite"
    DemoApp(source)
    traffic_path = workspace / "traffic.jsonl"

    # One worker first: the reference result.
    reference_twin = Twin(
        TwinSpec(
            command=python_command("mizan.demo.server", "--db", str(source), "--port", "{port}"),
            workdir=workspace,
            data_paths=[source],
        ),
        workspace=workspace / "reference",
    )
    reference_twin.start()
    proxy = RecordingProxy(reference_twin.base_url, traffic_path)
    proxy.start()
    try:
        principals = [
            Principal(id="alice", roles=("user",), token=make_token("alice")),
            Principal(id="bob", roles=("user",), token=make_token("bob")),
        ]
        alice = requests.Session()
        alice.headers["Authorization"] = f"Bearer {make_token('alice')}"
        bob = requests.Session()
        bob.headers["Authorization"] = f"Bearer {make_token('bob')}"
        alice.get(f"{proxy.base_url}/me")
        alice.get(f"{proxy.base_url}/orders/o1")
        alice.get(f"{proxy.base_url}/orders/o3")
        alice.put(f"{proxy.base_url}/orders/o1", json={"status": "paid"})
        alice.patch(f"{proxy.base_url}/users/me", json={"name": "Alice"})
        bob.get(f"{proxy.base_url}/me")
        bob.get(f"{proxy.base_url}/orders/o2")
        reference_twin.snapshot()

        engine = Mizan(
            Target(base_url=proxy.base_url, principals=principals),
            traffic_path=traffic_path,
            spec_path=SPEC_PATH,
            twin=reference_twin,
            attributor=SqliteAttributor(source),
        )
        engine.learn()
        reference = {violation.law for violation in engine.attack()}
        # The reference run attacked the application, so its state changed.
        # The twin puts it back: the parallel run must start from the same
        # state, or it would see a different application.
        reference_twin.restore()
    finally:
        proxy.stop()
        reference_twin.stop()

    def build(base_url: str, data: list[Path], worker_twin=None):
        attributor = SqliteAttributor(data[0]) if data else None
        return Mizan(
            Target(base_url=base_url, principals=principals),
            traffic_path=traffic_path,
            spec_path=SPEC_PATH,
            attributor=attributor,
        )

    findings, executed = run_parallel(
        _spec(),
        workers=2,
        workspace=workspace / "pool",
        data_paths=[source],
        build_engine=build,
    )
    parallel = {violation.law for violation in findings}
    assert reference == parallel, "the parallel run found different laws"
    assert {"L2", "L3", "L4"} <= parallel
    assert len(executed) >= 4


def test_replay_gate_reports_a_still_vulnerable_application(workspace: Path) -> None:
    """The CI gate: the attacks of the bundles are replayed against a target."""
    from mizan.benchmark.apps import BenchmarkApp, serve
    from mizan.regression import Attack, attack_succeeds

    app = BenchmarkApp(workspace / "app.sqlite", bugs=("idor_read",))
    server, port, _ = serve(app)
    try:
        attack = Attack(
            law="L2",
            title="alice read an object owned by bob",
            method="GET",
            path="/orders/ord1",
            token_var="MIZAN_TOKEN_ALICE",
            headers={},
            body=None,
            expectation="rejected",
            principal="alice",
        )
        token = app.tokens()["alice"]
        assert attack_succeeds(attack, token, f"http://127.0.0.1:{port}") is True
    finally:
        server.shutdown()

    fixed = BenchmarkApp(workspace / "fixed.sqlite", bugs=())
    server, port, _ = serve(fixed)
    try:
        assert attack_succeeds(attack, fixed.tokens()["alice"], f"http://127.0.0.1:{port}") is False
    finally:
        server.shutdown()
