"""The twin, without Docker.

These tests run the real application as a real process, record its traffic
through a proxy, derive the writes from the database itself, and check that
Mizan still finds the planted bugs - and that the state is restored between
probes.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import requests

from mizan.attribution import SqliteAttributor
from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.proxy import RecordingProxy
from mizan.tokens import make_token
from mizan.twin import Twin, TwinSpec, free_port, python_command

SPEC_PATH = Path(__file__).resolve().parents[1] / "src" / "mizan" / "demo" / "openapi.json"


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    return tmp_path


def _twin_spec(db_path: Path, workspace: Path) -> TwinSpec:
    return TwinSpec(
        command=python_command(
            "mizan.demo.server",
            "--db",
            str(db_path),
            "--port",
            "{port}",
        ),
        workdir=workspace,
        data_paths=[db_path],
        health_path="/",
        health_timeout=30.0,
    )


def test_free_port_is_usable() -> None:
    port = free_port()
    assert 1024 < port < 65536


def test_twin_starts_and_stops_a_process(workspace: Path) -> None:
    db_path = workspace / "demo.sqlite"
    twin = Twin(_twin_spec(db_path, workspace), workspace=workspace / "twin")
    try:
        base_url = twin.start()
        assert base_url.startswith("http://127.0.0.1:")
        response = requests.get(f"{base_url}/me", timeout=10)
        assert response.status_code == 401  # the demo API answers
    finally:
        twin.stop()
    assert twin.process is None


def test_twin_restores_the_data(workspace: Path) -> None:
    db_path = workspace / "demo.sqlite"
    twin = Twin(_twin_spec(db_path, workspace), workspace=workspace / "twin")
    try:
        base_url = twin.start()
        token = make_token("alice")
        headers = {"Authorization": f"Bearer {token}"}
        requests.get(f"{base_url}/me", headers=headers, timeout=10)
        requests.patch(f"{base_url}/users/me", json={"name": "Changed"}, headers=headers, timeout=10)
        changed = requests.get(f"{base_url}/me", headers=headers, timeout=10).json()
        assert changed["name"] == "Changed"

        twin.snapshot()
        requests.patch(f"{base_url}/users/me", json={"name": "Again"}, headers=headers, timeout=10)
        assert requests.get(f"{base_url}/me", headers=headers, timeout=10).json()["name"] == "Again"

        twin.restore()
        restored = requests.get(f"{base_url}/me", headers=headers, timeout=10).json()
        assert restored["name"] == "Changed", "the state was not restored"
    finally:
        twin.stop()


def test_end_to_end_through_twin_proxy_and_attribution(workspace: Path) -> None:
    """No application changes: the proxy records, the database provides the writes."""
    db_path = workspace / "demo.sqlite"
    traffic_path = workspace / "traffic.jsonl"
    twin = Twin(_twin_spec(db_path, workspace), workspace=workspace / "twin")
    proxy = RecordingProxy(twin.base_url if twin.process else "http://127.0.0.1:1", traffic_path)
    try:
        twin.start()
        proxy = RecordingProxy(twin.base_url, traffic_path)
        proxy.start()

        alice = requests.Session()
        alice.headers["Authorization"] = f"Bearer {make_token('alice')}"
        bob = requests.Session()
        bob.headers["Authorization"] = f"Bearer {make_token('bob')}"

        # Normal traffic, recorded by the proxy.
        alice.get(f"{proxy.base_url}/me")
        alice.get(f"{proxy.base_url}/orders/o1")
        alice.get(f"{proxy.base_url}/orders/o3")
        alice.put(f"{proxy.base_url}/orders/o1", json={"status": "paid"})
        alice.patch(f"{proxy.base_url}/users/me", json={"name": "Alice Updated"})
        alice.post(f"{proxy.base_url}/orders/o1/approve")
        bob.get(f"{proxy.base_url}/me")
        bob.get(f"{proxy.base_url}/orders/o2")

        twin.snapshot()

        engine = Mizan(
            Target(
                base_url=proxy.base_url,
                principals=[
                    Principal(id="alice", roles=("user",), token=make_token("alice")),
                    Principal(id="bob", roles=("user",), token=make_token("bob")),
                ],
            ),
            traffic_path=traffic_path,
            spec_path=SPEC_PATH,
            attributor=SqliteAttributor(db_path),
            twin=twin,
        )
        engine.learn()
        violations = engine.attack()
        laws = {violation.law for violation in violations}
    finally:
        proxy.stop()
        twin.stop()

    assert "L2" in laws, "the cross-identity read was not found through the proxy"
    assert "L3" in laws, "the cross-identity write was not found through the database diff"
    assert "L4" in laws, "the mass assignment was not found through the database diff"
    assert "L5" in laws, "the race was not found through the proxy"


def test_probes_do_not_depend_on_each_other(workspace: Path) -> None:
    """With a twin, every probe starts from the same state."""
    db_path = workspace / "demo.sqlite"
    traffic_path = workspace / "traffic.jsonl"
    twin = Twin(_twin_spec(db_path, workspace), workspace=workspace / "twin")
    proxy = RecordingProxy("http://127.0.0.1:1", traffic_path)
    try:
        twin.start()
        proxy = RecordingProxy(twin.base_url, traffic_path)
        proxy.start()

        alice = requests.Session()
        alice.headers["Authorization"] = f"Bearer {make_token('alice')}"
        bob = requests.Session()
        bob.headers["Authorization"] = f"Bearer {make_token('bob')}"
        alice.get(f"{proxy.base_url}/me")
        alice.get(f"{proxy.base_url}/orders/o1")
        alice.get(f"{proxy.base_url}/orders/o3")
        alice.put(f"{proxy.base_url}/orders/o1", json={"status": "paid"})
        alice.patch(f"{proxy.base_url}/users/me", json={"name": "Alice Updated"})
        alice.post(f"{proxy.base_url}/orders/o1/approve")
        bob.get(f"{proxy.base_url}/me")
        bob.get(f"{proxy.base_url}/orders/o2")
        twin.snapshot()

        principals = [
            Principal(id="alice", roles=("user",), token=make_token("alice")),
            Principal(id="bob", roles=("user",), token=make_token("bob")),
        ]

        def run() -> set[str]:
            engine = Mizan(
                Target(base_url=proxy.base_url, principals=principals),
                traffic_path=traffic_path,
                spec_path=SPEC_PATH,
                attributor=SqliteAttributor(db_path),
                twin=twin,
            )
            engine.learn()
            return {violation.law for violation in engine.attack()}

        first = run()
        second = run()
    finally:
        proxy.stop()
        twin.stop()

    assert first == second, "the findings depend on the order the probes ran in"
    assert {"L2", "L3", "L4", "L5"} <= first
