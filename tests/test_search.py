"""Tests for the guided search.

The search must find the breaches with a bounded number of requests, and it
must be able to chain requests: read something first, then use what it revealed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import requests

from mizan.attribution import SqliteAttributor
from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.search import GuidedSearch
from mizan.tokens import make_token
from mizan.twin import Twin, TwinSpec, python_command

SPEC_PATH = Path(__file__).resolve().parents[1] / "src" / "mizan" / "demo" / "openapi.json"


@pytest.fixture()
def demo(tmp_path: Path):
    """The demo application, running as a process, with a twin."""
    db_path = tmp_path / "demo.sqlite"
    twin = Twin(
        TwinSpec(
            command=python_command("mizan.demo.server", "--db", str(db_path), "--port", "{port}"),
            workdir=tmp_path,
            data_paths=[db_path],
        ),
        workspace=tmp_path / "twin",
    )
    twin.start()
    principals = [
        Principal(id="alice", roles=("user",), token=make_token("alice")),
        Principal(id="bob", roles=("user",), token=make_token("bob")),
    ]

    def session(user: str) -> requests.Session:
        s = requests.Session()
        s.headers["Authorization"] = f"Bearer {make_token(user)}"
        return s

    alice = session("alice")
    bob = session("bob")
    alice.get(f"{twin.base_url}/me")
    alice.get(f"{twin.base_url}/orders")
    alice.get(f"{twin.base_url}/orders/o1")
    alice.put(f"{twin.base_url}/orders/o1", json={"status": "paid"})
    alice.patch(f"{twin.base_url}/users/me", json={"name": "Alice"})
    bob.get(f"{twin.base_url}/me")
    bob.get(f"{twin.base_url}/orders/o2")
    twin.snapshot()

    engine = Mizan(
        Target(base_url=twin.base_url, principals=principals),
        traffic_path=None,
        spec_path=SPEC_PATH,
        twin=twin,
        attributor=SqliteAttributor(db_path),
    )
    # The traffic was written by the application itself in this fixture, so
    # the engine learns from a log built from the same requests.
    engine.traffic = _traffic_from_requests(twin, principals)
    engine.learn()
    try:
        yield engine
    finally:
        twin.stop()


def _traffic_from_requests(twin: Twin, principals: list[Principal]):
    """A traffic log built from the requests the fixture sent."""
    from mizan.traffic import TrafficLog, TrafficRecord, infer_resource, to_template

    log = TrafficLog()
    calls = [
        ("alice", "GET", "/me", None),
        ("alice", "GET", "/orders", None),
        ("alice", "GET", "/orders/o1", None),
        ("alice", "PUT", "/orders/o1", {"status": "paid"}),
        ("alice", "PATCH", "/users/me", {"name": "Alice"}),
        ("bob", "GET", "/me", None),
        ("bob", "GET", "/orders/o2", None),
    ]
    for principal, method, path, body in calls:
        session = requests.Session()
        session.headers["Authorization"] = f"Bearer {make_token(principal)}"
        url = f"{twin.base_url}{path}"
        if method == "GET":
            response = session.get(url, timeout=10)
        else:
            response = session.request(method, url, json=body, timeout=10)
        try:
            payload = response.json()
        except Exception:
            payload = None
        template = to_template(path)
        resource_type, resource_id, resource_owner = infer_resource(payload, template)
        log.records.append(
            TrafficRecord(
                method=method,
                path=path,
                template=template,
                status=response.status_code,
                principal=principal,
                body=body,
                response=payload,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_owner=resource_owner,
            )
        )
    return log


def test_guided_search_finds_the_breaches(demo: Mizan) -> None:
    search = GuidedSearch(demo, budget=30, depth=2)
    result = search.run()
    assert result.laws, "the search found nothing"
    assert "L2" in result.laws, "the search did not find the cross-identity read"
    assert result.requests <= 60, "the search used more requests than the budget allows"


def test_guided_search_is_reproducible(demo: Mizan) -> None:
    first = GuidedSearch(demo, budget=20, depth=2).run()
    second = GuidedSearch(demo, budget=20, depth=2).run()
    assert first.laws == second.laws
    assert [action.key for action in first.best_sequence] == [action.key for action in second.best_sequence]


def test_guided_search_chains_discovered_identifiers(demo: Mizan) -> None:
    """The search may use an identifier it found in a response."""
    search = GuidedSearch(demo, budget=30, depth=2)
    search.run()
    assert search._discovered_ids, "the search did not learn any identifier"


def test_guided_search_reports_a_sequence(demo: Mizan) -> None:
    result = GuidedSearch(demo, budget=25, depth=2).run()
    assert result.best_sequence, "the search has no sequence to report"
    for action in result.best_sequence:
        assert action.method
        assert action.path.startswith("/")
        assert action.principal
