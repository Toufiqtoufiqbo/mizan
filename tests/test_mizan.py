"""Tests for Mizan.

The end-to-end test runs the real engine against the real demo application:
no mocks, no monkeypatching of the vulnerability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests

from mizan import Mizan, Policy, Principal, Rule, Target, WriteEvent
from mizan.core import AccessMatrix
from mizan.demo.app import DemoApp, serve
from mizan.proof import ProofBundle
from mizan.races import RaceOutcome, detect_race
from mizan.taint import PostgresLogParser, TaintAnalyzer
from mizan.tokens import make_token

SPEC_PATH = Path(__file__).resolve().parents[1] / "src" / "mizan" / "demo" / "openapi.json"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture()
def demo(tmp_path: Path):
    """Run the demo application and produce normal traffic against it."""
    db_path = tmp_path / "demo.sqlite"
    traffic_path = tmp_path / "traffic.jsonl"
    ledger_path = tmp_path / "ledger.jsonl"
    app = DemoApp(db_path, ledger_path=ledger_path, traffic_path=traffic_path)
    server, port, _thread = serve(app)
    base_url = f"http://127.0.0.1:{port}"

    alice = requests.Session()
    alice.headers["Authorization"] = f"Bearer {make_token('alice')}"
    alice.get(f"{base_url}/me")
    alice.get(f"{base_url}/orders/o1")
    alice.post(f"{base_url}/orders/o1/approve")
    alice.put(f"{base_url}/orders/o1", json={"status": "paid"})
    alice.patch(f"{base_url}/users/me", json={"name": "Alice Updated"})

    bob = requests.Session()
    bob.headers["Authorization"] = f"Bearer {make_token('bob')}"
    bob.get(f"{base_url}/me")
    bob.get(f"{base_url}/orders/o2")

    try:
        yield {
            "base_url": base_url,
            "traffic": traffic_path,
            "ledger": ledger_path,
            "principals": [
                Principal(id="alice", roles=("user",), token=make_token("alice")),
                Principal(id="bob", roles=("user",), token=make_token("bob")),
                Principal(id="root", roles=("admin",), token=make_token("root", "admin")),
            ],
        }
    finally:
        server.shutdown()


@pytest.fixture()
def engine(demo) -> Mizan:
    engine = Mizan(
        Target(base_url=demo["base_url"], principals=demo["principals"]),
        traffic_path=demo["traffic"],
        ledger_path=demo["ledger"],
        spec_path=SPEC_PATH,
    )
    engine.learn()
    return engine


# --------------------------------------------------------------------------- #
# Learning
# --------------------------------------------------------------------------- #


def test_learn_infers_ownership_rules(engine: Mizan) -> None:
    policy = engine.policy
    assert "orders:o1" in policy.resources
    assert policy.resources["orders:o1"].owner == "alice"
    assert policy.resources["orders:o2"].owner == "bob"
    assert Rule(kind="owner", action="read", resource_type="orders") in policy.rules
    assert Rule(kind="owner", action="write", resource_type="orders") in policy.rules


def test_learn_does_not_turn_shared_roles_into_rules(engine: Mizan) -> None:
    # A shared role such as "user" says nothing about ownership.
    assert not [rule for rule in engine.policy.rules if rule.kind == "role" and rule.role == "user"]


def test_learn_marks_server_managed_fields(engine: Mizan) -> None:
    # `status` is written by the server when an order is approved.
    assert "status" in engine.policy.server_managed_fields.get("orders", set())


# --------------------------------------------------------------------------- #
# Access matrix
# --------------------------------------------------------------------------- #


def test_access_matrix_residual_and_norm() -> None:
    observed = AccessMatrix()
    permitted = AccessMatrix()
    observed.grant("alice", "orders:o1", "read")
    permitted.grant("alice", "orders:o1", "read")
    observed.grant("bob", "orders:o1", "read")
    observed.grant("bob", "orders:o1", "write")

    residual = observed.residual(permitted)
    assert len(residual) == 2
    assert residual.norm()["bob"] == pytest.approx(2**0.5)


# --------------------------------------------------------------------------- #
# Write taint
# --------------------------------------------------------------------------- #


def test_taint_flags_cross_identity_write() -> None:
    policy = Policy(
        principals={"bob": Principal(id="bob")},
        resources={"orders:o1": _resource("orders", "o1", owner="alice")},
        rules=[Rule(kind="owner", action="write", resource_type="orders")],
    )
    event = WriteEvent(
        ts=0.0,
        request_id="r1",
        principal="bob",
        method="PUT",
        path="/orders/o1",
        table="orders",
        row_id="o1",
        columns={"status": "paid"},
        source_fields={"status"},
        row_owner="alice",
    )
    violations = TaintAnalyzer(policy).analyze([event])
    assert [violation.law for violation in violations] == ["L3"]


def test_taint_flags_authority_creation() -> None:
    policy = Policy(
        principals={"alice": Principal(id="alice")},
        resources={"users:alice": _resource("users", "alice", owner="alice")},
        rules=[Rule(kind="owner", action="write", resource_type="users")],
    )
    event = WriteEvent(
        ts=0.0,
        request_id="r2",
        principal="alice",
        method="PATCH",
        path="/users/me",
        table="users",
        row_id="alice",
        columns={"role": "admin"},
        source_fields={"role"},
        row_owner="alice",
    )
    violations = TaintAnalyzer(policy).analyze([event])
    assert [violation.law for violation in violations] == ["L4"]
    assert violations[0].severity == "critical"


def test_taint_accepts_legitimate_self_write() -> None:
    policy = Policy(
        principals={"alice": Principal(id="alice")},
        resources={"users:alice": _resource("users", "alice", owner="alice")},
        rules=[Rule(kind="owner", action="write", resource_type="users")],
    )
    event = WriteEvent(
        ts=0.0,
        request_id="r3",
        principal="alice",
        method="PATCH",
        path="/users/me",
        table="users",
        row_id="alice",
        columns={"name": "Alice"},
        source_fields={"name"},
        row_owner="alice",
    )
    assert TaintAnalyzer(policy).analyze([event]) == []


def test_postgres_log_parser_attributes_writes() -> None:
    parser = PostgresLogParser()
    lines = [
        "2026-11-10 12:00:00.000 UTC [1] mizan:alice LOG:  statement: "
        "UPDATE orders SET status = 'approved' WHERE id = 'o1'",
        "2026-11-10 12:00:01.000 UTC [1] mizan:bob LOG:  statement: UPDATE orders SET amount = 5 WHERE id = 'o2'",
        "2026-11-10 12:00:02.000 UTC [1] someapp LOG:  statement: SELECT 1",
    ]
    events = parser.parse(lines)
    assert [event.principal for event in events] == ["alice", "bob"]
    assert events[0].table == "orders"
    assert events[0].columns["status"] == "approved"
    assert events[0].row_id == "o1"


# --------------------------------------------------------------------------- #
# Races
# --------------------------------------------------------------------------- #


def test_detect_race_flags_identical_transition_twice() -> None:
    events = [
        WriteEvent(
            ts=0.0,
            request_id="a",
            principal="alice",
            method="POST",
            path="/orders/o1/approve",
            table="orders",
            row_id="o1",
            columns={"status": "approved"},
            row_owner="alice",
        ),
        WriteEvent(
            ts=0.0,
            request_id="b",
            principal="alice",
            method="POST",
            path="/orders/o1/approve",
            table="orders",
            row_id="o1",
            columns={"status": "approved"},
            row_owner="alice",
        ),
    ]
    outcome = RaceOutcome(url="/orders/o1/approve", method="POST", statuses=[200, 200])
    violation = detect_race(outcome=outcome, before=[], after=events, principal="alice")
    assert violation is not None
    assert violation.law == "L5"


def test_detect_race_ignores_rejected_second_request() -> None:
    outcome = RaceOutcome(url="/orders/o1/approve", method="POST", statuses=[200, 409])
    assert detect_race(outcome=outcome, before=[], after=[], principal="alice") is None


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


def test_end_to_end_finds_every_planted_bug(engine: Mizan) -> None:
    violations = engine.attack()
    laws = {violation.law for violation in violations}
    assert "L2" in laws, "cross-identity read was not detected"
    assert "L3" in laws, "cross-identity write was not detected"
    assert "L4" in laws, "mass assignment was not detected"
    assert "L5" in laws, "the race condition was not detected"


def test_end_to_end_has_no_false_positives_on_legitimate_traffic(engine: Mizan) -> None:
    violations = engine.attack()
    # Writing your own profile is not a finding - unless the field grants
    # authority, which is L4 and expected.
    for violation in violations:
        if violation.law == "L3":
            assert violation.resource != "users:bob", "a self-write was reported"
    assert not [violation for violation in violations if violation.principal == "root"], "the admin was flagged"


def test_proof_bundle_is_replayable(engine: Mizan, tmp_path: Path) -> None:
    violations = engine.attack()
    directories = engine.write_bundles(violations, tmp_path / "proofs")
    assert directories
    for directory in directories:
        replay = json.loads((directory / "replay.json").read_text(encoding="utf-8"))
        assert replay["steps"], "a bundle without steps cannot be replayed"
        assert (directory / "violation.md").exists()
        assert (directory / "evidence.json").exists()
        assert (directory / "matrix.json").exists()


def test_proof_bundle_replays_against_the_target(engine: Mizan, demo, tmp_path: Path) -> None:
    violations = engine.attack()
    directories = engine.write_bundles(violations, tmp_path / "proofs")
    read_bundle = next(directory for directory in directories if directory.name.startswith("L2"))
    from mizan.tokens import TokenResolver

    resolver = TokenResolver(
        tokens={
            "alice": make_token("alice"),
            "bob": make_token("bob"),
        }
    )
    result = ProofBundle.load(read_bundle).verify(requests.Session(), resolver=resolver)
    statuses = [step.get("status") for step in result["steps"]]
    assert statuses and all(status == 200 for status in statuses), "the replay did not reproduce the finding"


def test_report_shows_the_residual(engine: Mizan) -> None:
    engine.attack()
    report = engine.report()
    assert report["residual_cells"] > 0
    assert any(value > 0 for value in report["residual_norm"].values())


def _resource(resource_type: str, resource_id: str, owner: str):
    from mizan.core import Resource

    return Resource(type=resource_type, id=resource_id, owner=owner)
