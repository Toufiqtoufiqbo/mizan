"""Generic/SQLite L4: trusted field policy with real persisted-state proof."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mizan.attribution import SqliteAttributor
from mizan.benchmark.apps import BenchmarkApp, serve
from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.ownership import RelationshipContract
from mizan.traffic import TrafficRecord


def _contract() -> RelationshipContract:
    return RelationshipContract.from_dict(
        {
            "version": 1,
            "authority": {
                "fields": [
                    {
                        "resource_type": "users",
                        "field": "role",
                        "source": "trusted_contract",
                        "confidence": "confirmed",
                        "authorized_roles": ["admin"],
                        "table": "users",
                    }
                ]
            },
        },
        strict=True,
    )


def _engine(bugs: tuple[str, ...], port: int, db: Path) -> Mizan:
    tokens = app_tokens(bugs, db)
    engine = Mizan(
        Target(
            base_url=f"http://127.0.0.1:{port}",
            principals=[Principal(id="alice", token=tokens["alice"], roles=("user",))],
        ),
        attributor=SqliteAttributor(db),
        relationship_contract=_contract(),
    )
    engine.traffic.records = [
        TrafficRecord(
            method="PATCH",
            path="/users/me",
            status=200,
            principal="alice",
            body={"role": "user"},
            response={"id": "alice", "role": "user"},
            resource_type="users",
            resource_id="alice",
            resource_owner="alice",
        )
    ]
    engine.learn()
    return engine


def app_tokens(bugs: tuple[str, ...], db: Path) -> dict[str, str]:
    app = BenchmarkApp(db, bugs=bugs)
    return app.tokens()


@pytest.mark.parametrize(
    ("bugs", "expected_findings"),
    [(("mass_assignment",), 1), ((), 0)],
)
def test_sqlite_l4_persisted_state_decides_authority(bugs, expected_findings) -> None:
    db = Path(tempfile.mkdtemp()) / "app.sqlite"
    app = BenchmarkApp(db, bugs=bugs)
    server, port, _ = serve(app)
    try:
        engine = _engine(bugs, port, db)
        violations = engine.attack(groups=["L4"])
        assert len(violations) == expected_findings
        if expected_findings:
            evidence = violations[0].evidence
            assert evidence["field"] == "role"
            assert evidence["original_value"] == "user"
            assert evidence["persisted_value"] == evidence["attempted_value"]
            assert evidence["state_verification"] == "attributed database write"
        assert engine.executed_by_law.get("L4") == 1
        assert engine.coverage().laws["L4"].state.value == "executed"
    finally:
        server.shutdown()
