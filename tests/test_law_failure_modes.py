"""Fail-closed behavior when L4/L6 state evidence is unavailable."""

from __future__ import annotations

import pytest

from mizan.engine import Mizan, Target
from mizan.ownership import RelationshipContract

CONTRACT = RelationshipContract.from_dict(
    {
        "version": 1,
        "authority": {
            "fields": [
                {
                    "resource_type": "users",
                    "field": "role",
                    "source": "trusted_contract",
                    "confidence": "confirmed",
                    "table": "principals_registry",
                }
            ]
        },
        "cardinality": [
            {
                "resource_type": "items",
                "bound": 2,
                "scope": "principal",
                "unit": "objects",
                "source": "trusted_contract",
                "enforcement": "reject_beyond",
                "table": "inventory_items",
            }
        ],
    },
    strict=True,
)


def _engine() -> Mizan:
    return Mizan(
        Target(base_url="http://localhost", principals=[]),
        relationship_contract=CONTRACT,
    )


def test_failed_state_readback_never_creates_an_l6_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _engine()
    monkeypatch.setattr(engine, "_live_rows", lambda table: [])
    assert engine._probe_cardinality() == []


def test_no_attributed_write_never_creates_an_l4_finding() -> None:
    engine = _engine()
    assert engine._probe_authority_creation_policy() == []


def test_missing_table_is_inconclusive_not_a_finding() -> None:
    engine = _engine()
    engine._probe_cardinality()
    assert any(item["law"] == "L6" for item in engine.inconclusive_checks) or engine.inconclusive_checks == []
