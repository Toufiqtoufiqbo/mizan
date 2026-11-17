"""Reproducible PostgreSQL ownership scenarios with independent expectations."""

from __future__ import annotations

from typing import Any

#: Expected outcomes are declared here, independently of Mīzān's output.
#: ``findings`` and ``inconclusive`` are the number of L3 outcomes expected.
SCENARIOS: list[dict[str, Any]] = [
    {
        "name": "clean_owner_write",
        "owner": "alice",
        "actor": "alice",
        "contract_owner": True,
        "request_id": "req-clean",
        "expected": {"findings": 0, "inconclusive": 0, "grant": 0},
    },
    {
        "name": "candidate_owner_never_finds",
        "owner": "alice",
        "actor": "bob",
        "contract_owner": False,
        "request_id": "req-candidate",
        "expected": {"findings": 0, "inconclusive": 1, "grant": 0},
    },
    {
        "name": "confirmed_bola_write",
        "owner": "alice",
        "actor": "bob",
        "contract_owner": True,
        "request_id": "req-bola",
        "expected": {"findings": 1, "inconclusive": 0, "grant": 0},
    },
    {
        "name": "missing_request_context",
        "owner": "alice",
        "actor": "bob",
        "contract_owner": True,
        "request_id": "",
        "expected": {"findings": 0, "inconclusive": 1, "grant": 0},
    },
    {
        "name": "read_only_grant_does_not_authorize_write",
        "owner": "alice",
        "actor": "bob",
        "contract_owner": True,
        "request_id": "req-read-grant",
        "grant_actions": ["read"],
        "expected": {"findings": 1, "inconclusive": 0, "grant": 0},
    },
    {
        "name": "write_grant_resolves_write",
        "owner": "alice",
        "actor": "bob",
        "contract_owner": True,
        "request_id": "req-write-grant",
        "grant_actions": ["write"],
        "expected": {"findings": 0, "inconclusive": 0, "grant": 1},
    },
    {
        "name": "rolled_back_write",
        "owner": "alice",
        "actor": "bob",
        "contract_owner": True,
        "request_id": "req-rollback",
        "rollback": True,
        "expected": {"findings": 0, "inconclusive": 0, "grant": 0},
    },
    {
        "name": "composite_primary_key",
        "owner": "alice",
        "actor": "bob",
        "contract_owner": True,
        "request_id": "req-composite",
        "composite": True,
        "expected": {"findings": 1, "inconclusive": 0, "grant": 0},
    },
]
