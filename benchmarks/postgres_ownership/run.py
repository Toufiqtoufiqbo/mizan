"""Reproducible PostgreSQL ownership benchmark with explicit denominators."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .check import check
from .scenarios import SCENARIOS

OUTPUT = Path(__file__).resolve().parent / "results.json"


def _dsn() -> str:
    dsn = os.environ.get("MIZAN_PG_DSN") or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if dsn:
        return dsn
    pgserver = __import__("pgserver")
    return pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-v6-bench-")), cleanup_mode="delete").get_uri()


def _write(
    connection, schema: str, table: str, key_column: str, key: str, principal: str, request_id: str, *, rollback: bool
) -> None:
    previous = connection.autocommit
    connection.autocommit = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('application_name', %s, true)", (f"mizan:{principal}",))
            cursor.execute("SELECT set_config('mizan.request_id', %s, true)", (request_id,))
            cursor.execute(
                f'UPDATE "{schema}"."{table}" SET label = %s WHERE {key_column} = %s',
                ("benchmark", key),
            )
        if rollback:
            connection.rollback()
        else:
            connection.commit()
    finally:
        connection.autocommit = previous


def _measure(scenario: dict[str, Any], dsn: str) -> dict[str, Any]:
    import psycopg

    from mizan.core import Policy, Principal, Resource
    from mizan.ownership import Observation, RelationshipContract, build_ownership_graph
    from mizan.postgres_attribution import PostgresAttributor
    from mizan.postgres_audit import PostgresAuditor
    from mizan.taint import TaintAnalyzer

    connection = psycopg.connect(dsn, connect_timeout=5, autocommit=True)
    schema = f"mizan_bench_{uuid.uuid4().hex[:10]}"
    composite = bool(scenario.get("composite"))
    key_column = "item_ref"
    try:
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE SCHEMA "{schema}"')
            cursor.execute(f'CREATE TABLE "{schema}".people (person_key TEXT PRIMARY KEY)')
            for principal in ("alice", "bob"):
                cursor.execute(f'INSERT INTO "{schema}".people VALUES (%s)', (principal,))
            if composite:
                cursor.execute(
                    f'''CREATE TABLE "{schema}".items (
                        tenant_ref TEXT NOT NULL, item_ref TEXT NOT NULL,
                        originator_ref TEXT REFERENCES "{schema}".people(person_key),
                        label TEXT NOT NULL, PRIMARY KEY (tenant_ref, item_ref))'''
                )
                cursor.execute(f'INSERT INTO "{schema}".items VALUES (%s,%s,%s,%s)', ("t1", "a1", "alice", "A"))
                resource_key = '["t1","a1"]'
            else:
                cursor.execute(
                    f'''CREATE TABLE "{schema}".items (
                        item_ref TEXT PRIMARY KEY,
                        originator_ref TEXT REFERENCES "{schema}".people(person_key),
                        label TEXT NOT NULL)'''
                )
                cursor.execute(f'INSERT INTO "{schema}".items VALUES (%s,%s,%s)', ("a1", "alice", "A"))
                resource_key = "a1"
            if scenario.get("grant_actions"):
                cursor.execute(
                    f'''CREATE TABLE "{schema}".grants (
                        grant_ref TEXT PRIMARY KEY,
                        item_ref TEXT REFERENCES "{schema}".items(item_ref),
                        person_ref TEXT REFERENCES "{schema}".people(person_key))'''
                )
                cursor.execute(f'INSERT INTO "{schema}".grants VALUES (%s,%s,%s)', ("g1", "a1", "bob"))
        provider = PostgresAttributor(connection, schemas=(schema,), audit_schema=schema)
        provider.auditor.install()  # benchmark owns a disposable schema
        ownership = None
        if scenario["contract_owner"]:
            ownership = {
                "items": {
                    "source": "database_foreign_key",
                    "column": "originator_ref",
                    "table": f"{schema}.items",
                }
            }
        contract = RelationshipContract.from_dict(
            {
                "version": 1,
                "identity": {"endpoint": "/whoami", "field": "person_key"},
                "ownership": ownership or {},
                "sharing": (
                    {
                        f"{schema}.grants": {
                            "resource_fk": "item_ref",
                            "principal_fk": "person_ref",
                            "semantics": "authorization_grant",
                            "actions": scenario["grant_actions"],
                        }
                    }
                    if scenario.get("grant_actions")
                    else {}
                ),
            },
            strict=True,
        )
        declared = provider.schema()
        graph = build_ownership_graph(
            resources={"items:" + resource_key: Resource("items", resource_key)},
            traffic=[
                Observation(principal, {"person_key": principal}, path="/whoami") for principal in ("alice", "bob")
            ],
            ledger=[],
            schema=declared,
            rows={name: provider.rows(name) for name in declared.tables},
            contract=contract,
        )
        before = provider.snapshot()
        _write(
            connection,
            schema,
            "items",
            key_column,
            "a1",
            scenario["actor"],
            scenario["request_id"],
            rollback=bool(scenario.get("rollback")),
        )
        events = provider.diff(
            before,
            principal=scenario["actor"],
            method="PUT",
            path="/items/" + resource_key,
            request_id=scenario["request_id"],
        )
        policy = Policy()
        for principal in ("alice", "bob"):
            policy.principals[principal] = Principal(principal, ("user",), f"{principal}-token")
        analyzer = TaintAnalyzer(policy, graph=graph)
        findings = analyzer.analyze(events)
        outcomes = analyzer.outcomes
        observed = {
            "findings": sum(1 for item in outcomes if item["outcome"] == "VIOLATION"),
            "inconclusive": sum(1 for item in outcomes if item["outcome"] == "INCONCLUSIVE"),
            "grant": sum(1 for item in outcomes if item["outcome"] == "ALLOWED_BY_GRANT"),
            "events": len(events),
            "status": "ran",
        }
        return {
            "name": scenario["name"],
            "expected": scenario["expected"],
            "observed": observed,
            "findings_detail": [finding.law for finding in findings],
            "inconclusive_reasons": [item["reason"] for item in analyzer.inconclusive],
            "debug_mapping": {
                "row_key": events[0].row_key if events else None,
                "table": events[0].table if events else None,
                "resource_rows": {key: list(value) for key, value in graph.resource_rows.items()},
            },
            "confirmed_ownership": sum(
                1
                for relation in graph.relationships
                if relation.type.value == "OWNS" and relation.state.value == "CONFIRMED"
            ),
            "candidate_ownership": sum(
                1
                for relation in graph.relationships
                if relation.type.value == "OWNS" and relation.state.value == "CANDIDATE"
            ),
            "unknown_ownership": 1 if graph.owner_of("items:" + resource_key) is None else 0,
            "request_count": 1,
        }
    finally:
        try:
            PostgresAuditor(connection, audit_schema=schema).uninstall()
            with connection.cursor() as cursor:
                cursor.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        finally:
            connection.close()


def main() -> None:
    dsn = _dsn()
    measurements = [_measure(scenario, dsn) for scenario in SCENARIOS]
    results = {"scenarios": measurements}
    results["problems"] = check(results)
    results["summary"] = {
        "scenarios": len(measurements),
        "passed": len(measurements) - len(results["problems"]),
        "findings": sum(item["observed"]["findings"] for item in measurements),
        "inconclusive": sum(item["observed"]["inconclusive"] for item in measurements),
        "grants": sum(item["observed"]["grant"] for item in measurements),
        "confirmed_ownership": sum(item["confirmed_ownership"] for item in measurements),
        "candidate_ownership": sum(item["candidate_ownership"] for item in measurements),
        "unknown_ownership": sum(item["unknown_ownership"] for item in measurements),
        "attribution_failures": sum(1 for item in measurements if item["name"] in {"missing_request_context"}),
        "requests": sum(item["request_count"] for item in measurements),
        "denominator_scenarios": len(SCENARIOS),
    }
    OUTPUT.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(results["summary"], indent=2))
    if results["problems"]:
        print(json.dumps(results["problems"], indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
