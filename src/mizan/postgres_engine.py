"""PostgreSQL backend for the generic Mīzān engine.

This module is an adapter, not a second engine: ``Mizan`` remains the single
execution engine, and the PostgreSQL backend supplies the attributor and worker
isolation that the generic engine already accepts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mizan.engine import Mizan, Target
from mizan.postgres_twin import DatabaseRegistry, PostgresSource, PostgresTwin


def normalize_finding(violation: Any) -> tuple[str, str, str, str, str]:
    """Deterministic comparison key for findings."""
    return (
        str(violation.law),
        str(violation.principal or ""),
        str(violation.resource or ""),
        str(violation.resource or ""),
        str(getattr(violation, "severity", "") or ""),
    )


class PostgresRun:
    """One generic Mīzān run against one or more disposable PostgreSQL workers."""

    def __init__(
        self,
        source: PostgresSource,
        baseline,
        registry: DatabaseRegistry,
        workspace: Path,
        command: list[str],
        *,
        tokens: dict[str, str],
        relationship_contract: Any | None = None,
        traffic_path: Path,
        pool_size: int = 0,
    ) -> None:
        self.source = source
        self.baseline = baseline
        self.registry = registry
        self.workspace = workspace
        self.command = command
        self.tokens = tokens
        self.relationship_contract = relationship_contract
        self.traffic_path = traffic_path
        self.pool_size = pool_size
        self.twins: list[PostgresTwin] = []
        self.results: list[Any] = []
        self.parallel_results: list[Any] = []

    def start_worker(self, worker_id: str) -> PostgresTwin:
        twin = PostgresTwin(
            self.source,
            self.baseline,
            self.registry,
            worker_id,
            command=self.command,
            workdir=self.workspace,
            pool_size=self.pool_size,
            env={
                "MIZAN_TOKEN_ALICE": self.tokens.get("alice", "engine-alice"),
                "MIZAN_TOKEN_BOB": self.tokens.get("bob", "engine-bob"),
            },
        )
        twin.start()
        self.twins.append(twin)
        return twin

    def build_engine(self, twin: PostgresTwin, out_path: Path) -> Mizan:
        from mizan.core import Principal
        from mizan.postgres_attribution import PostgresAttributor

        attributor = PostgresAttributor(
            twin.database.connect(),
            schemas=self.baseline.schemas,
            audit_schema=self.baseline.schemas[0],
        )
        principals = [Principal(id=name, roles=("user",), token=token) for name, token in sorted(self.tokens.items())]
        return Mizan(
            Target(base_url=twin.base_url, principals=principals),
            attributor=attributor,
            twin=twin,
            traffic_path=self.traffic_path,
            relationship_contract=self.relationship_contract,
        )

    def attack_worker(self, twin: PostgresTwin, out_path: Path) -> list[Any]:
        engine = self.build_engine(twin, out_path)
        violations = engine.attack()
        self.results.extend(violations)
        return violations

    def parallel_attack(self, worker_count: int) -> list[tuple[str, list[Any]]]:
        results: list[tuple[str, list[Any]]] = []
        existing = {twin.worker_id for twin in self.twins}
        for index in range(worker_count):
            worker_id = f"w{index}"
            if worker_id in existing:
                worker_id = f"p{index}"
            twin = self.start_worker(worker_id)
            violations = self.attack_worker(twin, self.workspace)
            results.append((worker_id, violations))
            twin.restore()
        return results

    def cleanup(self) -> list[str]:
        cleaned: list[str] = []
        for twin in reversed(self.twins):
            twin.stop(strict=True)
            twin.cleanup()
            cleaned.append(twin.database.name)
        return cleaned


def serial_and_parallel_equivalence(serial: list[Any], parallel: list[Any]) -> bool:
    return sorted(normalize_finding(v) for v in serial) == sorted(normalize_finding(v) for v in parallel)
