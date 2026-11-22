"""PostgreSQL backend for the generic Mīzān engine.

This module is an adapter, not a second engine: ``Mizan`` remains the single
execution engine, and the PostgreSQL backend supplies the attributor and worker
isolation that the generic engine already accepts.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from mizan.engine import Mizan, Target
from mizan.postgres_twin import (
    DatabaseRegistry,
    OwnershipError,
    PostgresSource,
    PostgresTwin,
    TwinLifecycleError,
    cleanup_run,
)


def normalize_finding(violation: Any) -> tuple[str, ...]:
    """Semantic comparison key for findings, excluding incidental fields.

    A worker runs on its own port and may name a database row by its audit-table
    identity or by the mapped API resource. Neither is a semantic difference, so
    the mapped API resource (when evidence provides one) and the finding title
    are used instead of the prose detail, which embeds the worker's URL.
    Missing values stay explicit: two findings cannot collide by both omitting
    the same field.
    """
    evidence = getattr(violation, "evidence", {}) or {}
    if not isinstance(evidence, dict):
        evidence = {}

    def evidence_text(*keys: str) -> str:
        for key in keys:
            value = evidence.get(key)
            if value not in (None, ""):
                return str(value)
        return ""

    mapping = evidence.get("resource_mapping")
    mapped = mapping.get("api_resource") if isinstance(mapping, dict) else None
    resource = str(mapped) if mapped not in (None, "") else str(violation.resource or "")

    return (
        str(violation.law),
        str(violation.principal or ""),
        resource,
        str(getattr(violation, "action", "") or ""),
        str(getattr(violation, "severity", "") or ""),
        evidence_text("expected_owner", "owner", "resource_owner"),
        evidence_text("observed_owner", "actual_owner", "owner_observed"),
        evidence_text("subtype", "reason", "evidence_kind", "finding_id"),
        str(getattr(violation, "title", "") or ""),
    )


def dedupe_findings(findings: list[Any]) -> list[Any]:
    """Keep the first finding per semantic key, preserving discovery order."""
    seen: dict[tuple[str, ...], Any] = {}
    for finding in findings:
        seen.setdefault(normalize_finding(finding), finding)
    return list(seen.values())


def findings_equivalent(left: list[Any], right: list[Any]) -> bool:
    """Semantic equivalence of two finding sets, order-insensitive.

    Two workers may independently discover the same breach; that is a duplicate
    observation, not a second finding. Comparison is therefore set-based.
    """
    return {normalize_finding(v) for v in left} == {normalize_finding(v) for v in right}


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
        env: dict[str, str] | None = None,
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
        self.env = dict(env or {})
        self.twins: list[PostgresTwin] = []
        self.results: list[Any] = []
        self.parallel_results: list[Any] = []
        #: Per-worker execution evidence, keyed by worker id. This is the single
        #: source of truth for benchmarks/cli that compare serial and parallel
        #: runs: it records what the engines actually did, not what a label says.
        self.worker_metrics: dict[str, dict[str, Any]] = {}
        self.parallel_metrics: list[dict[str, Any]] = []
        self._twins_lock = threading.Lock()

    # -- workers ------------------------------------------------------------ #

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
                **self.env,
                "MIZAN_TOKEN_ALICE": self.tokens.get("alice", "engine-alice"),
                "MIZAN_TOKEN_BOB": self.tokens.get("bob", "engine-bob"),
            },
        )
        # Register before starting: a half-started worker still owns a database
        # and must be reaped if the health check or audit install fails.
        with self._twins_lock:
            self.twins.append(twin)
        try:
            twin.start()
        except BaseException:
            with self._twins_lock:
                if twin in self.twins:
                    self.twins.remove(twin)
            self._cleanup_worker(twin)
            raise
        return twin

    def worker_traffic_path(self, twin: PostgresTwin) -> Path:
        """One traffic log per worker; no concurrent writes to a shared file."""
        return self.traffic_path.with_name(f"{self.traffic_path.stem}-{twin.worker_id}{self.traffic_path.suffix}")

    def build_engine(self, twin: PostgresTwin, out_path: Path, *, traffic_path: Path | None = None) -> Mizan:
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
            traffic_path=Path(traffic_path) if traffic_path is not None else self.traffic_path,
            relationship_contract=self.relationship_contract,
        )

    def attack_worker(
        self,
        twin: PostgresTwin,
        out_path: Path,
        *,
        traffic_path: Path | None = None,
        cancel: Callable[[], None] | None = None,
    ) -> list[Any]:
        if cancel is not None:
            cancel()
        engine = self.build_engine(twin, out_path, traffic_path=traffic_path)
        # Every worker learns for itself from its own copy of the traffic. A
        # parallel finding is the same engine's output, not a replay of w0's.
        engine.learn()
        violations = engine.attack()
        coverage = engine.coverage()
        self.worker_metrics[twin.worker_id] = {
            "worker": twin.worker_id,
            "requests": engine.requests,
            "probe_candidates": engine.probe_candidates,
            "probes_executed": engine.probes_executed,
            "resources": len(engine.policy.resources),
            "rules": len(engine.policy.rules),
            "findings": len(violations),
            "inconclusive": len(engine.inconclusive_checks),
            "coverage": coverage.to_dict(),
        }
        self.results.extend(violations)
        return violations

    def _cleanup_worker(self, twin: PostgresTwin) -> list[str]:
        """Best-effort reaping of one worker; never leaves a database behind."""
        errors: list[str] = []
        try:
            twin.cleanup()
        except Exception as exc:  # a stopped or crashed process must not block the DROP
            errors.append(str(exc))
            try:
                twin.database.drop()
            except Exception as drop_exc:
                errors.append(str(drop_exc))
        return errors

    def parallel_attack(
        self,
        worker_count: int,
        *,
        on_workers_ready: Callable[[list[PostgresTwin]], None] | None = None,
        on_worker_attack: Callable[[PostgresTwin], None] | None = None,
        cancel: Callable[[], None] | None = None,
    ) -> list[tuple[str, list[Any]]]:
        """Start and attack isolated workers *at the same time*.

        The executor starts every worker before any attack begins, so all worker
        processes and databases are alive simultaneously. Each worker then runs
        the generic ``Mizan.learn() -> attack()`` path in its own thread. Any
        failure - including a hook used for fault injection - reaps every worker
        started by this call and re-raises the original error.
        """
        count = max(1, int(worker_count))
        existing = {twin.worker_id for twin in self.twins}
        worker_ids: list[str] = []
        for index in range(count):
            candidate = f"p{index}"
            suffix = 2
            while candidate in existing or candidate in worker_ids:
                candidate = f"p{index}_{suffix}"
                suffix += 1
            worker_ids.append(candidate)

        started: list[PostgresTwin] = []
        results: list[tuple[str, list[Any]]] = []
        problem: BaseException | None = None
        try:
            with ThreadPoolExecutor(max_workers=count) as executor:
                start_futures = [executor.submit(self.start_worker, worker_id) for worker_id in worker_ids]
                for future in as_completed(start_futures):
                    started.append(future.result())
                if cancel is not None:
                    cancel()
                if on_workers_ready is not None:
                    on_workers_ready(list(started))

                learned = self.traffic_path.read_bytes() if self.traffic_path.exists() else b""

                def attack_one(twin: PostgresTwin) -> tuple[str, list[Any]]:
                    if cancel is not None:
                        cancel()
                    if on_worker_attack is not None:
                        on_worker_attack(twin)
                    traffic = self.worker_traffic_path(twin)
                    traffic.write_bytes(learned)
                    return twin.worker_id, self.attack_worker(twin, self.workspace, traffic_path=traffic)

                attack_futures = [executor.submit(attack_one, twin) for twin in started]
                for future in as_completed(attack_futures):
                    results.append(future.result())
        except BaseException as exc:
            problem = exc
        finally:
            cleanup_errors: list[str] = []
            for twin in reversed(started):
                try:
                    twin.stop(strict=False)
                except Exception as exc:  # pragma: no cover - defensive
                    cleanup_errors.append(str(exc))
                cleanup_errors.extend(self._cleanup_worker(twin))
                with self._twins_lock:
                    if twin in self.twins:
                        self.twins.remove(twin)

        if problem is not None:
            raise problem
        if cleanup_errors:
            raise TwinLifecycleError("worker cleanup failed: " + "; ".join(cleanup_errors))
        order = {worker_id: index for index, worker_id in enumerate(worker_ids)}
        results.sort(key=lambda item: order[item[0]])
        self.parallel_metrics = [
            self.worker_metrics[worker_id] for worker_id in worker_ids if worker_id in self.worker_metrics
        ]
        self.parallel_results = dedupe_findings([finding for _, findings in results for finding in findings])
        return results

    def cleanup(self) -> list[str]:
        cleaned: list[str] = []
        errors: list[str] = []
        with self._twins_lock:
            twins = list(reversed(self.twins))
            self.twins.clear()
        for twin in twins:
            try:
                twin.stop(strict=False)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(str(exc))
            errors.extend(self._cleanup_worker(twin))
            cleaned.append(twin.database.name)
        # The seed owns no twin, so it is not in the loop above. The whole-run
        # preflight drops it along with any worker that survived an early error.
        remaining: list[str] = []
        for attempt in range(3):
            try:
                remaining = cleanup_run(self.source.dsn_env, self.workspace, self.source.run_id)
                break
            except OwnershipError as exc:
                # A registry read can race with the atomic replace performed by
                # a worker that just finished. Retry the read-only preflight
                # before declaring the whole run's cleanup failed.
                if "could not be read" not in str(exc) or attempt == 2:
                    raise
                time.sleep(0.1)
        for name in remaining:
            if name not in cleaned:
                cleaned.append(name)
        if errors:
            raise TwinLifecycleError("run cleanup failed: " + "; ".join(errors))
        return cleaned


def serial_and_parallel_equivalence(serial: list[Any], parallel: list[Any]) -> bool:
    """Backwards-compatible alias for the normalized comparison."""
    return findings_equivalent(serial, parallel)
