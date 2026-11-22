"""PostgreSQL generic-engine benchmark: real workload, serial vs replicated parallel.

This benchmark is a measurement instrument, not a demo. It sends real HTTP
traffic through the supported learning path, runs the real attack pipeline, and
refuses to report a green result unless the workload actually did security work.

The parallel mode is **replicated**: every worker runs the complete
``learn() -> attack()`` workload on its own isolated database. It is measured as
a worker-isolation/equivalence experiment, never as a throughput or speedup
claim. See ``execution_mode`` in the results.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "external_apps" / "postgres_store"
SPEC = FIXTURE / "openapi-generic.json"
CONTRACT = FIXTURE / "mizan-relationships.json"
DSN_ENV = "MIZAN_VII_BENCH_DSN"
SCHEMA = "pgstore"
VARIANT = "both"
EXPECTED_LAWS = ("L2", "L3")
TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}
EXECUTION_MODE = "replicated: each isolated worker runs the full learn()->attack() workload"
BENCHMARK_VERSION = 2


def fixture_identity() -> dict[str, Any]:
    """A content-addressed identity for the workload, recorded in the results."""
    return {
        "name": "postgres_store",
        "variant": VARIANT,
        "app_sha256": hashlib.sha256((FIXTURE / "app.py").read_bytes()).hexdigest(),
        "spec_sha256": hashlib.sha256(SPEC.read_bytes()).hexdigest(),
        "contract_sha256": hashlib.sha256(CONTRACT.read_bytes()).hexdigest(),
        "schema": SCHEMA,
    }


def _pgserver() -> Any:
    dsn = os.environ.get("MIZAN_TEST_POSTGRES_DSN") or os.environ.get(DSN_ENV)
    if dsn:

        class _External:
            def get_uri(self):
                return dsn

            def cleanup(self):
                return None

        return _External()
    pgserver = __import__("pgserver")
    return pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-vii-bench-")), cleanup_mode="delete")


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location("pgstore_bench", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _prepare_source(module: Any, dsn: str) -> None:
    """Initialise the source database with the fixture's real schema and data."""
    previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
    os.environ["MIZAN_TOKEN_ALICE"] = TOKENS["alice"]
    os.environ["MIZAN_TOKEN_BOB"] = TOKENS["bob"]
    try:
        module.create_app("clean", dsn=dsn, schema=SCHEMA)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def _run_once(dsn: str, workspace: Path, workers: int, *, module: Any, contract: Any) -> dict[str, Any]:
    """Run one real serial workload, then the actual replicated parallel path."""
    from mizan.learning import learn_from_spec
    from mizan.postgres_engine import (
        PostgresRun,
        dedupe_findings,
        findings_equivalent,
        normalize_finding,
    )
    from mizan.postgres_twin import DatabaseRegistry, PostgresSource
    from mizan.proxy import RecordingProxy

    os.environ[DSN_ENV] = dsn
    instance = PostgresSource(DSN_ENV, schemas=(SCHEMA,))
    baseline = instance.prepare_baseline(workspace)
    traffic = workspace / "traffic.jsonl"
    run = PostgresRun(
        instance,
        baseline,
        DatabaseRegistry(workspace / "ownership.json"),
        workspace,
        [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}", "--vulnerability", VARIANT],
        tokens=dict(TOKENS),
        relationship_contract=contract,
        traffic_path=traffic,
        env={"MIZAN_PG_SCHEMA": SCHEMA},
        pool_size=2,
    )
    failures: list[str] = []
    cleanup: dict[str, Any] = {}
    result_data: dict[str, Any] = {}
    try:
        worker = run.start_worker("w0")
        proxy = RecordingProxy(worker.base_url, traffic, identity_map={token: name for name, token in TOKENS.items()})
        proxy.start()
        try:
            learned = learn_from_spec(SPEC, proxy.base_url, identities=dict(TOKENS), exclude_paths=("/login",))
        finally:
            proxy.stop()

        engine = run.build_engine(worker, workspace / "proofs")
        policy = engine.learn()
        started = time.perf_counter()
        serial_violations = engine.attack()
        serial_seconds = time.perf_counter() - started
        serial_coverage_object = engine.coverage()
        # Learning traffic is real and was counted by the learner; record it on
        # the coverage snapshot so ``meaningful`` reflects the actual workload.
        serial_coverage_object.learning_operations = len(learned)
        serial_coverage = serial_coverage_object.to_dict()
        serial = {
            "workers": 1,
            "duration_seconds": round(serial_seconds, 4),
            "findings": len(serial_violations),
            "normalized_findings": [list(key) for key in sorted({normalize_finding(v) for v in serial_violations})],
            "violations": len(serial_violations),
            "requests": engine.requests,
            "probe_candidates": engine.probe_candidates,
            "probes_executed": engine.probes_executed,
            "resources": len(policy.resources),
            "rules": len(policy.rules),
            "laws": sorted({str(v.law) for v in serial_violations}),
            "outcomes": len(engine.outcomes),
            "inconclusive": len(engine.inconclusive_checks),
            "coverage": serial_coverage,
        }

        parallel: dict[str, Any] = {"workers": workers}
        parallel_violations: list[Any] = []
        if workers > 1:
            started = time.perf_counter()
            by_worker = run.parallel_attack(workers)
            parallel_seconds = time.perf_counter() - started
            parallel_violations = dedupe_findings([violation for _, items in by_worker for violation in items])
            metrics = list(run.parallel_metrics)
            parallel = {
                "workers": workers,
                "duration_seconds": round(parallel_seconds, 4),
                "findings": len(parallel_violations),
                "normalized_findings": [
                    list(key) for key in sorted({normalize_finding(v) for v in parallel_violations})
                ],
                "violations": len(parallel_violations),
                "per_worker": [
                    {
                        "worker": worker_id,
                        "findings": len(items),
                        "requests": next((m["requests"] for m in metrics if m["worker"] == worker_id), 0),
                        "probes_executed": next((m["probes_executed"] for m in metrics if m["worker"] == worker_id), 0),
                        "resources": next((m["resources"] for m in metrics if m["worker"] == worker_id), 0),
                    }
                    for worker_id, items in by_worker
                ],
                "total_requests": sum(m["requests"] for m in metrics),
                "total_probes_executed": sum(m["probes_executed"] for m in metrics),
                "equivalent_to_serial": findings_equivalent(serial_violations, parallel_violations),
            }

        workload = {
            "learning_requests": len(learned),
            "traffic_records": len(engine.traffic),
            "resources_discovered": len(policy.resources),
            "rules_learned": len(policy.rules),
            "eligible_probes": engine.probe_candidates,
            "executed_probes": engine.probes_executed,
        }

        # -- loud gates ---------------------------------------------------- #
        _require(workload["learning_requests"] > 0, "the learning path sent no requests", failures)
        _require(workload["traffic_records"] > 0, "the workload produced no traffic", failures)
        _require(workload["resources_discovered"] > 0, "the workload discovered zero resources", failures)
        _require(workload["rules_learned"] > 0, "the workload learned zero rules", failures)
        _require(workload["eligible_probes"] > 0, "the workload had zero eligible probes", failures)
        _require(workload["executed_probes"] > 0, "the workload executed zero probes", failures)
        _require(serial["requests"] > 0, "the serial attack sent no requests", failures)
        _require(
            set(EXPECTED_LAWS).issubset(set(serial["laws"])),
            f"the fixture behavior was not detected: expected {EXPECTED_LAWS}, got {serial['laws']}",
            failures,
        )
        if workers > 1:
            _require(len(parallel.get("per_worker", [])) == workers, "not every worker produced a result", failures)
            _require(
                all(item["requests"] > 0 and item["probes_executed"] > 0 for item in parallel["per_worker"]),
                "at least one worker executed no probes",
                failures,
            )
            _require(
                parallel.get("equivalent_to_serial") is True,
                "serial and replicated parallel findings differ",
                failures,
            )
        result_data.update(
            {
                "workers": workers,
                "execution_mode": EXECUTION_MODE,
                "serial": serial,
                "parallel": parallel,
                "workload": workload,
            }
        )
    finally:
        try:
            removed = run.cleanup()
            cleanup = {"databases_removed": len(removed), "names": sorted(removed)}
            instance.assert_unchanged()
        except Exception as exc:  # a cleanup failure is a benchmark failure
            failures.append(f"cleanup failed: {exc}")
            cleanup = {"databases_removed": 0, "names": [], "error": str(exc)}
        result_data["cleanup"] = cleanup
        result_data["failures"] = list(failures)
    return result_data


def check_results(results: dict[str, Any]) -> list[str]:
    """Validate a results document without running the benchmark."""
    problems: list[str] = []
    workload = results.get("workload", {})
    for key in (
        "learning_requests",
        "traffic_records",
        "resources_discovered",
        "rules_learned",
        "eligible_probes",
        "executed_probes",
    ):
        _require(isinstance(workload.get(key), int) and workload[key] > 0, f"workload.{key} is not positive", problems)
    serial = results.get("serial", {})
    _require(serial.get("requests", 0) > 0, "serial requests are not positive", problems)
    _require(
        set(EXPECTED_LAWS).issubset(set(serial.get("laws", []))),
        "the expected fixture behavior was not detected",
        problems,
    )
    _require(results.get("execution_mode") == EXECUTION_MODE, "the execution mode is mislabelled", problems)
    _require(not results.get("failures"), "the run recorded failures", problems)
    parallel = results.get("parallel", {})
    parallel_items = parallel if isinstance(parallel, list) else [parallel]
    for item in parallel_items:
        if item.get("workers", 1) > 1:
            _require(item.get("equivalent_to_serial") is True, "parallel findings differ from serial", problems)
            _require(
                len(item.get("per_worker", [])) == item["workers"],
                "the parallel result has the wrong worker count",
                problems,
            )
    return problems


def main() -> None:
    from mizan.ownership import RelationshipContract

    module = _load_module()
    server = _pgserver()
    dsn = server.get_uri()
    if "connect_timeout" not in dsn:
        dsn += "?connect_timeout=5"
    _prepare_source(module, dsn)
    contract = RelationshipContract.load(CONTRACT, strict=True)
    from mizan.postgres_twin import PostgresSource

    os.environ[DSN_ENV] = dsn
    cluster = PostgresSource(DSN_ENV, schemas=(SCHEMA,)).cluster_id()

    workspace = Path(tempfile.mkdtemp(prefix="mizan-vii-bench-"))
    result = _run_once(dsn, workspace, 1, module=module, contract=contract)
    parallel_runs = [
        _run_once(dsn, Path(tempfile.mkdtemp(prefix="mizan-vii-bench-par-")), workers, module=module, contract=contract)
        for workers in (2, 4)
    ]
    durations = [item["parallel"]["duration_seconds"] for item in parallel_runs]
    results = {
        "benchmark_version": BENCHMARK_VERSION,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "psycopg": __import__("psycopg").__version__,
            "cluster": cluster,
            "git_sha": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
        },
        "fixture": fixture_identity(),
        "execution_mode": EXECUTION_MODE,
        "serial": result["serial"],
        "parallel": [item["parallel"] for item in parallel_runs],
        "parallel_duration_seconds": durations,
        "parallel_median_seconds": round(statistics.median(durations), 4),
        "workload": result["workload"],
        "comparison": {
            "mode": "replicated worker isolation and normalized finding equivalence",
            "speedup_claim": None,
            "serial_duration_seconds": result["serial"]["duration_seconds"],
            "parallel_durations_seconds": durations,
        },
        "failures": [message for item in [result, *parallel_runs] for message in item["failures"]],
        "problems": check_results(
            {
                "fixture": fixture_identity(),
                "execution_mode": EXECUTION_MODE,
                "workload": result["workload"],
                "serial": result["serial"],
                "parallel": parallel_runs[0]["parallel"],
                "failures": result["failures"],
            }
        ),
    }
    text = json.dumps(results, indent=2, sort_keys=True) + "\n"
    (Path(__file__).resolve().parent / "results.json").write_text(text, encoding="utf-8")
    print(text)
    server.cleanup()
    problems = check_results(results)
    if problems:
        raise SystemExit("benchmark validation failed: " + "; ".join(problems))


if __name__ == "__main__":
    main()
