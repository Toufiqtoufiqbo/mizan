"""The PostgreSQL benchmark is a measurement instrument: validate its output."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.postgres_engine.run import EXECUTION_MODE, EXPECTED_LAWS, check_results

RESULTS = Path(__file__).resolve().parents[1] / "benchmarks" / "postgres_engine" / "results.json"


def test_recorded_benchmark_result_is_a_real_nonempty_workload() -> None:
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert check_results(results) == [], check_results(results)
    workload = results["workload"]
    assert workload["learning_requests"] > 0
    assert workload["traffic_records"] > 0
    assert workload["resources_discovered"] > 0
    assert workload["rules_learned"] > 0
    assert workload["eligible_probes"] > 0
    assert workload["executed_probes"] > 0
    assert set(EXPECTED_LAWS).issubset(set(results["serial"]["laws"]))
    assert results["serial"]["requests"] > 0
    assert all(item["findings"] > 0 for item in results["parallel"])
    assert all(
        all(worker["requests"] > 0 and worker["probes_executed"] > 0 for worker in item["per_worker"])
        for item in results["parallel"]
    )
    assert all(item["equivalent_to_serial"] for item in results["parallel"])
    assert results["execution_mode"] == EXECUTION_MODE
    assert results["comparison"]["speedup_claim"] is None


def test_check_results_rejects_a_zero_workload() -> None:
    problems = check_results(
        {
            "workload": {
                "learning_requests": 0,
                "traffic_records": 0,
                "resources_discovered": 0,
                "rules_learned": 0,
                "eligible_probes": 0,
                "executed_probes": 0,
            },
            "serial": {"requests": 0, "laws": []},
            "execution_mode": EXECUTION_MODE,
            "failures": [],
        }
    )
    assert problems


def test_check_results_rejects_a_mislabelled_parallel_mode() -> None:
    problems = check_results(
        {
            "workload": {
                "learning_requests": 1,
                "traffic_records": 1,
                "resources_discovered": 1,
                "rules_learned": 1,
                "eligible_probes": 1,
                "executed_probes": 1,
            },
            "serial": {"requests": 1, "laws": list(EXPECTED_LAWS)},
            "execution_mode": "linear speedup",
            "failures": [],
            "parallel": {"workers": 2, "equivalent_to_serial": True, "per_worker": [{}, {}]},
        }
    )
    assert any("execution mode" in problem for problem in problems)
