"""The AuthzBugs benchmark: labelled authorization bugs and their patched twins."""

from __future__ import annotations

from mizan.benchmark.apps import BUGS, AppSpec, BenchmarkApp, serve
from mizan.benchmark.evaluate import AppResult, Report, run_application, run_suite
from mizan.benchmark.generator import BENCHMARK_NAME, Suite, build_suite, describe

__all__ = [
    "BUGS",
    "BENCHMARK_NAME",
    "AppResult",
    "AppSpec",
    "BenchmarkApp",
    "Report",
    "Suite",
    "build_suite",
    "describe",
    "run_application",
    "run_suite",
    "serve",
]
