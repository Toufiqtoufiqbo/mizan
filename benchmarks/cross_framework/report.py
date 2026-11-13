"""Turn the benchmark's measurements into a JSON file and a Markdown report.

Every number is shown with its denominator. A percentage without the counts
behind it is not a measurement, so none is printed on its own.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

from .scenarios import FRAMEWORKS, REPOSITORY_ROOT

# --------------------------------------------------------------------------- #
# The environment
# --------------------------------------------------------------------------- #


def tree_digest(paths: list[Path]) -> str:
    """A stable digest of a set of files.

    The machine has no ``git`` binary, so the commit SHA cannot be read. The
    digest identifies the exact tree that produced a result, which is what the
    number is for.
    """
    digest = hashlib.sha256()
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(item for item in path.rglob("*") if item.is_file() and "__pycache__" not in item.parts))
        elif path.is_file():
            files.append(path)
    for item in sorted(files):
        digest.update(str(item.relative_to(REPOSITORY_ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def commit_sha() -> tuple[str | None, str]:
    """The Mīzān commit, when git is available."""
    git = shutil.which("git")
    if not git:
        return None, "git is not installed on this machine"
    try:
        completed = subprocess.run(
            [git, "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:
        return None, f"git could not be run: {exc}"
    if completed.returncode != 0:
        return None, "this directory is not a git repository"
    return completed.stdout.strip(), "read from git"


def node_version() -> str | None:
    """The Node.js version, when it is installed.

    ``MIZAN_NODE`` wins, because it is the interpreter the run actually used.
    """
    node = os.environ.get("MIZAN_NODE") or shutil.which("node")
    if not node:
        return None
    try:
        completed = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    return completed.stdout.strip() or None


def _package_version(name: str) -> str | None:
    try:
        module = __import__(name)
    except Exception:
        return None
    return getattr(module, "__version__", None)


def total_memory_bytes() -> int | None:
    """The physical memory of the machine, when it can be read."""
    if os.name == "nt":
        try:
            import ctypes

            class MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GlobalMemoryStatusEx.restype = ctypes.c_ulong
            status = MemoryStatusEx()
            status.dwLength = ctypes.sizeof(status)
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
        except Exception:
            return None
        return None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except Exception:
        return None
    return None


def environment_report() -> dict[str, Any]:
    """Everything a reader needs to know about the machine and the tree."""
    commit, commit_note = commit_sha()
    return {
        "python": platform.python_version(),
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "memory_bytes": total_memory_bytes(),
        "sqlite": sqlite3.sqlite_version,
        "node": node_version(),
        "fastapi": _package_version("fastapi"),
        "uvicorn": _package_version("uvicorn"),
        "requests": _package_version("requests"),
        "mizan_commit": commit,
        "mizan_commit_note": commit_note,
        "mizan_tree_digest": tree_digest([REPOSITORY_ROOT / "src" / "mizan"]),
        "fixture_digests": {name: tree_digest([framework.directory]) for name, framework in FRAMEWORKS.items()},
    }


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


def aggregate(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    """The totals of a set of scenarios, with their raw counts."""
    true_positives = sum(item["true_positives"] for item in scenarios)
    false_positives = sum(item["false_positives"] for item in scenarios)
    false_negatives = sum(item["false_negatives"] for item in scenarios)
    expected = sum(1 for item in scenarios if item["outcome"] == "expected")
    errors = sum(1 for item in scenarios if item["outcome"] == "error")
    attempted = sum(item["reproduction"]["attempted"] for item in scenarios)
    replayed = sum(item["reproduction"]["succeeded"] for item in scenarios)
    return {
        "scenarios": len(scenarios),
        "scenarios_expected": expected,
        "scenarios_unexpected": sum(1 for item in scenarios if item["outcome"] == "unexpected"),
        "scenarios_error": errors,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": _ratio(true_positives, true_positives + false_positives),
        "recall": _ratio(true_positives, true_positives + false_negatives),
        "requests_total": sum(item["requests"]["total"] for item in scenarios),
        "requests_bootstrap": sum(item["requests"]["bootstrap"] for item in scenarios),
        "requests_learning": sum(item["requests"]["learning"] for item in scenarios),
        "requests_attack": sum(item["requests"]["attack"] for item in scenarios),
        "wall_clock_seconds": round(sum(item["wall_clock_seconds"] for item in scenarios), 3),
        "budget_exhausted": sum(1 for item in scenarios if item["budget_exhausted"]),
        "setup_errors": sum(len(item["setup_errors"]) for item in scenarios),
        "reproduction_attempted": attempted,
        "reproduction_succeeded": replayed,
        "peak_memory_bytes": _max_peak(scenarios),
    }


def _max_peak(scenarios: list[dict[str, Any]]) -> int | None:
    values = [item["peak_memory_bytes"] for item in scenarios if item.get("peak_memory_bytes")]
    return max(values) if values else None


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_json(results: dict[str, Any]) -> str:
    """The machine-readable result."""
    return json.dumps(results, indent=2, ensure_ascii=False, sort_keys=False)


def _percent(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value * 100:.1f}%"


def _bytes(value: int | None) -> str:
    if value is None:
        return "unavailable"
    return f"{value / (1024 * 1024):.1f} MiB"


def render_markdown(results: dict[str, Any]) -> str:
    """The human-readable report."""
    scenarios = results["scenarios"]
    environment = results["environment"]
    lines: list[str] = []

    lines.extend(
        [
            "# Mīzān 0.3.0 — cross-framework benchmark",
            "",
            "Every number below is a count. A percentage never appears without the",
            "counts behind it.",
            "",
            f"- repetitions: **{results['repetitions']}**",
            f"- request budget per scenario: **{results['budget']}**",
            f"- scenarios run: **{len(scenarios)}**",
            "",
            "## The matrix",
            "",
            "| Framework | Variant | Expected | Observed | TP | FP | FN | Precision | Recall | "
            "Requests (b/l/a) | Time | Peak memory | Replay |",
            "|---|---|---|---|---:|---:|---:|---|---|---|---:|---|---|",
        ]
    )
    for item in scenarios:
        requests = item["requests"]
        replay = item["reproduction"]
        replay_text = f"{replay['succeeded']}/{replay['attempted']}" if replay["attempted"] else "n/a"
        lines.append(
            "| {framework} | {variant} | {expected} | {observed} | {tp} | {fp} | {fn} | {precision} | {recall} | "
            "{total} ({bootstrap}/{learning}/{attack}) | {seconds:.2f} s | {memory} | {replay} |".format(
                framework=item["framework"],
                variant=item["variant"],
                expected=", ".join(item["expected_findings"]) or "none",
                observed=", ".join(item["observed_findings"]) or "none",
                tp=item["true_positives"],
                fp=item["false_positives"],
                fn=item["false_negatives"],
                precision=_percent(item["precision"]),
                recall=_percent(item["recall"]),
                total=requests["total"],
                bootstrap=requests["bootstrap"],
                learning=requests["learning"],
                attack=requests["attack"],
                seconds=item["wall_clock_seconds"],
                memory=_bytes(item["peak_memory_bytes"]),
                replay=replay_text,
            )
        )

    lines.extend(
        [
            "",
            "## Totals",
            "",
            "| Scope | Scenarios as expected | TP | FP | FN | Precision | Recall | Requests | Replay |",
            "|---|---|---:|---:|---:|---|---|---:|---|",
        ]
    )
    scopes: list[tuple[str, list[dict[str, Any]]]] = []
    for name in sorted({item["framework"] for item in scenarios}):
        scopes.append((name, [item for item in scenarios if item["framework"] == name]))
    scopes.append(("all", list(scenarios)))
    for name, group in scopes:
        totals = aggregate(group)
        lines.append(
            "| {name} | {expected}/{scenarios} | {tp} | {fp} | {fn} | {precision} | {recall} | "
            "{requests} | {replay} |".format(
                name=name,
                expected=totals["scenarios_expected"],
                scenarios=totals["scenarios"],
                tp=totals["true_positives"],
                fp=totals["false_positives"],
                fn=totals["false_negatives"],
                precision=_percent(totals["precision"]),
                recall=_percent(totals["recall"]),
                requests=totals["requests_total"],
                replay=f"{totals['reproduction_succeeded']}/{totals['reproduction_attempted']}",
            )
        )

    failures = [item for item in scenarios if item["outcome"] != "expected"]
    lines.extend(["", "## Scenarios that did not match the expectation", ""])
    if not failures:
        lines.append("None. Every scenario produced exactly the expected laws.")
    else:
        for item in failures:
            lines.append(
                f"- **{item['framework']} / {item['variant']} / repetition {item['repetition']}**: "
                f"outcome `{item['outcome']}`, expected {item['expected_findings']}, "
                f"observed {item['observed_findings']}, errors {item['errors'] + item['setup_errors']}"
            )

    replay_failures = [(item, failure) for item in scenarios for failure in item["reproduction"]["failures"]]
    lines.extend(["", "## Replay failures", ""])
    if not replay_failures:
        lines.append("None. Every finding was reproduced against the state the scan left behind.")
    else:
        for item, failure in replay_failures:
            lines.append(f"- **{item['framework']} / {item['variant']}**: {failure}")

    lines.extend(
        [
            "",
            "## The environment",
            "",
            "| Item | Value |",
            "|---|---|",
            f"| OS | `{environment['platform']}` |",
            f"| CPU | `{environment['processor']}`, {environment['cpu_count']} cores |",
            f"| Memory | {_bytes(environment['memory_bytes'])} |",
            f"| Python | `{environment['python']}` |",
            f"| Node.js | `{environment['node'] or 'not installed'}` |",
            f"| SQLite | `{environment['sqlite']}` |",
            f"| FastAPI | `{environment['fastapi'] or 'not installed'}` |",
            f"| uvicorn | `{environment['uvicorn'] or 'not installed'}` |",
            f"| Mīzān commit | `{environment['mizan_commit'] or 'unavailable'}` ({environment['mizan_commit_note']}) |",
            f"| Mīzān tree digest | `{environment['mizan_tree_digest']}` |",
        ]
    )
    for name, digest in environment["fixture_digests"].items():
        lines.append(f"| Fixture digest ({name}) | `{digest}` |")

    lines.extend(
        [
            "",
            "## What this is",
            "",
            "Two controlled fixtures, each written independently against the same",
            "behavioral contract. The numbers measure Mīzān against those two",
            "fixtures. They are not a measurement of any real application, and they",
            "are not statistically representative of anything else.",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "aggregate",
    "environment_report",
    "render_json",
    "render_markdown",
    "tree_digest",
]
