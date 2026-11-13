"""Measure the resource profile of the project on this machine.

Native Windows, no WSL. The script runs the parts of the release that matter
and records how long they take, how much memory they use and how much of the
disk they leave behind.

    python scripts/measure_windows.py --out reports/windows-profile.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str], *, timeout: float = 1800) -> dict[str, Any]:
    """Run a command and measure the time and the peak memory of the tree."""
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    peak = 0
    try:
        import psutil

        handle = psutil.Process(process.pid)
        while process.poll() is None:
            try:
                memory = handle.memory_info().rss
                for child in handle.children(recursive=True):
                    try:
                        memory += child.memory_info().rss
                    except Exception:
                        continue
                peak = max(peak, memory)
            except Exception:
                pass
            time.sleep(0.1)
    except ImportError:  # pragma: no cover - psutil is optional
        pass
    output = process.stdout.read() if process.stdout else ""
    process.wait()
    return {
        "command": " ".join(command),
        "seconds": round(time.perf_counter() - started, 2),
        "peak_memory_mb": round(peak / (1024 * 1024), 1),
        "exit_code": process.returncode,
        "output_tail": output.strip().splitlines()[-3:] if output.strip() else [],
    }


def _directory_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure Mizan's resource profile")
    parser.add_argument("--out", default="reports/windows-profile.json")
    arguments = parser.parse_args()

    measurements: dict[str, Any] = {}

    print("unit tests ...")
    measurements["unit_tests"] = _run([sys.executable, "-m", "pytest", "-q", "-m", "not postgres_integration"])

    print("postgres integration ...")
    measurements["postgres_integration"] = _run([sys.executable, "-m", "pytest", "-q", "-m", "postgres_integration"])

    print("self-scan ...")
    measurements["self_scan"] = _run([sys.executable, "-m", "mizan.cli", "self-scan"])

    print("independent validation ...")
    measurements["independent_validation"] = _run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_external_validation.py"]
    )

    print("benchmark (subset) ...")
    measurements["benchmark"] = _run(
        [sys.executable, "-m", "mizan.cli", "benchmark", "--size", "10", "--controls", "2", "--out", "measure-bench"]
    )

    print("sarif export ...")
    workspace = Path(tempfile.mkdtemp(prefix="mizan-measure-"))
    try:
        started = time.perf_counter()
        from mizan.sarif import to_sarif, validate_sarif

        document = to_sarif([]).document
        validate_sarif(document)
        measurements["sarif_export"] = {
            "seconds": round(time.perf_counter() - started, 3),
            "note": "an empty export; the full export runs in the self-scan",
        }
        measurements["temp_disk_bytes"] = _directory_size(workspace)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    profile = {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
        "measurements": measurements,
    }
    out = ROOT / arguments.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    print(json.dumps(profile, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
