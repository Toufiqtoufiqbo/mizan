"""Run one cross-framework scenario and measure it.

A scenario is: start an application in one security variant, attack it with
Mīzān, check that the expected laws were found, and replay every finding
against the same state.

Nothing here knows anything about Flask, FastAPI or Express. The only thing
the runner knows about an application is how to start it (``LaunchSpec``) and
where its database is.
"""

from __future__ import annotations

import ctypes
import os
import secrets
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from mizan.twin import Twin, TwinSpec
from mizan.validation import (
    LaunchSpec,
    _login,
    build_command,
    environment_for,
    scan_application,
)

from .scenarios import CREDENTIAL_ENV, EXPECTED, PRINCIPALS, Framework

#: The default request budget of one scenario.
DEFAULT_BUDGET = 60


def generate_credentials() -> dict[str, str]:
    """Unique, temporary credentials for one scenario.

    They are never written to disk and never appear in a report.
    """
    return {principal: secrets.token_urlsafe(18) for principal in PRINCIPALS}


def launch_for(framework: Framework, credentials: dict[str, str]) -> LaunchSpec:
    """A launch specification that carries this run's temporary credentials."""
    environment = {CREDENTIAL_ENV[principal]: password for principal, password in credentials.items()}
    return framework.launch.with_environment(environment)


# --------------------------------------------------------------------------- #
# Memory
# --------------------------------------------------------------------------- #


def peak_memory(process: Any) -> tuple[int | None, str]:
    """The peak working set of a child process, when the platform can tell us.

    Returns the number of bytes and a note saying where the number came from.
    A measurement that cannot be made is reported as unavailable - never as
    zero.
    """
    if process is None:
        return None, "the application was not running when the measurement was taken"
    pid = getattr(process, "pid", None)
    if not pid:
        return None, "the application process has no identifier"
    if os.name == "nt":
        value = _windows_peak(pid)
        if value is None:
            return None, "the Windows kernel did not report a peak working set"
        return value, "the peak working set reported by the Windows kernel"
    value = _linux_peak(pid)
    if value is not None:
        return value, "the peak resident set size reported by /proc"
    value = _posix_peak()
    if value is not None:
        return value, "the maximum resident set size of every child process - an upper bound, not this one alone"
    return None, "this platform does not expose a peak working set"


def _windows_peak(pid: int) -> int | None:
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCounters),
        wintypes.DWORD,
    ]

    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, int(pid))
    if not handle:
        return None
    try:
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.PeakWorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def _linux_peak(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    except Exception:
        return None
    return None


def _posix_peak() -> int | None:
    try:
        import resource

        return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# The scenario
# --------------------------------------------------------------------------- #


def run_scenario(
    framework: Framework,
    variant: str,
    repetition: int,
    *,
    budget: int = DEFAULT_BUDGET,
) -> dict[str, Any]:
    """Run one scenario and return its measurements."""
    credentials = generate_credentials()
    launch = launch_for(framework, credentials)
    logins = {principal: (principal, credentials[principal]) for principal in PRINCIPALS}
    measurement: dict[str, Any] = {"bytes": None, "note": "the application was never measured"}

    def observer(twin: Any) -> None:
        measurement["bytes"], measurement["note"] = peak_memory(twin.process)

    started = time.perf_counter()
    result = scan_application(
        framework.directory,
        variant=variant,
        budget=budget,
        credentials=logins,
        launch=launch,
        keep_workspace=True,
        observer=observer,
    )
    elapsed = time.perf_counter() - started

    workspace = Path(result.workspace) if result.workspace else None
    try:
        if workspace is None:
            reproduction = {
                "attempted": 0,
                "succeeded": 0,
                "requests": 0,
                "failures": [{"law": None, "reason": "the workspace was not kept, so nothing could be replayed"}],
            }
        else:
            reproduction = replay_findings(framework, variant, result.findings, workspace, launch, credentials)
    finally:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)

    expected = list(EXPECTED[variant])
    observed = sorted(set(result.law_types))
    true_positives = len([law for law in expected if law in observed])
    false_positives = len([law for law in observed if law not in expected])
    false_negatives = len([law for law in expected if law not in observed])

    if result.error or result.setup_error:
        outcome = "error"
    elif observed == sorted(expected):
        outcome = "expected"
    else:
        outcome = "unexpected"

    return {
        "framework": framework.name,
        "variant": variant,
        "repetition": repetition,
        "outcome": outcome,
        "expected_findings": expected,
        "observed_findings": observed,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": _ratio(true_positives, true_positives + false_positives),
        "recall": _ratio(true_positives, true_positives + false_negatives),
        "requests": {
            "bootstrap": result.requests.bootstrap,
            "learning": result.requests.learning,
            "attack": result.requests.attack,
            "total": result.requests.total,
            "budget": budget,
        },
        "budget_exhausted": result.requests.budget_exhausted,
        "wall_clock_seconds": round(elapsed, 3),
        "peak_memory_bytes": measurement["bytes"],
        "peak_memory_note": measurement["note"],
        "setup_errors": [result.setup_error] if result.setup_error else [],
        "errors": [result.error] if result.error else [],
        "missing_identities": list(result.missing_identities),
        "reproduction": reproduction,
        "evidence_complete": result.evidence_complete,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    """A ratio, or ``None`` when it is undefined - never zero for "unknown"."""
    if denominator == 0:
        return None
    return numerator / denominator


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #


def replay_findings(
    framework: Framework,
    variant: str,
    findings: list[dict[str, Any]],
    workspace: Path,
    launch: LaunchSpec,
    credentials: dict[str, str],
) -> dict[str, Any]:
    """Replay every finding against the same state, and report the outcome.

    The application is started again on the database the scan left behind, so
    the resource the finding names still exists. The request is replayed with
    the principal's own token - the token is resolved here, never taken from
    the report.
    """
    if not findings:
        return {"attempted": 0, "succeeded": 0, "requests": 0, "failures": []}

    database = Path(workspace) / launch.database
    twin = Twin(
        TwinSpec(
            command=build_command(launch, framework.directory, database, variant),
            workdir=workspace,
            env=environment_for(launch),
            data_paths=[database],
            health_path=launch.health_path,
            health_timeout=launch.health_timeout,
        ),
        workspace=Path(workspace) / "replay-twin",
    )
    attempted = 0
    succeeded = 0
    sent = 0
    failures: list[dict[str, Any]] = []
    twin.start()
    try:
        tokens: dict[str, str] = {}
        for principal in sorted({finding.get("principal") for finding in findings if finding.get("principal")}):
            token = _login(twin.base_url, principal, credentials[principal])
            if not token:
                failures.append({"law": None, "reason": f"the application refused {principal} during the replay"})
                continue
            tokens[principal] = token

        for finding in findings:
            attempted += 1
            principal = finding.get("principal") or ""
            steps = finding.get("steps") or []
            if not steps:
                failures.append({"law": finding.get("law"), "reason": "the finding has no reproduction step"})
                continue
            if principal not in tokens:
                failures.append({"law": finding.get("law"), "reason": "no token was issued for the principal"})
                continue
            step = steps[0]
            method = step["method"]
            path = urlsplit(step["url"]).path
            url = twin.base_url.rstrip("/") + path
            session = requests.Session()
            session.headers["Authorization"] = f"Bearer {tokens[principal]}"
            kwargs: dict[str, Any] = {"timeout": 20}
            if step.get("body") is not None:
                kwargs["json"] = step["body"]
            try:
                response = session.request(method, url, **kwargs)
            except Exception as exc:
                failures.append({"law": finding.get("law"), "reason": f"the replay failed: {exc}"})
                continue
            sent += 1
            problem = check_replay(finding, response, database)
            if problem is None:
                succeeded += 1
            else:
                failures.append(
                    {
                        "law": finding.get("law"),
                        "principal": principal,
                        "method": method,
                        "path": path,
                        "status": response.status_code,
                        "reason": problem,
                    }
                )
    finally:
        twin.stop()
    return {"attempted": attempted, "succeeded": succeeded, "requests": sent, "failures": failures}


def check_replay(finding: dict[str, Any], response: Any, database: Path) -> str | None:
    """Whether the replay reproduced the finding - and what did not."""
    law = finding.get("law")
    status = response.status_code
    if not (200 <= status < 300):
        return f"the replay was not accepted: {status}"
    resource = (finding.get("resource") or "").split(":")[-1]
    if law == "L2":
        try:
            payload = response.json()
        except Exception:
            return "the replay did not answer with JSON"
        if not _contains(payload, resource):
            return f"the replay did not return the object {resource}"
        return None
    if law == "L3":
        owner = order_owner(database, resource)
        if owner is None:
            return f"the order {resource} is not in the database"
        if owner == finding.get("principal"):
            return "the order belongs to the attacker"
        return None
    return None


def _contains(payload: Any, identifier: str) -> bool:
    if isinstance(payload, dict):
        return str(payload.get("id")) == str(identifier)
    if isinstance(payload, list):
        return any(isinstance(item, dict) and str(item.get("id")) == str(identifier) for item in payload)
    return False


def order_owner(database: Path, identifier: str) -> str | None:
    """Who owns an order, read straight from the application's database.

    The attributor may key a row by its primary key or by its row id, so both
    are tried.
    """
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        row = connection.execute("SELECT owner_id FROM orders WHERE id = ?", (identifier,)).fetchone()
        if row is None and identifier.isdigit():
            row = connection.execute("SELECT owner_id FROM orders WHERE rowid = ?", (int(identifier),)).fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None
    finally:
        connection.close()
