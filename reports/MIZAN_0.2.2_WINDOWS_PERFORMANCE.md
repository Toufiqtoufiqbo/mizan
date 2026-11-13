# Mīzān 0.2.2 — Native Windows Validation and Resource Profile

**Machine:** the actual development environment - native Windows, no WSL.
**Raw measurements:** `reports/windows-profile.json` (produced by
`scripts/measure_windows.py`).

---

## 1. Environment

| Item | Value |
|---|---|
| OS | Microsoft Windows 10 Pro, version 10.0.19045, 64-bit |
| CPU | Intel Core i5-6500 @ 3.20 GHz, 4 cores / 4 logical processors |
| RAM | 11.4 GB |
| Python | 3.12.10 (Windows-10-10.0.19045-SP0) |
| Mīzān | 0.2.2 (branch `feat/mizan-022-independent-validation`) |
| PostgreSQL | 16.2, run locally through the `pgserver` package (a PostgreSQL build shipped as a Python package) |

Relevant dependencies:

```
click 8.5.1        fastapi 0.162.4     flask 3.1.3      httpx 0.28.1
hypothesis 6.170.15 pgserver 0.1.4     psycopg 3.3.8    pytest 9.2.0
requests 2.34.2    ruff 0.16.10        schemathesis 4.33.1  starlette 1.10.0
uvicorn 0.54.0
```

## 2. Measurements

Every number below comes from an execution on this machine. Nothing is
estimated.

| Operation | Time | Peak memory (process tree) | Result |
|---|---|---|---|
| Unit suite (120 tests) | 96.4 s | - | PASS |
| PostgreSQL integration (15 tests, real server) | 11.5 s | - | PASS |
| Self-scan (both variants) | 5.9 s | 98.4 MB | PASS |
| Independent validation (8 tests, Flask target) | 8.0 s | 100.2 MB | PASS |
| Benchmark subset (10 applications, 2 controls) | 42.5 s | 34.8 MB | PASS - 100% detection, 0 false positives |
| SARIF export | 0.3 s | - | PASS |

The whole suite: **135 tests, 106 s**.

## 3. One worker and two workers

The twin can attack several isolated copies of the application at the same
time. Measured on the demo application (`mizan twin --workers N`):

| Workers | Time | Findings |
|---|---|---|
| 1 | 2.2 s | 8 |
| 2 | 3.3 s | 11 |

Two observations, both honest:

1. **Two workers are not faster here.** The workload is small (seconds), and
   each worker starts its own application process; the start-up cost dominates.
   The parallelism is there for long scans, not for these.
2. **Two workers find more.** In the serial run the probes share one
   application, so a probe that changes the state can hide a finding from the
   next one. With isolated copies every probe starts from the same state - which
   is the property the twin was built for.

## 4. Resource usage

| Resource | Observed |
|---|---|
| Peak memory (a full scan) | ~100 MB for the process tree (the application under test plus the engine) |
| Peak memory (the benchmark) | ~35 MB |
| Temporary disk (one scan) | the twin's workspace: a database, a traffic log and a snapshot per variant - a few megabytes |
| HTTP requests (a self-scan) | 6 per variant, 12 in total |
| HTTP requests (the independent validation) | 4 (clean) and 6 (vulnerable) |
| Evidence files | 6 files per finding (replay.json, violation.md, evidence.json, matrix.json, patch.diff, regression.test) |

No stress test was performed and no memory was exhausted - the instruction not
to stress the machine was respected.

## 5. Native Windows behaviour

| Area | Behaviour |
|---|---|
| process management | the twin starts the application with `subprocess` and stops the whole tree (`taskkill /T /F`), so no child process survives |
| port allocation | ports are reserved with `SO_EXCLUSIVEADDRUSE`; without it two workers could pick the same port on Windows |
| SQLite | the database file is copied for the snapshot while the application may hold it open; the copies are consistent because the application commits per request |
| PostgreSQL | a real 16.2 server runs locally through `pgserver`; the integration suite passes unchanged |
| encoding | the console code page is `cp1252`; the test suite sets `PYTHONIOENCODING=utf-8` where it prints non-ASCII |
| line endings | the repository is checked out with CRLF; the code itself is written for LF and does not depend on the line endings |

Nothing in the project requires WSL, a container or a POSIX shell.

## 6. Not measured

- Behaviour under a Windows service or a scheduled task.
- Behaviour on a machine with fewer than 4 cores or less than 8 GB of RAM.
- Long scans (more than a few hundred requests) - the measurements above cover
  scans of 4 to 12 requests and a benchmark of 10 applications.
