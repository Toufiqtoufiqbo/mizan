# Mīzān 0.2.2 — Baseline

**Date:** 2026-11-11
**Baseline commit:** `86b2ac2` (`main`, PR #5 merged: *Mīzān scans its own control plane*)
**Branch for this phase:** `feat/mizan-022-independent-validation`

---

## 1. Repository state

| Item | Value |
|---|---|
| `main` | `86b2ac228cc79f2b617e84e5805e0e89f88a708b` |
| PR #5 | closed, merged (`merge_commit_sha = 86b2ac2`) |
| Working tree vs `main` | identical (0 differing files) |
| Git binary | **not installed** - branches and commits are made through the GitHub Git Data API |

## 2. Environment (native Windows, no WSL)

| Item | Value |
|---|---|
| OS | Microsoft Windows 10 Pro, 10.0.19045 (64-bit) |
| CPU | Intel Core i5-6500 @ 3.20 GHz, 4 cores / 4 logical |
| RAM | 11.4 GB |
| Python | 3.12.10 (Windows-10-10.0.19045-SP0) |
| Mīzān | 0.1.0 (editable install) |

Installed dependencies that matter:

```
click==8.5.1          fastapi==0.162.4     httpx==0.28.1
hypothesis==6.170.15   pgserver==0.1.4      psycopg==3.3.8
pytest==9.2.0          requests==2.34.2     ruff==0.16.10
schemathesis==4.33.1   starlette==1.10.0    uvicorn==0.54.0
```

## 3. Test baseline

| Suite | Result | Time |
|---|---|---|
| `pytest` (everything) | **109 passed**, 1 warning | 89.2 s |
| `pytest -m "not postgres_integration"` | **94 passed**, 15 deselected | 76.3 s |
| `pytest -m "postgres_integration"` (real PostgreSQL 16.2 via `pgserver`) | **15 passed**, 94 deselected | 14.0 s |

The warning is a `starlette.testclient` deprecation notice about `httpx`
(third-party, not ours).

## 4. Benchmark baseline

AuthzBugs-50: detection 100% (50/50), false positives 0/55, regression-test
validity 100% (290 attacks reproduce before the fix, 290 are blocked after it).

## 5. Known weaknesses at the baseline

These are the defects this phase has to repair. They are stated here so that the
end of the phase can be compared against them.

1. **The self-scan shares one workspace between its two variants** - the
   weakened run starts from the state the clean run left behind.
2. **The self-scan reports `len(result.laws)` as the number of findings** -
   several findings under one law are counted as one.
3. **The self-scan is not fail-closed**: a crashed scanner, a server that did
   not start, or a scan that sent no request can be reported as "clean".
4. **`budget` and `--out` do not affect the execution** of the self-scan.
5. **The control plane uses predictable tokens** (`make_token` with a hard-coded
   signature) and **silently ignores unknown request fields**.
6. **`GET /scans/{id}/bundle` answers `501`** while the API documentation
   implies it serves bundles.
7. **The scan endpoint queues a record and never runs a scan** - the API
   overstates what it does.
8. **Mīzān has only ever been validated against its own control plane** - the
   self-scan uses Mīzān's own server, its own tokens and its own assumptions.
   Whether the tool can find a defect in an application that knows nothing
   about Mīzān is untested.
9. **No SARIF export**: findings can only be read as prose or JSON.
