# Mīzān 0.3.0 — baseline

**Date:** 2026-11-13
**Repository:** `Toufiqtoufiqbo/mizan`
**Baseline:** the PR #6 branch, `feat/mizan-022-independent-validation`

This is what Mīzān looked like before the cross-framework phase started, and
what the phase is measured against.

---

## 1. The prerequisite

| Item | Value |
|---|---|
| PR #6 | **open**, not merged (`mergeable_state: clean`) |
| PR #6 head | `4f208d035583fe68fcc716723dc188875ada3ea5` |
| `main` head | `86b2ac228cc79f2b617e84e5805e0e89f88a708b` |
| Files on the PR branch that are not on `main` | 42 |
| Latest CI on the branch | **success** — <https://github.com/Toufiqtoufiqbo/mizan/actions/runs/43316828058> |

The dependency gate is therefore **not** satisfied, and the branch
`feat/mizan-030-cross-framework-validation` was **not** created. All of the
0.3.0 work described in these reports exists only in the local working tree.
See `reports/MIZAN_0.3.0_READINESS_BLOCKER.md`.

## 2. The baseline suite (measured)

| Item | Value |
|---|---|
| tests | **178 passed**, 1 warning (a third-party `starlette` deprecation) |
| duration | 143 s |
| `ruff check .` | PASS |
| `ruff format --check .` | PASS |

The suite already contained the Flask independent-validation module: one
standalone application, four isolated security variants, a request accounting
that separates bootstrap/learning/attack traffic, and a per-finding evidence
validation.

## 3. The environment (measured)

| Item | Value |
|---|---|
| OS | Microsoft Windows 10 Pro 10.0.19045, 64-bit |
| CPU | Intel Core i5-6500 @ 3.20 GHz, 4 cores |
| Memory | 11.4 GiB |
| Python | 3.12.10 |
| PostgreSQL | 16.2 (via `pgserver`), 15 integration tests pass |
| Node.js | **v26.13.1** at `C:\Program Files\nodejs` — installed on 2026-11-10, but not resolvable from the long-lived shell this phase ran in (a stale `PATH`). The Express fixture was additionally verified on v24.20.0. |
| SQLite | 3.49.1 (the Python binding) / Node's built-in `node:sqlite` |
| FastAPI | 0.162.4 |
| uvicorn | 0.54.0 |
| httpx | 0.28.1 |
| Express | 4.21.2 (pinned in `package-lock.json`) |
| Docker | not used, not available |
| git | **not installed** - the tree has no `.git`, so no commit SHA can be read; the reports carry a content digest instead |

## 4. The seam that had to change

The baseline harness launched an application with a Python convention:

```python
script_command(app_dir / "app.py", "--db", ..., "--port", "{port}", "--vulnerability", variant)
```

and read its OpenAPI document from a file next to it. That is fine for one
Python application and useless for a Node one. The phase replaced it with a
**launch contract** - `LaunchSpec` and `SpecSource` in
`src/mizan/validation.py`:

| Piece | What it decides |
|---|---|
| `command` | the command, with the placeholders `{app}`, `{database}`, `{port}`, `{variant}`, `{node}` |
| `entry` | the entry point, relative to the application's directory (`app.py`, `server.js`) |
| `database` | the database file, relative to the temporary workspace |
| `spec` | where the OpenAPI document comes from - a file, or an endpoint the application generates |
| `variant_flag` / `variant_map` | how the security variant is selected |
| `environment` | the environment the application is started with |

The detectors themselves did not change. `L2` and `L3` work on HTTP responses
and on a database diff, and know nothing about the framework underneath.

## 5. What the phase added

| Artefact | Count |
|---|---|
| new tests | **87** (35 FastAPI, 37 Express, 15 benchmark) |
| fixtures | 2 independent applications (FastAPI, Express) |
| benchmark | `benchmarks/cross_framework/` - a harness, a JSON report, a Markdown report and an independent checker |
| CI | one new mandatory stage, **G** |
| reports | 6 files in `reports/` |

The suite is now **265 tests** (178 + 87).
