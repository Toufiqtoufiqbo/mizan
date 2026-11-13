# Mīzān 0.2.2.1 — Baseline

**Date:** 2026-11-12
**Repository:** `Toufiqtoufiqbo/mizan`
**Pull request:** #6 — <https://github.com/Toufiqtoufiqbo/mizan/pull/6>
**Branch:** `feat/mizan-022-independent-validation`

---

## 1. Repository state

| Item | Value |
|---|---|
| Branch | `feat/mizan-022-independent-validation` |
| HEAD at the start of this phase | `07de6a57ea2ead4262f511745ab802a85e0cad99` |
| PR #6 head at the start | `07de6a5` (matches the branch) |
| PR #6 state | open, not merged |
| Git binary | **not installed** - `git status --short` cannot be run. The state was inspected through the GitHub API, and the commits are made with the Git Data API (blobs → tree → commit → ref). |
| Working tree | identical to the branch head at the start (`changed files: 0` against `main` before the first edit of this phase) |

### A note on the history

One empty commit (`b1ec7e1d`, message `probe`) is on the branch. It was
produced by an accidental invocation of the publishing helper with the message
`probe`; its tree is identical to its parent's, so it changes nothing. It was
**not** rewritten, because rewriting shared history is not allowed.

### Uncommitted user work

None. The working tree matched the branch head, and no user changes were
discarded during this phase.

## 2. Baseline test results

| Suite | Result | Time |
|---|---|---|
| `pytest` (everything) | **135 passed**, 1 warning | 106 s |
| `pytest -m "not postgres_integration"` | 120 passed, 15 deselected | 96 s |
| `pytest -m "postgres_integration"` (real PostgreSQL 16.2) | 15 passed | 11.5 s |
| `ruff check .` | PASS | - |
| `ruff format --check .` | PASS | - |

The single warning is a third-party deprecation notice from
`starlette.testclient` about `httpx`; it is not produced by Mīzān's code.

## 3. CI state at the start

| Run | Commit | Result |
|---|---|---|
| <https://github.com/Toufiqtoufiqbo/mizan/actions/runs/43115998685> | `3f57c6f` | success - all six mandatory stages green |

## 4. Defects found during the audit of PR #6

These are the defects this phase set out to repair. They are listed here so
that the end of the phase can be compared against them.

| # | Defect | Where | Severity |
|---|---|---|---|
| 1 | The vulnerable fixture variant weakened **more than the ownership check**: the listing of orders also returned every user's orders. | `tests/fixtures/external_apps/flask_store/app.py` | experimental design |
| 2 | The write probe recorded the **original** request body, not the perturbed body it actually sent. | `mizan/engine.py` (`_probe_write_authorization`) | evidence integrity |
| 3 | The read probe sent `GET` but recorded the **method from the traffic** (which may be `HEAD`). | `mizan/engine.py` (`_probe_read_authorization`) | evidence integrity |
| 4 | The validation gate only checked that *at least one* finding had an owner. | `mizan/validation.py` | evidence integrity |
| 5 | The reported request count covered only the attack requests; the learning traffic was invisible. | `mizan/validation.py`, `mizan/learning.py` | accounting |
| 6 | `budget` was honoured by the attack phase only; the learning phase could overrun it. | `mizan/learning.py` | accounting |
| 7 | The control-plane database had **no migration**: a database from the previous version kept a plaintext `token` column, and `CREATE TABLE IF NOT EXISTS` did not notice. | `mizan/server.py` | data safety |
| 8 | The validator proceeded when only **some** expected identities authenticated; a partial setup could be reported as a clean scan. | `mizan/validation.py` | false confidence |
| 9 | The bundle endpoint built a path from the scan id without checking that it stayed inside the bundle root. | `mizan/server.py` | path traversal |
| 10 | The target validation did not understand the bracketed IPv6 form. | `mizan/server.py` | input validation |
| 11 | The SARIF validator was called "validation" without saying that it is **structural**. | `mizan/sarif.py` | documentation |
| 12 | The CI stages A, C and D could pass with a skipped suite. | `.github/workflows/mizan.yml` | CI |

## 5. Baseline CI runs observed during this phase

| Run | When | Result |
|---|---|---|
| 43115998685 | before this phase | success (all six stages) |

During this phase the CI caught three of its own defects - a missing
PostgreSQL driver, a broken guard step, and a missing Flask dependency. Each
time the stage failed loudly instead of passing quietly.
