# Mīzān 0.3.0 — Readiness Blocker

**Date:** 2026-11-12
**Repository:** `Toufiqtoufiqbo/mizan`
**Phase:** 0.3.0 — cross-framework validation (FastAPI + Express)

> **This phase did not start, and that is the correct outcome.**
> The mission defines a dependency gate: PR #6 is a prerequisite. PR #6 is
> **open**, so the gate is not satisfied. The mission's instruction in that
> case is explicit:
>
> > *Do not modify the existing PR. Do not merge it. Do not create a branch
> > from an outdated or ambiguous base. Perform only a non-mutating readiness
> > audit. Produce `reports/MIZAN_0.3.0_READINESS_BLOCKER.md` explaining
> > precisely what must happen before this phase can safely start.*
>
> No branch was created, no pull request was opened, and PR #6 was not
> touched.

---

## 1. The dependency gate

| Item | Value |
|---|---|
| PR #6 state | **open** |
| merged | **no** |
| head SHA | `292ad4a944195d7fae93f5822093977912b57ae7` |
| base branch | `main` |
| mergeable | `true` (state `clean`) |
| reviewers requested | none |
| latest CI on the branch | **success** — <https://github.com/Toufiqtoufiqbo/mizan/actions/runs/43215047929> |
| `main` head | `86b2ac228cc79f2b617e84e5805e0e89f88a708b` |
| files on the branch that are **not** on `main` | **41** |

**The changes this phase would build on are not on the default branch.**
Every one of the 41 files - including the whole `mizan.validation` harness, the
four-variant external fixture, the request accounting, the evidence validation
and the six reports - lives only on the PR branch.

### What this means concretely

A branch for 0.3.0 created from `main` today would be based on a tree that
**does not contain**:

| Missing | Consequence for 0.3.0 |
|---|---|
| `src/mizan/validation.py` | there is no harness to scan an external application at all |
| `tests/fixtures/external_apps/flask_store/` | there is no working external fixture, and no reference implementation of the contract |
| the four isolated variants (`clean`/`read`/`write`/`both`) | the variant matrix this phase is built on does not exist |
| the request accounting (`bootstrap`/`learning`/`attack`) | the benchmark could not report the metrics the mission requires |
| `validate_finding()` | the per-finding evidence validation the mission requires does not exist |
| the CI stages A-F with their skip guards | the new stage G would land on a workflow that lacks the guards the mission demands |
| `reports/MIZAN_0.2.2*.md` | the measured baseline this phase is supposed to extend would not exist |

Building 0.3.0 on that base would mean **re-implementing the 0.2.2.1 work**
(178 tests, 41 files) inside the 0.3.0 branch - producing two divergent
copies of the same code and a PR that mixes two phases. That is exactly the
"outdated or ambiguous base" the mission forbids.

## 2. Baseline and environment (measured)

| Item | Value |
|---|---|
| Local tree | identical to the PR head (`292ad4a`) |
| Baseline suite | **178 passed**, 1 warning (a third-party `starlette` deprecation) |
| Baseline suite duration | 151 s |
| `ruff check .` | PASS |
| `ruff format --check .` | PASS |
| OS | Microsoft Windows 10 Pro 10.0.19045, 64-bit |
| CPU / RAM | Intel Core i5-6500 @ 3.20 GHz, 4 cores / 11.4 GB |
| Python | 3.12.10 |
| PostgreSQL | 16.2 (via the `pgserver` package), 15 integration tests pass |

### A second, independent blocker: there is no Node.js on this machine

```
node : The term 'node' is not recognized ...
npm  : The term 'npm'  is not recognized ...
```

The Express fixture cannot be written, run, or measured without a Node
runtime. CI would have it (the `actions/setup-node` step), but the mission
requires **native local execution** and real measurements - and a fixture that
was never executed locally is exactly the kind of thing this phase exists to
prevent.

Node has to be installed before the Express half of this phase can start.

## 3. Readiness audit - what is already in place

The interfaces 0.3.0 would build on, inspected in the current tree:

### 3.1 The seams that exist and are reusable

| Seam | Where | Reusability |
|---|---|---|
| the twin launches an application on a free port | `mizan.twin.Twin` | framework-independent ✔ |
| the proxy records the traffic and resolves the identity from a map | `mizan.proxy.RecordingProxy(identity_map=...)` | framework-independent ✔ |
| the learning phase reads an OpenAPI document and exercises the endpoints | `mizan.learning.learn_from_spec` | framework-independent ✔ (it needs a **file**, see below) |
| the law detectors `L2` and `L3` | `mizan.engine._probe_read_authorization` / `_probe_write_authorization` | framework-independent ✔ |
| the write attribution from a database diff | `mizan.attribution.SqliteAttributor` | database-specific (SQLite) ✔ |
| the SARIF export and the CLI | `mizan.sarif`, `mizan.cli` | framework-independent ✔ |

### 3.2 The seams that are Python-shaped and would have to change

| Seam | Current shape | What 0.3.0 needs |
|---|---|---|
| the application launcher | `validation.py:186` → `script_command(app_dir / "app.py", "--db", ..., "--port", "{port}", "--vulnerability", variant)` | a **per-application launch contract** (a command, a database path, a variant flag), so a Node application can be launched the same way |
| the variant switch | a `--vulnerability` command-line flag | the same for Express - a flag with the same four values |
| the OpenAPI document | `validation.py:218` → a file `openapi.json` next to the application | Express must ship an equivalent document (FastAPI can generate its own, but the harness reads a file) |
| the authentication handshake | `validation.py:128` → `POST /login` with `{"username", "password"}` answering `{"token": ...}` | the **contract** must state this; both applications implement it independently |
| the credentials | the harness passes `username`/`password` pairs | both applications need the same *test* credentials, injected per run, never hardcoded |
| the database | `SqliteAttributor(database)` | Express must write a **SQLite file** the same attributor can read |

### 3.3 What is genuinely framework-independent today

- The engine's law detectors work on HTTP responses and on a database diff.
  Nothing in `L2` or `L3` knows about Flask, FastAPI or Express.
- The proxy, the twin, the learning phase and the SARIF export are all
  framework-agnostic.

That is the encouraging part of the audit: **the architecture is ready for a
second framework.** What is missing is a *contract* and a *launch abstraction* -
both of which are exactly what 0.3.0 was going to write.

## 4. What has to happen before 0.3.0 can start

| # | Action | Owner | Why it blocks |
|---|---|---|---|
| 1 | **Merge PR #6** (or land its 41 files on `main`) | the repository owner | the phase builds on its harness, its fixture, its accounting and its evidence validation; the mission forbids merging it, so the owner has to do it |
| 2 | **Install a Node.js runtime** (20.x LTS or 22.x) on the development machine | the repository owner | the Express fixture cannot be executed, measured or reported without it |
| 3 | Re-run the baseline on `main` after the merge | the agent | the baseline must be measured on the branch the phase starts from |
| 4 | Only then create `feat/mizan-030-cross-framework-validation` from the updated `main` | the agent | the mission's branch creation |

Two decisions are explicitly **not** mine to take:

- **merging PR #6** - the mission says twice that no pull request may be
  merged, and the previous phase was told to keep PR #6 open;
- **installing system software** (Node.js) - it changes the machine.

## 5. What this audit did and did not do

**Did** (read-only):

- inspected the GitHub state of PR #6, its head, base, mergeability, review
  status and CI results;
- compared the branch against `main` (41 files apart);
- inspected the local tree and confirmed it matches the PR head;
- read the 0.2.2.1 reports;
- ran the baseline suite (178 passed) and the linters;
- inspected the nine modules and the external fixture to map the seams that
  0.3.0 would build on;
- confirmed that Node.js is absent from this machine.

**Did not**:

- create the `feat/mizan-030-cross-framework-validation` branch;
- modify, merge, close or comment on PR #6;
- push anything to any branch;
- write any fixture, benchmark or report other than this one.

## 6. The recommendation

Merge PR #6 first. It is green on every mandatory stage
(<https://github.com/Toufiqtoufiqbo/mizan/actions/runs/43215047929>), it
closes the twelve defects of the 0.2.2.1 audit, and 0.3.0 is a direct
extension of it. Then install Node.js, and the cross-framework phase can start
from a base that is unambiguous.
