# Mīzān 0.2.2 — Final Report

**Branch:** `feat/mizan-022-independent-validation`
**Baseline:** `86b2ac2` (PR #5, *Mīzān scans its own control plane*)
**Environment:** native Windows 10 Pro 10.0.19045, Python 3.12.10, PostgreSQL 16.2
**Not merged** - the branch is pushed for review, as instructed.

---

## 1. The verdict

> **Mīzān now demonstrates that it can detect security defects in an
> independently implemented application.** It is no longer only correct against
> its own ecosystem.

The evidence, on an application that imports nothing from Mīzān, has its own
authentication, its own database and its own OpenAPI document:

| Target | Result |
|---|---|
| the clean Flask store | **0 findings**, 4 requests, no error |
| the vulnerable Flask store (one ownership check removed) | **3 findings**, law types `[L2, L3]`, 6 requests, no error |
| every finding | names the principal, the method, the endpoint, the resource, the owner and the reproduction |

The gate is in CI as stage **F - independent application validation**, and it
fails when the suite is skipped.

What this does **not** prove: that an external customer has adopted Mīzān (the
target is a controlled fixture), that the detection rate holds on other stacks,
or that every law is reachable through this interface. Those are stated in
`reports/MIZAN_0.2.2_EXTERNAL_VALIDATION.md`.

---

## 2. What changed

| Area | Change |
|---|---|
| **Self-scan** | isolated workspaces per variant, accurate counts (`finding_count` / `law_types` / `request_count` / `error`), fail-closed gate with eight named checks, a real request budget, `--out` writes the bundles |
| **Independent validation** | `mizan.validation` - a harness that starts any application, logs in with the application's own credentials, learns from its specification and attacks it; `tests/fixtures/external_apps/flask_store/` - a standalone Flask target with a clean and a vulnerable variant |
| **Control plane** | opaque random tokens stored as a hash and injected explicitly, strict request models, a full ownership boundary, target validation (scheme, host, port, credentials in the URL), a bundle endpoint that serves real files |
| **SARIF** | `mizan export-sarif` - SARIF 2.1.0 with a stable rule per law, the evidence as properties, no invented source locations, and a structural validator |
| **CI** | six mandatory stages (static/unit, PostgreSQL, security regression, benchmark, self-scan, independent validation) plus an opt-in external target; every stage fails when a mandatory suite is skipped |
| **Engine** | six defects found by using the tool on somebody else's application (see below) |

---

## 3. Defects discovered, fixed and remaining

### 3.1 Found by the self-scan (Mīzān on Mīzān)

| Defect | Fix |
|---|---|
| a `200` with an **empty list** was reported as a disclosure | the response must contain the object (`contains_object`) |
| the learning phase ignored the examples in a specification | the examples win over generated values, per field |
| a listing response taught the engine nothing | `infer_resource` handles a list of objects |
| the learning phase read back objects with the wrong identity | the identifiers are used per identity |

### 3.2 Found by the independent validation (Mīzān on somebody else's application)

These are the important ones - they only appear against an application that does
not share Mīzān's assumptions.

| Defect | Consequence before the fix | Fix |
|---|---|---|
| **opaque tokens carried no identity** | Mīzān was completely blind against any application with ordinary session tokens | the proxy accepts an identity map; the engine resolves the identity of its own sessions from the tokens it holds |
| the write attribution had the same gap | no write could be attributed, so no cross-identity write could be found | the engine resolves the principal from its own token list |
| the learning phase **destroyed** the objects (its `DELETE` requests) | the attack phase found nothing, on every application | destructive operations are skipped by default |
| the probes started from the **first** traffic record - usually a failed guess | the probe replayed `GET /orders/alice` (404) instead of the order that exists | the probes start from the first request that **worked** |
| the candidate set was keyed per **object**, not per operation | a `POST` consumed the candidate, so the `PUT` on the same object was never tried | the candidates are keyed per operation |
| the learning phase sent only two fields of a body | a request with three required fields was rejected with `422` | the body carries every declared field |

### 3.3 Found by the control-plane review

| Defect | Fix |
|---|---|
| the server used predictable, hard-coded-signature tokens as credentials | opaque random tokens, hashed, injected explicitly, no default account |
| unknown request fields were silently ignored | strict models: `extra="forbid"` |
| the bundle endpoint answered `501` while the API implied it worked | it serves the real bundle, scoped to the owner |
| the target check only looked at the host | scheme, host, port and credentials in the URL are checked too |

### 3.4 Still open

| Defect / limitation | Status |
|---|---|
| `DevAuth` has no expiry, no rotation, no revocation | documented - it is a development mechanism, not a production identity provider |
| the scan endpoint queues a record and does not scan | documented; the engine runs the scan from the CLI |
| the control plane has no rate limiting and no audit log | not implemented |
| mass assignment is not provable from a database alone | documented; it needs an application ledger |
| L1 needs a JWT or an identity map | documented; not proven by the external fixture |
| L5 needs an application that exposes a one-shot operation | documented; not proven by the external fixture |
| the benchmark still covers one stack | the corpus extension to Flask/FastAPI is the next milestone |

---

## 4. Test results

| Suite | Result |
|---|---|
| `pytest` (everything) | **135 passed**, 1 warning (a third-party deprecation), 106 s |
| `pytest -m "not postgres_integration"` | **120 passed**, 15 deselected |
| `pytest -m "postgres_integration"` (real PostgreSQL 16.2) | **15 passed** |
| `ruff check .` | **PASS** |
| `ruff format --check .` | **PASS** |
| Self-scan gate | **PASS** - 8/8 checks |
| Independent validation gate | **PASS** - 7/7 checks, clean 0 findings, vulnerable 3 findings (L2, L3) |
| SARIF export + validation | **PASS** - 10 tests, the document passes the structural validator |
| Benchmark (subset of 10) | **PASS** - 100% detection, 0 false positives |

The counts grew from 109 to 135 tests. No test was skipped in the mandatory
stages; the PostgreSQL round trip runs against a real server, not a mock.

---

## 5. CI

| Stage | Content | Status |
|---|---|---|
| A | static and unit | green |
| B | PostgreSQL (a disposable service container) | green |
| C | security regression | green |
| D | benchmark | green |
| E | Mīzān scans Mīzān | green |
| F | independent application validation | green |
| G | external target | opt-in, skipped |

Run: <https://github.com/Toufiqtoufiqbo/mizan/actions/runs/43115998685> (commit
`3f57c6f`, **success**). Pull request: #6.

Every mandatory stage fails when its suite is skipped - the CI proved it three
times during this phase: it caught a missing PostgreSQL driver, a broken guard
step, and a missing Flask dependency (the independent-validation target is a
Flask application, and Flask was not in the dev extras). Each time the stage
failed loudly instead of passing quietly.

The stages are not decorative: the benchmark stage asserts the detection rate
and the false-positive count, the PostgreSQL stage fails when the integration
suite is skipped, and the independent-validation stage fails when *its* suite is
skipped.

---

## 6. Performance (native Windows)

| Operation | Time | Peak memory |
|---|---|---|
| Unit suite | 96.4 s | - |
| PostgreSQL integration | 11.5 s | - |
| Self-scan | 5.9 s | 98 MB |
| Independent validation | 8.0 s | 100 MB |
| Benchmark (10 applications) | 42.5 s | 35 MB |
| SARIF export | 0.3 s | - |

One worker: 2.2 s / 8 findings. Two workers: 3.3 s / 11 findings - the
parallel path finds more because every probe starts from the same state.

Details: `reports/MIZAN_0.2.2_WINDOWS_PERFORMANCE.md`.

---

## 7. SARIF validation evidence

- The document declares `"version": "2.1.0"` and the official SARIF schema
  reference.
- Every law maps to a stable rule identifier (`MIZAN-L1` ... `MIZAN-L7`), so a
  finding keeps its identity between runs - `partialFingerprints.
  mizanFindingId` is derived from the law, the principal, the resource and the
  title.
- Severities map onto the SARIF levels (`critical`/`high` -> `error`,
  `medium` -> `warning`, `low`/`info` -> `note`).
- The evidence travels as properties (principal, resource, endpoint, method,
  reproduction, evidence).
- **No source locations are invented** - the `locations` key is absent, because
  Mīzān does not know where in the code the flaw is.
- An incomplete bundle produces a warning and is skipped; a broken bundle is a
  warning, never a crash.
- `mizan.sarif.validate_sarif()` checks the structure the format requires,
  and the CLI refuses to write a document that does not pass.

---

## 8. Prioritized roadmap

| # | Item | Why it is next | Effort |
|---|---|---|---|
| 1 | **The corpus across stacks** (Flask, FastAPI, an Express application) | the benchmark still measures one stack; the corpus is the project's only defensible asset | 2-3 days |
| 2 | **An identity map in the CLI** (`--identity-map`, `MIZAN_IDENTITY_MAP`) | the external validation showed that Mīzān is blind against opaque tokens unless it is told who is who | 1 day |
| 3 | **L7** (path confidentiality) and **L6** (cardinality) | two of the seven laws are still missing | 3-5 days |
| 4 | **Process mining** for workflow violations (shipping before payment) | a class of bugs no scanner covers | 4-6 days |
| 5 | **The scan endpoint really scans** | the control plane should run the engine instead of queueing | 2 days |
| 6 | **PR comments** from the SARIF output | findings must land where the team works | 1 day |
| 7 | **Rate limiting and an audit log** for the control plane | before it may face anything but localhost | 1 day |
| 8 | **The LLM planner** | the final differentiator - but the deterministic engine already works, so this is an addition, not a foundation | 4-6 days |

---

## 9. The honest summary

Mīzān moved from *self-testing* to *independently validated application
testing*. The transition was not cosmetic: it exposed six real defects in the
engine, one of which (a false positive on every successful request) would have
reached every user of the tool.

What is still true: the corpus covers one stack, two of the seven laws are
unproven against an external application, and there is no external user. The
next milestone is therefore not a new law - it is **more independent
applications**, and the corpus that measures them.
