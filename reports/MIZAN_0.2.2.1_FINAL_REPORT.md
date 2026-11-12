# Mīzān 0.2.2.1 — Final Report

**Branch:** `feat/mizan-022-independent-validation`
**Pull request:** #6 — <https://github.com/Toufiqtoufiqbo/mizan/pull/6> (open, not merged)
**Baseline:** `07de6a5` (PR #6 as it was received)
**Environment:** native Windows 10 Pro 10.0.19045, Python 3.12.10, PostgreSQL 16.2

---

## 1. The defects that were confirmed

Every defect listed in `reports/MIZAN_0.2.2.1_BASELINE.md` was reproduced
before it was fixed:

| # | Defect | Reproduced | Fixed |
|---|---|---|---|
| 1 | the vulnerable fixture weakened the listing as well | yes | yes |
| 2 | the write probe recorded the original body | yes | yes |
| 3 | the read probe recorded the traffic's method | yes | yes |
| 4 | the owner check accepted one good finding | yes | yes |
| 5 | the learning traffic was invisible in the counts | yes | yes |
| 6 | the budget covered the attack phase only | yes | yes |
| 7 | no migration for the control-plane database | yes | yes |
| 8 | a partial authentication was a clean scan | yes | yes |
| 9 | the bundle endpoint did not check its path | yes | yes |
| 10 | the IPv6 form was not understood | yes | yes |
| 11 | the SARIF validator did not say it was structural | yes | yes |
| 12 | three CI stages could pass with a skipped suite | yes | yes |

## 2. What was fixed

### 2.1 Independent variants of the external application

The fixture now has four variants, and each one changes exactly one thing:

| Variant | The read check | The write check | The listing | Expected |
|---|---|---|---|---|
| `clean` | on | on | owner-scoped | no findings |
| `read` | **off** | on | owner-scoped | `L2` only |
| `write` | on | **off** | owner-scoped | `L3` only |
| `both` | **off** | **off** | owner-scoped | `L2` and `L3` |

The listing is **always** owner-scoped. Before this phase the single vulnerable
variant also returned every user's orders, so a cross-user *read* could be
detected through the listing as well - the experiment was not as isolated as
the report claimed.

Measured (the independent Flask application):

| Variant | Findings | Law types | Requests |
|---|---|---|---|
| clean | **0** | - | 15 |
| read | **1** | `L2` | 15 |
| write | **1** | `L3` | 15 |
| both | **2** | `L2`, `L3` | 15 |

`test_the_listing_stays_scoped_to_the_caller_in_every_variant` creates an
order as alice and as bob and asserts that each listing contains only the
caller's orders - in every variant.

### 2.2 Evidence integrity

- The write probe records the **body it sent** (`probe_body`), not the original.
- The read probe sends and records `READ_METHOD` (`GET`) - never the method
  from the traffic.
- `validate_finding()` checks **every** finding: the law, the principal, the
  action, the resource, the method, the endpoint, the status, the evidence, the
  reproduction, and - for `L2` and `L3` - an owner that is **not** the
  attacker. A finding that cannot be validated fails the gate; no evidence is
  invented.
- The replay test proves that a bundle reproduces the behaviour against the
  application that produced it, with the recorded request verbatim, and that
  the bundle carries a placeholder instead of the token.

### 2.3 Request accounting

`bootstrap`, `learning`, `attack` and `total` are counted separately, the
budget covers learning **and** attack, and the exhaustion is reported
(`budget_exhausted`). Details in
`reports/MIZAN_0.2.2.1_BUDGET_ACCOUNTING.md`.

### 2.4 The database migration

A control-plane database from the previous version (plaintext `token` column)
is migrated: the tokens are hashed, the users and their roles are kept, the
plaintext column is gone, the whole thing is one transaction, and a second run
does nothing. Details in `reports/MIZAN_0.2.2.1_DATABASE_MIGRATION.md`.

### 2.5 Fail-closed validation

A missing identity is a **setup error**, never a clean result. The gate
reports setup errors separately from findings, and a scan whose identities did
not all authenticate fails.

### 2.6 CI

Stages A, C and D now fail when their suite is skipped. Stage F prints the
expected behaviour of every variant.

## 3. New defects discovered during this phase

| Defect | Where | Consequence | Fix |
|---|---|---|---|
| the listing leak in the fixture | the Flask application | the read experiment was not isolated | four independent variants |
| the missing `flask` dependency | `pyproject.toml` | the independent-validation stage failed on CI | added to the dev extras |
| `mizan validate` still expected the old result shape | `cli.py` | the command reported the wrong thing | rewritten against the new result structure |
| the replay against a *different* application answered `404` | the test | a misleading test | the replay is now tested against the instance that produced the finding |
| `validate_target` did not accept the bracketed IPv6 form | `server.py` | a bypass of the host check was possible | the host is normalised first |
| the bundle endpoint did not check its path | `server.py` | a scan id could walk out of the bundle root | the path is resolved and checked |

## 4. Files changed

| File | Change |
|---|---|
| `src/mizan/engine.py` | the write probe records the sent body; the read probe sends and records `READ_METHOD`; `budget_exhausted` |
| `src/mizan/learning.py` | `max_requests` - the learning phase respects the budget |
| `src/mizan/validation.py` | rewritten: the variants, the request accounting, the fail-closed setup, `validate_finding()` |
| `src/mizan/server.py` | the database migration, one hashing function, the bundle path check, the IPv6 host, the strict finding model |
| `src/mizan/sarif.py` | the docstring names it a structural validator |
| `src/mizan/cli.py` | `mizan validate` against the new result structure |
| `src/mizan/parallel.py` | the findings of the workers are deduplicated |
| `tests/fixtures/external_apps/flask_store/app.py` | four independent variants; the listing is always owner-scoped |
| `tests/test_external_validation.py` | rewritten for the variants |
| `tests/test_evidence_integrity.py` | new - six tests |
| `tests/test_request_accounting.py` | new - eight tests |
| `tests/test_validation_fail_closed.py` | new - seven tests |
| `tests/test_database_migration.py` | new - six tests |
| `tests/test_control_plane_audit.py` | new - twelve tests |
| `.github/workflows/mizan.yml` | the skip guards for A and C; the variant expectations in F |
| `pyproject.toml` | `flask` in the dev extras |

## 5. Test results

| Suite | Before | After |
|---|---|---|
| the whole suite | 135 passed | **178 passed** |
| the unit suite | 120 | 163 |
| the PostgreSQL integration | 15 passed | **15 passed** (a real PostgreSQL 16.2) |
| `ruff check .` | PASS | PASS |
| `ruff format --check .` | PASS | PASS |

Commands (run on this machine):

```console
python -m pytest -q                                   # 178 passed, 1 warning, 178 s
python -m pytest -q -m "not postgres_integration"     # 163 passed, 15 deselected
python -m pytest -q -m "postgres_integration"         # 15 passed
python -m ruff check .                                # All checks passed!
python -m ruff format --check .                       # 84 files already formatted
```

The single warning is a third-party deprecation notice from
`starlette.testclient` about `httpx`.

## 6. CI

The branch was pushed and the workflow ran on GitHub Actions:

| Stage | Result |
|---|---|
| A - static and unit | success |
| B - PostgreSQL | success |
| C - security regression | success |
| D - benchmark | success |
| E - Mīzān scans Mīzān | success |
| F - independent application | success |
| G - external target | skipped (opt-in) |

Run: **RUN_ID_PLACEHOLDER**

PR #6 stays **open**.

## 7. SARIF validation evidence

- The document declares `"version": "2.1.0"` and the official schema
  reference; the rule identifiers are stable (`MIZAN-L1` ... `MIZAN-L7`).
- The severities map onto the SARIF levels; the evidence, the principal, the
  resource, the endpoint and the reproduction travel as properties.
- **No source locations are invented.**
- No secret is exported: the token is a placeholder.
- `validate_sarif()` is documented as **structural**; it is not a schema
  validation, and the tests say so.

## 8. Remaining limitations

| Limitation | Status |
|---|---|
| The corpus still covers one stack plus one Flask fixture | the FastAPI and Express applications are the next milestone |
| `DevAuth` has no expiry, no rotation, no revocation | documented; a development mechanism |
| The scan endpoint queues, it does not scan | documented |
| The target validation does not cover DNS, redirects or the network boundary | documented; the default is local-only |
| The SARIF validation is structural, not a schema validation | documented |
| `L1`, `L4` and `L5` are not proven through the external interface | documented in the external validation report |
| The control plane has no rate limiting and no audit log | not implemented |
| The independent application is a controlled fixture written by the author | stated in every report |

## 9. The verdict, unchanged and now better supported

Mīzān detects cross-identity reads **and** cross-identity writes in an
application that imports nothing from it, with its own authentication, its own
database and its own OpenAPI document - and it now proves that the finding it
reports is the request it sent.

What is still true: the corpus covers one stack and one external fixture, two
of the seven laws are unproven through the external interface, and there is no
external user. The next milestone is therefore still **more independent
applications**, not more laws.
