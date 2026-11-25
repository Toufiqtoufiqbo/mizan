# Phase IX — Mīzān v1 product completion

## 1. Verdict

**PASS** for the frozen v1 scope. All declared v1 capabilities are implemented
and verified on both backends; L7 logs/metrics and other deferred capabilities
remain unsupported and are documented as such. Tests, lint, formatting and the
benchmark are green; CI verification is recorded below.

## 2. Baseline and SHAs

- Verified `origin/main`: `06aa2815dcb5935d84481455fef62062ea588567`
- Branch: `feat/product-completion-v1`
- Implementation SHA (all code, tests, benchmark and docs except this report):
  `27cca8bf40f487ecd905e9622fbe637e10c5a51d`
- Final documentation commit: the commit immediately after the implementation
  SHA; its SHA and CI result are recorded in PR metadata (no circular reference).
- Post-merge CI #291 (run `45233447307`, ID confirmed via API) initially failed
  `test_adversarial_scenarios[clean-expected1]` (`INCONCLUSIVE` instead of
  `CLEAN`) in job A on Ubuntu/Python 3.12. The failing job only was rerun and
  **succeeded** on the exact merge SHA; all mandatory jobs then passed. Local
  repetition of the test was 5/5 green on Python 3.11 with identical dependency
  versions, so the original failure is treated as environmental/non-safety and
  is tracked in `POST_V1_TECHNICAL_DEBT.md`.

## 3. Implemented features

- Generic/SQLite L4 field-based authority with trusted declarations and
  attributed persisted-state evidence (`tests/test_sqlite_l4.py`).
- Generic/SQLite L6 collection bounds and single-use capabilities with
  persisted row-count/consumption evidence (`tests/test_sqlite_l6.py`).
- L7 cache and queue providers observing **application-performed** HTTP
  operations, typed evidence, confidentiality policy, per-category coverage
  states and replay/regression
  (`src/mizan/confidentiality.py`, `tests/fixtures/external_apps/l7_store/app.py`,
  `tests/test_l7_application_backed.py`). Synthetic artifacts were removed;
  see `L7_APPLICATION_BACKED_REMEDIATION_REPORT.md`.
- CLI/JSON L7 per-category reporting; README quickstart and capability matrix.

## 4. Capability matrix

See `MIZAN_V1_CAPABILITY_MATRIX.md`.

## 5. Fixture results

- SQLite L4 vulnerable (`mass_assignment`): one confirmed finding with
  `original_value=user`, attempted value persisted by an attributed write;
  secure variant: zero findings (`tests/test_sqlite_l4.py`).
- SQLite L6 collection bound (2 per principal) and single-use capability:
  vulnerable variant yields violations verified from persisted row counts;
  secure variant blocks them (`tests/test_sqlite_l6.py`).
- PostgreSQL L4/L6 remain verified from Phase VIII (`tests/test_pg_l4_l6.py`).

## 6. Proof, replay and regression

L7 bundles carry category, provider, artifact digest, producer, consumer,
policy, application events, the three recorded HTTP steps and explicit outcome.
`mizan replay` re-executes those HTTP steps against the target and reclassifies
from the responses: vulnerable `confirmed_disclosure`, secure `blocked`.
Generated L7 regressions use the same function. The authorized owner read is a
gate — a secure mode that blocks everyone is inconclusive. Missing steps,
digest mismatch or identity mismatch never produce a confirmed finding.

## 7. Benchmarks

| Law/category | Variant | Findings | Executed probes | Duration |
|---|---|---|---|---|
| L4 | `l4_vulnerable` | 1 | 1 | 3.2444 s |
| L6 | `l6_vulnerable` | 3 | 1 | 4.2477 s |
| L7 cache | vulnerable | 1 | 1 | HTTP fixture probe, `confirmed_disclosure` |
| L7 cache | secure | 0 | 1 | HTTP fixture probe, `blocked` |
| L7 queue | vulnerable | 1 | 1 | HTTP fixture probe, `confirmed_disclosure` |
| L7 queue | secure | 0 | 1 | HTTP fixture probe, `blocked` |

Zero `failures`, zero benchmark/provider problems. Secure fixtures produce no
confirmed finding. No speedup claim is made.

## 8. Tests and environment

- 811 tests collected; executed in four disjoint batches (harness restarts
  prevent an uninterrupted run): 71 passed (31 s), 309 passed (381 s),
  300 passed + 3 skipped (452 s), 128 passed (361 s).
- **Total: 808 passed, 3 skipped, 0 failed, 1 warning** (pre-existing
  Starlette/httpx deprecation). Skips are POSIX-only signal tests on Windows.
- OS: Windows 10/11; Python 3.11.9; PostgreSQL via `pgserver`.
- `ruff check .`: clean; `ruff format --check .`: 186 files formatted.

## 9. CI

- Post-merge run **#291** (`45233447307`) on baseline `06aa2815`:
  mandatory jobs A, B, B2, C, D, E, F, G, S succeeded after rerunning the
  single transient A-job failure; external-target job skipped by design.
- CI on the final documentation HEAD is recorded in PR metadata; it does not
  change the implementation evidence above.

## 10. Issues and deferred scope

See `POST_V1_TECHNICAL_DEBT.md` and `MIZAN_V1_SCOPE.md`. L7 logs/metrics,
relationship-based L4, global quotas and partitioned scanning are deferred.

## 11. Git verification

- Branch `feat/product-completion-v1` created from verified `main`
  `06aa2815dcb5935d84481455fef62062ea588567`; final SHA pushed to origin.
- `main` and merged PRs #11/#12/#13 were never modified; no force-push or
  history rewrite; no merge performed.
- PR remains open and unmerged at final verification.
