# Phase VII.1.3 — B2 Linux CI Failure Forensics and Root-Cause Resolution

## 1. Confirmed failure evidence

- Authenticated GitHub Actions API was reached with `curl --http1.1` and the
  repository token (`api.github.com` times out with HTTP/2 but succeeds with
  HTTP/1.1). Job logs were downloaded from
  `GET /repos/Toufiqtoufiqbo/mizan/actions/jobs/137003669159/logs`
  (HTTP 200, 201,745 bytes).
- CI run **#278**, ID **44955850965**, head
  `840bcfea7bf48a3dc3671b7020af8a3497c4fdc0`; failed job B2, job ID
  **137003669159**, step **8** `Generic-engine proof, replay, regression and
  real parallelism`, exit code 1.
- Exact failing test:
  `tests/test_postgres_engine_generic_proof.py::test_regress_command_generates_failing_test_on_vulnerable_and_passing_on_clean`.
- Traceback excerpt from the generated regression test
  `/tmp/mizan-vii-gp-reg-mxl00361/test_mizan_l3.py`:

  ```
  response = requests.request("{ATTACK.METHOD}", URL, headers=HEADERS, json=BODY, timeout=15)
  ValueError: Method cannot contain non-token characters '{ATTACK.METHOD}' (found at least '{')
  ```

  The generated L3 regression failed with exit code 1 on the *vulnerable*
  fixture, so the assertion `(run.returncode != 0) == expected` failed for the
  clean app (`expected=False`).

## 2. Root cause (confirmed)

`src/mizan/regression.py::_render_body()` used a plain triple-quoted string for
the non-GET (write) branch while every other branch used an f-string. The
generated regression therefore contained the literal placeholder
`{ATTACK.METHOD}` instead of the recorded HTTP method (`PUT`). `urllib3`
rejects that as an invalid method before any request is sent.

Why local runs passed: the test selected the first proof bundle with
`next(directory for directory in out.iterdir() ...)`, which was usually the L2
(GET) bundle locally; CI selected the L3 (PUT) bundle. This is a confirmed
filesystem-order/test-selection dependency, not an infrastructure problem.
A separate earlier CI failure (run #275, job 136997487627) showed
`TwinLifecycleError('the immutable seed still has active sessions')` during the
same test's initial CLI run — a transient active seed backend at clone time.
Its session identity was not captured; it is classified as **suspected**
transient/autovacuum session, not confirmed.

## 3. Reproduction and regression evidence

- Runner environment from job logs: `ubuntu-latest`, Python 3.12.16,
  PostgreSQL service `postgres:16-alpine`, DSN
  `postgresql://postgres:mizan@localhost:5432/postgres`,
  `MIZAN_REQUIRE_POSTGRES=1`, pytest 9.2.0.
- Local B2 sequence on one shared PostgreSQL (Windows/Python 3.11/pgserver):
  56 passed + 4 passed + 14 passed; it did not reproduce the Linux failure,
  confirming the need for the real job logs.
- New unit regression `test_generated_write_regression_uses_the_real_http_method`
  asserts the generated source contains `requests.request("PUT"` and no
  `{ATTACK.METHOD}` placeholder. With the buggy renderer temporarily restored,
  this test failed (`BUGGY_EXIT 1`); with the fix it passes. This is direct
  evidence that the regression test fails under the original bug.

## 4. Audit of previous fixes

- `f6c97da` (run-scoped leak checks, closed health sockets, longer barrier
  timeout) and `25e2ff5` (deterministic process-death assertion) did not
  address the renderer bug. They changed test robustness, not the failure
  cause. They did not weaken the security assertions; the deterministic
  process-death assertion was kept.
- The diagnostic-only commit `840bcfea` added active-session details to the
  clone error. Its patch closed the `admin.cursor()` context before the
  "worker database already exists" check, leaving that check on a closed
  cursor. It was harmless while no seed session was present, but on CI run
  **#280** (head `9790262`, job 137012168569) the drain path was entered and
  the benchmark step failed with:

  ```
  psycopg.InterfaceError: the cursor is closed
  postgres_twin.py:2169 in create  -> cursor.execute("SELECT 1 FROM pg_database ...")
  ```

  This is a confirmed regression introduced by the diagnostic patch, not an
  environmental failure. The existence check now uses a fresh cursor and runs
  unconditionally, restoring the original fail-closed invariant.

## 5. Changes pushed (exact commit)

Commit `406bb1855d11315212ff56476afaaad864d4caa7` on
`feat/postgres-engine-integration`:

1. `src/mizan/regression.py`: write branch now an f-string, emitting the real
   HTTP method.
2. `tests/test_regression.py`: new regression test for the write-method
   placeholder.
3. `tests/test_postgres_engine_generic_proof.py`: selects the L3 bundle
   explicitly so the write path is always exercised.
4. `src/mizan/postgres_twin.py`: `DisposableDatabase.create()` now gives a
   transient seed backend the same bounded 5-second drain used by verified
   drops, then still fails closed with session details if it remains. The
   subsequent worker-existence check was moved back into its own cursor scope
   after the CI #280 closed-cursor regression.

All pushed files were byte-compared against local `git hash-object` values and
matched exactly. `ruff check .` and `ruff format --check .` pass.

## 6. Verification

- Local `python -m pytest -q`: **743 passed, 3 skipped (POSIX-only signal tests
  on Windows), 1 unrelated warning in 907.71 s**.
- `ruff check .` and `ruff format --check .`: clean.
- New unit regression fails on the buggy renderer (`BUGGY_EXIT 1`) and passes
  with the fix; the integration test now selects the L3 bundle deterministically.
- CI run **#279**, ID **44956914068**, on code HEAD
  `406bb1855d11315212ff56476afaaad864d4caa7`: overall **success**; A, B, B2,
  C, D, E, F, G, S all `success`; external target `skipped` by design.
- CI run **#280**, ID **44958607217**, on docs-only HEAD `9790262`: B2 failed
  in the benchmark step with the confirmed closed-cursor regression described
  above; all other jobs passed. This was not a recurrence of the renderer bug.
- The corrected cursor scope is included in the final push with this report;
  CI on that exact HEAD is verified in PR #11 before the final verdict.

## 7. Verdict

**READY FOR REVIEW** once the final exact-HEAD CI run is green: the original B2
failure was explained from real job logs, the renderer bug fixed, a
failing-before/passing-after regression added, and the diagnostic-introduced
cursor regression corrected. PR #11 remains open and unmerged; `main`, history
and the stash were not touched.

Remaining limitation: the earlier transient seed-session failure (run #275)
was mitigated with a bounded drain but its exact backend identity was never
captured; it did not recur in runs #278 or #279.
