# Phase VII.1.2 — Remote CI Verification and PR Readiness

## 1. State recorded before remediation

- Local branch: `feat/postgres-engine-integration`; local HEAD
  `22e70069a8a69d1aa0828f3e3ac271821f30bff7`; Phase VII.1 work uncommitted in the
  worktree (8 modified, 4 untracked); no staged changes.
- PR #11: open, unmerged, head `a5e3ec22d8bf130aabdf7a560077b63cf1894005`,
  base `main` `cac413733307651788670d42eaeb083c6ad8c946`; remote branch matched
  the PR head. `main` had not changed.
- `stash@{0}` inspected read-only: only `benchmarks/cross_framework/results/results.json`
  and results.md`; not applied, dropped or modified.

## 2. Remote CI on the ezact submitted HEAD

- Run **#273**, ID **44950357653**, event `pull_request`/`synchronize`,
  https://github.com/Toufiqtoufiqbo/mizan/actions/runs/44950357653,
  title `mizan@...a5e3ec2` (the full PR head above).
- Overall conclusion **FAILURE**, 7m 41s.
- Job results read from the run page and `get_check_runs`:

| Job | Result |
|---|---|
| A — static & unit | SUCCESS |
| B — PostgreSQL | SUCCESS |
| B2 — PostgreSQL lifecycle & destructive cleanup | **FAILURE** (exit code 1) |
| C — security regression | SUCCESS |
| D — benchmark | SUCCESS |
| E — Mizan scans Mizan | SUCCESS |
| F — independent application | SUCCESS |
| G — cross-framework gate | SUCCESS |
| G — external target (opt-in) | SKIPPED (documented opt-in job) |
| S — status summary | **FAILURE** (exit code 1, reflects B2) |

- B2 step conclusions: steps 1–7 SUCCESS; **step 8 "Generic-engine proof,
  replay, regression and real parallelism" FAILURE**; steps 9–22 SKIPPED.
- CI decision for that SHA: **FAILURE**. Run #261 (`22e7006`) was green but is
  an older commit and is not evidence for the Phase VII.1 head.

## 3. Reproduction attempt

Because GitHub Actions logs require a signed-in account in this environment,
the exact pytest output was not available. I reproduced the B2 step sequence
locally against a single shared PostgreSQL instance (same DSN for all steps,
as in the job):

```
tests/test_postgres_twin.py -m postgres_integration       56 passed, 3 skipped (269.39s)
tests/test_postgres_engine_integration.py -m postgres_integration   4 passed (78.95s)
tests/test_postgres_engine_generic_proof.py -m postgres_integration 14 passed (253.09s)
REPRO_FAILED False
```

The local reproduction therefore did **not** reproduce the CI failure; the
Linux/Python 3.12/PostgreSQL-service runner environment differs from the local
Windows/Python 3.11/pgserver environment.

## 4. Source inspection and comparison

Remote files at the submitted HEAD were fetched through GitHub's file API and
compared with local `git hash-object` values:

- Byte-identical: `.github/workflows/mizan.yml`, `src/mizan/cli.py`,
  `src/mizan/postgres_engine.py`, `src/mizan/regression.py`,
  fixture `app.py`, `openapi-generic.json`,
  `tests/test_postgres_engine_integration.py`,
  `tests/test_postgres_engine_generic_proof.py`, `tests/test_regression.py`,
  `PHASE_VII_1_SECURITY_AUDIT.md`.
- Divergent before this task: `tests/test_postgres_twin.py` (same test content,
  appended in a different order) and `PHASE_VII_1_COMPLETION_REPORT.md`
  (remote copy was truncated by a few characters). These were not functional
  divergences; A (static & unit) passed on the remote head.
- Source review confirms the generic CLI path (`learn → attack → write_bundles`),
  bounded real worker concurrency with independent databases/processes/logs,
  semantic finding normalization, replay/regression tests, and failure/cleanup
  tests are present in the pushed source. No legacy helper is used to manufacture
  generic-engine findings.

## 5. Remediation attempted (exact commits pushed)

1. `f6c97da8fe60144ef59246d0024ea056970e8bd6` — run-scoped database leak
   assertions, closed health-check sockets, longer barrier timeout.
2. `25e2ff5e7f64ca0e3e054f00da6b42a0f4c40454` — deterministic process-death
   recovery assertion (database object replacement) instead of PID sampling.

After each push the full new test module passed locally (14 passed; ruff clean).
CI run **#275**, ID **44953851616**, was triggered on the final HEAD
`25e2ff5e7f64ca0e3e054f00da6b42a0f4c40454`, URL
https://github.com/Toufiqtoufiqbo/mizan/actions/runs/44953851616:

| Job | Result |
|---|---|
| A, B, C, D, E, F, G | SUCCESS |
| B2 | **FAILURE** again at step 8 (exit code 1) |
| G external target | SKIPPED (opt-in) |
| S | **FAILURE** (exit code 1) |

The two remediation commits did not make CI green. No workflow definition was
modified, no test assertion was weakened, no PR was merged, `main` untouched,
and the stash remains intact.

## 6. Technical limitations

- GitHub Actions step logs cannot be retrieved in this environment: the browser
  is signed out ("Sign in to view logs") and no GitHub MCP tool exposes job log
  text or annotations beyond "Process completed with exit code 1".
- Therefore the exact failing test and traceback on the Linux runner are not
  known; the two remediation commits addressed plausible CI-specific brittleness
  but were not confirmed to address the root cause.
- Local reproduction uses Windows/Python 3.11/pgserver and is not equivalent to
  the runner's Linux/Python 3.12/PostgreSQL service.

## 7. Verdict

**INCOMPLETE.** A required CI job (B2) fails on the exact current PR head
`25e2ff5e7f64ca0e3e054f00da6b42a0f4c40454`; the failing step is the generic
PostgreSQL proof module. Green local results and green CI on older SHAs do not
override this. PR #11 remains open and unmerged.
