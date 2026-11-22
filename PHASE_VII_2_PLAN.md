# Phase VII.2 implementation plan

Baseline: `b095d11fa602cc2bb03c785e7df8302d6553639a` (exact).
Branch: `feat/phase-vii-2` (created from the baseline worktree; PR #11 untouched).

## Audit findings (verified on the baseline)

1. `benchmarks/postgres_engine/run.py` never calls `learn_from_spec` and never
   supplies a relationship contract. `engine.learn()` therefore sees an empty
   traffic file: 0 resources, 0 rules, 0 probes, 0 findings. The recorded
   `results.json` confirms all three counters are zero.
2. `PostgresRun.parallel_attack()` runs the **full** `learn() -> attack()` on
   every worker (replicated execution). It does not partition probes. No
   speedup claim may be made; it is a worker-isolation/equivalence experiment.
3. `cli._run_postgres_cli()` hardcodes
   `laws_executed = findings' laws | {'L1','L2','L3','L5'}`.
4. `_eligible_probe_targets()` counts POST/PUT/PATCH/DELETE for L5 while
   `_probe_races()` only processes POST. L6 is only inferred by `detect_race`.
5. `regression.py` asserts status codes for L1/L2/L3, always uses PATCH for L4,
   checks an echoed sentinel in the response body, uses only `steps[0]`, and
   `EXPECTATION` is documentation-only.
6. `DisposableDatabase.create()` has the bounded seed drain, but no test drives
   the exact creation path with a disappearing session and a fresh cursor.
7. `pyproject.toml` has no `postgres` extra; README install/version/capability
   documentation is inconsistent.

## Workstreams and files

- **W1 benchmark** — `benchmarks/postgres_engine/run.py`,
  `benchmarks/postgres_engine/results.json`,
  `tests/fixtures/external_apps/postgres_store/app.py`,
  `tests/test_postgres_benchmark.py` (new).
- **W2 coverage** — `src/mizan/core.py`, `src/mizan/engine.py`,
  `src/mizan/cli.py`, `tests/test_phase_v2_2_coverage.py`,
  `tests/test_postgres_engine_generic_proof.py`, `tests/test_law_execution_states.py` (new).
- **W3 regressions** — `src/mizan/regression.py`, `src/mizan/engine.py`
  (evidence for state verification), `tests/test_regression.py`.
- **W4 lifecycle** — `src/mizan/postgres_twin.py` (only if a defect is found),
  `tests/test_postgres_twin.py`, `tests/test_seed_session_race.py` (new).
- **W5 packaging/docs** — `pyproject.toml`, `README.md`,
  `tests/test_packaging.py` (new).
- **W6 safety** — existing safety suites must stay green, unchanged semantics.

## Commit sequence

1. plan
2. benchmark repair + tests
3. coverage truthfulness + tests
4. regression correctness + tests
5. seed-session race test
6. packaging/docs + tests
7. final report, lint, focused + full suite, push, CI, PR update

No force-push, no history rewrite, no merge, no `main` changes.
