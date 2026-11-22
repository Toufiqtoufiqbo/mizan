# Phase VII.2 — Evidence, Coverage & Benchmark Integrity

## 1. Verdict

**PASS** — with the explicit limitations in section 10. The benchmark executes a
real nonempty workload, parallel mode is accurately identified as replicated,
law coverage is derived from actual probe execution, generated regressions test
security invariants, and all required CI jobs are green on the final HEAD.

## 2. Baseline and final HEAD

- Baseline: `b095d11fa602cc2bb03c785e7df8302d6553639a`
- Final HEAD: `79c31b3bcdefb25362808c48a7db9986cc23c363`
- Branch: `feat/phase-vii-2`, PR #12 (open, unmerged)
- PR #11 (`feat/postgres-engine-integration`): open, unmerged, still at
  `b095d11fa602cc2bb03c785e7df8302d6553639a`; never modified.
- `main`: `cac413733307651788670d42eaeb083c6ad8c946`; never modified.

## 3. Changes

| File | Reason |
|---|---|
| `benchmarks/postgres_engine/run.py` | Real workload via `learn_from_spec` through the recording proxy; real attack; loud gates; honest replicated-mode label; environment/workload metadata; result validation. |
| `benchmarks/postgres_engine/results.json` | Fresh measurement on the final HEAD; zero counters eliminated. |
| `tests/fixtures/external_apps/postgres_store/app.py` | Returns its real `owner_id`, so learning derives genuine ownership evidence and nonzero rules. |
| `src/mizan/postgres_engine.py` | Per-worker execution metrics captured from the engines that actually ran. |
| `src/mizan/postgres_twin.py` | Bounded retry for a transient registry read during concurrent atomic replace; actionable missing-driver error. |
| `src/mizan/core.py` | `LawExecutionState` (seven documented states), derived per-law state and `executed_laws`. |
| `src/mizan/engine.py` | Probe execution recorded per law; L5 eligibility matches the POST-only implementation; L6 never standalone; state-verification evidence added to L3/L4 proofs. |
| `src/mizan/cli.py` | Backend status derived from engine records, no hardcoded law list; replay/regress use full proof evidence. |
| `src/mizan/proof.py` | `replay.json` now carries the evidence needed to regenerate a semantic regression. |
| `src/mizan/regression.py` | Invariant-based assertions, full proof sequence, original HTTP method, explicit unsupported outcome. |
| `pyproject.toml`, `README.md` | `postgres` extra, version aligned to the 0.2.2 release record, accurate identity and capability documentation. |

## 4. Benchmark

Measured on Windows 11, Python 3.11.9, psycopg 3.3.9, fixture `postgres_store`
variant `both`, schema `pgstore` (content-addressed fixture identity in
`results.json`):

| Metric | Value |
|---|---|
| Learning requests / traffic records | 10 / 10 |
| Resources discovered / rules learned | 2 / 2 |
| Eligible probes / executed probes | 4 / 2 |
| Serial requests / findings | 5 / 2 (`L2`, `L3`) |
| Serial duration | 13.2626 s |
| Parallel 2 workers | 21.6813 s, 10 requests, 4 probe executions, 2 findings, equivalent `true` |
| Parallel 4 workers | 30.9834 s, 20 requests, 8 probe executions, 2 findings, equivalent `true` |
| Execution mode | **replicated** — every isolated worker runs the whole `learn() → attack()` workload |
| Speedup claim | **none** |
| Failures / validation problems | 0 / 0 |

The parallel path is a worker-isolation and normalized-finding-equivalence
experiment. It is not partitioned scanning; no linear scalability is claimed.

## 5. Coverage

`laws_executed` is derived from `engine.executed_by_law`, which is incremented
only when a probe group actually issued requests. Serial benchmark coverage:

- `L2`: eligible 2, attempted 2, findings 1, inconclusive 1, state `executed`.
- `L3`: eligible 1, attempted 1, findings 1, state `executed`.
- `L1`, `L4`, `L5`: implemented but not exercised by this workload
  (`supported_not_exercised` where present).
- `L6`: `skipped` — only partially detected through L5 race heuristics, never
  a standalone executed law.
- `L7`: `unsupported`.

Generic and PostgreSQL backends share the same `LawExecutionState` schema.

## 6. Regression correctness

- **L1**: a valid authenticated HTTP 200 whose identity matches the token
  subject is accepted; a mismatch is reported through identity coherence.
- **L2/L3**: assertions use the disclosed object/persisted state and confirmed
  ownership evidence, not status codes alone. Missing evidence produces an
  explicit `unsupported` skip.
- **L4**: the original HTTP method is preserved; the assertion checks the
  privileged field in a state readback. An echoed sentinel no longer proves
  anything.
- **Multi-step**: all recorded steps are replayed in order with per-step
  authentication; `EXPECTATION` is consumed in the assertion message.
- Quality gates cover secure L1/200, vulnerable L2, blocked L2, original L4
  method, echo rejection, persisted state detection, sequence preservation and
  insufficient evidence.

## 7. PostgreSQL lifecycle

Five direct deterministic tests drive `DisposableDatabase.create()` itself:
a seed session seen during inspection then disappearing during the bounded
drain (with a fresh, independent cursor for the existence check), a persistent
session that fails closed before `CREATE DATABASE`, a missing catalog OID,
marker/record binding to the owned worker only, and timeout expiry. The
bounded registry read retry preserves all ownership and deletion checks.

## 8. Tests

- Focused suites: coverage soundness (88 passed), regression/generated tests
  (22 passed), law execution states, seed-session race (5 passed), packaging
  (5 passed), benchmark validation (3 passed), and the three previously failing
  replay/regress integration tests — all green after the fixes.
- Full local suite on the code commit `79c31b3bcdefb25362808c48a7db9986cc23c363`:
  **774 passed, 3 skipped, 1 warning in 1070.11 s (17:50)**.
- `ruff check .`: **All checks passed**; `ruff format --check .`:
  **171 files already formatted**.
- OS: Windows 10/11, Python 3.11.9. The 3 skips are the pre-existing POSIX-only
  signal tests; the single warning is the pre-existing Starlette/httpx
  deprecation notice.
- The earlier full run exposed 3 real failures (replay and regress lost proof
  evidence; a bare L2 `Attack` had no object identity). All three were fixed
  with the evidence-carrying proof bundle and explicit object-id handling; the
  final full suite is green.

## 9. CI

Workflow run **#285 / ID `45018335120`** on exact code HEAD
`79c31b3bcdefb25362808c48a7db9986cc23c363`: **success**.

| Job | Result |
|---|---|
| A - static & unit | success |
| B - PostgreSQL | success |
| B2 - PostgreSQL lifecycle & destructive cleanup | success |
| C - security regression | success |
| D - benchmark | success |
| E - Mizan scans Mizan | success |
| F - independent application | success |
| G - cross-framework gate | success |
| G - external target (opt-in) | skipped (by design) |
| S - status summary | success |

The final report commit is documentation-only; CI is re-run on that exact HEAD
as well, and the result is recorded in the same PR.

## 10. Known limitations

- Parallel execution is replicated, not partitioned. Each isolated worker runs
  the complete workload; no linear scalability or speedup is claimed.
- PostgreSQL L4, L6 and L7 remain unsupported. L6 is reported as `skipped`,
  never executed.
- Semantic regressions require proof evidence (object identity, state
  verification endpoint, privileged field/value). Where absent they skip with
  an explicit reason instead of inventing an assertion.
- The earlier transient seed-session identity was never captured; the bounded
  drain is covered deterministically, but that backend's identity remains
  unattributed.
- This phase does not make Mīzān complete: genuine backend capability gaps and
  remaining incomplete generic-law implementations still require a later phase.

## 11. Git state

- Local branch `feat/phase-vii-2` at `79c31b3bcdefb25362808c48a7db9986cc23c363`.
- Remote branch verified at the same SHA; no force-push, no history rewrite.
- PR #12 open against `main`; PR #11 and `main` untouched; stash from the
  previous phase preserved.
