# Phase VII.1 — Generic Proof, Real Parallelism & Failure Recovery

## 1. Verdict

`INCOMPLETE` until the full local suite, lint and CI B2 are green. This report
is updated with the exact evidence once those checks finish. No second attack
engine was added: `Mizan` remains the only engine.

## 2. Starting state

- Branch `feat/postgres-engine-integration`, starting HEAD
  `22e70069a8a69d1aa0828f3e3ac271821f30bff7`; PR #11 open and unmerged.
- Pre-implementation audit: `PHASE_VII_1_SECURITY_AUDIT.md`.
- Stashes preserved; `main` untouched; no new PR.

## 3. Defects found and fixed

### 3.1 The generic CLI learned nothing

`mizan twin --backend postgres` produced **0 learned resources** on every
fixture variant, so a zero-finding run was not evidence of anything. Two root
causes were fixed in `src/mizan/cli.py`:

1. The recording proxy was created without `identity_map`, so traffic had no
   principal and the ownership graph had no identity evidence.
2. `learn_from_spec` received `name=token` strings instead of raw token values,
   so the app returned 401 to every learning request.

The CLI now passes the reverse token map to the proxy and `identities=token_map`
to the learner. With the independent `openapi-generic.json`, the same generic
path produces real findings:

| Fixture variant | Findings from `Mizan.learn() -> attack() -> write_bundles()` |
|---|---|
| `clean` | 0 |
| `read` | 1 × L2 (cross-identity read) |
| `write` | 1 × L3 (PostgreSQL audit-attributed cross-identity write) |
| `both` | 1 × L2 + 1 × L3 |

### 3.2 Finding normalization

`normalize_finding()` now keys on law, principal, **mapped API resource**,
action, severity, expected/observed owner, subtype and title. It deliberately
excludes the prose detail because that embeds the worker's port. Duplicate
observations from different workers are deduplicated and equivalence is
set-based (`dedupe_findings`, `findings_equivalent`).

### 3.3 Parallel execution was sequential

`PostgresRun.parallel_attack()` now starts every worker in one bounded
thread pool, then runs the unchanged generic engine per worker in the same
pool. Each worker owns its database, OID, process, session identity, audit
trail and traffic log. Failure of any worker reaps all of them; `cleanup()`
attempts every worker even when one fails.

The independent fixture exposes a `/__barrier` endpoint that is absent from
its OpenAPI document. The test waits for all workers to rendezvous there,
which is only possible when the worker processes are alive simultaneously.

### 3.4 Failure injection

Covered: one worker's attack raises, a worker's app fails to start,
cancellation, worker process death, and normal teardown. Each case asserts that
all generated databases are gone and the source fingerprint is unchanged.

## 4. Files changed

- `src/mizan/cli.py`: identity map and token values for spec learning; parallel
  deduplication before serial/parallel comparison.
- `src/mizan/postgres_engine.py`: normalized findings, bounded real worker
  concurrency, per-worker traffic logs, failure-safe cleanup.
- `tests/fixtures/external_apps/postgres_store/app.py`: `both` variant and the
  independent concurrency rendezvous endpoint.
- `tests/fixtures/external_apps/postgres_store/openapi-generic.json`: an
  independent OpenAPI document describing exactly the fixture's endpoints.
- `tests/test_postgres_engine_generic_proof.py`: CLI detection, finding-producing
  serial/parallel equivalence, replay, regression, overlap and failure tests.
- `tests/test_postgres_engine_integration.py`: database OID and process
  isolation assertions.
- `tests/test_postgres_twin.py`: normalization unit tests.
- `.github/workflows/mizan.yml`: B2 runs the new real-PostgreSQL test module.

## 5. Verification

- Full local suite: **742 passed, 3 skipped, 1 warning in 772.93 s**. The skips
  are the POSIX-only signal-delivery tests on Windows.
- New `tests/test_postgres_engine_generic_proof.py`: **14 passed** against a real
  PostgreSQL server; all other changed unit tests pass.
- `ruff check .` and `ruff format --check .`: clean (163 files).
- Real PostgreSQL: generic CLI produced 0 findings on `clean`, 1 L2 on `read`,
  1 audit-attributed L3 on `write`, and L2 + L3 on `both`; serial/parallel
  normalized finding sets were equal with two workers on every variant.
- Replay reproduced both findings on the vulnerable app and was blocked on the
  clean app; the generated regression test failed on the vulnerable app and
  passed on the clean one.
- The cross-process barrier proved that two worker processes were alive at the
  same instant; injection of attack failure, start failure, cancellation and
  process death all ened with zero leaked databases and an unchanged source.


CI: all changes were pushed to PR #11, which triggers the workflow on
`pull_request`. CI status could not be read from this environment (outbound
network from the shell and the browser relay is blocked), so the verdict remains
`INCOMPLETE` until CI is confirmed green by the reviewer. Nothing is claimed
about CI in this report.
