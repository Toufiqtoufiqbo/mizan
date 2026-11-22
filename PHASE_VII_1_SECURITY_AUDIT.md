# Phase VII.1 — Generic Proof, Real Parallelism & Failure Recovery Audit

Starting state verified before this audit was written:

- Branch `feat/postgres-engine-integration`; HEAD `22e70069a8a69d1aa0828f3e3ac271821f30bff7`.
- Local branch checked; remote fetch retried after a transient GitHub outage.
- PR #11 open and unmerged; base `main` at `cac413733307651788670d42eaeb083c6ad8c946`.
- Clean worktree; `stash@{0}` preserved.
- Phase VII reports and implementation audit were read and match the code at
  `22e7006`.
- No production code changed before this audit was written.

## Finding 1 — `normalize_finding()` omits semantic dimensions (CONFIRMED)

`src/mizan/postgres_engine.py` returns `(law, principal, resource, resource,
severity)`. It drops `action`, and it cannot distinguish expected vs observed
ownership when both are present in evidence.

Proposed fix is audited against the actual `Violation` model in
`src/mizan/core.py:481-510`: `law`, `title`, `detail`, `severity`, `principal`,
`resource`, `action`, `evidence`, `steps`. So the normalized key becomes
`(law, principal, resource, action, severity, observed_owner_from_evidence,
expected_owner_from_evidence)` with explicit handling of missing values, plus
stable subtype if needed for different proofs of the same law.

## Finding 2 — generic-engine L2/L3 acceptance is unproven (CONFIRMED)

Existing tests use `run_l2_l3_probes()`; generic CLI tests run a clean variant
and accept zero findings. The decisive `Mizan.attack()` path has not produced
findings against an independent PostgreSQL-backed vulnerable application.

New required generic-engine tests (`tests/test_postgres_engine_generic_proof.py`)
must exercise `mizan twin --backend postgres` against the real fixture app and
assert actual findings from the generic engine.

## Finding 3 — proof replay and regression are unproven (CONFIRMED)

No generic PostgreSQL proof bundle has been replayed against a vulnerable/patched
application, and no generic PostgreSQL regression has been executed.

## Finding 4 — parallelism is sequential (CONFIRMED)

`PostgresRun.parallel_attack()` starts and restores each worker one after
another. True concurrency is unproven; distinct DB names are not concurrency.

## Finding 5 — failure injection matrix is incomplete (CONFIRMED)

The Phase VII report lists failures not covered.

## Design decisions for this phase

- Fix normalization first.
- Add independent PostgreSQL fixture variants `read`, `write`, `both`.
- Drive the generic engine through the real CLI path.
- Implement true bounded parallelism in `PostgresRun` using an executor over
  the real engine per worker; prove overlap with a barrier endpoint.
- Reuse `mizan regress`/`replay` as-is.
- Extend the existing B2 destructive job with the new adversarial tests.
- Update documentation and reports honestly; keep verdict `INCOMPLETE` until CI passes.

## Post-audit implementation notes

### Finding 2 root cause (verified by experiment)

Before the fix, `mizan twin --backend postgres` learned **0 resources** on every
fixture variant, so a zero-finding CLI run proved nothing. Two independent CLI
defects caused this:

1. `RecordingProxy` was created without `identity_map`, so recorded traffic had
   `principal = null` and the ownership graph had no identity evidence.
2. `learn_from_spec` was given `name=token` strings instead of token values, so
   the app received `Authorization: Bearer alice=twin-alice` and answered 401.

Both are fixed in `src/mizan/cli.py`: the proxy gets the reverse token map, and
the learner gets `identities=token_map`. With the independent
`openapi-generic.json`, the generic CLI now learns 2 resources and produces:

| Fixture variant | Generic-engine findings |
|---|---|
| `clean` | 0 |
| `read` | 1 × L2 |
| `write` | 1 × L3 (audit-attributed) |
| `both` | 1 × L2 + 1 × L3 |

### Finding 1 resolution

`normalize_finding()` now returns law, principal, mapped API resource, action,
severity, expected/observed owner, subtype and title. The incidental URL and
prose detail are excluded, because each worker uses a different port. Two
workers independently finding the same breach is a duplicate observation, so
`findings_equivalent()` compares sets and the CLI deduplicates parallel
findings before printing the comparison.

### Finding 4 resolution

`PostgresRun.parallel_attack()` now starts all workers in one bounded
`ThreadPoolExecutor`, waits for all of them, then runs the unchanged generic
`Mizan.learn() -> attack()` path per worker in the same pool. Each worker has
its own database, process, OID, session identity, audit trail and traffic log.
Overlap is observed with an independent fixture barrier endpoint that is absent
from the OpenAPI document.

### Finding 5 resolution

Fault injection covers: attack failure inside one worker, app start failure,
cancellation, worker process death, and normal cleanup. Every path reaps all
started workers, asserts the source is unchanged and checks that no generated
database remains.
