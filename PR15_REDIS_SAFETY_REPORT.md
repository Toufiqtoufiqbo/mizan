# PR #15 — Redis safety fix report

Base: `main` at merge commit `8aef41886d442b3361df91be5b79fdaa5553d240`
(PR #14 merged). PR #15 was merged into `main` by `Toufiqtoufiqbo` on
`2026-11-25T23:57:44Z` as merge commit
`665b5e8caea4c41fce83846a97a24d1dae3dcd70`; it is now `closed / merged`.
The verified head was `423504396784ebeebcfcbcf87729b30d20522417`.

## 1. Original problem

The first Redis integration worked, but its test fixture called `client.flushdb()`
at setup and teardown. With a user-supplied `MIZAN_TEST_REDIS_DSN` that could
delete unrelated data. The fixture application also used the fallback
`owner = connection.get(...) or principal`, which promotes the current caller
to owner when ownership metadata is missing. Redis was only a `dev`
dependency, and the queue path was described as consumption even though it
uses a non-destructive read.

## 2. Root cause

- The fixture assumed it owned the whole Redis database instead of a scoped
  set of keys; cleanup was defined at database level, not namespace level.
- Missing ownership data was treated as "no restriction" rather than "no
  authority", turning absent evidence into an authorization grant.
- The optional dependency was declared only inside `dev`, so Redis support
  had no standalone install path.
- Documentation named `LRANGE` visibility reads "consumption".

## 3. The fix

- The Redis fixture and every app key use a unique session namespace
  `mizan:test:<uuid>-<pid>:l7`, injected through `MIZAN_REDIS_NAMESPACE`.
- Cleanup scans `SCAN MATCH <namespace>:*` and deletes only those keys.
- Content and ownership metadata are written in one atomic Redis pipeline.
- Missing ownership metadata in the secure variant returns 403 for everyone,
  records `granted=false`, and can never produce a confirmed disclosure.
- Redis is declared as `redis = ["redis>=5.0"]` optional extra.
- Stream observation is a bounded `XREVRANGE … COUNT 512`, still read-only.
- Documentation and tests call the queue path a visibility/indirect read.

## 4. No database-wide deletion

`tests/test_l7_redis_source.py::test_no_database_wide_flush_commands` inspects
the test module, the fixture app and `confidentiality.py` and asserts neither
database-wide deletion command name appears. The fixture cleanup helper only
issues `SCAN` and per-key `DELETE`, scoped to the namespace.

## 5. Namespace isolation

- `test_external_key_survives_namespace_cleanup` plants an unrelated key,
  runs cleanup, and asserts the unrelated key is intact.
- `test_parallel_namespaces_are_isolated` plants keys in two independent test
  namespaces, cleans one, and asserts the other survives.
- The module-scoped fixture generates a fresh UUID+PID namespace per session.

## 6. Ownership fail-closed

- `test_missing_ownership_fails_closed` writes an artifact, removes only its
  ownership key, and asserts 403 for Alice *and* Bob in the secure variant,
  plus no `confirmed_disclosure` from `evaluate()` on Bob's event.
- Valid owner access and the unauthorized consumer's 403 remain asserted by
  the existing cache/queue acceptance tests.

## 7. Redis packaging

`pyproject.toml` now has an independent `redis = ["redis>=5.0"]` extra;
`pip install -e '.[redis]'` was verified locally and CI stage H installs that
extra before the dev tools. `test_redis_is_an_optional_dependency` asserts the
extra is declared. Redis is not required by the base install.

## 8. Queue semantics

Option A was chosen: the fixture uses `RPUSH` + `LRANGE`, documented and
tested as **queue visibility / indirect read**, not destructive consumption.
`test_queue_visibility_is_non_destructive` asserts two reads return the same
digest and the list length stays 1.

## 9. Event-stream observation

`_RedisProvider._event()` uses bounded, newest-first `XREVRANGE` (512 entries)
and correlates on request id + artifact id. It never appends, deletes or
modifies events. `test_redis_observation_does_not_mutate_the_stream` compares
the complete stream snapshot and all namespaced keys before and after
observation and `cleanup()`. Older events beyond the window fail closed.

## 10. New and updated tests

| Test | Proves |
| --- | --- |
| `test_external_key_survives_namespace_cleanup` | unrelated data survives |
| `test_parallel_namespaces_are_isolated` | sessions cannot delete each other |
| `test_no_database_wide_flush_commands` | no database-wide deletion commands |
| `test_missing_ownership_fails_closed` | absent owner metadata never grants access |
| `test_queue_visibility_is_non_destructive` | declared visibility semantics |
| `test_redis_observation_does_not_mutate_the_stream` | observer is read-only |
| `test_redis_is_an_optional_dependency` | standalone `.[redis]` extra |

## 11. Full corpus

842 tests collected; executed in four disjoint batches (harness restarts):
128 passed, 283 passed, 300 passed + 3 skipped, 128 passed → **839 passed,
3 skipped, 0 failed** on the clean runs. Individual suites:
`test_l7_redis_source.py` 14 passed, `test_confidentiality.py` 4 passed,
`test_postgres_twin.py` 97 passed + 3 skipped. The 3 skips are pre-existing
POSIX-only signal tests on Windows; no new skip was introduced.

Honest note: one PostgreSQL-heavy batch run initially reported 6 transient
failures in `test_postgres_twin.py` under load. The named tests passed in
isolation and a rerun of the same batch passed 300/3. This known flake was
neither deleted nor downgraded.

## 12. Benchmark

`python -m benchmarks.postgres_engine.run`: L4 1 finding, L6 3 findings; L7
cache and queue vulnerable `confirmed_disclosure` (1 finding each) and secure
`blocked` (0); `l7_benchmark_problems=[]`, `law_benchmark_problems=[]`,
`failures=[]`.

## 13. Ruff

`ruff check .` — clean. `ruff format --check .` — 194 files already formatted.

## 14. CI

Run **#298**, id `45715971527`, on the fix commit `ed523c5`:
https://github.com/Toufiqtoufiqbo/mizan/actions/runs/45715971527

| Job | Result |
| --- | --- |
| A — static & unit | success |
| B — PostgreSQL | success |
| B2 — PostgreSQL lifecycle & destructive cleanup | success |
| C — security regression | success |
| D — benchmark | success |
| E — Mīzān scans Mīzān | success |
| F — independent application | success |
| G — cross-framework gate | success |
| G — external target (opt-in) | skipped (by design) |
| H — Redis event source | success |
| S — status summary | success |

All mandatory jobs passed. The external-target job is optional and skipped as
designed. A documentation-only commit after this run carries the recorded
result; its own CI run is recorded in PR #15.

## 15. Exact tested HEAD

Fix commit: `ed523c5648924b176b38b51674e6cbe75f8ec9ba`
(the commit with all code and test changes, verified by CI #298).
Final verified head: `423504396784ebeebcfcbcf87729b30d20522417` (CI #299).
Merged into `main` as `665b5e8caea4c41fce83846a97a24d1dae3dcd70`; only those
three SHAs were involved — no history rewrite.

## 16. Remaining limitations

- No RabbitMQ, Kafka, logs or metrics providers.
- Queue tests prove visibility confidentiality, not destructive consumption
  or retry races.
- Only the newest 512 stream events are observable; older ones fail closed.
- Redis integration needs a real server; CI stage H supplies one and fails on
  any skip.

## Verdict

**PASS** — all acceptance conditions above were executed: no database-wide
deletion command, namespace-scoped cleanup, unrelated and parallel-session data
survive, missing ownership metadata fails closed, Redis is a standalone extra,
queue semantics are stated honestly, stream observation is bounded and
read-only, the full corpus and benchmark pass, ruff is clean, and every mandatory
CI job succeeded on the fix commit. remaining limitations are listed in §16.
