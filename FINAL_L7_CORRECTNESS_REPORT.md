# Final L7 correctness patch — report

Branch: `feat/product-completion-v1` · PR: `Toufiqtoufiqbo/mizan#14`
Baseline HEAD: `00c07fc1ce311b55414336a71946249deafc4ddf`

This is a scope-limited correction of two remaining L7 defects. No new phase, no
L7 redesign, no product-scope expansion: L1–L6 and the rest of L7 are unchanged
apart from the replay/cli plumbing described below.

## 1. The two original problems

1. **Roles were assigned by list position.** `engine._probe_confidentiality()`
   used `producer, consumer = principals[0], principals[1]`. That assumed the
   first identity in `target.principals` is authorized and the second is not.
   Nothing enforced it: an unauthorized user could become the producer, and the
   check would then compare the wrong pair (or silently find nothing).
2. **Replay trusted the reads before proving the write.** `replay_l7()` sent all
   recorded requests, then interpreted the two read responses. The producer
   response was never validated, so an older record with the same artifact id
   could be read as if the fresh write had created it, and an operational
   failure could be reported as `blocked` — i.e. as if the application had been
   fixed.

## 2. Root causes

1. The probe treated `Target.principals` as an ordered role assignment instead
   of deriving roles from the trusted `ConfidentialityPolicy.authorized_readers`
   set. There was no authorised/unauthorised partition at all, and no
   inconclusive state for "the policy has no usable pair".
2. Replay validated only the read responses. The write response was a discarded
   side effect: its status code, body, artifact id and digest were never
   checked. Because the two reads ran unconditionally, their content could come
   from a pre-existing row, and every non-reproduced outcome collapsed to the
   same "safe" answer.

## 3. Files changed

| File | Change |
| --- | --- |
| `src/mizan/engine.py` | Policy-based producer/consumer selection, no HTTP without a valid pair, explicit inconclusive reasons |
| `src/mizan/confidentiality.py` | Sequential `replay_l7()` with a producer-write gate, digest/id validation per step, `replay_outcome_is_inconclusive()` |
| `src/mizan/cli.py` | `mizan replay` reports inconclusive L7 outcomes as "could not run", never as "fixed" |
| `src/mizan/regression.py` | Generated L7 regression fails on an inconclusive replay instead of passing silently |
| `tests/test_l7_application_backed.py` | 17 new tests (policy selection, replay gate, stale record, owner/consumer matrix) |
| `FINAL_L7_CORRECTNESS_REPORT.md` | This report |

## 4. Identity selection after the fix

Candidate principals are the target identities that have a token, a non-empty
id and are testable. They are partitioned by the trusted policy:

```python
authorized = sorted((p for p in principals if policy.authorizes(p.id)), key=lambda p: p.id)
unauthorized = sorted((p for p in principals if not policy.authorizes(p.id)), key=lambda p: p.id)
```

- `producer = authorized[0]` — the first authorized reader by identity.
- `consumer = unauthorized[0]` — the first non-authorized identity by identity.
- If either group is empty, the check records `INCONCLUSIVE` with a specific
  reason (`no authorized producer identity for this policy …` /
  `no unauthorized consumer identity for this policy …`) and continues **before
  any HTTP request**.
- A final guard rejects a non-distinct producer/consumer pair.
- Sorting both groups by identity makes the result independent of the order of
  `target.principals`; there is no positional fallback and no "first two users"
  heuristic left.

Consequences, proven by tests:

- `[alice, bob]` and `[bob, alice]` both produce `producer=alice`,
  `consumer=bob`, and identical request identities
  (`${MIZAN_TOKEN_ALICE}`, `${MIZAN_TOKEN_ALICE}`, `${MIZAN_TOKEN_BOB}`).
- With `authorized_readers=["alice","carol"]` and principals
  `[bob, alice, carol]`, Bob is never the producer.
- With only `[alice]` or only `[bob]` the run makes **zero** HTTP requests,
  records `INCONCLUSIVE`, and emits no finding.

## 5. Replay behaviour when the producer write fails

`replay_l7()` now executes the sequence step by step and stops at the first
step it cannot trust.

**Step 1 — producer write (must succeed before anything is read):**

| Condition | Result |
| --- | --- |
| HTTP not 2xx (500, 401, 403, …) | `producer_write_failed:<status>` — stop |
| Body is not valid JSON, or not a JSON object | `producer_response_invalid_json` — stop |
| No returned id (`artifact_id` / `message_id` / `id`) | `producer_artifact_id_missing` — stop |
| Returned id ≠ evidence artifact id | `producer_artifact_id_mismatch` — stop |
| No returned digest | `producer_digest_missing` — stop |
| Returned digest ≠ recorded `expected_digest` | `producer_digest_mismatch` — stop |

On any of these the replay returns immediately: **no read request is sent**, so
an older row that still carries the same artifact id cannot be turned into a
finding, and the failure is never labelled `blocked`.

**Step 2 — authorized owner read:** must be 2xx and carry the expected digest.
Otherwise `authorized_read_failed`, `authorized_read_unverifiable`,
`authorized_read_digest_missing` or `authorized_read_digest_mismatch`. Blocking
the owner is never treated as a security fix, and the consumer request is not
sent after an unverified owner read.

**Step 3 — unauthorized consumer read:** a non-2xx response (e.g. 403) yields
`blocked`; a 2xx response with the producer's exact digest yields
`confirmed_disclosure` only when the trusted policy does not authorize that
consumer; a 2xx response with a different digest yields `payload_mismatch`,
which is **not** a confirmed disclosure.

`replay_outcome_is_inconclusive()` classifies the operational/unverifiable
states. `mizan replay` prints them as "could not run" (counted as unreachable),
and the generated L7 regression asserts the replay was decisive, so a broken
producer write fails the regression instead of passing it.

## 6. New tests and results

All new tests are in `tests/test_l7_application_backed.py`.

| Test | Proves |
| --- | --- |
| `test_principal_selection_follows_the_policy_not_the_list_order[alice-bob]` | `[Alice, Bob]` → Alice producer, Bob consumer |
| `test_principal_selection_follows_the_policy_not_the_list_order[bob-alice]` | `[Bob, Alice]` → same roles and same request identities |
| `test_multiple_authorized_readers_never_choose_an_unauthorized_producer` | Bob listed first is still never the producer |
| `test_missing_unauthorized_consumer_is_inconclusive_without_http` | no finding, no HTTP, `INCONCLUSIVE` reason |
| `test_missing_authorized_producer_is_inconclusive_without_http` | no finding, no HTTP, `INCONCLUSIVE` reason |
| `test_replay_stops_when_the_producer_write_cannot_be_trusted` (6 cases) | 500 / 401 / 403 / invalid JSON / wrong id / wrong digest stop replay; only the POST is sent |
| `test_stale_record_cannot_become_a_finding_after_a_failed_write` | an existing artifact with the same id is not read after a failed write → no finding |
| `test_replay_continues_after_a_verified_producer_write` | verified write → owner read → consumer read → `confirmed_disclosure` |
| `test_replay_reports_blocked_when_the_consumer_is_refused` | consumer 403 → `blocked` (not inconclusive) |
| `test_replay_rejects_an_owner_read_with_the_wrong_digest` | owner digest mismatch is inconclusive and stops before the consumer request |
| `test_replay_does_not_confirm_a_disclosure_when_the_content_differs` | consumer gets different content → no `confirmed_disclosure` |
| `test_replay_fails_closed_when_the_owner_cannot_read` | owner 403 → `authorized_read_failed`, never `blocked` |

Focused run (`tests/test_l7_application_backed.py` + `tests/test_confidentiality.py`):
**29 passed in 15.33 s** (25 application-backed incl. 17 new, 4 contract tests).

The pre-existing Alice/Bob cache and queue tests still pass for both vulnerable
and secure variants, with `owner_can_read=True` asserted in secure mode, so
"block everyone" cannot be mistaken for a fix.

## 7. Full test, lint and benchmark results

The harness restarts prevent one uninterrupted ~20-minute run, so the corpus was
executed as five disjoint batches; every collected test is accounted for.

| Batch | Files | Result | Duration |
| --- | --- | --- | --- |
| 1 | `test_l7_application_backed`, `test_confidentiality` | 29 passed | 15.33 s |
| 2 | regression, parallel, SQLite L4/L6, pg L4/L6, law policy/states/failure modes, postgres benchmark, packaging, opaque CLI, control-plane audit | 85 passed | 132.80 s |
| 3 | adversarial store, benchmark, cross-framework, migration, dogfood, evidence integrity, express/external/fastapi validation, identity map, linked store, mizan, ownership graph/semantics | 283 passed | 186.14 s |
| 4 | postgres attribution/audit/engine/ownership/roundtrip/twin, recorder, request accounting, sarif, search(+benchmark), seed race, tokens, trusted identity, twin, validation | 300 passed, 3 skipped | 363.44 s |
| 5 | phase v2 soundness/coverage/integration, postgres generic proof | 128 passed | 280.09 s |

**Total: 825 passed, 3 skipped, 0 failed, 1 pre-existing warning**
(`828 tests collected`; the 3 skips are the POSIX-only signal tests on Windows).

- `ruff check .` — clean.
- `ruff format --check .` — 190 files already formatted.
- `python -m benchmarks.postgres_engine.run` — L4: 1 finding (2.0164 s);
  L6: 3 findings (3.2243 s); L7 cache vulnerable `confirmed_disclosure`
  (1 finding) / secure `blocked` (0); L7 queue vulnerable `confirmed_disclosure`
  (1 finding) / secure `blocked` (0); `l7_benchmark_problems=[]`,
  `law_benchmark_problems=[]`, `failures=[]`.

## 8. Final SHA and CI

- Baseline HEAD: `00c07fc1ce311b55414336a71946249deafc4ddf`.
- Final SHA: the HEAD of `feat/product-completion-v1` that carries this report.
  `a196d226e672db417f98882feb2bd98d3be4c589` introduces the fix; a follow-up
  formatting commit carries this ruff-formatted report (the report cannot embed
  its own hash without changing it). The exact HEAD SHA and the CI run id /
  conclusion are recorded in the PR #14 metadata.
- CI: the workflow run triggered by that HEAD; job-by-job conclusions are
  recorded in PR #14.

## 9. Remaining limitations

- The verified L7 integration is still a PostgreSQL-backed fixture application;
  no Redis/RabbitMQ, logs or metrics category is claimed.
- Replay proves the *recorded* path: it validates the producer id/digest and the
  two reads, not the application's storage layer or a different payload.
- Queue replay covers sequential consumption and authorization; distributed
  worker/retry races remain outside v1 scope.
- The producer gate validates what the application returns, not what it stores;
  an application that lies in its own response would need an independent
  storage-level check.

## 10. Verdict

**PASS** — all eight acceptance criteria are proven by executing tests:

1. Producer/consumer come from `authorized_readers`, never from list order.
2. No L7 finding and no HTTP request when the required identities are missing.
3. Replay validates the producer write before any read.
4. A stale record cannot produce a finding after a failed write.
5. Replay enforces the artifact id and content digest on both sides.
6. The previous Alice/Bob cache and queue tests still pass (vulnerable and
   secure).
7. L4 and L6 show no regression (1 and 3 findings, unchanged).
8. Tests, `ruff check`, `ruff format --check` and the benchmark are green.
