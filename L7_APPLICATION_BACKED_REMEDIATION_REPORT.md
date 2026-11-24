# L7 application-backed verification — remediation report

## 1. Original problem

The v1 L7 implementation classified `confirmed_disclosure` from artifacts that
Mīzān itself created in its own PostgreSQL tables. `engine._probe_confidentiality()`
manufactured an `Artifact`, providers wrote it into `mizan_v1_*` tables, and
`replay_l7()` re-tested those tables. Secure fixtures were accepted when they
blocked both the owner and the unauthorized consumer.

## 2. Root causes

- **Synthetic provenance**: the producer identity and payload were chosen by
  the engine, not by an application operation.
- **Provider-owned state**: providers wrote and read their own tables, so a
  "leak" proved only that Mīzān could read what it wrote.
- **Formal replay**: replay reconstructed a provider instead of repeating the
  application sequence over HTTP.
- **One-sided authorization test**: only the unauthorized consumer was
  evaluated; an authorized read that failed was never a gate.

## 3. Chosen design

A small independent fixture application (`tests/fixtures/external_apps/l7_store/app.py`)
executes real cache and queue operations over HTTP and records its **own**
events (`l7_events`) with the inbound request id. PostgreSQL is used as the
fixture's real backend because it is already in the project and CI; no Redis or
RabbitMQ is introduced. Providers are read-only observers of application events.

## 4. Files changed

- `tests/fixtures/external_apps/l7_store/app.py` (new): HTTP artifact/message
  operations, vulnerable/secure variants, application-owned audit events.
- `src/mizan/confidentiality.py`: providers read application events; evidence
  checks identity, digest and source; `replay_l7` replays HTTP steps.
- `src/mizan/engine.py`: L7 probe executes producer → owner → consumer HTTP
  sequence, extracts digests, requires an authorized read to succeed, and records
  real request ids and steps.
- `src/mizan/cli.py`, `src/mizan/regression.py`: replay/regression use the HTTP
  sequence.
- `tests/test_l7_application_backed.py` (new), `tests/test_confidentiality.py`,
  `benchmarks/postgres_engine/run.py`.
- Documentation: scope, capability matrix, provider architecture, technical
  debt, README, ROADMAP, `PHASE_IX_REPORT.md`.

## 5. Authorized and unauthorized access

For each category the probe performs three HTTP calls: Alice writes a controlled
payload, Alice reads/consumes it, then Bob attempts the same. A finding requires:
Alice's read succeeded with the expected digest, Bob received that same digest,
the application event for Bob's request names Bob with `granted=true`, and the
trusted policy does not authorize Bob. Secure mode returns 403 for Bob while
Alice still receives 200 — this is explicitly asserted by the tests.

## 6. Evidence correlation

Each request carries `X-Mizan-Request-Id`. Application events record that id,
operation, principal, artifact id, scope, payload digest, grant decision and
timestamp. Provider evidence links artifact, observation, policy and events;
digest, identity or source mismatches produce `inconclusive`, never a finding.
Mīzān never writes or deletes application-owned rows.

## 7. Replay and regression

`replay_l7(evidence, target)` re-executes the three recorded HTTP steps with
tokens resolved from the environment, recomputes digests and reclassifies the
result. Against the vulnerable fixture it returns `confirmed_disclosure`; against
the secure fixture it returns `blocked`. Generated L7 regressions call the same
function via `mizan replay`/pytest.

## 8. Test results

- Acceptance matrix: 8/8 application-backed tests passed — cache and queue ×
  vulnerable (Alice 200, Bob disclosure) and secure (Alice 200, Bob 403),
  evidence correlation, payload integrity/missing evidence, replay and
  regression. Both negative cases (different digest, absent consumer identity)
  returned no confirmed result.
- Focused regression batch: 71 passed (including 8 new application-backed tests,
  L4/L6, replay/regression, law states, packaging).
- Benchmark: L4 1 finding, L6 3 findings; L7 cache vulnerable `confirmed_disclosure`
  / secure `blocked`; queue vulnerable `confirmed_disclosure` / secure `blocked`;
  zero failures and zero workload problems.
- Complete corpus: 811 collected tests executed in four disjoint batches
  (harness restarts prevent one uninterrupted run): **808 passed, 3 skipped,
  0 failed, 1 pre-existing warning**. `ruff check .` and `ruff format --check .`
  clean. CI result on the final HEAD: recorded in PR #14 metadata.

## 9. Remaining limitations

- The verified L7 provider integration is a PostgreSQL-backed fixture
  application. No Redis/RabbitMQ, logs, metrics or background-job provider is
  claimed.
- Provider evidence depends on the fixture's audit table being trustworthy; a
  real deployment would need an equivalent application-side event source.
- Queue tests cover sequential consumption and authorization; distributed
  worker/retry races remain outside the v1 scope.

## 10. Verdict

**PASS** for the remediation: the application, not Mīzān, performs the cache and
queue operations; L7 findings are derived from HTTP-observable application state;
secure mode permits the owner and blocks the other principal; replay and
regression repeat the real HTTP sequence.
