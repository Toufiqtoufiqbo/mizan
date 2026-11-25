# v2 — real Redis application event source (P1 slice)

Branch: `feat/v2-real-event-sources` (stacked on `feat/product-completion-v1`,
HEAD `9c38e6a6acc2327768df234657fe7cdb7ec502dc`). No change to `main` and no
merge of PR #14.

This phase addresses the first P1 gap: the v1 L7 evidence came from an
application whose real backend was PostgreSQL. The verified integration now
includes a **real Redis server** with the application performing the cache and
queue operations itself.

## 1. What changed

| Area | Change |
| --- | --- |
| `src/mizan/confidentiality.py` | Extracted `_EventObserver` (the shared fail-closed logic) and added `_RedisProvider`, `RedisCacheProvider`, `RedisQueueProvider`; extended `provider_from_evidence` |
| `tests/fixtures/external_apps/l7_redis/app.py` (new) | Flask application performing `SET`/`GET` (cache) and `LPUSH`/`LINDEX` (queue) against a real Redis server, recording its own events with `XADD` |
| `tests/test_l7_redis_source.py` (new) | 8 integration tests against a real Redis server |
| `tests/test_postgres_twin.py` | Deterministic vanishing-session preflight test (flake remediation) |
| `pyproject.toml` | `redis>=5.0` dev dependency, `redis_integration` marker |
| `.github/workflows/mizan.yml` | Stage H with a real `redis:7-alpine` service; stages A and S updated |

## 2. Trust model

The application, not Mīzān, owns the data and the audit trail:

1. `POST /artifacts` writes the content with Redis `SET` and stores the owner,
   then appends a `cache_write` event to the `mizan:l7:events` stream with the
   inbound `X-Mizan-Request-Id`, principal, artifact id, scope, digest and
   grant decision.
2. `GET /artifacts/<id>` reads with `GET` and appends a `cache_read` event.
3. `POST /messages` / `POST /messages/<id>/consume` use Redis list operations
   and append `queue_publish` / `queue_consume` events.

`RedisCacheProvider` and `RedisQueueProvider` issue **only `XRANGE`**. They
never write content, append events or delete keys. `write()` and `observe()`
still fail closed on a missing event, identity mismatch or digest mismatch.
The test `test_redis_provider_is_read_only` asserts the stream length and all
`mizan:l7:*` keys are unchanged after provider use and `cleanup()`.

## 3. Flake remediation

`test_session_that_disappears_during_preflight_allows_cleanup` used a fixed
`time.sleep(0.2)` while the preflight drain window is 1.0 s, so the session was
usually gone before preflight ever saw it — the test passed without exercising
the race it was named for. It now synchronises on the preflight hook:

- the client keeps its connection open until preflight has observed the backend;
- an immediate `_wait_for_no_sessions(..., timeout=0)` must still find it;
- only then is the connection closed, and the real drain must complete.

The 14 reproduction runs before the change (6 isolated, 8 during a concurrent
benchmark) all passed, so there was no failing run to debug; the fix removes
the timing dependence rather than masking a speculative failure. The second
reported test (`..._are_idempotent`) could not be reproduced in any of those
runs, so it was deliberately left unchanged.

## 4. Results

- `tests/test_l7_redis_source.py`: **8 passed** against a real Redis server
  (Redis 5.0.14 locally, Redis 7 in CI).
- Focused regression batch: **122 passed**, 1 pre-existing warning (L7 contract,
  application-backed tests, replay/regression, L4/L6, law states, packaging,
  CLI, control-plane audit).
- `ruff check .` and `ruff format --check .`: clean (193 files).
- CI: a new mandatory stage **H — Redis event source** runs the integration
  suite with a real Redis service and fails if any test is skipped.

## 5. Remaining scope

- RabbitMQ, logs and metrics are **not** implemented in this slice.
- The Redis fixture proves cache and queue confidentiality for one application
  flow; distributed consumers and retry races remain outside scope.
- Stage H uses a container service; local runs need `MIZAN_TEST_REDIS_DSN` or a
  `redis-server` binary via `MIZAN_REDIS_SERVER`.

Verdict for this slice: **PASS** — a real Redis backend now produces
application-owned evidence, and the preflight race test is deterministic.
