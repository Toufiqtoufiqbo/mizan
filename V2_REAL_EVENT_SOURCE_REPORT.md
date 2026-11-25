# v2 — real Redis application event source

Base: `main` at merge commit `8aef41886d442b3361df91be5b79fdaa5553d240`
(PR #14 was merged). PR #15 is open and **not** merged; its branch is
`feat/v2-real-event-sources`.

This phase adds a second real backend for L7 evidence: a Redis server whose
application performs the operations itself. It does not redesign L7, add new
categories, or claim production readiness.

## 1. Redis support as it stands

- **PostgreSQL support**: unchanged v1 path (`.[postgres]` dev dependency),
  application-owned `l7_events` table, observers `PostgresCacheProvider` /
  `PostgresQueueProvider`.
- **Redis support**: separate optional extra `pip install -e '.[redis]'`. The
  base install does not pull in a Redis client, and installing Redis does not
  require the `dev` group. `RedisCacheProvider` / `RedisQueueProvider` observe
  application-owned events in a Redis stream.
- No RabbitMQ, Kafka, logs or metrics support is claimed.

## 2. Application-owned evidence

The fixture application (`tests/fixtures/external_apps/l7_redis/app.py`)
performs:

- cache: `SET` content + owner, `GET` on read;
- queue: `RPUSH` + `LRANGE`, which is a **visibility / indirect read**, not a
  destructive message consumption;
- event recording: `XADD` into the namespaced stream, with the inbound
  `X-Mizan-Request-Id`, principal, artifact id, scope, digest and grant result.

Mīzān only reads the stream with bounded `XREVRANGE`. It never appends events,
writes content, deletes keys or deletes stream entries.

## 3. Stream observation limit

`_RedisProvider._event()` reads at most the newest **512** stream entries
(`XREVRANGE … COUNT 512`) and correlates on request id + artifact id. Older
events are not visible and fail closed as `missing_event` / inconclusive; they
are never treated as a secure result. This is a deliberate limitation of the
observer, not a new event-store architecture.

## 4. Safe, namespace-scoped cleanup

Every key is prefixed by a per-session namespace
`mizan:test:<uuid>-<pid>:l7`, injected via `MIZAN_REDIS_NAMESPACE`. Keys are:

```text
mizan:test:<run_id>:l7:artifact:<id>
mizan:test:<run_id>:l7:owner:<id>
mizan:test:<run_id>:l7:queue:<id>
mizan:test:<run_id>:l7:consumer:<id>
mizan:test:<run_id>:l7:events
```

Cleanup uses `SCAN MATCH <namespace>:*` and deletes only matching keys. There
is no database-wide deletion command in the fixture, the tests or the
provider. Tests assert that an unrelated key survives cleanup and that two
namespaces cannot delete each other's data.

## 5. Ownership fails closed

The previous `owner = get(...) or principal` fallback is gone. When ownership
metadata is absent, the secure variant returns 403 for every caller and
records `granted=false`; the caller is never promoted to owner and no
`confirmed_disclosure` can be produced. Only the deliberately vulnerable
variant ignores authorization, and that is documented as fixture weakness.
Content and ownership are written together in one atomic Redis pipeline, so
content without an owner is never a valid artifact.

## 6. Verification

- `tests/test_l7_redis_source.py`: 14 passed (real Redis 5 locally, Redis 7 in
  the CI service).
- `tests/test_confidentiality.py`: 4 passed.
- `tests/test_postgres_twin.py`: 97 passed, 3 skipped (POSIX-only signal tests).
- Full corpus: 842 collected; executed in four disjoint batches: 128 passed,
  283 passed, 300 passed + 3 skipped, 128 passed → **839 passed, 3 skipped,
  0 failed** on the clean runs. One earlier PostgreSQL-heavy batch showed 6
  transient failures under load; the named tests passed individually and a
  rerun of the same batch passed 300/3. This known flake is documented in
  `PR15_REDIS_SAFETY_REPORT.md`, not hidden or removed.
- `ruff check .` / `ruff format --check .`: clean (194 files).
- Benchmark: L4 1 finding, L6 3 findings, L7 cache/queue vulnerable
  `confirmed_disclosure` / secure `blocked`, zero problems.
- CI: stage **H — Redis event source** runs with a real Redis service; A, B,
  B2, C, D, E, F, G and S remain mandatory.

## 7. Limitations

- Queue tests prove visibility/read confidentiality, not destructive
  consumption or retry semantics.
- Only the newest 512 stream events are observable.
- Redis tests require a real server; they are skipped locally when none is
  configured, but stage H fails if any integration test skips in CI.
