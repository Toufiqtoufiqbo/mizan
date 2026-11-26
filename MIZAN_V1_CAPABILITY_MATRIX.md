# Mīzān v1 — verified capability matrix

Statuses: `supported` (implemented and verified by vulnerable+secure tests),
`partial`, `unsupported`. `supported_not_exercised` describes a single scan.

| Law / category | Generic / SQLite | PostgreSQL | Evidence |
|---|---|---|---|
| L1 | supported | supported | trusted identity endpoint |
| L2 | supported | supported | confirmed ownership |
| L3 | supported | supported | confirmed attributed write |
| L4 (field-based) | supported | supported | trusted protected-field policy + persisted state (`tests/test_sqlite_l4.py`, `tests/test_pg_l4_l6.py`) |
| L5 (POST races) | supported | partial | POST-only race probe; deterministic barrier |
| L6 (collection bounds) | supported | supported | declared bound + persisted row counts (`tests/test_sqlite_l6.py`) |
| L6 (single-use) | supported | supported | declared single-use + persisted consumption |
| L7 cache | supported | supported | application-backed HTTP probe + application events (PostgreSQL fixture, and Redis fixture via `.[redis]`) |
| L7 queue | supported | supported | application-backed HTTP probe + application events (PostgreSQL fixture, and Redis fixture via `.[redis]`; queue visibility/read semantics) |
| L7 logs | unsupported | unsupported | no provider |
| L7 metrics | unsupported | unsupported | no provider |
| L7 background jobs | unsupported | unsupported | deferred from v1 |

Scope boundaries: L4 does not cover relationship-based authority changes; L6
does not cover global quotas or `maxItems` input bounds; L5 is POST-only.

L7 `supported` here means: a real HTTP operation executed by the fixture
application, evidence recorded by the application, and both authorized and
unauthorized consumers verified. It does **not** mean a mock/synthetic artifact
was accepted (none is). **RabbitMQ, logs, metrics and background jobs are not
supported.** L7 cache and queue are verified against real PostgreSQL fixtures
and a real Redis fixture (`pip install .[redis]`, CI stage H); Redis support is
not a claim of RabbitMQ or other queues. Queue `supported` means queue
*visibility / read* confidentiality, not destructive consumption. Only the
newest 512 Redis stream events are observable; older events fail closed. See
`MIZAN_V1_SCOPE.md`, `V2_REAL_EVENT_SOURCE_REPORT.md`,
`POST_V1_TECHNICAL_DEBT.md`.
