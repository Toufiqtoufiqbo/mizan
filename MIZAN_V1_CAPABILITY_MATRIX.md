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
| L7 cache | supported | supported | PostgreSQL-backed cache provider, vulnerable/secure fixtures |
| L7 queue | supported | supported | PostgreSQL-backed queue provider, vulnerable/secure fixtures |
| L7 logs | unsupported | unsupported | no provider |
| L7 metrics | unsupported | unsupported | no provider |
| L7 background jobs | unsupported | unsupported | deferred from v1 |

Scope boundaries: L4 does not cover relationship-based authority changes; L6
does not cover global quotas or `maxItems` input bounds; L5 is POST-only. L7
providers establish artifact provenance and consumer authorization, not a
response-only string match.
