# Post-v1 tracked technical debt

## P1 — Intermittent PostgreSQL Twin lifecycle tests (inherited)

`tests/test_postgres_twin.py::test_session_that_disappears_during_preflight_allows_cleanup`
and `::test_valid_cleaned_intent_and_cleaned_record_are_idempotent` failed once
while the Phase VIII benchmark ran concurrently, passed in isolation and in a
clean sequential batch. Post-merge CI #291 initially failed an unrelated
adversarial-store case and succeeded on rerun; no safety check was weakened.
Impact: possible resource contention under parallel load; ownership and
destructive-drop safeguards were not changed. Reproduce with concurrent
benchmark + full suite; do not mask with retries. PR #15 also documented 6
transient failures in a PostgreSQL-heavy batch under load that passed on a
clean rerun (see `PR15_REDIS_SAFETY_REPORT.md` §11).

## P1 — L5 PostgreSQL scope

POST-only race probe. PUT/PATCH/DELETE race support is not implemented and is
documented as unsupported rather than claimed.

## P1 — L7 fixture backend scope

L7 cache/queue detection is verified through real HTTP operations of
independent fixture applications whose storage is PostgreSQL or Redis
(`RedisCacheProvider` / `RedisQueueProvider`, `pip install .[redis]`, CI stage
H; PR #15). It is not a general RabbitMQ/Kafka integration; a production
application needs an equivalent trusted event source. Queue support means queue
*visibility / read* confidentiality, not destructive consumption. Only the
newest 512 Redis stream events are observable; older events fail closed. Redis
test cleanup is namespace-scoped (`SCAN MATCH <namespace>:*`); no database-wide
deletion command is used, and missing ownership metadata fails closed (403).

## P2 — L7 additional categories

Logs, metrics and background-job providers are deferred from v1.

## P2 — L4 relationship-based authority

Grant tables and tenant membership relationships are deferred; v1 covers
declared scalar protected fields only.

## P2 — L6 global quotas and bounded inputs

Global quota analysis and `maxItems` semantics are deferred.

## P2 — Distributed parallel scanning

Current parallel mode is replicated worker isolation, not partitioned scanning.
