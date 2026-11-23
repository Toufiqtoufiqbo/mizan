# Phase VIII — L7 Path Confidentiality feasibility audit

## Conclusion

L7 remains **unsupported** for both backends. No detector was added in this
phase. A weak detector would inflate the law count without an evidence path
that can distinguish a confidentiality breach from ordinary application
behaviour.

## What counts as a genuine L7 violation

Data leaving the caller's authority through a path the caller is not allowed to
observe. Direct response disclosure is already covered by L2; L7 requires an
*indirect* path (cache, queue, log, metric, error, async job, metadata) and a
provable identity link between the leaked data and a different principal.

## Categories and required evidence

| Category | Evidence provider | Trust boundary | Identity/attribution | Reproducibility | False-positive risk | Instrumentation required |
|---|---|---|---|---|---|---|
| Cache leakage | Cache key → principal binding, read-after-write trace | Cache server / process boundary | Every cache entry must carry an authenticated principal and an issuance event | Controlled prime, switch identity, read, assert absence | Shared caches legitimately serve public data; key collisions | Cache access log with principal, key, timestamp, TTL |
| Queue / async leakage | Producer identity, consumer identity, message payload provenance | Queue broker / worker boundary | Producer and consumer must both be authenticated and attributed | Enqueue under A, consume under B, observe leaked field | Async retries, DLQs, eventual consistency | Message envelope with principal, correlation id, immutable payload digest |
| Background job output | Job input principal, output artifact ACL | Job runner boundary | Job must preserve the initiating principal | Run as A, inspect B's view | Aggregated jobs have no single principal | Job metadata with owner and ACL |
| Log / diagnostic leakage | Log sink, request id, redaction policy | Logging pipeline boundary | Request id must resolve to one principal | Trigger with sentinel, search logs as another principal | Structured logs legitimately contain non-sensitive fields | Sentinel-safe log capture with access control |
| Metrics leakage | Metric labels and cardinality | Metrics backend boundary | Metric label must encode principal scope | Emit under A, query from B | Aggregated counters intentionally hide identity | Per-tenant label registry |
| Error messages | Error response provenance | API boundary | Error context must be attributable | Same request under A and B | Generic errors are intentionally identical | operator-controlled error corpus |
| Indirect response paths | Response field → storage origin | API/DB boundary | Data origin owner must be proven | A writes sentinel, B reads unrelated endpoint | Public reference data | Field-level provenance metadata |

## Why the current engine cannot support L7 safely

- `Mizan.learn()` observes HTTP traffic and database writes. It has no provider
  interface for cache, queue, log, metric or job artifacts.
- Traffic correlation uses `mizan.request_id`, which identifies requests, not
  secondary artifacts. There is no durable link from a leaked value to its
  origin owner outside the immediate response.
- `PostgresAttributor` proves *who wrote a database row*. It cannot prove that
  a value later appeared in a cache entry, log line or queue message, or that
  the reader was unauthorized.
- The existing L2 probe covers direct cross-identity response disclosure.
  Re-labelling it as L7 would be dishonest.

## Minimum viable future implementation

1. A `ConfidentialityProvider` interface with `observe(principal, sentinel)`
   and `assert_absent(other_principal, sentinel)` operations.
2. At least two independent providers (for example cache and queue) before any
   support claim.
3. A trusted mapping from each artifact to its owning principal, not an
   inferred one.
4. Proof evidence containing artifact identity, producer, reader, timestamp,
   sentinel and the exact assertion.
5. Generated regressions that replay the producer flow and assert the reader
   cannot observe the sentinel.

Until these exist, L7 remains `unsupported` in the capability matrix.
