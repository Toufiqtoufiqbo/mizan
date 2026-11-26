# Mīzān v1 — frozen product scope

Baseline: merged `main`. Frozen v1 scope unchanged by PR #14
(`8aef41886d442b3361df91be5b79fdaa5553d240`, PR #14 merge) and by PR #15
Redis L7 verification (merge `665b5e8caea4c41fce83846a97a24d1dae3dcd70`).
CI must succeed on merged main; a known transient PostgreSQL flake under load
is tracked in `POST_V1_TECHNICAL_DEBT.md`, not hidden or retried away.

## In scope

| Law | v1 capability |
|---|---|
| L1 | Authentication coherence |
| L2 | Read authorization / BOLA |
| L3 | Write authorization |
| L4 | Field-based authority creation / mass assignment, on both backends |
| L5 | Atomicity / TOCTOU on supported methods (POST) |
| L6 | Per-principal collection bounds and single-use capabilities, on both backends |
| L7 | Cache and queue path confidentiality via real application HTTP operations (real PostgreSQL and real Redis backends; cache and queue only) |

Providers and backends must report capability per category, not as a single
umbrella claim.

## Deferred (not advertised in v1)

- General log, metrics and background-job confidentiality analysis.
- Full relationship-based authority analysis.
- Global quota analysis without reliable evidence.
- Arbitrary application-specific security inference.
- Distributed high-performance parallel scanning.

## Safety invariants

Never weaken: database ownership/cluster/OID checks, durable deletion intents,
session verification, bounded waits, fail-closed cleanup, disposable namespaces,
and proof integrity. Missing evidence is never a confirmed finding.
