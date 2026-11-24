# Mīzān v1 — frozen product scope

Baseline: `06aa2815dcb5935d84481455fef62062ea588567` (merged main; CI #291
success on this exact SHA after rerun of the single transient A-job failure).

## In scope

| Law | v1 capability |
|---|---|
| L1 | Authentication coherence |
| L2 | Read authorization / BOLA |
| L3 | Write authorization |
| L4 | Field-based authority creation / mass assignment, on both backends |
| L5 | Atomicity / TOCTOU on supported methods (POST) |
| L6 | Per-principal collection bounds and single-use capabilities, on both backends |
| L7 | Cache and queue/message path confidentiality only |

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
