# Mīzān 0.3.0 — cross-framework benchmark

Every number below is a count. A percentage never appears without the
counts behind it.

- repetitions: **3**
- request budget per scenario: **60**
- scenarios run: **24**

## The matrix

| Framework | Variant | Expected | Observed | TP | FP | FN | Precision | Recall | Requests (b/l/a) | Time | Peak memory | Replay |
|---|---|---|---|---:|---:|---:|---|---|---|---:|---|---|
| express | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 1.68 s | 51.7 MiB | n/a |
| express | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.61 s | 51.8 MiB | 1/1 |
| express | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.60 s | 52.9 MiB | 1/1 |
| express | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.61 s | 52.0 MiB | 2/2 |
| fastapi | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 2.25 s | 47.9 MiB | n/a |
| fastapi | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.37 s | 48.0 MiB | 1/1 |
| fastapi | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.18 s | 48.0 MiB | 1/1 |
| fastapi | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.40 s | 47.9 MiB | 2/2 |
| express | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 1.59 s | 52.1 MiB | n/a |
| express | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.70 s | 52.7 MiB | 1/1 |
| express | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.64 s | 52.1 MiB | 1/1 |
| express | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.84 s | 52.1 MiB | 2/2 |
| fastapi | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 2.24 s | 48.0 MiB | n/a |
| fastapi | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.43 s | 47.9 MiB | 1/1 |
| fastapi | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.41 s | 47.8 MiB | 1/1 |
| fastapi | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.38 s | 47.9 MiB | 2/2 |
| express | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 1.66 s | 52.0 MiB | n/a |
| express | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.66 s | 52.0 MiB | 1/1 |
| express | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.63 s | 52.1 MiB | 1/1 |
| express | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.19 s | 52.5 MiB | 2/2 |
| fastapi | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 2.31 s | 48.1 MiB | n/a |
| fastapi | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.81 s | 47.7 MiB | 1/1 |
| fastapi | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.37 s | 47.6 MiB | 1/1 |
| fastapi | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.38 s | 48.2 MiB | 2/2 |

## Totals

| Scope | Scenarios as expected | TP | FP | FN | Precision | Recall | Requests | Replay |
|---|---|---:|---:|---:|---|---|---:|---|
| express | 12/12 | 12 | 0 | 0 | 100.0% | 100.0% | 168 | 12/12 |
| fastapi | 12/12 | 12 | 0 | 0 | 100.0% | 100.0% | 168 | 12/12 |
| all | 24/24 | 24 | 0 | 0 | 100.0% | 100.0% | 336 | 24/24 |

## Scenarios that did not match the expectation

None. Every scenario produced exactly the expected laws.

## Replay failures

None. Every finding was reproduced against the state the scan left behind.

## The environment

| Item | Value |
|---|---|
| OS | `Windows-10-10.0.19045-SP0` |
| CPU | `Intel64 Family 6 Model 94 Stepping 3, GenuineIntel`, 4 cores |
| Memory | 11687.6 MiB |
| Python | `3.12.10` |
| Node.js | `v26.13.1` |
| SQLite | `3.49.1` |
| FastAPI | `0.162.4` |
| uvicorn | `0.54.0` |
| Mīzān commit | `unavailable` (git is not installed on this machine) |
| Mīzān tree digest | `587d1c6d08a205cb` |
| Fixture digest (fastapi) | `c812fdcc0270a3e3` |
| Fixture digest (express) | `8395cee58b03bf04` |

## What this is

Two controlled fixtures, each written independently against the same
behavioral contract. The numbers measure Mīzān against those two
fixtures. They are not a measurement of any real application, and they
are not statistically representative of anything else.
