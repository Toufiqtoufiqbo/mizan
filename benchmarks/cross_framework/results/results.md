# Mīzān 0.3.0 — cross-framework benchmark

Every number below is a count. A percentage never appears without the
counts behind it.

- repetitions: **3**
- request budget per scenario: **60**
- scenarios run: **24**

## The matrix

| Framework | Variant | Expected | Observed | TP | FP | FN | Precision | Recall | Requests (b/l/a) | Time | Peak memory | Replay |
|---|---|---|---|---:|---:|---:|---|---|---|---:|---|---|
| express | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 1.72 s | 49.2 MiB | n/a |
| express | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.28 s | 49.0 MiB | 1/1 |
| express | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.71 s | 49.3 MiB | 1/1 |
| express | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.64 s | 49.2 MiB | 2/2 |
| fastapi | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 2.35 s | 46.8 MiB | n/a |
| fastapi | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.37 s | 46.6 MiB | 1/1 |
| fastapi | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.42 s | 46.6 MiB | 1/1 |
| fastapi | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.46 s | 46.9 MiB | 2/2 |
| express | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 1.65 s | 49.1 MiB | n/a |
| express | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.59 s | 49.1 MiB | 1/1 |
| express | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.72 s | 49.1 MiB | 1/1 |
| express | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.65 s | 49.0 MiB | 2/2 |
| fastapi | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 2.38 s | 46.8 MiB | n/a |
| fastapi | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.26 s | 46.6 MiB | 1/1 |
| fastapi | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.49 s | 46.7 MiB | 1/1 |
| fastapi | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.38 s | 46.5 MiB | 2/2 |
| express | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 1.71 s | 49.1 MiB | n/a |
| express | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.74 s | 49.4 MiB | 1/1 |
| express | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.68 s | 49.2 MiB | 1/1 |
| express | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 1.65 s | 49.1 MiB | 2/2 |
| fastapi | clean | none | none | 0 | 0 | 0 | n/a | n/a | 14 (2/9/3) | 2.47 s | 46.7 MiB | n/a |
| fastapi | read | L2 | L2 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.42 s | 46.8 MiB | 1/1 |
| fastapi | write | L3 | L3 | 1 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.36 s | 46.6 MiB | 1/1 |
| fastapi | both | L2, L3 | L2, L3 | 2 | 0 | 0 | 100.0% | 100.0% | 14 (2/9/3) | 2.39 s | 46.9 MiB | 2/2 |

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
| Mīzān commit | `59d47675958643d82df0e7fc6995e6e641eb89ca` (read from git) |
| Mīzān tree digest | `1919893081ec1834` |
| Fixture digest (fastapi) | `c812fdcc0270a3e3` |
| Fixture digest (express) | `af78dca4c686f060` |

## What this is

Two controlled fixtures, each written independently against the same
behavioral contract. The numbers measure Mīzān against those two
fixtures. They are not a measurement of any real application, and they
are not statistically representative of anything else.
