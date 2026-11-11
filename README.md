# Mizan

> **لا نبحث عن ثغرات… نكسر قوانين تطبيقك.**

Mizan is a law-driven API security tool. It learns the security laws of an
application from the application's own normal behaviour, then tries to break
them, and reports only what it can prove.

It is built **on top of [Schemathesis](https://github.com/schemathesis/schemathesis)**
(MIT): Schemathesis already explores APIs with Hypothesis, performs stateful
testing, and covers the *read* side of object-level authorization. Mizan adds
the part that is still missing in the ecosystem:

| Layer | What Mizan adds |
|---|---|
| **Write side** (L3) | Attributes every database write to the principal that caused it and checks it against the row's owner - cross-identity writes (IDOR on write) are invisible to HTTP-level scanners |
| **Authority** (L4) | Detects mass assignment: a client that may set `role`, `tenant_id`, `owner_id`, `permissions`, ... |
| **Concurrency** (L5, L6) | Releases two identical requests through a barrier and proves a check-then-act race |
| **Proof** | Every finding ships as a replayable bundle: the exact requests, the evidence, the matrix diff, an optional patch and a regression test |
| **Algebra** | Observed access matrix vs. permitted access matrix; the residual and its norm show how far each identity strayed |

## Install

```bash
pip install -e .
```

## Try it in 30 seconds

```bash
mizan demo
```

This starts the bundled deliberately vulnerable API, produces normal traffic
against it, learns its laws, attacks them and writes a proof bundle per
finding:

```
Learned 3 resources, 6 rules from 7 traffic records and 3 writes

Found 7 proven violation(s):
  [high    ] L5 The same state transition was applied twice
  [high    ] L2 bob read an object owned by alice
  [high    ] L2 alice read an object owned by bob
  [high    ] L3 bob wrote into an object owned by alice
  [high    ] L3 alice wrote into an object owned by bob
  [critical] L4 alice created authority by writing `role`
  [critical] L4 bob created authority by writing `role`

Access matrix: 8 observed cells, 4 outside the permitted space,
residual norm {'bob': 1.41, 'alice': 1.41}
```

## The twin - a private copy of your app, without Docker

The usual way to test an application safely is a container. Mizan does not need
one. It needs a process, a temporary directory and a copy of the data:

```bash
mizan twin \
  --command "python -m myapp --port {port}" \
  --data data/app.db \
  --spec openapi.json \
  --token alice=eyJhbGciOi... \
  --token bob=eyJhbGciOi... \
  --out mizan-proofs
```

What happens:

| Step | Who does it |
|---|---|
| the application starts on a free port | `mizan.twin.Twin` |
| the pristine state is snapshotted | `mizan.twin` (a copy of the data files) |
| every request is recorded | `mizan.proxy.RecordingProxy` - the app is **not** modified |
| the writes are attributed | `mizan.attribution.SqliteAttributor` - the database diff is the ledger |
| the laws are learned | `mizan.engine.Mizan.learn()` |
| the laws are attacked | every probe restores the state first, so the findings do not depend on the order of the probes |
| the findings are written | one proof bundle per finding, with a regression test |

The result on the bundled vulnerable application, with **no change to the
application at all**:

```
application started on http://127.0.0.1:56543
recorded 19 requests
learned 4 resources and 3 rules

Found 11 proven violation(s):
  [high    ] L5 The same state transition was applied twice
  [high    ] L2 bob read an object owned by alice
  [high    ] L2 alice read an object owned by bob
  [high    ] L3 bob wrote into an object owned by alice
  [high    ] L3 alice wrote into an object owned by bob
  [critical] L4 alice created authority by writing `role`
```

Two things make this possible without touching the application:

* the **recording proxy** - traffic is observed from the outside;
* the **data-level attribution** - the difference between two snapshots of the
  database is the write, attributed to the identity that made the request.

### Attacking in parallel

`--workers N` starts N isolated copies of the application, each with its own
copy of the data and its own port, and splits the probes between them:

```bash
mizan twin ... --workers 4
# attacked with 4 isolated copies: L5, L2, L4, L1, L3, T
```

The result is the same as a serial run - the copies are isolated, so a probe
cannot hide a finding from another one.

### The CI gate

Every proof bundle carries the attack that found it. `mizan replay` replays
them all against a target and fails when an attack still works:

```bash
mizan replay mizan-proofs --target https://staging.example.com
#   ✗ L4 alice created authority by writing `role` - STILL REPRODUCIBLE
#   ✓ L2 bob read an object owned by alice - fixed
```

That is the gate for a pull request: a fixed vulnerability cannot come back.

> A race (L5/L6) needs a fresh instance to reproduce - the first replay consumes
> the resource. Run the gate against a twin (`mizan twin --keep`) or a fresh
> staging deployment, not against a long-lived environment.

## Two ways to attack

| | fixed probes | guided search |
|---|---|---|
| what it does | runs the hypotheses a human wrote down | searches for the request that breaks a law |
| how | one probe per law, over every candidate | UCT over executed actions, a bandit over the templates, and a prior taken from the learned policy |
| on AuthzBugs-50 | 10/10 breaches, 49.4 requests per app | **10/10 breaches, 20.6 requests per app** |
| finds a race | yes | yes (two identical requests at the same time, on the caller's own resource) |
| chains requests | no | yes - identifiers found in a response are offered back to the templates |

```bash
mizan compare --size 10
# | mode | average requests | breaches found |
# | probes | 49.4 | 10 |
# | guided | 20.6 | 10 |
```

The search is not a replacement for the probes: the probes are predictable, the
search explores. Run both - `mizan twin --guided` runs the search, and the
probes are one command away.

## The laws

| ID | Law | Severity | Breaks |
|---|---|---|---|
| L1 | Authentication coherence | critical | the server acts as a different identity than the token claims |
| L2 | Read authorization (read-taint) | high | IDOR / BOLA on reads |
| L3 | Write authorization (write-taint) | high | IDOR on writes, writes to somebody else's row |
| L4 | No authority creation | critical | mass assignment of `role`, `tenant_id`, `owner_id`, `permissions` |
| L5 | Atomicity (TOCTOU) | high | check-then-act without an atomic guard |
| L6 | Cardinality and bounds | medium | single-use resources consumed twice |
| L7 | Path confidentiality | medium | data leaving the system outside the caller's authority |

## AuthzBugs-50 - the benchmark

Nobody publishes a measurement for this class of bugs, so Mizan ships its own.
**AuthzBugs-50** is 50 applications with exactly one labelled vulnerability each
(10 per law), plus a *patched twin* of every application.

```bash
mizan benchmark --size 50 --controls 5 --out authzbugs-report
```

| metric | value |
|---|---|
| detection rate | **100%** (50/50) |
| false positives on patched twins | **0** / 55 apps |
| unexpected findings on buggy apps | 0 |
| regression tests valid | **100%** (290 attacks reproduce before the fix, 290 are blocked after it) |

The third metric is the one that matters for trust: an attack that reproduces on
the vulnerable application and is rejected by the patched one proves that both
the finding *and* the fix are real.

## Proof bundles and regression tests

Every finding is a directory:

```
mizan-proofs/L4-alice-created-authority-by-writing-role/
    replay.json        # the exact requests, in order
    violation.md       # which law broke, and why
    evidence.json      # machine-readable evidence
    matrix.json        # observed vs permitted access matrix
    patch.diff         # the shape of the fix (a template, adapted to your code)
    regression.test    # a pytest that fails today and passes after the fix
```

The regression test is standard pytest and talks to the target through the
environment, so it drops into any CI:

```bash
mizan regress mizan-proofs/L4-alice-created-authority-by-writing-role --out tests/

MIZAN_TARGET=https://staging.example.com \
MIZAN_TOKEN_ALICE=... \
pytest tests/test_mizan_l4.py
```

## Workflow

```bash
# 1. Learn the laws from normal traffic and a ledger of attributed writes
mizan learn --traffic traffic.jsonl --ledger ledger.jsonl --out mizan-policy.json

# 2. Attack them
mizan attack --target http://127.0.0.1:8000 \
             --traffic traffic.jsonl --ledger ledger.jsonl \
             --spec openapi.json --out mizan-proofs

# 3. Replay any finding against a live target
mizan verify mizan-proofs/L3-bob-wrote-into-an-object-owned-by-alice
```

## Where the ledger comes from

The write ledger is the one input Mizan cannot invent. There are three ways to
get one, and none of them requires a container:

**1. The data itself (no cooperation needed).** `mizan.attribution.SqliteAttributor`
compares two snapshots of the database around a request; the difference is the
write, attributed to the identity that made it. This is what the twin uses.

**2. Postgres.** `mizan.postgres_audit.PostgresAuditor` installs an audit table
and a trigger on every table of the schemas you point it at. The identity
travels in `application_name`:

```sql
SET LOCAL application_name = 'mizan:' || current_user_id;
```

`SET LOCAL` is transaction-scoped, so a pooled connection cannot carry one
user's identity into another user's work.

The auditor needs to own the tables it instruments (creating a trigger requires
it), and it keeps both the row before and after the change, so the changed
columns are computed exactly instead of guessed.

Primary keys are read from the catalog: `id`, UUID, text and composite keys all
work. A table without a primary key is recorded but reported as unidentified -
it is never given a made-up identity, and its writes are never reported as
breaches.

```python
import psycopg

from mizan.postgres_audit import PostgresAuditor

with psycopg.connect("postgresql://localhost/app") as connection:
    auditor = PostgresAuditor(connection, schemas=("public",))
    auditor.install()
    ...
    auditor.refresh()  # after a migration
    events = auditor.read()
```

.. warning::

    ``application_name`` is metadata, not authentication. Anyone who can run
    SQL on that connection can claim any identity. The attribution is only as
    trustworthy as the application's ability to control its own database
    connections - which is the assumption an audit of *your own* application
    rests on. A write whose author cannot be established is recorded with the
    principal ``unknown`` and is **never** reported as a confirmed breach.

.. note::

    Mass assignment cannot be proven from the database alone: the database
    cannot tell whether a field was sent by the client or set by the server.
    Use an application ledger (`source_fields`) for that check - Mizan does.

**3. The application itself.** A ledger is a JSONL file of attributed writes:

```json
{"ts": 1794311241.68, "request_id": "req-8", "principal": "alice",
 "method": "PUT", "path": "/orders/o1", "table": "orders", "row_id": "o1",
 "columns": {"status": "paid"}, "source_fields": ["status"], "row_owner": "alice"}
```

* **Postgres logs** - set `log_statement = 'all'` and tag connections with
  `SET application_name = 'mizan:<principal>'`. `mizan.taint.PostgresLogParser`
  turns the log into ledger events.
* **An ORM hook / middleware** - write one line per transaction.
* **The demo app** - `mizan.demo.app.DemoApp` shows the smallest possible
  implementation.

## Recording the traffic

`mizan.recorder.Recorder` is a WSGI middleware that writes the traffic log:

```python
from mizan.recorder import Recorder

application = Recorder(app, "traffic.jsonl")
```

For applications you cannot wrap, use the recording proxy instead - it needs no
cooperation from the application at all:

```python
from mizan.proxy import RecordingProxy

proxy = RecordingProxy("http://127.0.0.1:8000", "traffic.jsonl")
proxy.start()
```

## Using the law checks inside Schemathesis

```bash
export SCHEMATHESIS_HOOKS=mizan.schemathesis_hooks
export MIZAN_POLICY=mizan-policy.json
export MIZAN_LEDGER=ledger.jsonl
schemathesis run http://127.0.0.1:8000/openapi.json --checks MizanLawCheck
```

## Proof bundle

```
mizan-proofs/L4-alice-created-authority-by-writing-role/
    replay.json        # the exact requests, in order
    violation.md       # which law broke, and why
    evidence.json      # machine-readable evidence
    matrix.json        # observed vs permitted access matrix
```

## Tests

```bash
python -m pytest
```

The end-to-end test runs the real engine against the real demo application -
no mocks, and the vulnerabilities are genuine. The twin tests start a real
process, record it through a real proxy and diff a real database.

## Status

The vertical slice works end to end: learn -> attack -> prove -> regress. Five of
the seven laws are implemented and measured; L6 is partially covered and L7 is
not yet. See `ROADMAP.md` for what comes next.

## License

MIT.
