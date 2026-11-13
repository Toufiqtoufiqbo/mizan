# The cross-framework benchmark

Mīzān is run against two independently implemented applications that share
**only** a behavioral contract
(`tests/fixtures/external_apps/contract/CONTRACT.md`):

| Framework | Fixture | Runtime |
|---|---|---|
| FastAPI | `tests/fixtures/external_apps/fastapi_store` | Python 3.12, FastAPI + uvicorn |
| Express | `tests/fixtures/external_apps/express_store` | Node.js, Express 4.21.2 |

Neither fixture imports Mīzān. Each has its own authentication, its own SQLite
database, its own authorization functions and its own OpenAPI document.

## Running it

From the repository root:

```console
# the Express dependencies, installed from the committed lockfile
npm ci --prefix tests/fixtures/external_apps/express_store

# three independent repetitions of the whole matrix
python -m benchmarks.cross_framework.run --repetitions 3

# check the result against the expected matrix
python -m benchmarks.cross_framework.check benchmarks/cross_framework/results/results.json
```

Useful switches:

| Switch | Meaning |
|---|---|
| `--repetitions N` | how many independent repetitions of the whole matrix (default 3) |
| `--budget N` | the request budget of one scenario (default 60) |
| `--framework NAME` | restrict the run to one framework; may be repeated |
| `--output DIR` | where `results.json` and `results.md` are written |

The command exits non-zero when a scenario did not produce exactly the
expected laws, when a scan failed, or when a finding could not be reproduced.
The checker is a separate program: the benchmark produces the numbers, the
checker judges them.

## What one repetition does

For every framework and every variant (`clean`, `read`, `write`, `both`):

1. **unique credentials** - a fresh random password per principal, injected
   into the application through the environment. Nothing is reused between
   repetitions, and nothing is written to a report;
2. **an isolated workspace** - a fresh temporary directory with its own
   database, its own traffic log and its own twin log. The previous
   repetition's state is never visible;
3. **a bounded scan** - Mīzān attacks the application with a request budget,
   and the accounting separates the bootstrap, learning and attack traffic;
4. **a replay** - every finding is replayed against the state the scan left
   behind, with the principal's own token. A finding that cannot be replayed
   is a failure, not a footnote;
5. **a measurement** - the wall-clock time, the peak working set of the
   application process, whether the budget was exhausted, and whether anything
   failed to set up.

## What is recorded

`results.json` holds, per scenario:

- the expected and the observed laws, and the raw counts of true positives,
  false positives and false negatives;
- the requests: bootstrap, learning, attack, total, and the budget;
- the wall-clock time and the peak memory of the application process, with a
  note saying where the number came from (or why it is unavailable);
- whether the budget was exhausted, and every setup error;
- the replay: how many findings were replayed, how many reproduced, and why
  the others did not;
- the outcome: `expected`, `unexpected` or `error`.

`results.md` is the same information as a table, plus the environment the run
happened in: the operating system, the CPU, the memory, the Python, Node.js
and SQLite versions, the Mīzān commit (or the tree digest when git is not
installed) and the digest of each fixture.

## The CI stage

Stage **G - cross-framework validation** in `.github/workflows/mizan.yml` runs
the whole thing:

| Step | What it does |
|---|---|
| `setup-node` | installs Node.js **26.13.1**, pinned - the version the benchmark was measured on |
| `npm ci` | installs the Express dependencies from the committed lockfile; the lockfile is never rewritten |
| the fixture suites | `tests/test_fastapi_validation.py`, `tests/test_express_validation.py`, `tests/test_cross_framework_benchmark.py` |
| the benchmark | `python -m benchmarks.cross_framework.run --repetitions 3` |
| the checker | `python -m benchmarks.cross_framework.check ...` - a separate program that fails on a missing finding, an unexpected finding, an exhausted budget, a setup error, incomplete evidence, or a finding that could not be reproduced |
| the skip guard | the stage fails if any of those suites was skipped |
| the cleanup | any application still running is stopped, even when a test failed |
| the artifacts | the JSON and the Markdown report are uploaded, always |

The job has a 30-minute timeout, and the external-target stage stays optional
and unchanged.

## What it is not

The numbers measure Mīzān against **two controlled fixtures**. They are not a
measurement of any real application, they are not statistically representative
of anything else, and they say nothing about frameworks beyond these two.
