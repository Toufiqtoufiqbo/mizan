# Phase VII Security & Architecture Audit

Scope of this audit: the generic engine's PostgreSQL backend adapter, the CLI
path, worker isolation, proof bundles and the independent fixture. All PR #10
cleanup and ownership guarantees are treated as invariants and are not changed.

## Backend trust boundaries

- The source database is read only for dump/catalog/fingerprint operations.
- Worker databases carry the immutable baseline and the audit triggers.
- `application_name` remains diagnostic metadata; no session is terminated.
- Attribution is supplied by `PostgresAttributor` (transaction-local principal,
  request correlation, monotonic cursor); unknown/ambiguous writes remain
  inconclusive and never produce confirmed L3.
- The backend adapter does not create a new ownership graph: `Mizan.learn()`
  uses `PostgresAttributor.schema()/rows()` and the existing graph builder.

## Worker identity and isolation

Each `PostgresTwin` creates a separate disposable database and process. No
worker receives another worker's DSN, and no psycopg connection is shared.
`PostgresRun.parallel_attacks()` creates one twin per worker and compares
normalized findings to the serial run. Active-session refusal and cleanup are
unchanged from PR #10.

## Probe authorization and law support

L1/L2/L3 run through the generic engine; L4, L6 and L7 are reported unsupported
because the database alone cannot supply the required evidence. L5 reuses the
existing race harness on one worker. Unsupported laws are never represented as
a clean result.

## Concurrency/cancellation/cleanup

The run-level advisory lock, whole-run preflight, durable deletion intents and
atomic completion from PR #10 are unchanged. Cancellation stops new scheduling
by returning through the existing cleanup path. No new deletion helper exists.

## Credentials and proof integrity

DSNs are read from environment-variable names; passwords are not printed.
Proof bundles use `Mizan.write_bundles` and inherit its secret redaction. The
new CLI emits only a status summary with counts, never a DSN or token.

## Failure modes

- Missing schema allowlist / DSN env / disposable authorization: fails closed.
- Clone or application start failure: existing `PostgresTwin` lifecycle fails
  closed and cleanup is invoked on all started workers.
- Parallel finding mismatch: non-zero exit with both normalized sets printed.
- Cleanup failure: the existing verified lifecycle reports exact state.

## Network exposure

No new network target is contacted. The fixture is started locally by the
disposable Twin; `replay` remains an explicit operator command.
