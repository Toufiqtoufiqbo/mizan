# v1 L7 provider architecture (application-backed)

## Interface

`mizan.confidentiality.ConfidentialityEvidenceProvider` is a typed protocol:
`category`, `name`, `write(artifact)`, `observe(artifact_id, consumer, request_id)`,
`events()`, `cleanup()`. `EvidenceState` enumerates nine explicit outcomes;
missing policy, missing provenance or provider failure is never a confirmed
finding.

## Trust model (remediated)

The fixture application (`tests/fixtures/external_apps/l7_store/app.py`) owns the
cache/queue artifacts and records its **own** operations in `l7_events` with the
inbound `X-Mizan-Request-Id`. Mīzān never writes these rows. Providers are
read-only observers of application events:

- `PostgresCacheProvider`: observes `cache_write` / `cache_read` events.
- `PostgresQueueProvider`: observes `queue_publish` / `queue_consume` events.

`evaluate()` requires the application event's producer, digest and identity to
match the HTTP operation. A digest mismatch, identity mismatch or missing event
produces `inconclusive`, never a finding.

## HTTP sequence (engine probe)

1. Producer Alice `POST /artifacts` (or `/messages`) with a controlled payload
   and request id.
2. Alice reads/consumes with her own identity — this must succeed and the
   returned digest must match, otherwise the check is inconclusive (a secure
   mode that blocks everyone is not accepted).
3. Bob reads/consumes with his request id.
4. The provider reads the corresponding application events and `evaluate()`
   classifies: `confirmed_disclosure` only when Bob received the producer's
   exact content without authorization.

## Replay and regression

`replay_l7(evidence, target)` re-executes the recorded three HTTP steps against
the target with tokens resolved from the environment, recomputes digests and
classifies again from the HTTP responses. `mizan replay` and generated L7
regressions use this function. Provider tables are corroborating evidence only.

## Scope and limitations

- The verified integration uses a PostgreSQL-backed fixture application. This
  is not a general Redis/RabbitMQ/cache implementation; no such service is
  claimed.
- Logs, metrics and background-job categories remain unsupported.
- Provider `cleanup()` clears only Mīzān's in-memory event list; it never deletes
  application-owned rows.
