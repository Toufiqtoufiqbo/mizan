# v1 L7 provider architecture

## Interface

`mizan.confidentiality.ConfidentialityEvidenceProvider` is a typed protocol:
`category`, `name`, `write(artifact)`, `observe(artifact_id, consumer, request_id)`,
`events()`, `cleanup()`. `EvidenceState` enumerates nine explicit outcomes;
missing policy/provenance or provider failure is never a confirmed finding.

## Trust model

An `Artifact` carries producer, scope, payload digest, request id and a stable
id. The producer is supplied by the engine from its authenticated principals —
not by a client header. A `ConfidentialityPolicy` names resource, scope,
classification, authorized readers, source and confidence. Authorization uses
only the policy; a cache hit or message delivery is not evidence by itself.

## Concrete providers

- `PostgresCacheProvider`: table `mizan_v1_cache_artifacts`; secure key includes
  tenant scope, vulnerable key omits it; events recorded in
  `mizan_v1_cache_events`.
- `PostgresQueueProvider`: table `mizan_v1_queue_messages` with intended consumer
  and `consumed_by`; secure consume requires matching consumer, vulnerable
  consume ignores it.

Both use unique disposable namespaces and `cleanup()` deletes only rows in that
namespace. PostgreSQL is the real service; no external cache/broker dependency
is added. This is a bounded v1 implementation, not a general cache/broker
scanner: provider events are controlled artifacts produced by Mīzān, not
arbitrary application cache traffic.

## Replay and regression

`replay_l7(evidence, dsn)` reconstructs a provider from proof evidence, rewrites
the artifact into a fresh namespace, observes the recorded consumer and cleans
up. Generated regressions call the same helper and assert the artifact is no
longer observable without authorization. Missing evidence produces an explicit
`unsupported` skip.

## Deferred

Logs, metrics and background-job output have no provider and remain
`unsupported`.
