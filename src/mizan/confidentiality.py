"""L7 path confidentiality: typed evidence providers for indirect data paths.

This module is deliberately small. It provides a typed contract and two real,
PostgreSQL-backed providers (cache and queue). It is NOT a second engine: the
generic ``Mizan`` engine drives the providers and records their evidence.

A provider proves where an artifact came from and who observed it. It never
treats a cache hit, a message delivery or an equal string as a disclosure on
its own: authorization comes from an explicit policy.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class PathCategory(StrEnum):
    CACHE = "cache"
    QUEUE = "queue"
    LOGS = "logs"
    METRICS = "metrics"


IMPLEMENTED_CATEGORIES = frozenset({PathCategory.CACHE, PathCategory.QUEUE})


class EvidenceState(StrEnum):
    CONFIRMED_DISCLOSURE = "confirmed_disclosure"
    AUTHORIZED_SHARING = "authorized_sharing"
    BLOCKED = "blocked"
    NOT_OBSERVABLE = "not_observable"
    MISSING_PROVENANCE = "missing_provenance"
    MISSING_POLICY = "missing_policy"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class Artifact:
    """A controlled artifact with provenance and a stable identity."""

    artifact_id: str
    producer: str
    scope: str
    payload: str
    request_id: str = ""
    created_at: float = field(default_factory=time.time)

    def digest(self) -> str:
        return hashlib.sha256(self.payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "producer": self.producer,
            "scope": self.scope,
            "payload_digest": self.digest(),
            "request_id": self.request_id,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class Observation:
    """What a provider established about one consumer's observation."""

    artifact_id: str
    consumer: str
    observable: bool
    payload: str | None
    request_id: str = ""
    occurred_at: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "consumer": self.consumer,
            "observable": self.observable,
            "payload_digest": hashlib.sha256(self.payload.encode()).hexdigest() if self.payload else None,
            "request_id": self.request_id,
            "occurred_at": self.occurred_at,
            "details": self.details,
        }


@dataclass(frozen=True)
class ConfidentialityPolicy:
    """An explicit, trusted policy for one artifact scope."""

    resource: str
    scope: str
    classification: str
    authorized_readers: frozenset[str]
    source: str
    confidence: str

    def authorizes(self, principal: str) -> bool:
        return principal in self.authorized_readers

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "scope": self.scope,
            "classification": self.classification,
            "authorized_readers": sorted(self.authorized_readers),
            "source": self.source,
            "confidence": self.confidence,
        }


@dataclass
class ProviderEvidence:
    """The complete, serializable evidence for one L7 check."""

    category: PathCategory
    provider: str
    namespace: str
    artifact: dict[str, Any] | None
    observation: dict[str, Any] | None
    policy: dict[str, Any] | None
    state: EvidenceState
    outcome: str
    events: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "law": "L7",
            "category": self.category.value,
            "provider": self.provider,
            "namespace": self.namespace,
            "artifact": self.artifact,
            "observation": self.observation,
            "policy": self.policy,
            "state": self.state.value,
            "outcome": self.outcome,
            "events": self.events,
            "limitations": self.limitations,
        }


@runtime_checkable
class ConfidentialityEvidenceProvider(Protocol):
    """Typed contract for one indirect-path category.

    All operations are scoped to a disposable namespace so one test can never
    observe another test's artifacts.
    """

    @property
    def category(self) -> PathCategory: ...

    @property
    def name(self) -> str: ...

    def write(self, artifact: Artifact) -> None: ...

    def observe(self, artifact_id: str, consumer: str, *, request_id: str = "") -> Observation: ...

    def events(self) -> list[dict[str, Any]]: ...

    def cleanup(self) -> None: ...


class _PostgresProvider:
    """Shared PostgreSQL plumbing for the two concrete providers."""

    def __init__(self, dsn: str, namespace: str, *, shared_key: bool) -> None:
        self.dsn = dsn
        self.namespace = namespace
        self.shared_key = shared_key
        self._events: list[dict[str, Any]] = []

    def _connect(self) -> Any:
        import psycopg

        return psycopg.connect(self.dsn, autocommit=True, connect_timeout=5)

    def cleanup(self) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM mizan_v1_cache_artifacts WHERE namespace = %s", (self.namespace,))
                cursor.execute("DELETE FROM mizan_v1_cache_events WHERE namespace = %s", (self.namespace,))
                cursor.execute("DELETE FROM mizan_v1_queue_messages WHERE namespace = %s", (self.namespace,))
                cursor.execute("DELETE FROM mizan_v1_queue_events WHERE namespace = %s", (self.namespace,))
        self._events = []

    def events(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._events]

    @staticmethod
    def install(dsn: str) -> None:
        """Create the disposable artifact tables. Safe to call repeatedly."""
        import psycopg

        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mizan_v1_cache_artifacts (
                        namespace TEXT NOT NULL, cache_key TEXT NOT NULL,
                        artifact_id TEXT NOT NULL, producer TEXT NOT NULL,
                        scope TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL,
                        created_at REAL NOT NULL, PRIMARY KEY (namespace, cache_key))
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mizan_v1_cache_events (
                        namespace TEXT NOT NULL, artifact_id TEXT, consumer TEXT,
                        event TEXT, detail TEXT, occurred_at REAL NOT NULL)
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mizan_v1_queue_messages (
                        namespace TEXT NOT NULL, message_id TEXT NOT NULL,
                        producer TEXT NOT NULL, intended_consumer TEXT NOT NULL,
                        scope TEXT NOT NULL, payload TEXT NOT NULL,
                        consumed_by TEXT, consumed_at REAL,
                        PRIMARY KEY (namespace, message_id))
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mizan_v1_queue_events (
                        namespace TEXT NOT NULL, message_id TEXT, consumer TEXT,
                        event TEXT, detail TEXT, occurred_at REAL NOT NULL)
                    """
                )


class PostgresCacheProvider(_PostgresProvider):
    """A PostgreSQL-backed cache artifact provider."""

    category = PathCategory.CACHE
    name = "postgres-cache-v1"

    def write(self, artifact: Artifact) -> None:
        # A vulnerable provider keys only by artifact id (tenant scope omitted);
        # a secure provider includes the tenant scope in the cache key.
        cache_key = artifact.artifact_id if self.shared_key else f"{artifact.scope}:{artifact.artifact_id}"
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO mizan_v1_cache_artifacts
                       (namespace, cache_key, artifact_id, producer, scope, digest, payload, created_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (namespace, cache_key) DO UPDATE SET payload = EXCLUDED.payload""",
                    (
                        self.namespace,
                        cache_key,
                        artifact.artifact_id,
                        artifact.producer,
                        artifact.scope,
                        artifact.digest(),
                        artifact.payload,
                        artifact.created_at,
                    ),
                )
        self._events.append(
            {
                "event": "write",
                "artifact_id": artifact.artifact_id,
                "producer": artifact.producer,
                "scope": artifact.scope,
                "key": cache_key,
            }
        )

    def observe(self, artifact_id: str, consumer: str, *, request_id: str = "") -> Observation:
        # The artifact id is supplied by the engine, never by the consumer.
        candidates = [artifact_id, f"*:{artifact_id}"] if not self.shared_key else [artifact_id]
        with self._connect() as connection:
            with connection.cursor() as cursor:
                row = None
                for key in candidates:
                    cursor.execute(
                        """SELECT artifact_id, payload, producer, scope FROM mizan_v1_cache_artifacts
                           WHERE namespace = %s AND (cache_key = %s OR cache_key = %s)""",
                        (self.namespace, key, artifact_id),
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        break
        observable = row is not None
        self._events.append(
            {
                "event": "observe",
                "artifact_id": artifact_id,
                "consumer": consumer,
                "observable": observable,
                "request_id": request_id,
            }
        )
        return Observation(
            artifact_id=artifact_id,
            consumer=consumer,
            observable=observable,
            payload=str(row[1]) if row else None,
            request_id=request_id,
            details={"producer": row[2] if row else None, "scope": row[3] if row else None, "cache_key_used": True},
        )


class PostgresQueueProvider(_PostgresProvider):
    """A PostgreSQL-backed queue/message provider."""

    category = PathCategory.QUEUE
    name = "postgres-queue-v1"

    def write(self, artifact: Artifact) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO mizan_v1_queue_messages
                       (namespace, message_id, producer, intended_consumer, scope, payload)
                       VALUES (%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (namespace, message_id) DO UPDATE SET
                           producer = EXCLUDED.producer, payload = EXCLUDED.payload""",
                    (
                        self.namespace,
                        artifact.artifact_id,
                        artifact.producer,
                        artifact.scope,
                        artifact.scope,
                        artifact.payload,
                    ),
                )
        self._events.append(
            {
                "event": "publish",
                "message_id": artifact.artifact_id,
                "producer": artifact.producer,
                "intended_consumer": artifact.scope,
            }
        )

    def observe(self, artifact_id: str, consumer: str, *, request_id: str = "") -> Observation:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT message_id, producer, intended_consumer, payload, consumed_by
                       FROM mizan_v1_queue_messages WHERE namespace = %s AND message_id = %s""",
                    (self.namespace, artifact_id),
                )
                row = cursor.fetchone()
                observable = bool(row and (self.shared_key or str(row[2]) == consumer))
                payload = str(row[3]) if row and observable else None
                if row and observable:
                    cursor.execute(
                        """UPDATE mizan_v1_queue_messages SET consumed_by = %s, consumed_at = %s
                           WHERE namespace = %s AND message_id = %s""",
                        (consumer, time.time(), self.namespace, artifact_id),
                    )
        self._events.append(
            {
                "event": "consume",
                "message_id": artifact_id,
                "consumer": consumer,
                "observable": observable,
                "request_id": request_id,
            }
        )
        return Observation(
            artifact_id=artifact_id,
            consumer=consumer,
            observable=observable,
            payload=payload,
            request_id=request_id,
            details={
                "producer": row[1] if row else None,
                "intended_consumer": row[2] if row else None,
                "already_consumed_by": row[4] if row else None,
            },
        )


def evaluate(
    provider: ConfidentialityEvidenceProvider,
    artifact: Artifact,
    consumer: str,
    policy: ConfidentialityPolicy | None,
    *,
    request_id: str = "",
) -> ProviderEvidence:
    """Run one provider check and classify it without guessing."""
    if provider.category not in IMPLEMENTED_CATEGORIES:
        return ProviderEvidence(
            provider.category,
            provider.name,
            getattr(provider, "namespace", ""),
            artifact.to_dict(),
            None,
            policy.to_dict() if policy else None,
            EvidenceState.UNSUPPORTED,
            "unsupported category",
        )
    if policy is None:
        return ProviderEvidence(
            provider.category,
            provider.name,
            getattr(provider, "namespace", ""),
            artifact.to_dict(),
            None,
            None,
            EvidenceState.MISSING_POLICY,
            "no trusted confidentiality policy",
        )
    if not artifact.producer or not consumer:
        return ProviderEvidence(
            provider.category,
            provider.name,
            getattr(provider, "namespace", ""),
            artifact.to_dict(),
            None,
            policy.to_dict(),
            EvidenceState.MISSING_PROVENANCE,
            "producer or consumer identity is missing",
        )
    try:
        provider.write(artifact)
        observation = provider.observe(artifact.artifact_id, consumer, request_id=request_id)
    except Exception as exc:  # provider outage must fail closed
        return ProviderEvidence(
            provider.category,
            provider.name,
            getattr(provider, "namespace", ""),
            artifact.to_dict(),
            None,
            policy.to_dict(),
            EvidenceState.PROVIDER_UNAVAILABLE,
            f"provider failure: {type(exc).__name__}",
            limitations=[str(exc)],
        )
    authorized = policy.authorizes(consumer)
    if observation.observable:
        state = EvidenceState.AUTHORIZED_SHARING if authorized else EvidenceState.CONFIRMED_DISCLOSURE
        outcome = "authorized_sharing" if authorized else "unauthorized_observation"
    else:
        state = EvidenceState.BLOCKED
        outcome = "blocked_or_not_observable"
    return ProviderEvidence(
        provider.category,
        provider.name,
        getattr(provider, "namespace", ""),
        artifact.to_dict(),
        observation.to_dict(),
        policy.to_dict(),
        state,
        outcome,
        events=provider.events(),
    )


def policy_from_dict(data: dict[str, Any]) -> ConfidentialityPolicy | None:
    if not data:
        return None
    required = ("resource", "scope", "classification", "source", "confidence")
    if any(key not in data for key in required):
        return None
    readers = data.get("authorized_readers") or []
    if not isinstance(readers, list):
        return None
    return ConfidentialityPolicy(
        resource=str(data["resource"]),
        scope=str(data["scope"]),
        classification=str(data["classification"]),
        authorized_readers=frozenset(str(item) for item in readers),
        source=str(data["source"]),
        confidence=str(data["confidence"]),
    )


def serialize_evidence(evidence: ProviderEvidence) -> str:
    return json.dumps(evidence.to_dict(), sort_keys=True, default=str)
