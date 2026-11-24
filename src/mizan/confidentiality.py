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
import uuid
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
            "payload_digest": str(self.details.get("digest") or "")
            if self.details.get("digest")
            else (hashlib.sha256(self.payload.encode()).hexdigest() if self.payload else None),
            "request_id": self.request_id,
            "occurred_at": self.occurred_at,
            "source": str(self.details.get("source", "")),
            "principal": str(self.details.get("principal", "")),
            "granted": bool(self.details.get("granted", False)),
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
    provider_config: dict[str, Any] = field(default_factory=dict)

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
            "provider_config": self.provider_config,
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
    """Read-only observer of application-owned L7 event tables.

    The fixture application writes its own cache/queue artifacts and records an
    event for every HTTP-triggered operation. Mīzān reads those events; it never
    manufactures them. ``namespace`` is only an evidence label, not a store.
    """

    operations: tuple[str, ...] = ()

    def __init__(self, dsn: str, namespace: str, *, shared_key: bool = False) -> None:
        self.dsn = dsn
        self.namespace = namespace
        # Kept for API compatibility; the application variant, not this flag,
        # decides whether data leaks. Evidence never assumes it.
        self.shared_key = shared_key
        self._events: list[dict[str, Any]] = []

    def _connect(self) -> Any:
        import psycopg

        return psycopg.connect(self.dsn, autocommit=True, connect_timeout=5)

    def cleanup(self) -> None:
        # No application-owned rows may ever be deleted by Mīzān.
        self._events = []

    def events(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._events]

    @staticmethod
    def install(dsn: str) -> None:
        """Deprecated compatibility hook; the application owns its tables."""
        return None

    def _event(self, request_id: str, operation: str, artifact_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT request_id, operation, principal, artifact_id, scope,
                              digest, granted, occurred_at
                       FROM l7_events
                       WHERE request_id = %s AND operation = ANY(%s) AND artifact_id = %s
                       ORDER BY id DESC LIMIT 1""",
                    (request_id, list(self.operations), artifact_id),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        return {
            "request_id": row[0],
            "operation": row[1],
            "principal": row[2],
            "artifact_id": row[3],
            "scope": row[4],
            "digest": row[5],
            "granted": bool(row[6]),
            "occurred_at": row[7],
            "source": "application_http_operation",
        }

    def write(self, artifact: Artifact) -> None:
        event = self._event(artifact.request_id, "", artifact.artifact_id)
        if event is None:
            raise LookupError("no application write event for the producer request")
        if event["principal"] != artifact.producer or event["digest"] != artifact.digest():
            raise ValueError("application write event does not match the producer artifact")
        self._events.append(event)

    def observe(self, artifact_id: str, consumer: str, *, request_id: str = "") -> Observation:
        event = self._event(request_id, "", artifact_id)
        if event is None:
            return Observation(
                artifact_id=artifact_id,
                consumer=consumer,
                observable=False,
                payload=None,
                request_id=request_id,
                details={"missing_event": True, "source": "application_http_operation"},
            )
        self._events.append(event)
        mismatch = event["principal"] != consumer
        return Observation(
            artifact_id=artifact_id,
            consumer=consumer,
            observable=bool(event["granted"]) and not mismatch,
            payload=event["digest"] if event["granted"] and not mismatch else None,
            request_id=request_id,
            details={
                "principal": event["principal"],
                "scope": event["scope"],
                "digest": event["digest"],
                "granted": event["granted"],
                "operation": event["operation"],
                "occurred_at": event["occurred_at"],
                "source": "application_http_operation",
                "identity_mismatch": mismatch,
            },
        )


class PostgresCacheProvider(_PostgresProvider):
    """Evidence adapter for application-performed cache operations."""

    category = PathCategory.CACHE
    name = "postgres-cache-app-v1"
    operations = ("cache_write", "cache_read")


class PostgresQueueProvider(_PostgresProvider):
    """Evidence adapter for application-performed queue operations."""

    category = PathCategory.QUEUE
    name = "postgres-queue-app-v1"
    operations = ("queue_publish", "queue_consume")


def evaluate(
    provider: ConfidentialityEvidenceProvider,
    artifact: Artifact,
    consumer: str,
    policy: ConfidentialityPolicy | None,
    *,
    request_id: str = "",
) -> ProviderEvidence:
    """Run one provider check and classify it without guessing."""
    config = {"shared_key": bool(getattr(provider, "shared_key", False))}

    def _evidence(*args: Any, **kwargs: Any) -> ProviderEvidence:
        return ProviderEvidence(*args, provider_config=config, **kwargs)

    if provider.category not in IMPLEMENTED_CATEGORIES:
        return _evidence(
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
        return _evidence(
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
        return _evidence(
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
        return _evidence(
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
    if observation.details.get("missing_event"):
        return _evidence(
            provider.category,
            provider.name,
            getattr(provider, "namespace", ""),
            artifact.to_dict(),
            observation.to_dict(),
            policy.to_dict(),
            EvidenceState.INCONCLUSIVE,
            "no application event for the consumer request",
            events=provider.events(),
        )
    if observation.details.get("identity_mismatch"):
        return _evidence(
            provider.category,
            provider.name,
            getattr(provider, "namespace", ""),
            artifact.to_dict(),
            observation.to_dict(),
            policy.to_dict(),
            EvidenceState.INCONCLUSIVE,
            "application event identity does not match the consumer",
            events=provider.events(),
        )
    if observation.observable and observation.payload != artifact.digest():
        return _evidence(
            provider.category,
            provider.name,
            getattr(provider, "namespace", ""),
            artifact.to_dict(),
            observation.to_dict(),
            policy.to_dict(),
            EvidenceState.INCONCLUSIVE,
            "observed content digest does not match the producer artifact",
            events=provider.events(),
        )
    authorized = policy.authorizes(consumer)
    if observation.observable:
        state = EvidenceState.AUTHORIZED_SHARING if authorized else EvidenceState.CONFIRMED_DISCLOSURE
        outcome = "authorized_sharing" if authorized else "unauthorized_observation"
    else:
        state = EvidenceState.BLOCKED
        outcome = "blocked_or_not_observable"
    return _evidence(
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


def provider_from_evidence(data: dict[str, Any], dsn: str) -> ConfidentialityEvidenceProvider | None:
    """Reconstruct a provider from proof evidence for replay."""
    name = data.get("provider")
    namespace = data.get("namespace") or f"replay-{uuid.uuid4().hex}"
    shared_key = bool((data.get("provider_config") or {}).get("shared_key", False))
    if name == PostgresCacheProvider.name:
        return PostgresCacheProvider(dsn, namespace=namespace, shared_key=shared_key)
    if name == PostgresQueueProvider.name:
        return PostgresQueueProvider(dsn, namespace=namespace, shared_key=shared_key)
    return None


def replay_l7(evidence: dict[str, Any], target: str, *, dsn: str = "") -> tuple[bool, str]:
    """Replay the recorded producer/consumer HTTP sequence against a target.

    The provider tables are only read as corroborating evidence; the result is
    recomputed from the actual HTTP responses. Missing steps, missing tokens or
    missing provenance fail closed.
    """
    import requests

    from mizan.tokens import MissingToken, TokenResolver, resolve_headers

    steps = evidence.get("steps") or []
    if len(steps) < 3:
        return False, "insufficient_http_steps"
    policy = policy_from_dict(evidence.get("policy") or {})
    if policy is None:
        return False, "insufficient_policy"
    integrity = evidence.get("payload_integrity") or {}
    expected = str(integrity.get("expected_digest") or "")
    if not expected:
        return False, "insufficient_provenance"
    consumer = str((evidence.get("observation") or {}).get("consumer") or "")
    if not consumer:
        return False, "insufficient_consumer_identity"
    resolver = TokenResolver.from_env()
    responses: list[Any] = []
    try:
        for step in steps:
            headers = resolve_headers(step.get("headers") or {}, resolver)
            url = str(step.get("url") or "")
            from urllib.parse import urlsplit

            parsed = urlsplit(url)
            full_url = target.rstrip("/") + (parsed.path or "/") if parsed.scheme else target.rstrip("/") + url
            method = str(step.get("method") or "GET").upper()
            kwargs: dict[str, Any] = {"headers": headers, "timeout": 15}
            if step.get("body") is not None:
                kwargs["json"] = step["body"]
            responses.append(requests.request(method, full_url, **kwargs))
    except MissingToken:
        return False, "missing_consumer_token"
    except Exception as exc:
        return False, f"replay_failed:{type(exc).__name__}"

    owner_response, consumer_response = responses[1], responses[2]
    owner_ok = 200 <= owner_response.status_code < 300
    consumer_ok = 200 <= consumer_response.status_code < 300
    if not owner_ok:
        return False, "authorized_read_failed"
    for response in (owner_response, consumer_response):
        if not (200 <= response.status_code < 300):
            continue
        try:
            if str((response.json() or {}).get("digest", "")) != expected:
                return False, "payload_mismatch"
        except Exception:
            return False, "payload_unverifiable"
    still_vulnerable = consumer_ok and not policy.authorizes(consumer)
    return still_vulnerable, ("confirmed_disclosure" if still_vulnerable else "blocked")


def serialize_evidence(evidence: ProviderEvidence) -> str:
    return json.dumps(evidence.to_dict(), sort_keys=True, default=str)
