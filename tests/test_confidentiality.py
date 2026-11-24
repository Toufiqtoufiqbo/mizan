"""Typed L7 evidence contract: fail-closed states that do not need HTTP."""

from __future__ import annotations

from mizan.confidentiality import (
    Artifact,
    ConfidentialityPolicy,
    EvidenceState,
    PathCategory,
    PostgresCacheProvider,
    evaluate,
    policy_from_dict,
)


def _policy() -> ConfidentialityPolicy:
    return ConfidentialityPolicy(
        resource="items",
        scope="tenant-a",
        classification="private",
        authorized_readers=frozenset({"alice"}),
        source="trusted_contract",
        confidence="confirmed",
    )


def test_unsupported_category_is_not_a_finding() -> None:
    class Provider:
        category = PathCategory.LOGS
        name = "fake-logs"
        namespace = "x"

        def write(self, artifact):
            raise AssertionError("unsupported providers must not be invoked")

        def observe(self, artifact_id, consumer, *, request_id=""):
            raise AssertionError("unsupported providers must not be invoked")

        def events(self):
            return []

        def cleanup(self):
            return None

    result = evaluate(Provider(), Artifact("a", "alice", "tenant-a", "content"), "bob", _policy())
    assert result.state is EvidenceState.UNSUPPORTED


def test_missing_policy_and_identity_fail_closed() -> None:
    provider = PostgresCacheProvider("postgresql://unused", namespace="unit")
    artifact = Artifact("a", "alice", "tenant-a", "content", request_id="r1")
    assert evaluate(provider, artifact, "bob", None).state is EvidenceState.MISSING_POLICY
    anonymous = Artifact("a", "", "tenant-a", "content", request_id="r1")
    assert evaluate(provider, anonymous, "bob", _policy()).state is EvidenceState.MISSING_PROVENANCE


def test_policy_parsing_requires_trusted_fields() -> None:
    assert policy_from_dict({}) is None
    assert (
        policy_from_dict(
            {
                "resource": "items",
                "scope": "tenant-a",
                "classification": "private",
                "authorized_readers": ["alice"],
                "source": "operator",
                "confidence": "confirmed",
            }
        )
        is not None
    )


def test_provider_cleanup_never_touches_application_tables() -> None:
    provider = PostgresCacheProvider("postgresql://unused", namespace="unit")
    provider.cleanup()
    assert provider.events() == []
