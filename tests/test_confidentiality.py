"""L7 cache and queue providers: real PostgreSQL state, typed evidence."""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

import pytest

from mizan.confidentiality import (
    Artifact,
    ConfidentialityPolicy,
    EvidenceState,
    PathCategory,
    PostgresCacheProvider,
    PostgresQueueProvider,
    evaluate,
    policy_from_dict,
)


def _policy(scope: str = "tenant-a", readers: tuple[str, ...] = ("alice",)) -> ConfidentialityPolicy:
    return ConfidentialityPolicy(
        resource="items",
        scope=scope,
        classification="private",
        authorized_readers=frozenset(readers),
        source="trusted_contract",
        confidence="confirmed",
    )


def _artifact(producer: str = "alice", scope: str = "tenant-a") -> Artifact:
    return Artifact(
        artifact_id=f"artifact-{uuid.uuid4().hex}",
        producer=producer,
        scope=scope,
        payload="mizan-v1-private-marker",
        request_id="req-1",
    )


@pytest.fixture(scope="module")
def dsn():
    value = os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if value:
        return value if "connect_timeout" in value else value + "?connect_timeout=5"
    pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required")
    server = pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-ix-l7-")), cleanup_mode="delete")
    return server.get_uri()


@pytest.mark.parametrize("provider_cls", [PostgresCacheProvider, PostgresQueueProvider])
@pytest.mark.parametrize("shared_key", [False, True])
def test_provider_evidence_classifies_authorization(dsn, provider_cls, shared_key) -> None:
    PostgresCacheProvider.install(dsn)
    provider = provider_cls(dsn, namespace=f"test-{uuid.uuid4().hex}", shared_key=shared_key)
    try:
        vulnerable = evaluate(provider, _artifact(), "bob", _policy(), request_id="req-2")
        if shared_key:
            assert vulnerable.state is EvidenceState.CONFIRMED_DISCLOSURE
            assert vulnerable.observation and vulnerable.observation["observable"] is True
        else:
            assert vulnerable.state is EvidenceState.BLOCKED
        provider.cleanup()

        authorized = evaluate(provider, _artifact(), "alice", _policy(), request_id="req-3")
        assert authorized.state in {EvidenceState.AUTHORIZED_SHARING, EvidenceState.BLOCKED}
    finally:
        provider.cleanup()


def test_missing_policy_and_provenance_never_confirm(dsn) -> None:
    PostgresCacheProvider.install(dsn)
    provider = PostgresCacheProvider(dsn, namespace=f"test-{uuid.uuid4().hex}", shared_key=True)
    try:
        missing_policy = evaluate(provider, _artifact(), "bob", None)
        assert missing_policy.state is EvidenceState.MISSING_POLICY
        artifact = _artifact(producer="")
        missing_producer = evaluate(provider, artifact, "bob", _policy())
        assert missing_producer.state is EvidenceState.MISSING_PROVENANCE
    finally:
        provider.cleanup()


def test_namespaces_do_not_contaminate_each_other(dsn) -> None:
    PostgresCacheProvider.install(dsn)
    ns_a, ns_b = f"a-{uuid.uuid4().hex}", f"b-{uuid.uuid4().hex}"
    first = PostgresCacheProvider(dsn, namespace=ns_a, shared_key=True)
    second = PostgresCacheProvider(dsn, namespace=ns_b, shared_key=True)
    try:
        artifact = _artifact()
        first.write(artifact)
        observation = second.observe(artifact.artifact_id, "bob")
        assert observation.observable is False
    finally:
        first.cleanup()
        second.cleanup()


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


def test_l7_proof_replay_and_regression(dsn, tmp_path, monkeypatch) -> None:
    import json as _json

    from mizan.core import Principal
    from mizan.engine import Mizan, Target
    from mizan.regression import attack_succeeds, build_attack, render_test

    PostgresCacheProvider.install(dsn)
    provider = PostgresCacheProvider(dsn, namespace=f"test-{uuid.uuid4().hex}", shared_key=True)
    policy = {
        "category": PathCategory.CACHE.value,
        "resource": "items",
        "scope": "tenant-a",
        "classification": "private",
        "authorized_readers": ["alice"],
        "source": "trusted_contract",
        "confidence": "confirmed",
    }
    engine = Mizan(
        Target(
            base_url="http://localhost", principals=[Principal(id="alice", token="a"), Principal(id="bob", token="b")]
        ),
        confidentiality_providers=[provider],
        confidentiality_policies={"items": policy},
    )
    monkeypatch.setenv("MIZAN_L7_DSN", dsn)
    try:
        violations = engine.attack(groups=["L7"])
        assert violations
        directories = engine.write_bundles(violations, tmp_path)
        evidence = _json.loads((directories[0] / "replay.json").read_text(encoding="utf-8"))["evidence"]
        assert evidence["law"] == "L7" and evidence["category"] == "cache"
        assert evidence["artifact"]["producer"] == "alice"
        assert evidence["observation"]["consumer"] == "bob"
        assert "mizan-probe" in evidence["policy"]["source"] or evidence["policy"]["source"] == "trusted_contract"

        from mizan.confidentiality import replay_l7

        still, state = replay_l7(evidence, dsn)
        assert still is True and state == "confirmed_disclosure"

        safe = dict(evidence)
        safe["provider_config"] = {"shared_key": False}
        still_safe, _ = replay_l7(safe, dsn)
        assert still_safe is False

        attack = build_attack(violations[0])
        assert attack is not None and attack.supported
        assert attack_succeeds(attack, "b", "http://localhost") is True
        source = render_test(violations[0])
        assert "replay_l7" in source
        assert "SUPPORTED = True" in source
    finally:
        provider.cleanup()


def test_l7_regression_is_unsupported_without_provider_evidence() -> None:
    from mizan.core import Step, Violation
    from mizan.regression import build_attack, render_test

    violation = Violation(
        law="L7",
        title="cache leak",
        detail="",
        principal="bob",
        steps=[Step(method="PROVIDER", url="cache/write", note="producer wrote")],
        law_category="cache",
    )
    attack = build_attack(violation)
    assert attack is not None and attack.supported is False
    assert "pytest.skip" in render_test(violation)


def test_engine_records_independent_l7_execution(dsn) -> None:
    from mizan.core import Principal
    from mizan.engine import Mizan, Target

    PostgresCacheProvider.install(dsn)
    provider = PostgresCacheProvider(dsn, namespace=f"test-{uuid.uuid4().hex}", shared_key=True)
    policy = {
        "category": PathCategory.CACHE.value,
        "resource": "items",
        "scope": "tenant-a",
        "classification": "private",
        "authorized_readers": ["alice"],
        "source": "trusted_contract",
        "confidence": "confirmed",
    }
    engine = Mizan(
        Target(
            base_url="http://localhost",
            principals=[Principal(id="alice", token="a"), Principal(id="bob", token="b")],
        ),
        confidentiality_providers=[provider],
        confidentiality_policies={"items": policy},
    )
    try:
        violations = engine.attack(groups=["L7"])
        assert len(violations) == 1
        assert violations[0].law == "L7" and violations[0].law_category == "cache"
        assert engine.executed_by_law.get("L7") == 1
        coverage = engine.coverage()
        assert coverage.to_dict()["l7_categories"]["cache"] == "confirmed_disclosure"
        assert coverage.to_dict()["l7_categories"]["logs"] == "unsupported"
        assert coverage.to_dict()["l7_categories"]["metrics"] == "unsupported"
    finally:
        provider.cleanup()
