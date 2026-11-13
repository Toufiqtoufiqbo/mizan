"""Evidence integrity: what a finding claims must be what actually happened.

A finding is not trustworthy because the engine detected something. It is
trustworthy because the recorded reproduction is the request that was really
sent, and replaying it reproduces the behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests

from mizan.core import Principal, Step, Violation
from mizan.engine import Mizan, Target
from mizan.proof import ProofBundle
from mizan.tokens import TokenResolver
from mizan.validation import scan_application, validate_finding

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "flask_store"


@pytest.fixture(scope="module")
def both_variant() -> dict:
    """The findings of the vulnerable variant, with both weaknesses."""
    result = scan_application(APP, variant="both", budget=60)
    assert result.error is None, result.error
    assert result.setup_error is None, result.setup_error
    return result.to_dict()


def test_the_read_probe_records_the_method_it_sent(tmp_path: Path) -> None:
    """A GET probe must never be recorded as a HEAD."""
    from mizan.engine import READ_METHOD

    traffic = tmp_path / "traffic.jsonl"
    traffic.write_text(
        json.dumps(
            {
                "method": "HEAD",
                "path": "/orders/o1",
                "template": "/orders/{id}",
                "status": 200,
                "principal": "alice",
                "body": None,
                "response": {"id": "o1", "owner_id": "alice"},
                "resource_type": "orders",
                "resource_id": "o1",
                "resource_owner": "alice",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    engine = Mizan(
        Target(
            base_url="http://127.0.0.1:1",
            principals=[Principal(id="alice", token="t"), Principal(id="bob", token="u")],
        ),
        traffic_path=traffic,
    )
    engine.learn()
    assert READ_METHOD == "GET"
    # The traffic says HEAD; the probe sends GET and must record GET.
    source = Path(__file__).resolve().parents[1] / "src" / "mizan" / "engine.py"
    text = source.read_text(encoding="utf-8")
    assert "method=READ_METHOD" in text, "the read probe still records the traffic method"
    assert "self._request(session, READ_METHOD, url" in text, "the read probe does not send READ_METHOD"


def test_every_finding_is_complete(both_variant: dict) -> None:
    findings = both_variant["findings"]
    assert findings, "the vulnerable variant produced no finding"
    for finding in findings:
        problems = validate_finding(finding)
        assert not problems, f"{finding['law']}: {problems}"


def test_the_owner_differs_from_the_attacker(both_variant: dict) -> None:
    for finding in both_variant["findings"]:
        evidence = finding.get("evidence") or {}
        owner = evidence.get("owner") or evidence.get("row_owner") or (evidence.get("event") or {}).get("row_owner")
        assert owner, f"{finding['law']} does not name an owner"
        assert owner != finding["principal"], "the attacker is reported as the owner"


def test_the_write_finding_records_the_body_that_was_sent(both_variant: dict) -> None:
    """The recorded payload must be the payload the application received."""
    writes = [finding for finding in both_variant["findings"] if finding["law"] == "L3"]
    assert writes, "the cross-user write was not reported"
    step = writes[0]["steps"][0]
    assert step.get("body"), "the write has no recorded body"
    assert "mizan-probe" in json.dumps(step["body"]), (
        "the recorded body is the original one, not the payload that was sent"
    )


def test_the_read_finding_records_a_get(both_variant: dict) -> None:
    reads = [finding for finding in both_variant["findings"] if finding["law"] == "L2"]
    assert reads, "the cross-user read was not reported"
    for finding in reads:
        assert finding["steps"][0]["method"] == "GET"


def test_a_bundle_replays_the_exact_request(tmp_path: Path) -> None:
    """Replaying the bundle must reproduce the behaviour, not a reconstruction.

    The application that produced the finding is still running, and the replay
    uses the recorded request verbatim - same method, same path, same body, and
    the token placeholder is resolved from the environment.
    """
    from mizan.attribution import SqliteAttributor
    from mizan.learning import learn_from_spec
    from mizan.proxy import RecordingProxy
    from mizan.twin import Twin, TwinSpec, script_command
    from mizan.validation import _login

    root = tmp_path / "app"
    root.mkdir(parents=True, exist_ok=True)
    database = root / "app.sqlite"
    traffic = root / "traffic.jsonl"
    twin = Twin(
        TwinSpec(
            command=script_command(
                APP / "app.py",
                "--db",
                str(database),
                "--port",
                "{port}",
                "--vulnerability",
                "both",
            ),
            workdir=root,
            data_paths=[database],
            health_path="/health",
            health_timeout=60.0,
        ),
        workspace=root / "twin",
    )
    twin.start()
    try:
        tokens = {name: _login(twin.base_url, name, f"{name}-secret") for name in ("alice", "bob")}
        assert all(tokens.values()), "the application issued no token"
        proxy = RecordingProxy(twin.base_url, traffic)
        proxy.identity_map = {token: name for name, token in tokens.items()}
        proxy.start()
        try:
            spec_path = APP / "openapi.json"
            learn_from_spec(spec_path, proxy.base_url, identities=tokens)
            engine = Mizan(
                Target(
                    base_url=proxy.base_url,
                    principals=[Principal(id=name, roles=("user",), token=token) for name, token in tokens.items()],
                ),
                traffic_path=traffic,
                spec_path=spec_path,
                twin=twin,
                attributor=SqliteAttributor(database),
            )
            engine.learn()
            violations = engine.attack()
            finding = next(violation.to_dict() for violation in violations if violation.law == "L2")

            violation = Violation(
                law=finding["law"],
                title=finding["title"],
                detail=finding.get("detail", ""),
                severity=finding.get("severity", "high"),
                principal=finding.get("principal"),
                resource=finding.get("resource"),
                action=finding.get("action"),
                steps=[Step(**step) for step in finding["steps"]],
            )
            bundle = ProofBundle.create(tmp_path / "bundles", violation, evidence=finding.get("evidence", {}))
            replay = json.loads((bundle / "replay.json").read_text(encoding="utf-8"))
            assert replay["steps"], "the bundle has no steps"
            assert replay["steps"][0]["method"] == "GET"

            # The bundle must not carry the secret: it carries a placeholder.
            headers = replay["steps"][0].get("headers") or {}
            assert "MIZAN_TOKEN_" in json.dumps(headers), "the bundle carries no token placeholder"

            # Replaying it against the same application reproduces the read.
            resolver = TokenResolver(tokens={name: token for name, token in tokens.items()})
            session = requests.Session()
            result = ProofBundle.load(bundle).verify(session, resolver=resolver)
            statuses = [step.get("status") for step in result["steps"]]
            assert statuses and statuses[0] == 200, f"the replay did not reproduce the finding: {result}"
        finally:
            proxy.stop()
    finally:
        twin.stop()
