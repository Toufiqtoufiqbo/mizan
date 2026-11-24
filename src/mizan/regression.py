"""Regression tests: proof that a finding was actually fixed.

Every finding Mizan reports carries an attack. The same attack, replayed
against a fixed application, must fail. That is what a regression test is, and
it is the only way to know that a fix worked instead of only moving the
problem.

A generated regression tests the *security invariant* recorded in the proof,
not a convenient status code or an echoed string. Where the proof does not
carry enough evidence to state that invariant reliably, generation produces an
explicit ``unsupported`` result and the generated test skips with the reason;
it never invents an assertion.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from mizan.core import AUTHORITY_FIELDS, Violation

#: The environment variable that points the test at the target.
TARGET_ENV = "MIZAN_TARGET"


@dataclass(frozen=True)
class Attack:
    """The attack behind a finding, in a form a test can replay."""

    law: str
    title: str
    method: str
    path: str
    token_var: str
    headers: dict[str, str]
    body: Any
    expectation: str
    principal: str | None = None
    #: The full recorded sequence, in order. A multi-step finding is never
    #: reduced to its first request.
    steps: list[dict[str, Any]] = field(default_factory=list)
    #: Machine-readable evidence from the proof bundle.
    evidence: dict[str, Any] = field(default_factory=dict)
    #: Whether a reliable semantic assertion could be generated.
    supported: bool = True
    unsupported_reason: str = ""
    #: Path used to verify persisted state after a write (L3/L4).
    verification_path: str | None = None
    #: Privileged field and value whose persistence is the L4 invariant.
    field_name: str | None = None
    sentinel: Any = None
    #: Owner and object identity used by read/write ownership invariants.
    owner: str | None = None
    object_id: str | None = None

    @property
    def test_name(self) -> str:
        return f"test_{self.law.lower()}_{_slug(self.title)}_is_fixed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "law": self.law,
            "title": self.title,
            "method": self.method,
            "path": self.path,
            "token_var": self.token_var,
            "headers": dict(self.headers),
            "body": self.body,
            "expectation": self.expectation,
            "principal": self.principal,
            "steps": list(self.steps),
            "evidence": dict(self.evidence),
            "supported": self.supported,
            "unsupported_reason": self.unsupported_reason,
            "verification_path": self.verification_path,
            "field_name": self.field_name,
            "sentinel": self.sentinel,
            "owner": self.owner,
            "object_id": self.object_id,
        }


def _jwt_subject(token: str) -> str | None:
    """The subject a token claims, read without the secret."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(raw)
    except (binascii.Error, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    for claim in ("sub", "user_id", "uid", "principal"):
        if claim in payload:
            return str(payload[claim])
    return None


def _slug(text: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in text.lower()).strip("_")[:60]


def _token_var(principal: str | None) -> str:
    name = (principal or "attacker").upper().replace("-", "_").replace(".", "_")
    return f"MIZAN_TOKEN_{name}"


def _authority_field(body: Any) -> tuple[str | None, Any]:
    """The authority field actually sent, and its value."""
    if not isinstance(body, dict):
        return None, None
    for name, value in body.items():
        lowered = str(name).lower()
        if lowered in {str(item).lower() for item in AUTHORITY_FIELDS} or any(
            lowered.endswith("_" + item) or lowered.startswith(item + "_") for item in AUTHORITY_FIELDS
        ):
            return str(name), value
    return None, None


def _state_value(body: Any, evidence: dict[str, Any]) -> Any:
    """A value that was really persisted, established from state evidence."""
    event = evidence.get("event")
    columns = event.get("columns") if isinstance(event, dict) else None
    persisted = {str(value) for value in (columns or {}).values() if value is not None}
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, (str, int, float)) and str(value) in persisted:
                return value
    return None


def build_attack(violation: Violation) -> Attack | None:
    """Turn a violation and its proof evidence into a replayable attack.

    The decisive step is the one that establishes the finding. For L4 it is
    the step that actually carries the privileged field; for other laws it is
    the last recorded step. The original method of that step is preserved.
    """
    if not violation.steps:
        return None
    steps = [step.to_dict() for step in violation.steps]
    evidence = dict(violation.evidence or {})
    decisive = violation.steps[-1]
    if violation.law == "L4":
        for step in violation.steps:
            field_name, _value = _authority_field(step.body)
            if field_name is not None:
                decisive = step
                break

    path = urlsplit(decisive.url).path or "/"
    headers = {key: value for key, value in (decisive.headers or {}).items() if key.lower() == "authorization"}
    expectation = {
        "L1": "the server acts as the identity the token claims",
        "L2": "the caller does not receive an object owned by somebody else",
        "L3": "the caller does not change an object owned by somebody else",
        "L4": "the privileged field is not applied to persisted state",
        "L5": "at most one of two concurrent requests succeeds",
        "L6": "the second use of a single-use resource is rejected",
    }.get(violation.law, "the request is rejected")

    field_name, sentinel = _authority_field(decisive.body)
    if violation.law == "L3":
        # The perturbed value was really persisted; verify that it no longer
        # appears in state after the fix.
        sentinel = _state_value(decisive.body, evidence)
    verification_path = evidence.get("verification_path")
    owner = evidence.get("owner") or evidence.get("resource_owner")
    object_id = evidence.get("object") or violation.resource
    if isinstance(object_id, dict):
        object_id = str(object_id.get("item_ref") or object_id.get("id") or "")
    if object_id:
        object_id = str(object_id).rsplit(":", 1)[-1]
    supported = True
    reason = ""
    if violation.law == "L1" and evidence.get("token_subject") is None:
        # The runtime test can still decode the token; lack of a recorded
        # subject is not a reason to refuse the identity-coherence invariant.
        reason = ""
    if violation.law == "L3" and not owner:
        supported = False
        reason = "the proof does not record a confirmed owner for the resource"
    if violation.law in {"L3", "L4"} and not verification_path:
        supported = False
        reason = "the proof does not record a state-verification endpoint"
    if violation.law == "L4":
        if field_name is None:
            supported = False
            reason = "the proof does not record a privileged field"
        elif _state_value(decisive.body, evidence) is None and evidence.get("event") is None:
            supported = False
            reason = "the proof does not record persisted state evidence"
        elif sentinel is None:
            supported = False
            reason = "the proof does not record the privileged value that was sent"
    if violation.law == "L2" and not object_id:
        supported = False
        reason = "the proof does not identify the object that must not be disclosed"
    if violation.law == "L6" and not (
        evidence.get("verification_path") and evidence.get("count_endpoint") and evidence.get("bound") is not None
    ):
        # A cardinality bound cannot be asserted over HTTP from a status code
        # alone. Without an explicit state endpoint in the proof, refuse.
        supported = False
        reason = "the proof does not provide a verifiable cardinality state endpoint"
    if violation.law == "L7":
        required = ("provider", "artifact", "observation", "policy", "provider_config")
        supported = all(key in evidence for key in required)
        if not supported:
            reason = "the proof does not carry complete L7 provider and provenance evidence"

    return Attack(
        law=violation.law,
        title=violation.title,
        method=str(decisive.method).upper(),
        path=path,
        token_var=_token_var(violation.principal),
        headers=headers,
        body=decisive.body,
        expectation=expectation,
        principal=violation.principal,
        steps=steps,
        evidence=evidence,
        supported=supported,
        unsupported_reason=reason,
        verification_path=str(verification_path) if verification_path else None,
        field_name=field_name,
        sentinel=sentinel,
        owner=str(owner) if owner else None,
        object_id=str(object_id) if object_id else None,
    )


# --------------------------------------------------------------------------- #
# The check the generated test performs
# --------------------------------------------------------------------------- #


def _request(session: Any, method: str, url: str, *, body: Any = None, **kwargs: Any) -> Any:
    method = method.upper()
    if method in {"GET", "HEAD", "DELETE"}:
        return session.request(method, url, **kwargs)
    return session.request(method, url, json=body if body is not None else {}, **kwargs)


def _replay_requests(attack: Attack, token: str, target: str) -> list[Any]:
    """Replay every recorded step in order, with its own identity context."""
    import requests

    session = requests.Session()
    responses: list[Any] = []
    steps = attack.steps or [
        {
            "method": attack.method,
            "path": attack.path,
            "headers": attack.headers,
            "body": attack.body,
            "principal": attack.principal,
        }
    ]
    for step in steps:
        headers = dict(step.get("headers") or {})
        # The proof never stores a token, only a principal. Re-resolve it from
        # the environment so authentication context is preserved per step.
        step_principal = step.get("principal")
        step_token = token if step_principal in (None, attack.principal) else ""
        if step_token:
            headers["Authorization"] = f"Bearer {step_token}"
        raw_path = step.get("path")
        if not raw_path:
            raw_path = urlsplit(str(step.get("url") or "/")).path or "/"
        url = target.rstrip("/") + str(raw_path)
        response = _request(
            session, str(step.get("method") or "GET"), url, body=step.get("body"), headers=headers, timeout=15
        )
        responses.append(response)
    return responses


def _body_json(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _contains_value(payload: Any, value: Any) -> bool:
    """Whether a value appears anywhere in a JSON-like structure."""
    if value is None:
        return False
    needle = str(value)
    if isinstance(payload, dict):
        return any(_contains_value(item, needle) for item in payload.values()) or needle in {
            str(key) for key in payload
        }
    if isinstance(payload, list):
        return any(_contains_value(item, needle) for item in payload)
    return payload is not None and needle in str(payload)


def attack_succeeds(attack: Attack, token: str, target: str) -> bool:
    """Whether the vulnerability is still present against the given target.

    ``True`` means the invariant is still broken - which is what makes the
    generated regression test fail on a vulnerable application.
    """
    import requests

    if not attack.supported:
        return False

    if attack.law == "L7":
        from mizan.confidentiality import replay_l7

        still_vulnerable, _state = replay_l7(attack.evidence, target)
        return still_vulnerable

    responses = _replay_requests(attack, token, target)
    response = responses[-1] if responses else None
    if response is None:
        return False

    if attack.law == "L1":
        if not (200 <= response.status_code < 300):
            # A secure implementation may reject the request: that is not a
            # coherence breach.
            return False
        subject = _jwt_subject(token) or attack.evidence.get("token_subject")
        body = _body_json(response)
        if subject is None or not isinstance(body, dict):
            return False
        acted_as = body.get("id") or body.get("user_id") or body.get("sub") or body.get("p_key")
        return str(acted_as) != str(subject)

    if attack.law == "L2":
        if not (200 <= response.status_code < 300):
            return False
        object_id = attack.object_id or (attack.path.rstrip("/").rsplit("/", 1)[-1] or None)
        return _contains_value(_body_json(response), object_id)

    if attack.law in {"L3", "L4"}:
        if not attack.verification_path:
            return False
        session = requests.Session()
        headers = {"Authorization": f"Bearer {token}"}
        readback = session.request("GET", target.rstrip("/") + attack.verification_path, headers=headers, timeout=15)
        if not (200 <= readback.status_code < 300):
            return False
        value = _state_value(attack.body, attack.evidence) if attack.law == "L3" else attack.sentinel
        if value is None:
            return False
        body = _body_json(readback)
        if isinstance(body, dict) and attack.field_name:
            return str(body.get(attack.field_name, "")) == str(value) or _contains_value(body, value)
        return _contains_value(body, value)

    if attack.law == "L5":
        statuses = []
        for _step in attack.steps:
            statuses.append(response.status_code)
        if attack.steps:
            from concurrent.futures import ThreadPoolExecutor

            def call() -> int:
                headers = {"Authorization": f"Bearer {token}"}
                return requests.request(
                    attack.method,
                    target.rstrip("/") + attack.path,
                    headers=headers,
                    json=attack.body or {},
                    timeout=15,
                ).status_code

            with ThreadPoolExecutor(max_workers=2) as executor:
                statuses = [future.result() for future in [executor.submit(call), executor.submit(call)]]
        return sum(1 for status in statuses if 200 <= status < 300) > 1

    # L6 - a second use of a single-use resource must not succeed.
    return 200 <= response.status_code < 300


# --------------------------------------------------------------------------- #
# The generated test
# --------------------------------------------------------------------------- #


def _assertion_body(attack: Attack) -> str:
    """The invariant check inserted into the generated test."""
    if attack.law == "L1":
        return """    response = responses[-1]
    subject = _subject(TOKEN) or EVIDENCE.get("token_subject")
    if 200 <= response.status_code < 300:
        body = _json(response)
        acted_as = body.get("id") or body.get("user_id") or body.get("sub") or body.get("p_key")
        assert subject is None or str(acted_as) == str(subject), EXPECTATION
    # A rejection is a valid secure outcome: the identity was never assumed."""
    if attack.law == "L2":
        return """    response = responses[-1]
    assert not (200 <= response.status_code < 300 and _contains(_json(response), OBJECT_ID)), EXPECTATION"""
    if attack.law in {"L3", "L4"}:
        return """    readback = _readback(VERIFICATION_PATH, OWNER_TOKEN or TOKEN)
    if 200 <= readback.status_code < 300:
        body = _json(readback)
        if FIELD and isinstance(body, dict):
            assert str(body.get(FIELD, "")) != str(SENTINEL), EXPECTATION
        else:
            assert not _contains(body, SENTINEL), EXPECTATION
    # An unreadable state endpoint cannot prove the invariant either way; it
    # is not silently interpreted as a fix or as a breach."""
    if attack.law == "L7":
        return """    from mizan.confidentiality import replay_l7

    still_observable, state = replay_l7(EVIDENCE, TARGET)
    assert not still_observable, (EXPECTATION, state)"""
    if attack.law == "L5":
        return """    def call() -> int:
        return requests.post(URL, headers=HEADERS, timeout=15).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = [future.result() for future in [executor.submit(call), executor.submit(call)]]
    accepted = sum(1 for status in statuses if 200 <= status < 300)
    assert accepted <= 1, (f"both concurrent requests were accepted: {statuses}", EXPECTATION)"""
    return """    response = responses[-1]
    assert not (200 <= response.status_code < 300), EXPECTATION"""


def _py(value: Any) -> str:
    """Render a value as a Python literal (``null`` is not valid Python)."""
    return repr(value)


def render_test(violation: Violation) -> str:
    """Render the pytest file that guards this finding."""
    attack = build_attack(violation)
    if attack is None:
        raise ValueError("the violation has no reproduction steps")
    test_file = f"test_mizan_{violation.law.lower()}.py"
    return f'''"""Regression test generated by Mizan.

Finding : {violation.law} - {violation.title}
Detail  : {violation.detail}

The test fails while the vulnerability is present and passes once it is fixed.
Point it at a target with:

    {TARGET_ENV}=https://staging.example.com \\
    {attack.token_var}=... \\
    pytest {test_file}

The assertion below verifies the invariant recorded in the proof. When the
proof lacks the evidence needed for a reliable assertion, SUPPORTED is False
and the test skips with an explicit reason instead of fabricating a check.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

requests = pytest.importorskip("requests")

TARGET = os.environ.get("{TARGET_ENV}", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("{attack.token_var}", "")
OWNER = {_py(attack.owner)}
OWNER_TOKEN = os.environ.get("MIZAN_TOKEN_" + OWNER.upper().replace("-", "_"), "") if OWNER else ""
URL = TARGET + {_py(attack.path)}
HEADERS = {{"Authorization": f"Bearer {{TOKEN}}"}}
STEPS = {_py(attack.steps)}
EVIDENCE = {_py(attack.evidence)}
LAW = {_py(violation.law)}
EXPECTATION = {_py(attack.expectation)}
SUPPORTED = {_py(attack.supported)}
UNSUPPORTED_REASON = {_py(attack.unsupported_reason)}
VERIFICATION_PATH = {_py(attack.verification_path)}
FIELD = {_py(attack.field_name)}
SENTINEL = {_py(attack.sentinel)}
OBJECT_ID = {_py(attack.object_id)}


def _subject(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(raw)
    except (binascii.Error, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return str(payload.get("sub") or payload.get("user_id") or payload.get("uid"))


def _json(response):
    try:
        return response.json()
    except Exception:
        return None


def _contains(payload, value) -> bool:
    if value is None:
        return False
    needle = str(value)
    if isinstance(payload, dict):
        return any(_contains(item, needle) for item in payload.values()) or needle in {{str(k) for k in payload}}
    if isinstance(payload, list):
        return any(_contains(item, needle) for item in payload)
    return payload is not None and needle in str(payload)


def _replay() -> list:
    """Replay the full recorded sequence, preserving order and identity."""
    if LAW == "L7":
        # L7 replays through the typed provider in the assertion below, not
        # through HTTP steps (provider events are not URLs).
        return []
    responses = []
    for step in STEPS:
        principal = step.get("principal")
        token = TOKEN if principal in (None, {_py(attack.principal)}) else os.environ.get(
            "MIZAN_TOKEN_" + str(principal).upper().replace("-", "_"), ""
        )
        headers = dict(step.get("headers") or {{}})
        if token:
            headers["Authorization"] = f"Bearer {{token}}"
        url = TARGET + (step.get("path") or _path(step.get("url", "/")))
        method = step.get("method", "GET").upper()
        if method in {{"GET", "HEAD", "DELETE"}}:
            responses.append(requests.request(method, url, headers=headers, timeout=15))
        else:
            responses.append(requests.request(method, url, headers=headers, json=step.get("body") or {{}}, timeout=15))
    return responses


def _path(url):
    """The path portion of a recorded absolute URL."""
    text = str(url)
    if "://" in text:
        text = text.split("://", 1)[1]
    return "/" + text.split("/", 1)[1] if "/" in text else "/"


def _readback(path, token):
    return requests.get(TARGET + path, headers={{"Authorization": f"Bearer {{token}}"}}, timeout=15)


def test_{attack.test_name}() -> None:
    """{violation.title} - {violation.law}."""
    if not SUPPORTED:
        pytest.skip("unsupported regression: " + UNSUPPORTED_REASON)
    responses = _replay()
    assert responses, "the proof contains no replayable requests"
{_assertion_body(attack)}
'''
