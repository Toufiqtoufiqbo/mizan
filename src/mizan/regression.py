"""Regression tests: proof that a finding was actually fixed.

Every finding Mizan reports carries an attack. The same attack, replayed
against a fixed application, must fail. That is what a regression test is, and
it is the only way to know that a fix worked instead of only moving the
problem.

Mizan writes that test for you:

    mizan regress mizan-proofs/L4-alice-created-authority-by-writing-role --out tests/

The generated test is standard pytest and talks to the target through
environment variables, so it fits into any CI:

    MIZAN_TARGET=https://staging.example.com \\
    MIZAN_TOKEN_ALICE=... \\
    pytest tests/test_mizan_L4.py
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from mizan.core import Violation

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


def build_attack(violation: Violation) -> Attack | None:
    """Turn a violation into a replayable attack."""
    if not violation.steps:
        return None
    step = violation.steps[0]
    path = urlsplit(step.url).path or "/"
    headers = {key: value for key, value in (step.headers or {}).items() if key.lower() == "authorization"}
    expectation = {
        "L1": "the response describes the identity the token claims",
        "L2": "the request is rejected",
        "L3": "the request is rejected",
        "L4": "the authority field is not applied",
        "L5": "at most one of two concurrent requests succeeds",
        "L6": "the second use is rejected",
    }.get(violation.law, "the request is rejected")
    return Attack(
        law=violation.law,
        title=violation.title,
        method=step.method,
        path=path,
        token_var=_token_var(violation.principal),
        headers=headers,
        body=step.body,
        expectation=expectation,
        principal=violation.principal,
    )


# --------------------------------------------------------------------------- #
# The check the generated test performs
# --------------------------------------------------------------------------- #


def attack_succeeds(attack: Attack, token: str, target: str) -> bool:
    """Whether the attack still works against the given target.

    ``True`` means the vulnerability is still there - which is what makes the
    generated regression test fail on a vulnerable application.
    """
    import requests

    url = target.rstrip("/") + attack.path
    headers = dict(attack.headers)
    headers["Authorization"] = f"Bearer {token}"

    if attack.law == "L1":
        response = requests.get(url, headers=headers, timeout=15)
        if not (200 <= response.status_code < 300):
            return False
        try:
            body = response.json()
        except Exception:
            return False
        subject = _jwt_subject(token)
        if subject is None:
            return False
        return str(body.get("id")) != subject

    if attack.law == "L5":
        from concurrent.futures import ThreadPoolExecutor

        def call() -> int:
            return requests.post(url, headers=headers, timeout=15).status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = [future.result() for future in [executor.submit(call), executor.submit(call)]]
        return sum(1 for status in statuses if 200 <= status < 300) > 1

    if attack.law == "L4":
        response = requests.patch(url, headers=headers, json=attack.body or {}, timeout=15)
        if not (200 <= response.status_code < 300):
            return False
        text = response.text
        sent = attack.body or {}
        for value in sent.values():
            if isinstance(value, str) and value.startswith("mizan-probe-") and value in text:
                return True
        return False

    # L2, L3, L6 - the request must be rejected.
    if attack.method == "GET":
        response = requests.get(url, headers=headers, timeout=15)
    else:
        response = requests.request(attack.method, url, headers=headers, json=attack.body or {}, timeout=15)
    return 200 <= response.status_code < 300


# --------------------------------------------------------------------------- #
# The generated test
# --------------------------------------------------------------------------- #


def render_test(violation: Violation) -> str:
    """Render the pytest file that guards this finding."""
    attack = build_attack(violation)
    if attack is None:
        raise ValueError("the violation has no reproduction steps")
    body = json.dumps(attack.body, indent=4) if attack.body is not None else "None"
    test_file = f"test_mizan_{violation.law.lower()}.py"
    return f'''"""Regression test generated by Mizan.

Finding : {violation.law} - {violation.title}
Detail  : {violation.detail}

The test fails while the vulnerability is present and passes once it is fixed.
Point it at a target with:

    {TARGET_ENV}=https://staging.example.com \\
    {attack.token_var}=... \\
    pytest {test_file}
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
URL = TARGET + "{attack.path}"
HEADERS = {{"Authorization": f"Bearer {{TOKEN}}"}}
BODY = json.loads(r"""{body}""")

#: What a fixed application must do.
EXPECTATION = "{attack.expectation}"


def _jwt_subject(token: str) -> str | None:
    """The subject the token claims, read without the secret."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(raw)
    except (binascii.Error, ValueError):
        return None
    for claim in ("sub", "user_id", "uid"):
        if claim in payload:
            return str(payload[claim])
    return None


def test_{attack.test_name}() -> None:
    """{violation.title} - {violation.law}."""
{_render_body(attack)}
'''


def _render_body(attack: Attack) -> str:
    if attack.law == "L1":
        return """    response = requests.get(URL, headers=HEADERS, timeout=15)
    assert response.status_code in (401, 403), (
        f"the identity endpoint answered {{response.status_code}} instead of rejecting the mismatch"
    )
    subject = _jwt_subject(TOKEN)
    assert subject is None or str(response.json().get("id")) == subject, (
        f"the server acted as {{response.json().get('id')}} while the token claimed {{subject}}"
    )"""
    if attack.law == "L5":
        return '''    def call() -> int:
        return requests.post(URL, headers=HEADERS, timeout=15).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = [future.result() for future in [executor.submit(call), executor.submit(call)]]

    accepted = sum(1 for status in statuses if 200 <= status < 300)
    assert accepted <= 1, f"both concurrent requests were accepted: {{statuses}}"'''
    if attack.law == "L4":
        return """    response = requests.patch(URL, headers=HEADERS, json=BODY, timeout=15)
    assert response.status_code >= 400 or "mizan-probe-" not in response.text, (
        f"the authority field was applied: {{response.text[:200]}}"
    )"""
    if attack.method == "GET":
        return """    response = requests.get(URL, headers=HEADERS, timeout=15)
    assert response.status_code not in (200, 201), (
        f"the cross-identity request was still accepted: {{response.status_code}}"
    )"""
    return """    response = requests.request("{attack.method}", URL, headers=HEADERS, json=BODY, timeout=15)
    assert response.status_code not in (200, 201), (
        f"the cross-identity write was still accepted: {{response.status_code}}"
    )"""
