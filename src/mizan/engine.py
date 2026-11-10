"""The Mizan engine: learn the application's laws, then try to break them.

The flow is deliberately small:

1. ``learn``  - read a traffic log and a write ledger, and derive a policy:
                 which principals exist, which resources they own, which access
                 rules hold, and which fields the server manages itself.
2. ``attack`` - probe the policy with targeted requests (cross-identity reads,
                 cross-identity writes, authority fields, concurrent actions),
                 attribute every effect through the ledger, and report only what
                 can be reproduced.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import requests

from mizan.core import (
    AccessMatrix,
    Policy,
    Principal,
    Resource,
    Rule,
    Step,
    Violation,
    actions_for,
    is_authority_field,
)
from mizan.identity import decode_token, forge_unsigned, subject_of
from mizan.patching import render as patch_render
from mizan.regression import render_test as regression_render
from mizan.proof import ProofBundle
from mizan.races import RaceOutcome, detect_race, looks_single_use, run_concurrently
from mizan.taint import Ledger, TaintAnalyzer, WriteEvent
from mizan.traffic import TrafficLog, TrafficRecord, infer_resource


# --------------------------------------------------------------------------- #
# Target description
# --------------------------------------------------------------------------- #


@dataclass
class Target:
    """Where to attack and with which identities."""

    base_url: str
    principals: list[Principal] = field(default_factory=list)
    timeout: float = 10.0

    def principal(self, principal_id: str) -> Principal | None:
        for principal in self.principals:
            if principal.id == principal_id:
                return principal
        return None

    def session_for(self, principal: Principal) -> requests.Session:
        session = requests.Session()
        if principal.token:
            session.headers["Authorization"] = f"Bearer {principal.token}"
        return session


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class Mizan:
    def __init__(
        self,
        target: Target,
        *,
        policy: Policy | None = None,
        traffic_path: str | Path | None = None,
        ledger_path: str | Path | None = None,
        spec_path: str | Path | None = None,
    ) -> None:
        self.target = target
        self.policy = policy or Policy()
        self.traffic_path = Path(traffic_path) if traffic_path else None
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self.spec_path = Path(spec_path) if spec_path else None
        self.traffic: TrafficLog = TrafficLog(self.traffic_path)
        self.ledger: Ledger = Ledger(self.ledger_path)
        self.observed = AccessMatrix()
        self.permitted = AccessMatrix()
        self.observed_principals: set[str] = set()

    # -- learning ---------------------------------------------------------- #

    def learn(self) -> Policy:
        """Derive the application's laws from its own normal behaviour."""
        if self.traffic_path is not None and self.traffic_path.exists():
            self.traffic = TrafficLog.load(self.traffic_path)
        if self.ledger_path is not None and self.ledger_path.exists():
            self.ledger = Ledger.load(self.ledger_path)

        policy = self.policy

        self.observed_principals = {record.principal for record in self.traffic if record.principal}

        for principal in self.target.principals:
            policy.principals.setdefault(principal.id, principal)
        for record in self.traffic:
            if record.principal and record.principal not in policy.principals:
                policy.principals[record.principal] = Principal(id=record.principal)

        # Resources and observed accesses.
        owned_by_principal: dict[str, set[str]] = {}
        accessed: dict[tuple[str, str, str], set[str]] = {}
        for record in self.traffic:
            resource = record.resource
            if resource is not None:
                if resource.owner:
                    policy.resources.setdefault(resource.key, resource)
                    owned_by_principal.setdefault(record.principal or "", set()).add(resource.key)
                elif record.principal:
                    policy.resources.setdefault(resource.key, resource)
            if record.principal and resource is not None:
                accessed.setdefault((record.principal, resource.type, record.action), set()).add(resource.key)
                self.observed.grant(record.principal, resource.key, record.action)

        # Ownership rules: a principal that only ever touched resources it owns.
        for (principal_id, resource_type, action), keys in accessed.items():
            owned = owned_by_principal.get(principal_id, set())
            if not owned or not keys.issubset(owned):
                continue
            rule = Rule(kind="owner", action=action, resource_type=resource_type)
            if rule not in policy.rules:
                policy.rules.append(rule)

        # Role rules for principals we know the roles of. Only privileged roles
        # become rules: a shared role like "user" says nothing about ownership,
        # and turning it into a rule would hide every cross-identity access.
        privileged_roles = {"admin", "superuser", "owner", "root"}
        for principal in policy.principals.values():
            for role in principal.roles:
                if role not in privileged_roles:
                    continue
                for (principal_id, resource_type, action) in accessed:
                    if principal_id != principal.id:
                        continue
                    rule = Rule(kind="role", action=action, resource_type=resource_type, role=role)
                    if rule not in policy.rules:
                        policy.rules.append(rule)

        # Server-managed fields: columns the server writes although the client
        # never sent them.
        managed: dict[str, set[str]] = {}
        for event in self.ledger.events:
            for column in event.columns:
                if column not in event.source_fields:
                    managed.setdefault(event.table, set()).add(column)
        for table, fields in managed.items():
            policy.server_managed_fields.setdefault(table, set()).update(fields)

        # The permitted matrix, derived from the policy.
        self.permitted = AccessMatrix()
        for principal in policy.principals.values():
            for key, resource in policy.resources.items():
                for action in ("read", "write"):
                    if policy.permitted(principal, resource, action):
                        self.permitted.grant(principal.id, key, action)

        policy.notes.append(
            f"learned from {len(self.traffic)} traffic records, {len(self.ledger.events)} write events, "
            f"{len(policy.resources)} resources, {len(policy.rules)} rules"
        )
        self.policy = policy
        return policy

    # -- attacking --------------------------------------------------------- #

    def attack(self) -> list[Violation]:
        """Probe the learned policy and return the proven violations."""
        violations: list[Violation] = []
        # Races run first: every other probe mutates state, and a probe that
        # changes the state of a resource would hide a race on it. (With a local
        # twin each probe would get a fresh snapshot instead.)
        violations.extend(self._probe_races())
        violations.extend(self._probe_identity_coherence())
        violations.extend(self._probe_read_authorization())
        violations.extend(self._probe_write_authorization())
        violations.extend(self._probe_authority_creation())

        # The data-level view of the same run.
        analyzer = TaintAnalyzer(self.policy)
        violations.extend(analyzer.analyze(self.ledger.events))
        return _dedupe(violations)

    def _is_testable(self, principal: Principal) -> bool:
        """Whether it makes sense to attack with this identity.

        Privileged identities are allowed to see more, and identities that the
        application never used are not worth attacking with - they would only
        produce noise.
        """
        if principal.is_privileged():
            return False
        if self.observed_principals and principal.id not in self.observed_principals:
            return False
        return True

    # -- probes ------------------------------------------------------------ #

    def _examples(self) -> dict[tuple[str, str], list[TrafficRecord]]:
        """Group observed traffic by `(method, template)`."""
        grouped: dict[tuple[str, str], list[TrafficRecord]] = {}
        for record in self.traffic:
            grouped.setdefault((record.method.upper(), record.template or ""), []).append(record)
        return grouped

    def _probe_read_authorization(self) -> list[Violation]:
        """L2 - can one principal read another principal's object?"""
        violations: list[Violation] = []
        examples = self._examples()
        for (method, template), records in examples.items():
            if method not in {"GET", "HEAD"}:
                continue
            for record in records:
                resource = record.resource
                if resource is None or not resource.owner:
                    continue
                owner = resource.owner
                for attacker in self.target.principals:
                    if attacker.id == owner:
                        continue
                    if not attacker.token or not self._is_testable(attacker):
                        continue
                    url = self._url(record.path)
                    session = self.target.session_for(attacker)
                    response = session.get(url, timeout=self.target.timeout)
                    if not (200 <= response.status_code < 300):
                        continue
                    body = _json(response)
                    returned_owner = None
                    if isinstance(body, dict):
                        for key in ("owner_id", "user_id", "owner"):
                            if isinstance(body.get(key), (str, int)):
                                returned_owner = str(body[key])
                                break
                    if returned_owner is not None and returned_owner == attacker.id:
                        continue
                    self.observed.grant(attacker.id, resource.key, "read")
                    violations.append(
                        Violation(
                            law="L2",
                            title=f"{attacker.id} read an object owned by {owner}",
                            detail=(
                                f"`{method} {url}` returned `{record.resource.key}` to `{attacker.id}` although the "
                                f"object belongs to `{owner}`. Reading it back with the victim's own identity "
                                f"returned the same content, so no ownership check was applied."
                            ),
                            severity="high",
                            principal=attacker.id,
                            resource=resource.key,
                            action="read",
                            evidence={
                                "attacker_status": response.status_code,
                                "owner": owner,
                                "returned_owner": returned_owner,
                                "object": _truncate(body),
                            },
                            steps=[
                                Step(
                                    method=method,
                                    url=url,
                                    headers={"Authorization": f"Bearer {attacker.token}"},
                                    status=response.status_code,
                                    note=f"cross-identity read of `{resource.key}`",
                                )
                            ],
                        )
                    )
        return violations

    def _probe_identity_coherence(self) -> list[Violation]:
        """L1 - does the server act as the identity the token claims?"""
        violations: list[Violation] = []
        endpoints = self._identity_endpoints()
        if not endpoints:
            return violations
        for principal in self.target.principals:
            if not principal.token:
                continue
            claims = decode_token(principal.token)
            if claims is None or claims.subject is None:
                continue
            for method, template, url in endpoints:
                session = self.target.session_for(principal)
                response = session.request(method, url, timeout=self.target.timeout)
                if not (200 <= response.status_code < 300):
                    continue
                body = _json(response)
                if not isinstance(body, dict):
                    continue
                acted_as = body.get("id") or body.get("user_id") or body.get("sub")
                if acted_as is None or str(acted_as) == claims.subject:
                    continue
                violations.append(
                    Violation(
                        law="L1",
                        title=f"the token claims to be {claims.subject}, the server acted as {acted_as}",
                        detail=(
                            f"`{method} {url}` was authenticated with a token whose subject is `{claims.subject}`, "
                            f"but the response describes `{acted_as}`. The server did not act as the identity the "
                            f"client presented."
                        ),
                        severity="critical",
                        principal=principal.id,
                        resource=None,
                        action="authenticate",
                        evidence={
                            "token_subject": claims.subject,
                            "acted_as": str(acted_as),
                            "claims": claims.raw,
                        },
                        steps=[
                            Step(
                                method=method,
                                url=url,
                                headers={"Authorization": f"Bearer {principal.token}"},
                                status=response.status_code,
                                note="the token claimed one identity, the server acted as another",
                            )
                        ],
                    )
                )
        return violations

    def _identity_endpoints(self) -> list[tuple[str, str, str]]:
        """Endpoints that answer "who am I?", learned from the traffic."""
        endpoints: list[tuple[str, str, str]] = []
        for (method, template), records in self._examples().items():
            if method != "GET":
                continue
            for record in records:
                body = record.response
                if isinstance(body, dict) and str(body.get("id", "")) == str(record.principal):
                    endpoints.append((method, template, self._url(record.path)))
                    break
        return endpoints

    def _probe_write_authorization(self) -> list[Violation]:
        """L3 - can one principal write into another principal's object?"""
        violations: list[Violation] = []
        seen: set[tuple[str, str]] = set()
        examples = self._examples()
        for (method, template), records in examples.items():
            if method not in {"POST", "PUT", "PATCH"}:
                continue
            record = next((r for r in records if isinstance(r.body, dict)), None)
            if record is None:
                continue
            body = record.body
            for url, resource in self._candidate_urls(method, template, records):
                if resource is None or not resource.owner:
                    continue
                owner = resource.owner
                for attacker in self.target.principals:
                    if attacker.id == owner or not attacker.token:
                        continue
                    if not self._is_testable(attacker):
                        continue
                    if (attacker.id, resource.key) in seen:
                        continue
                    seen.add((attacker.id, resource.key))
                    before = len(self._ledger_events())
                    session = self.target.session_for(attacker)
                    response = session.request(method, url, json=body, timeout=self.target.timeout)
                    new_events = self._ledger_events()[before:]
                    tainted = [event for event in new_events if event.principal == attacker.id]
                    if not tainted:
                        continue
                    event = tainted[0]
                    # The row that was actually touched decides, not the row the
                    # URL was built from: `/users/me` resolves to whoever calls it.
                    owner = event.row_owner
                    if owner is None:
                        known = self.policy.resource(event.resource_key)
                        owner = known.owner if known else None
                    if owner is None or owner == attacker.id:
                        continue
                    self.observed.grant(attacker.id, event.resource_key, "write")
                    violations.append(
                        Violation(
                            law="L3",
                            title=f"{attacker.id} wrote into an object owned by {owner}",
                            detail=(
                                f"`{method} {url}` performed by `{attacker.id}` changed `{event.resource_key}`, which "
                                f"belongs to `{owner}`. The write landed in the database, it was not rejected."
                            ),
                            severity="high",
                            principal=attacker.id,
                            resource=event.resource_key,
                            action="write",
                            evidence={
                                "attacker_status": response.status_code,
                                "columns": sorted(event.columns),
                                "owner": owner,
                                "event": event.to_dict(),
                            },
                            steps=[
                                Step(
                                    method=method,
                                    url=url,
                                    headers={"Authorization": f"Bearer {attacker.token}"},
                                    body=body,
                                    status=response.status_code,
                                    note="cross-identity write",
                                )
                            ],
                        )
                    )
        return violations

    def _probe_authority_creation(self) -> list[Violation]:
        """L4 - can a caller mint authority for itself?"""
        violations: list[Violation] = []
        for principal in self.target.principals:
            if principal.is_privileged() or not self._is_testable(principal):
                continue
            for field_name in sorted(self._authority_fields()):
                for (method, template), records in self._examples().items():
                    if method not in {"POST", "PUT", "PATCH"}:
                        continue
                    record = next((r for r in records if isinstance(r.body, dict)), None)
                    if record is None:
                        continue
                    sentinel = _sentinel(field_name)
                    body = dict(record.body)
                    body[field_name] = sentinel
                    before = len(self.ledger.events)
                    url = self._url(record.path)
                    session = self.target.session_for(principal)
                    response = session.request(method, url, json=body, timeout=self.target.timeout)
                    new_events = self._ledger_events()[before:]
                    applied = [
                        event
                        for event in new_events
                        if event.principal == principal.id
                        and any(str(value) == str(sentinel) for value in event.columns.values())
                    ]
                    if not applied:
                        continue
                    event = applied[0]
                    violations.append(
                        Violation(
                            law="L4",
                            title=f"{principal.id} created authority by writing `{field_name}`",
                            detail=(
                                f"`{method} {url}` sent `{field_name}={sentinel!r}` and the server persisted it "
                                f"on `{event.resource_key}`. `{field_name}` carries authority and the caller is "
                                f"not privileged, so the request should have been rejected or the field ignored."
                            ),
                            severity="critical",
                            principal=principal.id,
                            resource=event.resource_key,
                            action="write",
                            evidence={
                                "field": field_name,
                                "sentinel": sentinel,
                                "status": response.status_code,
                                "event": event.to_dict(),
                            },
                            steps=[
                                Step(
                                    method=method,
                                    url=url,
                                    headers={"Authorization": f"Bearer {principal.token}"},
                                    body=body,
                                    status=response.status_code,
                                    note="authority creation attempt",
                                )
                            ],
                        )
                    )
                    break
        return violations

    def _probe_races(self) -> list[Violation]:
        """L5 / L6 - concurrent identical actions that must not both succeed."""
        violations: list[Violation] = []
        for (method, template), records in self._examples().items():
            if method != "POST":
                continue
            record = records[0]
            principal = self.target.principal(record.principal or "")
            if principal is None:
                continue
            url = self._url(record.path)
            if not (looks_single_use(url) or self._changes_state(record)):
                continue
            body = record.body if isinstance(record.body, dict) else None
            for candidate_url, _resource in self._candidate_urls(method, template, records):
                session = self.target.session_for(principal)
                before = list(self._ledger_events())

                def call() -> requests.Response:
                    return session.request(method, candidate_url, json=body, timeout=self.target.timeout)

                responses = run_concurrently([call, call])
                after = self._ledger_events()
                outcome = RaceOutcome(
                    url=candidate_url,
                    method=method,
                    statuses=[getattr(response, "status_code", None) for response in responses],
                    bodies=[_json(response) for response in responses if hasattr(response, "json")],
                )
                violation = detect_race(
                    outcome=outcome,
                    before=before,
                    after=after,
                    principal=principal.id,
                )
                if violation is None:
                    continue
                violation.steps = [
                    Step(
                        method=method,
                        url=candidate_url,
                        headers={"Authorization": f"Bearer {principal.token}"} if principal.token else {},
                        body=body,
                        status=outcome.statuses[0] if outcome.statuses else None,
                        note="first of two concurrent identical requests",
                    ),
                    Step(
                        method=method,
                        url=candidate_url,
                        headers={"Authorization": f"Bearer {principal.token}"} if principal.token else {},
                        body=body,
                        status=outcome.statuses[1] if len(outcome.statuses) > 1 else None,
                        note="second, concurrent - it should have been rejected",
                    ),
                ]
                violations.append(violation)
        return violations

    def _candidate_urls(
        self, method: str, template: str, records: list[TrafficRecord]
    ) -> list[tuple[str, Resource | None]]:
        """URLs to try for a template, with every known resource substituted in.

        ``/orders/{id}/approve`` becomes one candidate per known order, so the
        engine can find a resource that is still in a state where the action is
        supposed to be rejected the second time.
        """
        if "{id}" not in template:
            return [(self._url(record.path), record.resource) for record in records]
        prefix = template.split("{id}")[0].rstrip("/")
        type_hint = prefix.split("/")[-1] if prefix else None
        candidates: list[tuple[str, Resource | None]] = []
        for resource in self.policy.resources.values():
            if type_hint and resource.type != type_hint:
                continue
            candidates.append((self._url(template.replace("{id}", resource.id)), resource))
        return candidates

    # -- helpers ----------------------------------------------------------- #

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.target.base_url.rstrip("/") + "/" + path.lstrip("/")

    def _ledger_events(self) -> list[WriteEvent]:
        """Reload the ledger so probes see writes produced by the application."""
        if self.ledger_path is not None and self.ledger_path.exists():
            self.ledger = Ledger.load(self.ledger_path)
            return self.ledger.events
        return self.ledger.events

    def _changes_state(self, record: TrafficRecord) -> bool:
        body = record.body
        if not isinstance(body, dict):
            return False
        return any(key in body for key in ("status", "state", "approved", "used", "redeemed"))

    def _authority_fields(self) -> set[str]:
        """Fields that could carry authority, discovered from the spec and traffic."""
        fields: set[str] = set()
        for record in self.traffic:
            body = record.body
            if isinstance(body, dict):
                fields.update(key for key in body if is_authority_field(key))
        fields.update(self._spec_authority_fields())
        return fields

    def _spec_authority_fields(self) -> set[str]:
        """Read the OpenAPI document and list body properties that look like authority."""
        if self.spec_path is None or not self.spec_path.exists():
            return set()
        try:
            document = json.loads(self.spec_path.read_text(encoding="utf-8"))
        except Exception:
            return set()
        schemas = document.get("components", {}).get("schemas", {})
        found: set[str] = set()
        for path_item in document.get("paths", {}).values():
            for operation in path_item.values():
                if not isinstance(operation, dict):
                    continue
                body = operation.get("requestBody", {})
                for media in body.get("content", {}).values():
                    schema = media.get("schema", {})
                    for name in _schema_properties(schema, schemas):
                        if is_authority_field(name):
                            found.add(name)
        return found

    # -- reporting --------------------------------------------------------- #

    def report(self) -> dict[str, Any]:
        residual = self.observed.residual(self.permitted)
        return {
            "principals": {pid: p.roles for pid, p in self.policy.principals.items()},
            "resources": len(self.policy.resources),
            "rules": [rule.to_dict() for rule in self.policy.rules],
            "observed_cells": len(self.observed),
            "residual_cells": len(residual),
            "residual_norm": residual.norm(),
            "server_managed_fields": {k: sorted(v) for k, v in self.policy.server_managed_fields.items()},
        }

    def write_bundles(self, violations: Iterable[Violation], root: str | Path) -> list[Path]:
        directories = []
        residual = self.observed.residual(self.permitted)
        for violation in violations:
            patch = patch_render(violation)
            regression_test = regression_render(violation)
            directory = ProofBundle.create(
                root,
                violation,
                evidence=violation.evidence,
                matrix={
                    "observed": self.observed.to_dict(),
                    "permitted": self.permitted.to_dict(),
                    "residual": residual.to_dict(),
                },
                patch=patch,
                regression_test=regression_test,
            )
            directories.append(directory)
        return directories


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _json(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return getattr(response, "text", "")[:500]


def _dedupe(violations: list[Violation]) -> list[Violation]:
    """Drop duplicates: the same breach found by two different detectors."""
    seen: set[tuple[str, str | None, str | None]] = set()
    unique: list[Violation] = []
    for violation in violations:
        key = (violation.law, violation.principal, violation.resource)
        if key in seen:
            continue
        seen.add(key)
        unique.append(violation)
    return unique


def _truncate(value: Any, limit: int = 800) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "..."
    return value


def _sentinel(field_name: str) -> Any:
    return f"mizan-probe-{field_name}"


def _schema_properties(schema: dict[str, Any], schemas: dict[str, Any], depth: int = 0) -> list[str]:
    """Resolve local `$ref`s and collect the property names of an object schema."""
    if depth > 5 or not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return _schema_properties(schemas.get(name, {}), schemas, depth + 1)
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return list(properties)
    return []
