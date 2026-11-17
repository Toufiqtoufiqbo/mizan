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
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from mizan.core import (
    UNKNOWN_PRINCIPAL,
    AccessMatrix,
    AuthorizationOutcome,
    LawCoverage,
    Policy,
    Principal,
    RequestBudgetExhausted,
    Resource,
    Rule,
    ScanCoverage,
    Step,
    Violation,
    actions_for,
    is_authority_field,
)
from mizan.identity import decode_token
from mizan.ownership import (
    EvidenceState,
    Observation,
    OwnershipGraph,
    RelationshipContractError,
    RelationshipType,
    build_ownership_graph,
    parse_identity,
)
from mizan.patching import render as patch_render
from mizan.proof import ProofBundle
from mizan.races import RaceOutcome, detect_race, looks_single_use, run_concurrently
from mizan.regression import render_test as regression_render
from mizan.taint import Ledger, TaintAnalyzer, WriteEvent
from mizan.tokens import mask_authorization
from mizan.traffic import TrafficLog, TrafficRecord

# --------------------------------------------------------------------------- #
# Target description
# --------------------------------------------------------------------------- #


@dataclass
class Target:
    """Where to attack and with which identities."""

    base_url: str
    principals: list[Principal] = field(default_factory=list)
    timeout: float = 20.0

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
        spec_document: dict[str, Any] | None = None,
        twin: Any | None = None,
        attributor: Any | None = None,
        relationship_contract: Any | None = None,
        request_budget: int | None = None,
    ) -> None:
        self.target = target
        self.policy = policy or Policy()
        self.traffic_path = Path(traffic_path) if traffic_path else None
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self.spec_path = Path(spec_path) if spec_path else None
        #: The OpenAPI document itself.  A document that was fetched at runtime
        #: (a FastAPI application serves ``/openapi.json``) has no file, so the
        #: document is what the engine needs - the path is only a fallback.
        self.spec_document = spec_document
        #: An optional twin: a disposable copy of the application with a
        #: restorable state. Every probe starts from the same state.
        self.twin = twin
        #: An optional data-level attributor that derives writes from the
        #: database itself, so the application needs no instrumentation.
        self.attributor = attributor
        #: Phase V.1: trusted, explicit semantic declarations. Without one,
        #: structural evidence is never promoted to confirmed semantics.
        self.relationship_contract = relationship_contract
        self.traffic: TrafficLog = TrafficLog(self.traffic_path)
        self.ledger: Ledger = Ledger(self.ledger_path)
        self.observed = AccessMatrix()
        self.permitted = AccessMatrix()
        self.observed_principals: set[str] = set()
        self._attributed_events: list[WriteEvent] = []
        #: Phase V: the evidence-based ownership graph built by ``learn()``.
        self.graph: OwnershipGraph | None = None
        #: Checks that could not be completed, with the reason (never a clean result).
        self.inconclusive_checks: list[dict[str, str]] = []
        #: Every authorization check and how it ended - resolved grants and
        #: decided checks included. The basis of per-law coverage; never a
        #: request count and never a merged L2/L3 counter.
        self.outcomes: list[dict[str, str]] = []
        self._outcome_seen: set[tuple[str, str, str, str, str]] = set()
        self._inconclusive_seen: set[tuple[str, str, str, str]] = set()
        #: Eligible checks per law, computed before the probes run.
        self.eligible_by_law: dict[str, int] = {}
        #: How many requests the engine sent - the cost of a finding.
        self.requests = 0
        #: The number of requests the engine may send. ``None`` means no limit.
        self.request_budget = request_budget
        #: Whether the last attack stopped because the budget ran out.
        self.budget_exhausted = False
        #: How many eligible security checks the attack identified.
        self.probe_candidates = 0
        #: How many probe groups actually issued a check during the attack.
        self.probes_executed = 0

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
                known = policy.resources.get(resource.key)
                if known is None:
                    policy.resources[resource.key] = resource
                elif known.owner is None and resource.owner:
                    # The same object, seen with its owner this time.
                    policy.resources[resource.key] = resource
                if resource.owner:
                    owned_by_principal.setdefault(record.principal or "", set()).add(resource.key)
            if record.principal and resource is not None:
                accessed.setdefault((record.principal, resource.type, record.action), set()).add(resource.key)
                self.observed.grant(record.principal, resource.key, record.action)

        # Phase V: evidence-based ownership. Only a confirmed, unambiguous
        # relationship may add an owner; a contradiction removes the claim
        # instead of silently preferring whichever source arrived last.
        schema = (
            self.attributor.schema() if self.attributor is not None and hasattr(self.attributor, "schema") else None
        )
        db_rows: dict[str, list[dict[str, Any]]] = {}
        if schema is not None and hasattr(self.attributor, "rows"):
            db_rows = {name: self.attributor.rows(name) for name in schema.tables}
        # Phase V.2: an operator-supplied contract is configuration, not a hint.
        # It must describe this database, and a bad declaration stops the scan
        # instead of silently running with different semantics.
        if self.relationship_contract is not None:
            if schema is None or not schema.tables:
                raise RelationshipContractError(
                    "a relationship contract was supplied, but no database schema is available"
                )
            self.relationship_contract.validate_schema(schema)
        observations = self._identity_observations() if schema is not None else []
        self.graph = build_ownership_graph(
            resources=policy.resources,
            traffic=[*self.traffic.records, *observations],
            ledger=self.ledger.events,
            schema=schema,
            rows=db_rows,
            contract=self.relationship_contract,
        )
        for key, resource in list(policy.resources.items()):
            owner = self.graph.owner_of(key)
            if owner is None:
                if resource.owner and self.graph.owner_state(key) is EvidenceState.CONTRADICTED:
                    policy.resources[key] = replace(resource, owner=None)
                continue
            if resource.owner is None:
                policy.resources[key] = replace(resource, owner=owner)
            elif resource.owner != owner:
                policy.resources[key] = replace(resource, owner=None)

        # The probes iterate the traffic records, so their resource view must
        # carry the same confirmed owner as the policy.
        for record in self.traffic.records:
            if not record.resource_type or not record.resource_id:
                continue
            key = f"{record.resource_type}:{record.resource_id}"
            owner = self.graph.owner_of(key)
            if owner is not None:
                record.resource_owner = owner
            elif record.resource_owner and self.graph.owner_state(key) is EvidenceState.CONTRADICTED:
                record.resource_owner = None

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
                for principal_id, resource_type, action in accessed:
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
        self._normalize_templates()
        self.policy = policy
        return policy

    def _normalize_templates(self) -> None:
        """Collapse the paths that only differ by an identifier.

        A traffic log records concrete paths, so `/orders/o1` and `/orders/o2`
        look like two different operations. Once the resources are known, the
        identifiers can be put back, and the engine works with one template per
        operation instead of one per object.
        """
        identifiers = {resource.id for resource in self.policy.resources.values() if resource.id}
        identifiers |= {pid for pid in self.policy.principals}
        for record in self.traffic.records:
            record.template = _normalize_path(record.path, identifiers)

    # -- attacking --------------------------------------------------------- #

    def attack(self, *, groups: list[str] | None = None) -> list[Violation]:
        """Probe the learned policy and return the proven violations.

        The coverage counters are reset here, so they describe the attack that
        just ran. They are what a clean claim is made of: a probe that never
        had an eligible target proves nothing, and one that never ran proves
        even less.
        """
        violations: list[Violation] = []
        candidates = self._eligible_probe_targets()
        self.eligible_by_law = dict(candidates)
        self.probe_candidates = sum(candidates.values())
        self.probes_executed = 0
        self.inconclusive_checks = []
        self.outcomes = []
        self._outcome_seen = set()
        self._inconclusive_seen = set()
        # Unresolved ownership is not silence: record it as an inconclusive
        # security check before the probes run, so it is part of the same
        # per-law accounting as the outcomes the probes produce.
        self._record_unresolved_checks()
        for name, probe in self.probe_groups():
            if groups is not None and name not in groups:
                continue
            issued_before = self.requests
            try:
                violations.extend(probe())
            except RequestBudgetExhausted:
                # The budget is a limit, not a failure: stop cleanly - and say
                # so, because a truncated scan is not a complete one.
                self.budget_exhausted = True
                break
            if self.requests > issued_before:
                self.probes_executed += 1
        return _dedupe(violations)

    # -- relevance of unresolved ownership -------------------------------- #

    def _ownership_unresolved(self, resource_key: str) -> bool:
        """Whether a discovered resource lacks a unique confirmed owner.

        Candidate, unknown, ambiguous and contradicted ownership are all
        unresolved. Ledger-only scans (no graph) have no ownership evidence and
        therefore no relevance claim: they keep the historical behavior instead
        of inventing uncertainty for every resource.
        """
        if self.graph is None:
            return False
        return self.graph.owner_state(resource_key) is not EvidenceState.CONFIRMED or (
            self.graph.owner_of(resource_key) is None
        )

    def _ownership_relevant(self, resource_key: str, resource: Resource) -> bool:
        """Whether an unresolved resource belongs to the ownership-sensitive surface.

        A resource is relevant when it has a unique database row mapping, any
        ownership relationship evidence (even a candidate), an explicit
        ownership/sharing declaration for its type, or a recorded ownership
        mapping ambiguity. Health/login endpoints and static metadata have no
        resource record at all, so they never reach this predicate; a resource
        with no ownership signal of any kind is outside the model.
        """
        if self.graph is None:
            return False
        if resource_key in self.graph.resource_rows:
            return True
        if self.graph.owner_state(resource_key) is not EvidenceState.UNKNOWN:
            return True
        reason = self.graph.inconclusive.get(resource_key, "").lower()
        if "mapping" in reason or "ownership" in reason or "owner" in reason:
            return True
        contract = self.relationship_contract
        return contract is not None and (resource.type in contract.ownership or resource.type in contract.sharing)

    def _representative_principal(self, resource_key: str, observed: str | None) -> str | None:
        """A stable, non-privileged, testable identity for an unresolved check.

        The identity is derived from the resource and the configured identities
        only, so repeated traffic observations cannot create new checks.
        """
        candidates = sorted(
            principal.id for principal in self.target.principals if principal.token and self._is_testable(principal)
        )
        if not candidates:
            return None
        owner_hints = {
            relation.subject
            for relation in (self.graph.relationships if self.graph is not None else [])
            if relation.type is RelationshipType.OWNS and relation.object == resource_key
        }
        remaining = [pid for pid in candidates if pid not in owner_hints and pid != observed]
        if remaining:
            return remaining[0]
        remaining = [pid for pid in candidates if pid not in owner_hints]
        return remaining[0] if remaining else candidates[0]

    def _mapped_ledger_resource(self, event: Any) -> str | None:
        """Unique API resource for a ledger write, or ``None`` when unmapped."""
        if self.graph is None:
            return event.resource_key
        components = parse_identity(event.row_key) if event.row_key else None
        if components:
            return self.graph.row_to_resource(event.table, components)
        candidates = [
            resource
            for resource, (table, values) in self.graph.resource_rows.items()
            if table == event.table and values == (str(event.row_id),)
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _unresolved_checks(self) -> list[tuple[str, str, str, str, str]]:
        """Relevant ownership checks that the probes cannot resolve.

        Returns ``(law, action, resource, principal, reason)`` tuples, one per
        stable check identity. They are counted as eligible, attempted and
        inconclusive: an unresolved fact is never a finding and never a
        successful check.
        """
        if self.graph is None:
            return []
        found: dict[tuple[str, str, str, str], str] = {}
        for (method, _template), records in self._examples().items():
            action = actions_for(method)
            if action == "read":
                law = "L2"
            elif action == "write":
                law = "L3"
            else:
                continue
            for record in records:
                if not (200 <= record.status < 400):
                    continue
                resource = record.resource
                if resource is None:
                    continue
                key = resource.key
                if not self._ownership_unresolved(key) or not self._ownership_relevant(key, resource):
                    continue
                principal = self._representative_principal(key, record.principal)
                if principal is None:
                    continue
                reason = self.graph.inconclusive.get(key) or (
                    f"ownership is {self.graph.owner_state(key).value}; a confirmed owner is required"
                )
                found.setdefault((law, action, key, principal), reason)

        # A write whose database row cannot be mapped to an API resource is a
        # relevant unresolved L3 check too. The ledger analyzer records it with
        # the raw event resource key, so the same identity must be eligible.
        observed_write_tables = {
            record.resource.type
            for (method, _template), records in self._examples().items()
            if method in {"POST", "PUT", "PATCH"}
            for record in records
            if 200 <= record.status < 400 and record.resource is not None
        }
        for event in self._ledger_events():
            if event.action != "write" or event.table not in observed_write_tables:
                continue
            if self._mapped_ledger_resource(event) is not None:
                continue
            principal = (
                event.principal
                if self.target.principal(event.principal)
                else self._representative_principal(event.resource_key, event.principal)
            )
            if principal is None:
                continue
            found.setdefault(
                ("L3", "write", event.resource_key, principal),
                "the changed database row does not map uniquely to an API resource",
            )
        return [(*identity, found[identity]) for identity in sorted(found)]

    def _record_unresolved_checks(self) -> None:
        """Expose relevant unresolved checks as inconclusive security checks."""
        for law, action, resource, principal, reason in self._unresolved_checks():
            self._inconclusive(law, resource, reason, action=action, principal=principal)

    def _eligible_probe_targets(self) -> dict[str, int]:
        """How many checks each probe could legitimately run, before it runs.

        This mirrors the guards the probes themselves apply, counted rather
        than sent. It answers the question a clean claim has to answer: was
        there anything worth probing at all?

        The count is deliberately conservative in one direction only - a check
        that could not have happened is not counted. Counting something that
        cannot happen would make a scan look better than it was; not counting
        something that could have happened only makes the scan more cautious,
        and a finding overrides the verdict anyway.
        """
        examples = self._examples()
        attackers = [p for p in self.target.principals if self._is_testable(p)]

        owned = {
            resource.key for record in self.traffic if (resource := record.resource) is not None and resource.owner
        }

        counts: dict[str, int] = {}

        # L5 / L6 - a mutating operation on an object somebody owns.
        counts["L5"] = sum(
            1
            for (method, _template), records in examples.items()
            if method in {"POST", "PUT", "PATCH", "DELETE"}
            and any(record.resource is not None and record.resource.key in owned for record in records)
        )

        # L1 - an identity endpoint per testable principal.
        counts["L1"] = len(self._identity_endpoints()) * len(attackers)

        # L2/L3 - one check per stable (law, action, resource, principal)
        # identity. The set is what makes duplicate traffic observations collapse
        # into a single denominator entry. Ownership-unresolved resources that
        # are relevant to an observed read/write are eligible too: a missing
        # owner is not evidence that the operation was safe.
        l2_checks: set[tuple[str, str, str, str]] = set()
        l3_checks: set[tuple[str, str, str, str]] = set()
        for (method, _template), records in examples.items():
            if method in {"GET", "HEAD"}:
                for record in records:
                    resource = record.resource
                    if resource is None or not resource.owner:
                        continue
                    for attacker in attackers:
                        if attacker.id != resource.owner and attacker.token:
                            l2_checks.add(("L2", "read", resource.key, attacker.id))
            elif method in {"POST", "PUT", "PATCH"} and any(isinstance(record.body, dict) for record in records):
                for _url, resource in self._candidate_urls(method, _template, records):
                    if resource is None or not resource.owner:
                        continue
                    for attacker in attackers:
                        if attacker.id == resource.owner or not attacker.token:
                            continue
                        l3_checks.add(("L3", "write", resource.key, attacker.id))
        for law, action, resource, principal, _reason in self._unresolved_checks():
            (l2_checks if law == "L2" else l3_checks).add((law, action, resource, principal))
        counts["L2"] = len(l2_checks)
        counts["L3"] = len(l3_checks)

        # L4 - an authority-carrying field to try writing.
        fields = sorted(self._authority_fields())
        counts["L4"] = len(fields) * len(attackers) if fields else 0

        # T - the data-level view needs attributed writes to compare.
        counts["T"] = 1 if self._ledger_events() or owned else 0

        return counts

    # -- check recording --------------------------------------------------- #

    def _outcome(self, law: str, action: str, resource: str, principal: str, outcome: AuthorizationOutcome) -> None:
        """Record one check result, deduplicated by its full identity."""
        key = (law, action, str(resource), principal, outcome.value)
        if key in self._outcome_seen:
            return
        self._outcome_seen.add(key)
        self.outcomes.append(
            {
                "law": law,
                "action": action,
                "resource": str(resource),
                "principal": principal,
                "outcome": outcome.value,
            }
        )

    def _merge_outcomes(self, outcomes: Iterable[dict[str, str]]) -> None:
        """Fold the data-level analyzer's outcomes into engine accounting."""
        for item in outcomes:
            try:
                outcome = AuthorizationOutcome(str(item["outcome"]))
            except ValueError:
                continue
            self._outcome(
                str(item.get("law", "L3")),
                str(item.get("action", "write")),
                str(item.get("resource", "")),
                str(item.get("principal", "")),
                outcome,
            )

    def _inconclusive(
        self,
        law: str,
        resource: str,
        reason: str,
        *,
        action: str | None = None,
        principal: str = "",
    ) -> None:
        """Record an unresolved check once, and count it as unresolved."""
        key = (law, str(resource), reason, principal)
        if key not in self._inconclusive_seen:
            self._inconclusive_seen.add(key)
            self.inconclusive_checks.append(
                {
                    "law": law,
                    "resource": str(resource),
                    "reason": reason,
                    "action": action or ("read" if law == "L2" else "write"),
                    "principal": principal,
                }
            )
        self._outcome(
            law,
            action or ("read" if law == "L2" else "write"),
            resource,
            principal,
            AuthorizationOutcome.INCONCLUSIVE,
        )

    def probe_names(self) -> list[str]:
        """The names of the probes, in the order they run."""
        return [name for name, _probe in self.probe_groups()]

    def coverage(self) -> ScanCoverage:
        """What the last attack actually looked at.

        The counters are deliberately about *coverage*, not about traffic: a
        login request, a health request and an unsuccessful learning request all
        produce traffic while proving nothing. A clean claim has to be made of
        checks that existed and checks that ran.
        """
        resources = list(self.policy.resources.values())
        owned = [resource for resource in resources if resource.owner]
        # A resource counts as usable when somebody other than its owner can act
        # on it - otherwise there is no cross-identity check to perform.
        testable = {principal.id for principal in self.target.principals if self._is_testable(principal)}
        usable = [resource for resource in owned if testable - {resource.owner}]
        corroborated = sum(
            1
            for relation in (self.graph.relationships if self.graph else [])
            if relation.type is RelationshipType.OWNS and len(relation.evidence) > 1
        )
        report = self.graph.report() if self.graph is not None else {}
        reasons = list((self.graph.inconclusive if self.graph else {}).items())
        # L2 and L3 are accounted separately. A completed read check is never
        # allowed to stand in for an unresolved write check (or vice versa).
        laws: dict[str, LawCoverage] = {}
        for law in ScanCoverage.required_laws:
            records = [item for item in self.outcomes if item.get("law") == law]
            eligible = self.eligible_by_law.get(law, 0)
            if not eligible and not records:
                continue
            # Every recorded outcome is, by definition, an eligible check that
            # actually ran. Ledger writes discovered only while the probes run
            # (for example a row created by a POST) may not have been in the
            # pre-computed target list; include them in the denominator so the
            # counters stay internally consistent.
            counter = LawCoverage(eligible=max(eligible, len(records)), attempted=len(records))
            for item in records:
                value = item.get("outcome")
                if value == AuthorizationOutcome.DECIDED.value:
                    counter.decided += 1
                elif value == AuthorizationOutcome.ALLOWED_BY_GRANT.value:
                    counter.allowed_by_grant += 1
                elif value == AuthorizationOutcome.VIOLATION.value:
                    counter.findings += 1
                elif value == AuthorizationOutcome.INCONCLUSIVE.value:
                    counter.inconclusive += 1
            laws[law] = counter
        return ScanCoverage(
            resources_discovered=len(resources),
            resources_owned=len(usable),
            probe_candidates=self.probe_candidates,
            probes_executed=self.probes_executed,
            budget_exhausted=self.budget_exhausted,
            resources_with_ownership_evidence=report.get("confirmed_ownership_edges", 0),
            resources_corroborated=corroborated,
            ownership_candidates=report.get("candidate_ownership_edges", 0),
            ownership_ambiguous=report.get("ambiguous_relationships", 0) + report.get("contradicted_relationships", 0),
            sharing_explained=sum(law.allowed_by_grant for law in laws.values()),
            inconclusive_checks=len(self.inconclusive_checks),
            identity_anchors_unresolved=sum(1 for key, _ in reasons if key.startswith("identity:")),
            ownership_semantics_missing=sum(
                1
                for key, reason in reasons
                if not key.startswith(("identity:", "sharing:")) and "ownership" in reason.lower()
            ),
            resource_row_mapping_ambiguous=sum(1 for _, reason in reasons if "mapping" in reason.lower()),
            sharing_semantics_ambiguous=sum(1 for key, _ in reasons if key.startswith("sharing:")),
            laws=laws,
        )

    def attack_groups(self, groups: list[str]) -> list[Violation]:
        """Run only the named probes."""
        return self.attack(groups=groups)

    def probe_groups(self) -> list[tuple[str, Any]]:
        """The probes of the engine.

        Races run first: every other probe mutates state, and a probe that
        changes the state of a resource would hide a race on it. (With a local
        twin each probe gets a fresh snapshot instead.)
        """
        return [
            ("L5", self._probe_races),
            ("L1", self._probe_identity_coherence),
            ("L2", self._probe_read_authorization),
            ("L3", self._probe_write_authorization),
            ("L4", self._probe_authority_creation),
            ("T", self._probe_data_view),
        ]

    def _data_view_graph(self) -> OwnershipGraph | None:
        """The graph the data-level analyzer may use.

        Mapping a written database row to an API resource requires a database
        schema. In a ledger-only deployment there is nothing to map, so every
        write would become an inconclusive check and a real cross-identity
        write would be lost. That deployment keeps the historical,
        policy-level behaviour; a database-backed scan is graph-backed.
        """
        return self.graph if self.attributor is not None else None

    def _probe_data_view(self) -> list[Violation]:
        """The data-level view: what the ledger says about the writes.

        When the engine has an ownership graph the analyzer shares it, so the
        write probes and the data view apply one standard of evidence. The
        analyzer's own uncertainty is reported with the engine's.
        """
        analyzer = TaintAnalyzer(self.policy, graph=self._data_view_graph())
        violations = analyzer.analyze(self._ledger_events())
        for item in analyzer.inconclusive:
            self._inconclusive(
                str(item.get("law", "L3")),
                str(item.get("resource", "")),
                str(item.get("reason", "")),
                action=str(item.get("action", "write")),
                principal=str(item.get("principal", "")),
            )
        self._merge_outcomes(analyzer.outcomes)
        return violations

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
        self._restore()
        examples = self._examples()
        for (method, template), records in examples.items():
            if method not in {"GET", "HEAD"}:
                continue
            for record in records:
                resource = record.resource
                if resource is None or not resource.owner:
                    continue
                owner = resource.owner
                owner_principal = self.target.principal(owner)
                if owner_principal is None or not owner_principal.token:
                    self._inconclusive("L2", resource.key, "owner has no testable identity", principal=owner)
                    continue
                # Control: the alleged owner must actually be able to read the
                # exact object. Without it the accusation is unverified.
                control = self._request(
                    self.target.session_for(owner_principal),
                    READ_METHOD,
                    self._url(record.path),
                    timeout=self.target.timeout,
                )
                control_body = _json(control)
                if not (200 <= control.status_code < 300) or not contains_object(control_body, resource.id):
                    self._inconclusive("L2", resource.key, "owner control could not read the object", principal=owner)
                    continue
                ownership_evidence = (
                    sorted(
                        {
                            evidence
                            for relation in self.graph.relationships
                            if relation.type is RelationshipType.OWNS and relation.object == resource.key
                            for evidence in relation.evidence
                        }
                    )
                    if self.graph is not None
                    else []
                )
                for attacker in self.target.principals:
                    if attacker.id == owner:
                        continue
                    if not attacker.token or not self._is_testable(attacker):
                        continue
                    url = self._url(record.path)
                    session = self.target.session_for(attacker)
                    # The read probe always sends a GET, whatever the traffic
                    # contained: the evidence must name the method that was
                    # transmitted.
                    response = self._request(session, READ_METHOD, url, timeout=self.target.timeout)
                    if not (200 <= response.status_code < 300):
                        # The application refused the read: a decided check.
                        self._outcome("L2", "read", resource.key, attacker.id, AuthorizationOutcome.DECIDED)
                        continue
                    body = _json(response)
                    if not contains_object(body, resource.id):
                        # The request was accepted, but the object was not
                        # returned: nothing was disclosed.
                        self._outcome("L2", "read", resource.key, attacker.id, AuthorizationOutcome.DECIDED)
                        continue
                    returned_owner = None
                    if isinstance(body, dict):
                        for key in ("owner_id", "user_id", "owner"):
                            if isinstance(body.get(key), (str, int)):
                                returned_owner = str(body[key])
                                break
                    if returned_owner is not None and returned_owner == attacker.id:
                        self._outcome("L2", "read", resource.key, attacker.id, AuthorizationOutcome.DECIDED)
                        continue
                    if self.graph is not None and self.graph.explained_by_sharing(
                        owner, attacker.id, resource.key, "read"
                    ):
                        # A confirmed READ grant resolves this L2 check. It is
                        # evidence, not uncertainty, and it does not authorize
                        # a write on the same resource.
                        self._outcome("L2", "read", resource.key, attacker.id, AuthorizationOutcome.ALLOWED_BY_GRANT)
                        continue
                    self._outcome("L2", "read", resource.key, attacker.id, AuthorizationOutcome.VIOLATION)
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
                                "owner_control_status": control.status_code,
                                "ownership_evidence": ownership_evidence,
                            },
                            steps=[
                                Step(
                                    method=READ_METHOD,
                                    url=url,
                                    headers=mask_authorization(
                                        {"Authorization": f"Bearer {attacker.token}"}, attacker.id
                                    ),
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
        self._restore()
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
                response = self._request(session, method, url, timeout=self.target.timeout)
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
                                headers=mask_authorization(
                                    {"Authorization": f"Bearer {principal.token}"}, principal.id
                                ),
                                status=response.status_code,
                                note="the token claimed one identity, the server acted as another",
                            )
                        ],
                    )
                )
        return violations

    def _identity_paths(self) -> set[str]:
        """The paths that answer "who am I?", learned from the traffic."""
        paths: set[str] = set()
        for (method, template), records in self._examples().items():
            if method != "GET":
                continue
            for record in records:
                body = record.response
                if isinstance(body, dict) and str(body.get("id", "")) == str(record.principal):
                    paths.add(record.path)
        return paths

    def _is_identity_path(self, path: str) -> bool:
        """Whether this request asked for the caller's own identity."""
        if not hasattr(self, "_identity_path_cache"):
            self._identity_path_cache = self._identity_paths()
        cache: set[str] = self._identity_path_cache
        if path in cache:
            return True
        # The same endpoint with a different identifier is still the identity
        # endpoint when the template has no placeholder.
        for known in cache:
            if "{" not in known and known == path:
                return True
        return False

    def _identity_observations(self) -> list[Observation]:
        """Replay the contract-declared identity endpoint for each principal.

        A response that merely contains a database value is *not* identity
        evidence: it may be a document, an assignment or a task. Only the
        application's explicit declaration makes an endpoint an identity
        source, and no endpoint name is assumed here.
        """
        contract = self.relationship_contract
        if contract is None or contract.identity is None:
            return []
        endpoint, _field = contract.identity
        observations: list[Observation] = []
        for principal in self.target.principals:
            if not principal.token or not self._is_testable(principal):
                continue
            response = self._request(
                self.target.session_for(principal), READ_METHOD, self._url(endpoint), timeout=self.target.timeout
            )
            body = _json(response)
            if isinstance(body, dict):
                observations.append(Observation(principal.id, body, path=endpoint))
        return observations

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
        self._restore()
        seen: set[tuple[str, str, str]] = set()
        examples = self._examples()
        for (method, template), records in examples.items():
            if method not in {"POST", "PUT", "PATCH"}:
                continue
            record = next((r for r in records if isinstance(r.body, dict)), None)
            if record is None:
                continue
            body = record.body
            working = self._primary_record(records)
            if working is not record:
                record = working
                body = record.body if isinstance(record.body, dict) else body
            for url, resource in self._candidate_urls(method, template, records):
                if resource is None or not resource.owner:
                    continue
                owner = resource.owner
                for attacker in self.target.principals:
                    if attacker.id == owner or not attacker.token:
                        continue
                    if not self._is_testable(attacker):
                        continue
                    candidate = (attacker.id, resource.key, method)
                    if candidate in seen:
                        continue
                    seen.add(candidate)
                    # The body is perturbed on purpose: replaying the recorded
                    # values would change nothing, and a write that changes
                    # nothing is invisible in the data.
                    probe_body = _perturb(body)
                    before = len(self._ledger_events())
                    session = self.target.session_for(attacker)
                    response = self._request(session, method, url, json=probe_body, timeout=self.target.timeout)
                    new_events = self._ledger_events()[before:]
                    tainted = [event for event in new_events if event.principal == attacker.id]
                    if not tainted:
                        # No row changed: the application refused the write.
                        # This is a decided check, not an unresolved one.
                        self._outcome("L3", "write", resource.key, attacker.id, AuthorizationOutcome.DECIDED)
                        continue
                    event = tainted[0]
                    # The write event's database identity is mapped to an API
                    # resource explicitly. Naming coincidence is never enough.
                    row_components = parse_identity(event.row_key) if event.row_key else None
                    mapped_resource = (
                        self.graph.row_to_resource(event.table, row_components)
                        if self.graph is not None and row_components
                        else None
                    )
                    if mapped_resource is None and self.graph is not None and not event.row_key:
                        # Legacy ledger: no declared row identity. Accept only
                        # a unique, unambiguous single-column mapping.
                        candidates = [
                            resource
                            for resource, (table, values) in self.graph.resource_rows.items()
                            if table == event.table and values == (str(event.row_id),)
                        ]
                        if len(candidates) == 1:
                            mapped_resource = candidates[0]
                    if mapped_resource is None:
                        self._inconclusive(
                            "L3",
                            event.resource_key,
                            "the changed database row does not map uniquely to an API resource",
                            action=event.action,
                            principal=attacker.id,
                        )
                        continue
                    row_key = mapped_resource
                    if self.graph is not None:
                        # Graph-backed mode: the graph is the only ownership
                        # source. A legacy row_owner hint never decides here.
                        state = self.graph.owner_state(row_key)
                        if state is not EvidenceState.CONFIRMED:
                            self._inconclusive(
                                "L3",
                                row_key,
                                f"ownership is {state.value}",
                                action=event.action,
                                principal=attacker.id,
                            )
                            continue
                        owner = self.graph.owner_of(row_key)
                        if owner is None:
                            self._inconclusive(
                                "L3",
                                row_key,
                                "ownership is CONFIRMED but not unique",
                                action=event.action,
                                principal=attacker.id,
                            )
                            continue
                    else:
                        owner = event.row_owner
                        if owner is None:
                            known = self.policy.resource(row_key) or self.policy.resource(event.resource_key)
                            owner = known.owner if known else None
                    if owner is None:
                        self._inconclusive(
                            "L3",
                            row_key,
                            "the write owner cannot be established",
                            action=event.action,
                            principal=attacker.id,
                        )
                        continue
                    if owner == attacker.id:
                        self._outcome("L3", event.action, row_key, attacker.id, AuthorizationOutcome.DECIDED)
                        continue
                    if self.graph is not None and self.graph.explained_by_sharing(
                        owner, attacker.id, row_key, event.action
                    ):
                        # A confirmed WRITE grant resolves this L3 check. A
                        # read-only grant never reaches this branch.
                        self._outcome("L3", event.action, row_key, attacker.id, AuthorizationOutcome.ALLOWED_BY_GRANT)
                        continue
                    self._outcome("L3", event.action, row_key, attacker.id, AuthorizationOutcome.VIOLATION)
                    # The reported resource key stays compatible with the
                    # ledger/proof conventions so the data-level view of the
                    # same row deduplicates with this finding. The real PK
                    # (``row_key``) is used above for graph resolution.
                    self.observed.grant(attacker.id, event.resource_key, "write")
                    ownership_evidence = (
                        sorted(
                            {
                                evidence
                                for relation in self.graph.relationships
                                if relation.type is RelationshipType.OWNS
                                and relation.object in {row_key, event.resource_key}
                                for evidence in relation.evidence
                            }
                        )
                        if self.graph is not None
                        else []
                    )
                    violations.append(
                        Violation(
                            law="L3",
                            title=f"{attacker.id} wrote into an object owned by {owner}",
                            detail=(
                                f"`{method} {url}` performed by `{attacker.id}` changed `{row_key}`, which "
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
                                "ownership_evidence": ownership_evidence,
                                "resource_mapping": {
                                    "database_table": event.table,
                                    "database_key": event.row_key or event.row_id,
                                    "api_resource": mapped_resource,
                                },
                            },
                            steps=[
                                Step(
                                    method=method,
                                    url=url,
                                    headers=mask_authorization(
                                        {"Authorization": f"Bearer {attacker.token}"}, attacker.id
                                    ),
                                    body=probe_body,
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
        self._restore()
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
                    before = len(self._ledger_events())
                    url = self._url(record.path)
                    session = self.target.session_for(principal)
                    response = self._request(session, method, url, json=body, timeout=self.target.timeout)
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
                                    headers=mask_authorization(
                                        {"Authorization": f"Bearer {principal.token}"}, principal.id
                                    ),
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
        self._restore()
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
                    return self._request(session, method, candidate_url, json=body, timeout=self.target.timeout)

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
                        headers=mask_authorization({"Authorization": f"Bearer {principal.token}"}, principal.id)
                        if principal.token
                        else {},
                        body=body,
                        status=outcome.statuses[0] if outcome.statuses else None,
                        note="first of two concurrent identical requests",
                    ),
                    Step(
                        method=method,
                        url=candidate_url,
                        headers=mask_authorization({"Authorization": f"Bearer {principal.token}"}, principal.id)
                        if principal.token
                        else {},
                        body=body,
                        status=outcome.statuses[1] if len(outcome.statuses) > 1 else None,
                        note="second, concurrent - it should have been rejected",
                    ),
                ]
                violations.append(violation)
        return violations

    def _primary_record(self, records: list[TrafficRecord]) -> TrafficRecord:
        """The record that worked.

        A traffic log starts with guesses - a path parameter that did not
        exist, an identifier nobody knew yet. Probing those teaches nothing, so
        the first successful request is the one to build on.
        """
        for record in records:
            if 200 <= record.status < 300:
                return record
        return records[0]

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

    def evaluate_action(
        self, principal_id: str, method: str, path: str, body: Any = None
    ) -> tuple[Any, list[Violation], list[str]]:
        """Send one request and measure what it breaks.

        Returns the response, the violations it caused and the identifiers it
        revealed. The guided search uses this as its evaluation function.
        """
        principal = self.target.principal(principal_id)
        if principal is None or not principal.token:
            return None, [], []
        session = self.target.session_for(principal)
        url = self._url(path)
        before = len(self._ledger_events())
        if method.upper() in {"GET", "HEAD", "DELETE"}:
            response = self._request(session, method.upper(), url, timeout=self.target.timeout)
        else:
            response = self._request(
                session, method.upper(), url, json=body if body is not None else {}, timeout=self.target.timeout
            )
        new_events = self._ledger_events()[before:]

        violations: list[Violation] = []
        payload = _json(response)
        is_read = method.upper() in {"GET", "HEAD"}
        if (
            is_read
            and isinstance(payload, dict)
            and 200 <= response.status_code < 300
            and not self._is_identity_path(path)
        ):
            owner = None
            for key in ("owner_id", "user_id", "owner"):
                if isinstance(payload.get(key), (str, int)):
                    owner = str(payload[key])
                    break
            if owner is not None and owner != principal_id:
                violations.append(
                    Violation(
                        law="L2",
                        title=f"{principal_id} received an object owned by {owner}",
                        detail=(
                            f"`{method.upper()} {url}` answered with an object owned by `{owner}` while the "
                            f"request was authenticated as `{principal_id}`."
                        ),
                        severity="high",
                        principal=principal_id,
                        resource=None,
                        action="read",
                        evidence={"status": response.status_code, "object": _truncate(payload)},
                        steps=[
                            Step(
                                method=method.upper(),
                                url=url,
                                headers=mask_authorization(
                                    {"Authorization": f"Bearer {principal.token}"}, principal.id
                                ),
                                status=response.status_code,
                                note="the request that crossed the ownership boundary",
                            )
                        ],
                    )
                )
        data_analyzer = TaintAnalyzer(self.policy, graph=self._data_view_graph())
        violations.extend(data_analyzer.analyze(new_events))
        for item in data_analyzer.inconclusive:
            self._inconclusive(
                str(item.get("law", "L3")),
                str(item.get("resource", "")),
                str(item.get("reason", "")),
                action=str(item.get("action", "write")),
                principal=str(item.get("principal", "")),
            )
        self._merge_outcomes(data_analyzer.outcomes)

        # L1 - did the server act as the identity the token claims?
        claims = decode_token(principal.token) if principal.token else None
        if claims is not None and claims.subject and isinstance(payload, dict) and self._is_identity_path(path):
            acted_as = payload.get("id")
            if isinstance(acted_as, (str, int)) and str(acted_as) != claims.subject:
                violations.append(
                    Violation(
                        law="L1",
                        title=f"the token claims to be {claims.subject}, the server acted as {acted_as}",
                        detail=(
                            f"`{method.upper()} {url}` was authenticated with a token whose subject is "
                            f"`{claims.subject}`, but the response describes `{acted_as}`."
                        ),
                        severity="critical",
                        principal=principal_id,
                        resource=None,
                        action="authenticate",
                        evidence={"token_subject": claims.subject, "acted_as": str(acted_as)},
                        steps=[
                            Step(
                                method=method.upper(),
                                url=url,
                                headers=mask_authorization(
                                    {"Authorization": f"Bearer {principal.token}"}, principal.id
                                ),
                                status=response.status_code,
                                note="the token claimed one identity, the server acted as another",
                            )
                        ],
                    )
                )
        return response, violations, _identifiers_in(payload)

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.target.base_url.rstrip("/") + "/" + path.lstrip("/")

    def _restore(self) -> None:
        """Bring the application back to the state it had before the probes."""
        if self.twin is not None:
            self.twin.restore()

    def _principal_of(self, session: requests.Session) -> str:
        """The identity of the request the session makes.

        The engine holds the tokens, so it knows who they belong to - even when
        the token itself says nothing (an opaque token). Only when nothing is
        known is the identity unknown.
        """
        header = session.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[len("Bearer ") :].strip()
            for principal in self.target.principals:
                if principal.token == token:
                    return principal.id
            claims = decode_token(token)
            if claims and claims.subject:
                return claims.subject
        return UNKNOWN_PRINCIPAL

    def _request(self, session: requests.Session, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Send a request and attribute what it changed.

        With an attributor attached, the database is compared before and after
        the request, and the difference becomes a write event. The application
        needs no instrumentation for this.
        """
        before = self.attributor.snapshot() if self.attributor is not None else None
        if self.request_budget is not None and self.requests >= self.request_budget:
            raise RequestBudgetExhausted(f"the scan reached its budget of {self.request_budget} requests")
        self.requests += 1
        response = session.request(method, url, **kwargs)
        if before is not None:
            payload = kwargs.get("json")
            source_fields = set(payload) if isinstance(payload, dict) else set()
            events = self.attributor.diff(
                before,
                principal=self._principal_of(session),
                method=method,
                path=urlsplit(url).path,
                source_fields=source_fields,
            )
            self._attributed_events.extend(events)
        return response

    def _ledger_events(self) -> list[WriteEvent]:
        """The write events the engine knows about.

        When an attributor is attached, the database is the source of truth and
        the ledger file is ignored - otherwise every write would be counted
        twice.
        """
        if self.attributor is not None:
            return list(self._attributed_events)
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
        document = self.spec_document
        if document is None:
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
            "ownership": self.graph.report() if self.graph is not None else {},
            "inconclusive_checks": list(self.inconclusive_checks),
            "authorization_outcomes": list(self.outcomes),
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


#: The method the read probe sends. The evidence must always match it.
READ_METHOD = "GET"


def contains_object(payload: Any, resource_id: str | None) -> bool:
    """Whether a response body actually contains the given object.

    A `200` with an empty list is not a disclosure: the object was not
    returned. Without this check every successful request would look like a
    cross-identity read.

    The identifier is matched by *value*, not by a field called ``id``: an
    application is free to call its public identifier ``document_key``.
    """
    if resource_id is None:
        return False
    target = str(resource_id)

    def search(value: Any, depth: int) -> bool:
        if depth > 4:
            return False
        if isinstance(value, dict):
            return any(search(item, depth + 1) for item in value.values())
        if isinstance(value, (list, tuple)):
            return any(search(item, depth + 1) for item in value[:50])
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return str(value) == target
        return False

    return search(payload, 0)


def _normalize_path(path: str, identifiers: set[str]) -> str:
    """Replace the known identifiers in a path with a placeholder."""
    parts = path.split("/")
    return "/".join("{id}" if part in identifiers else part for part in parts)


def _identifiers_in(payload: Any, depth: int = 0) -> list[str]:
    """Identifiers found in a response body."""
    if depth > 4:
        return []
    found: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in {"id", "order_id", "user_id", "uuid"} and isinstance(value, (str, int)):
                found.append(str(value))
            else:
                found.extend(_identifiers_in(value, depth + 1))
    elif isinstance(payload, list):
        for item in payload[:20]:
            found.extend(_identifiers_in(item, depth + 1))
    return found


def _perturb(body: Any) -> Any:
    """Change the values of a request body, so the write becomes visible."""
    if not isinstance(body, dict):
        return body
    perturbed: dict[str, Any] = {}
    for key, value in body.items():
        if isinstance(value, str):
            perturbed[key] = f"mizan-probe-{key}"
        elif isinstance(value, bool):
            perturbed[key] = not value
        elif isinstance(value, int):
            perturbed[key] = value + 1
        elif isinstance(value, float):
            perturbed[key] = value + 1.0
        else:
            perturbed[key] = value
    return perturbed


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
