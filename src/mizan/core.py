"""Core data model: principals, resources, access, laws, policy and the access matrix.

The whole engine revolves around one idea: an application has *laws* (security
invariants) that can be learned from its own normal behaviour, and every violation
of those laws is a reportable, reproducible finding.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

# --------------------------------------------------------------------------- #
# Laws
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Law:
    id: str
    name: str
    severity: str
    description: str


LAWS: dict[str, Law] = {
    law.id: law
    for law in (
        Law(
            "L1",
            "Authentication coherence",
            "high",
            "The identity used to serve a request is the one the client presented.",
        ),
        Law(
            "L2",
            "Read authorization (read-taint)",
            "high",
            "An object returned to a caller must belong to that caller or be visible to their role.",
        ),
        Law(
            "L3",
            "Write authorization (write-taint)",
            "high",
            "Every database write must be attributable to a principal and permitted for that exact row.",
        ),
        Law(
            "L4",
            "No authority creation",
            "critical",
            "A request must never change the authority of its sender or of anybody else.",
        ),
        Law(
            "L5",
            "Atomicity (TOCTOU)",
            "high",
            "A check followed by an action must be atomic; concurrent identical actions must not both succeed.",
        ),
        Law(
            "L6", "Cardinality and bounds", "medium", "Counters are bounded and single-use resources are not reusable."
        ),
        Law(
            "L7",
            "Path confidentiality",
            "medium",
            "No field may leave the system outside the caller's authority, including through caches and queues.",
        ),
    )
}

#: Field names that carry *authority*. A non-privileged caller must never be able
#: to set them. Matched case-insensitively as a whole word.
#:
#: Business data (prices, balances, amounts) is deliberately *not* here: those
#: fields are data, not authority, and treating them as authority produces
#: false positives on every ordinary update.
AUTHORITY_FIELDS: frozenset[str] = frozenset(
    {
        "role",
        "roles",
        "is_admin",
        "admin",
        "is_superuser",
        "superuser",
        "permissions",
        "scopes",
        "owner_id",
        "owner",
        "tenant_id",
        "tenant",
        "is_verified",
        "verified",
        "email_verified",
        "is_active",
        "disabled",
        "limit",
        "quota",
    }
)

#: Operations whose semantics are naturally single-use. Used to decide when a
#: successful race is a real violation instead of an idempotent no-op.
SINGLE_USE_HINTS: tuple[str, ...] = (
    "approve",
    "redeem",
    "claim",
    "consume",
    "apply",
    "activate",
    "verify",
    "coupon",
    "discount",
    "promo",
    "voucher",
    "checkout",
    "pay",
    "confirm",
    "submit",
    "use",
)


# --------------------------------------------------------------------------- #
# Actors and data
# --------------------------------------------------------------------------- #


class RequestBudgetExhausted(RuntimeError):
    """The scan reached the number of requests it was allowed to send."""


#: The principal used when the identity of a write is missing or malformed.
#: A write with this principal is never reported as a confirmed breach.
UNKNOWN_PRINCIPAL = "unknown"


class Verdict(StrEnum):
    """What a scan concluded.

    A scan that cannot make a clean claim says so. The verdict is deliberately
    not a boolean: "nothing was found" and "nothing could be found" are
    different answers, and only the first one is a security result.
    """

    CLEAN = "CLEAN"
    """Meaningful eligible checks ran to completion and produced no finding."""

    FINDINGS = "FINDINGS"
    """At least one finding was proven."""

    INCONCLUSIVE = "INCONCLUSIVE"
    """The scan could not establish enough coverage to make a clean claim."""

    ERROR = "ERROR"
    """The setup or the execution failed."""


#: The action vocabulary of the authorization model.
#:
#: It mirrors :func:`actions_for` exactly: every read method maps to ``read``
#: and every mutating method maps to ``write``. Authorization grants are
#: declared in the same vocabulary, so a grant can never be written for one
#: operation and silently applied to another.
READ_ACTION = "read"
WRITE_ACTION = "write"
GRANT_ACTIONS = frozenset({READ_ACTION, WRITE_ACTION})


class AuthorizationOutcome(StrEnum):
    """How one authorization check ended.

    These four states are deliberately distinct. ``ALLOWED_BY_GRANT`` is a
    *resolved* check: the access was explained by an explicit, action-scoped
    grant. ``INCONCLUSIVE`` is the opposite: the evidence was insufficient.
    Collapsing either of them into the other turns a permission to read into a
    permission to write, or an unknown into a clean result.
    """

    DECIDED = "DECIDED"
    """The check completed with a defensible decision and no grant."""

    ALLOWED_BY_GRANT = "ALLOWED_BY_GRANT"
    """A confirmed, action-scoped grant explains the observed access."""

    VIOLATION = "VIOLATION"
    """The check proved a violation."""

    INCONCLUSIVE = "INCONCLUSIVE"
    """The check could not be decided from the available evidence."""

    @property
    def resolved(self) -> bool:
        """Whether this outcome is a real decision rather than uncertainty."""
        return self is not AuthorizationOutcome.INCONCLUSIVE


#: Deterministic reconciliation order for provisional outcomes of one logical
#: check. A proven violation is the strongest result; uncertainty is the
#: weakest, so direct observations can replace it but can never be replaced by
#: it. This maps the abstract outcome to a rank, not to a verdict.
OUTCOME_PRECEDENCE: dict[AuthorizationOutcome, int] = {
    AuthorizationOutcome.INCONCLUSIVE: 0,
    AuthorizationOutcome.DECIDED: 1,
    AuthorizationOutcome.ALLOWED_BY_GRANT: 2,
    AuthorizationOutcome.VIOLATION: 3,
}


class LawExecutionState(StrEnum):
    """The single source of truth for what a scan did about one law.

    The states are ordered by evidence strength, not by severity:

    ``unsupported``
        This backend has no implementation for the law. No assertion about the
        law is made from this scan.
    ``supported_not_exercised``
        The law is implemented, but this workload offered no eligible target.
        It is deliberately distinct from ``unsupported``.
    ``eligible``
        An eligible target existed, but no check was attempted (for example
        the budget stopped the scan first).
    ``attempted``
        A check was recorded without a probe issuing an HTTP request (for
        example a provisional uncertainty from ownership evidence).
    ``executed``
        A probe for this law actually issued requests and reached a decided
        outcome (including a finding).
    ``inconclusive``
        Only inconclusive outcomes were recorded; no successful execution.
        Never reported as a successful execution.
    ``skipped``
        The law is intentionally not evaluated as a standalone law in this
        backend (L6 is only detected through the L5 race heuristics).
    """

    UNSUPPORTED = "unsupported"
    SUPPORTED_NOT_EXERCISED = "supported_not_exercised"
    ELIGIBLE = "eligible"
    ATTEMPTED = "attempted"
    EXECUTED = "executed"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


@dataclass
class LawCoverage:
    """Per-law accounting for one authorization law.

    Every count answers a different question, and none of them is a request
    count:

    ``eligible``
        checks the scan could legitimately perform (the denominator);
    ``attempted``
        eligible checks that were actually started;
    ``decided``
        attempts that reached a defensible decision without a grant;
    ``allowed_by_grant``
        attempts resolved as legitimate, action-scoped shared access;
    ``findings``
        attempts that proved a violation;
    ``inconclusive``
        attempts that could not be decided.

    ``eligible`` is the denominator for every rate. A check that never had a
    valid target is never counted as attempted, and a resolved grant is never
    counted as unresolved.
    """

    eligible: int = 0
    attempted: int = 0
    decided: int = 0
    allowed_by_grant: int = 0
    findings: int = 0
    inconclusive: int = 0
    #: Probe groups that actually issued requests for this law. Unlike
    #: ``attempted``, this cannot be raised by a recorded outcome alone.
    executed: int = 0
    supported: bool = True
    skipped: bool = False

    @property
    def state(self) -> LawExecutionState:
        """The derived execution state of this law."""
        if self.skipped:
            return LawExecutionState.SKIPPED
        if not self.supported:
            return LawExecutionState.UNSUPPORTED
        if self.attempted and self.resolved == 0:
            return LawExecutionState.INCONCLUSIVE
        if self.executed > 0:
            return LawExecutionState.EXECUTED
        if self.attempted > 0:
            return LawExecutionState.ATTEMPTED
        if self.eligible > 0:
            return LawExecutionState.ELIGIBLE
        return LawExecutionState.SUPPORTED_NOT_EXERCISED

    @property
    def resolved(self) -> int:
        """Attempts that ended in a decision (including a resolved grant)."""
        return self.decided + self.allowed_by_grant + self.findings

    @property
    def unresolved(self) -> int:
        """Eligible-and-attempted checks that remain undecided."""
        return self.inconclusive

    @property
    def pending(self) -> int:
        """Eligible checks that were never attempted."""
        return max(0, self.eligible - self.attempted)

    @property
    def relevant(self) -> bool:
        """Whether this law carried any security check for this scan."""
        return bool(self.eligible or self.attempted or self.resolved or self.inconclusive)

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "attempted": self.attempted,
            "decided": self.decided,
            "allowed_by_grant": self.allowed_by_grant,
            "findings": self.findings,
            "inconclusive": self.inconclusive,
            "executed": self.executed,
            "supported": self.supported,
            "skipped": self.skipped,
            "state": self.state.value,
            "resolved": self.resolved,
            "unresolved": self.unresolved,
            "pending": self.pending,
            # Explicit denominators: every rate is over ``eligible`` and is
            # reported with the count it was computed from.
            "attempt_rate": round(self.attempted / self.eligible, 4) if self.eligible else None,
            "resolution_rate": round(self.resolved / self.eligible, 4) if self.eligible else None,
        }


@dataclass
class ScanCoverage:
    """What the scan actually managed to look at.

    Request traffic is not evidence of security coverage: a login request, a
    health request and a set of unsuccessful learning requests all produce
    traffic while proving nothing. These counters are what a clean claim has
    to be made of.
    """

    learning_operations: int = 0
    """The learning requests that succeeded."""

    resources_discovered: int = 0
    """The resources the learning phase identified."""

    resources_owned: int = 0
    """The discovered resources whose owner is known.

    A resource without an owner cannot take part in an ownership check, so it
    is not a candidate for anything.
    """

    probe_candidates: int = 0
    """The eligible security checks the scan identified."""

    probes_executed: int = 0
    """The eligible security checks that actually ran to completion."""

    budget_exhausted: bool = False
    """Whether the request budget cut the scan short."""

    # Phase V: ownership evidence is a separate dimension from raw discovery.
    resources_with_ownership_evidence: int = 0
    """Discovered resources with any confirmed ownership evidence."""

    resources_corroborated: int = 0
    """Ownership edges supported by more than one independent source."""

    ownership_candidates: int = 0
    """Resources whose owner is only a candidate - never a finding basis."""

    ownership_ambiguous: int = 0
    """Relationships whose evidence is ambiguous or contradictory."""

    sharing_explained: int = 0
    """Cross-principal accesses explained by an explicit sharing relationship."""

    inconclusive_checks: int = 0
    """Checks that could not be completed, with a recorded reason."""

    identity_anchors_unresolved: int = 0
    """Principals with no confirmed database identity anchor."""

    ownership_semantics_missing: int = 0
    """Resources whose ownership evidence is only structural/candidate."""

    resource_row_mapping_ambiguous: int = 0
    """Resources whose API id does not map uniquely to a database row."""

    sharing_semantics_ambiguous: int = 0
    """Associations whose permission semantics are unproven."""

    laws: dict[str, LawCoverage] = field(default_factory=dict)
    """Per-law coverage, keyed by law (``L2``, ``L3``).

    L2 and L3 are never merged: a completed read check says nothing about an
    unresolved write check, and the verdict has to look at each of them.
    """

    #: The laws whose *own* coverage decides whether a clean claim is allowed.
    #: Other laws (L1, L4, L5) keep their historical probe-level accounting;
    #: their eligible/executed counters live in this object already.
    required_laws: ClassVar[tuple[str, ...]] = ("L2", "L3")

    @property
    def relevant_laws(self) -> dict[str, LawCoverage]:
        """The per-law counters that describe an actual check."""
        return {law: coverage for law, coverage in self.laws.items() if coverage.relevant}

    @property
    def has_law_coverage(self) -> bool:
        """Whether at least one authorization law had something to check."""
        return any(coverage.eligible > 0 for coverage in self.laws.values())

    @property
    def executed_laws(self) -> list[str]:
        """Laws with a real probe execution, in deterministic order.

        This is the only list a reporting layer may use for ``laws_executed``:
        a hardcoded law, an eligible target or a finding alone never qualifies.
        """
        return sorted(law for law, coverage in self.laws.items() if coverage.state is LawExecutionState.EXECUTED)

    def law_state(self, law: str) -> LawExecutionState:
        """The recorded state of one law (absent means unsupported)."""
        coverage = self.laws.get(law)
        return coverage.state if coverage is not None else LawExecutionState.UNSUPPORTED

    @property
    def resolved_checks(self) -> int:
        """Decided checks, including checks resolved by a confirmed grant.

        Only the laws whose own coverage decides a clean claim are aggregated:
        including probe-level laws that never record outcomes would invent
        pending work and turn every scan inconclusive.
        """
        return sum(coverage.resolved for law, coverage in self.laws.items() if law in self.required_laws)

    @property
    def unresolved_checks(self) -> int:
        """Checks that remain undecided, including legacy recorded reasons."""
        recorded = sum(coverage.inconclusive for law, coverage in self.laws.items() if law in self.required_laws)
        return max(self.inconclusive_checks, recorded)

    @property
    def pending_checks(self) -> int:
        """Eligible checks that were never attempted."""
        return sum(coverage.pending for law, coverage in self.laws.items() if law in self.required_laws)

    @property
    def meaningful(self) -> bool:
        """Whether the scan established enough coverage to make a clean claim."""
        return (
            self.learning_operations > 0
            and self.resources_discovered > 0
            and self.probe_candidates > 0
            and self.probes_executed > 0
            and not self.budget_exhausted
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "learning_operations": self.learning_operations,
            "resources_discovered": self.resources_discovered,
            "resources_owned": self.resources_owned,
            "probe_candidates": self.probe_candidates,
            "probes_executed": self.probes_executed,
            "budget_exhausted": self.budget_exhausted,
            "meaningful": self.meaningful,
            "resources_with_ownership_evidence": self.resources_with_ownership_evidence,
            "resources_corroborated": self.resources_corroborated,
            "ownership_candidates": self.ownership_candidates,
            "ownership_ambiguous": self.ownership_ambiguous,
            "sharing_explained": self.sharing_explained,
            "inconclusive_checks": self.inconclusive_checks,
            "identity_anchors_unresolved": self.identity_anchors_unresolved,
            "ownership_semantics_missing": self.ownership_semantics_missing,
            "resource_row_mapping_ambiguous": self.resource_row_mapping_ambiguous,
            "sharing_semantics_ambiguous": self.sharing_semantics_ambiguous,
            "laws": {law: coverage.to_dict() for law, coverage in sorted(self.laws.items())},
            "executed_laws": self.executed_laws,
            "resolved_checks": self.resolved_checks,
            "unresolved_checks": self.unresolved_checks,
            "pending_checks": self.pending_checks,
        }


@dataclass(frozen=True)
class Principal:
    """An identity that can act on the system."""

    id: str
    roles: tuple[str, ...] = ()
    token: str | None = None

    def is_privileged(self) -> bool:
        return any(role in {"admin", "superuser", "owner", "root"} for role in self.roles)


@dataclass(frozen=True)
class Resource:
    """A row-like object owned by somebody."""

    type: str
    id: str
    owner: str | None = None
    tenant: str | None = None

    @property
    def key(self) -> str:
        return f"{self.type}:{self.id}"


@dataclass(frozen=True)
class Access:
    """One `(principal, resource, action)` triple."""

    principal: str
    resource: str
    action: str

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.principal, self.resource, self.action)


@dataclass
class Step:
    """A single step of a reproduction."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    status: int | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "status": self.status,
            "note": self.note,
        }


@dataclass
class Violation:
    """A proven breach of one law."""

    law: str
    title: str
    detail: str
    severity: str = "high"
    principal: str | None = None
    resource: str | None = None
    action: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)

    @property
    def law_name(self) -> str:
        law = LAWS.get(self.law)
        return law.name if law else self.law

    def to_dict(self) -> dict[str, Any]:
        return {
            "law": self.law,
            "law_name": self.law_name,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
            "principal": self.principal,
            "resource": self.resource,
            "action": self.action,
            "evidence": self.evidence,
            "steps": [step.to_dict() for step in self.steps],
        }


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    """One access rule.

    ``kind`` is one of:

    ``owner``    - the principal may act when it owns the resource
    ``role``     - the principal may act when it holds ``role``
    ``public``   - everybody may act
    ``explicit`` - the named principal may act on the named resource
    """

    kind: str
    action: str
    resource_type: str | None = None
    role: str | None = None
    principal: str | None = None
    resource: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class Policy:
    """What the application is allowed to do, as learned from its normal behaviour."""

    principals: dict[str, Principal] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    #: resource type -> fields a client must never be able to write
    read_only_fields: dict[str, set[str]] = field(default_factory=dict)
    #: resource type -> fields written by the server itself
    server_managed_fields: dict[str, set[str]] = field(default_factory=dict)
    authority_fields: set[str] = field(default_factory=lambda: set(AUTHORITY_FIELDS))
    notes: list[str] = field(default_factory=list)

    # -- queries ---------------------------------------------------------- #

    def principal(self, principal_id: str) -> Principal:
        return self.principals.get(principal_id, Principal(id=principal_id))

    def resource(self, key: str) -> Resource | None:
        return self.resources.get(key)

    def permitted(self, principal: Principal, resource: Resource, action: str) -> bool:
        """Whether `principal` may perform `action` on `resource`."""
        for rule in self.rules:
            if rule.action not in {action, "*"}:
                continue
            if rule.resource_type is not None and rule.resource_type != resource.type:
                continue
            if rule.kind == "public":
                return True
            if rule.kind == "owner":
                if resource.owner is not None and resource.owner == principal.id:
                    return True
            elif rule.kind == "role":
                if rule.role is not None and rule.role in principal.roles:
                    return True
            elif rule.kind == "explicit":
                if rule.principal == principal.id and (rule.resource is None or rule.resource == resource.key):
                    return True
        return False

    def may_write_field(self, principal: Principal, resource: Resource, field_name: str) -> bool:
        """Whether `principal` may set `field_name` on `resource`."""
        if field_name in self.read_only_fields.get(resource.type, set()):
            return False
        return self.permitted(principal, resource, "write")

    # -- serialization ---------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {
            "principals": {
                pid: {"id": p.id, "roles": list(p.roles), "token": p.token} for pid, p in self.principals.items()
            },
            "resources": {
                key: {"type": r.type, "id": r.id, "owner": r.owner, "tenant": r.tenant}
                for key, r in self.resources.items()
            },
            "rules": [rule.to_dict() for rule in self.rules],
            "read_only_fields": {k: sorted(v) for k, v in self.read_only_fields.items()},
            "server_managed_fields": {k: sorted(v) for k, v in self.server_managed_fields.items()},
            "authority_fields": sorted(self.authority_fields),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        principals = {
            pid: Principal(id=item["id"], roles=tuple(item.get("roles", ())), token=item.get("token"))
            for pid, item in data.get("principals", {}).items()
        }
        resources = {
            key: Resource(type=item["type"], id=item["id"], owner=item.get("owner"), tenant=item.get("tenant"))
            for key, item in data.get("resources", {}).items()
        }
        rules = [Rule(**item) for item in data.get("rules", [])]
        policy = cls(
            principals=principals,
            resources=resources,
            rules=rules,
            read_only_fields={k: set(v) for k, v in data.get("read_only_fields", {}).items()},
            server_managed_fields={k: set(v) for k, v in data.get("server_managed_fields", {}).items()},
            authority_fields=set(data.get("authority_fields", AUTHORITY_FIELDS)),
            notes=list(data.get("notes", [])),
        )
        return policy


# --------------------------------------------------------------------------- #
# Access matrix
# --------------------------------------------------------------------------- #


class AccessMatrix:
    """A sparse `(principal, resource, action) -> allowed` matrix.

    The engine keeps two matrices: the *observed* one (what actually happened)
    and the *permitted* one (what the policy allows). Their difference is the
    residual, and the residual is what a vulnerability looks like.
    """

    def __init__(self, cells: dict[tuple[str, str, str], bool] | None = None) -> None:
        self._cells: dict[tuple[str, str, str], bool] = dict(cells or {})

    def grant(self, principal: str, resource: str, action: str) -> None:
        self._cells[(principal, resource, action)] = True

    def allowed(self, principal: str, resource: str, action: str) -> bool:
        return self._cells.get((principal, resource, action), False)

    def cells(self) -> dict[tuple[str, str, str], bool]:
        return dict(self._cells)

    def residual(self, permitted: AccessMatrix) -> AccessMatrix:
        """Cells that are observed but not permitted."""
        residual = AccessMatrix()
        for cell, value in self._cells.items():
            if value and not permitted.allowed(*cell):
                residual.grant(*cell)
        return residual

    def norm(self) -> dict[str, float]:
        """L2 norm of the residual per principal - how far each identity strayed."""
        norms: dict[str, float] = {}
        for (principal, _resource, _action), value in self._cells.items():
            if value:
                norms[principal] = norms.get(principal, 0.0) + 1.0
        return {principal: math.sqrt(count) for principal, count in norms.items()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "cells": [
                {"principal": p, "resource": r, "action": a, "allowed": v}
                for (p, r, a), v in sorted(self._cells.items())
            ]
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccessMatrix:
        matrix = cls()
        for cell in data.get("cells", []):
            matrix.grant(cell["principal"], cell["resource"], cell["action"])
        return matrix

    def __iter__(self) -> Iterator[Access]:
        for (principal, resource, action), value in self._cells.items():
            if value:
                yield Access(principal=principal, resource=resource, action=action)

    def __len__(self) -> int:
        return len(self._cells)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"AccessMatrix(cells={len(self._cells)})"


def actions_for(method: str) -> str:
    """Map an HTTP method to an abstract action."""
    method = method.upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "read"
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "write"
    return method.lower()


def is_authority_field(name: str, extra: Iterable[str] = ()) -> bool:
    """Whether a field name looks like it carries authority."""
    lowered = name.lower()
    if lowered in {e.lower() for e in extra}:
        return True
    if lowered in AUTHORITY_FIELDS:
        return True
    return any(lowered.endswith(f"_{field}") or lowered.startswith(f"{field}_") for field in AUTHORITY_FIELDS)
