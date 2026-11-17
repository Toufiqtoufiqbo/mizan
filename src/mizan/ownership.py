"""Evidence-based ownership and relationship discovery (v1).

This module answers one narrow question: *what may Mīzān believe about who
owns a resource, and why?* It does not decide whether access was authorized.
It never invents an ownership relation, and it keeps ownership, reference,
membership and sharing as different kinds of relationship.

Design decisions and the audit of the previous behaviour are recorded in
``PHASE_V_DESIGN.md``.

No raw bearer token, password or request/response payload is stored here.
Evidence records a **stable reference** - the source, the principal, the
resource or entity, and the table/column where applicable - so a finding can
be explained without copying secrets into a new artifact.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from mizan.attribution import DatabaseSchema
from mizan.core import GRANT_ACTIONS, UNKNOWN_PRINCIPAL, Resource
from mizan.taint import WriteEvent


def canonical_key(values: Sequence[Any]) -> str:
    """An unambiguous identity for a (possibly composite) primary key.

    A JSON array is used instead of a delimiter join: ``["a:b", "c"]`` and
    ``["a", "b:c"]`` cannot collide.
    """
    return json.dumps([str(value) for value in values], separators=(",", ":"))


def parse_identity(value: str | None) -> tuple[str, ...]:
    """Parse a resource identifier into its key components.

    A canonical JSON array denotes a composite key; anything else is a single
    component. Older ledgers and proof formats therefore keep working.
    """
    if value is None:
        return ()
    text = str(value)
    if text.startswith("[") and text.endswith("]"):
        try:
            decoded = json.loads(text)
        except ValueError:
            return (text,)
        if isinstance(decoded, list):
            return tuple(str(item) for item in decoded)
    return (text,)


class RelationshipContractError(ValueError):
    """An explicitly supplied relationship contract is invalid.

    This is a configuration error, not a scan result: continuing with weaker
    semantics would silently change what the scan is allowed to conclude.
    """


def _resolve_declared_table(mapping: dict[str, Any], name: str) -> Any:
    """Resolve a contract declaration against schema-qualified table names.

    An exact key always wins. A bare name is accepted only when it matches
    exactly one declared qualified table; an ambiguous name is rejected rather
    than resolving to an arbitrary schema.
    """
    if name in mapping:
        return mapping[name]
    matches = [key for key in mapping if key.split(".", 1)[-1] == name]
    if len(matches) == 1:
        return mapping[matches[0]]
    if len(matches) > 1:
        raise RelationshipContractError(f"ambiguous unqualified table {name!r}: matches {sorted(matches)}")
    return None


#: Ownership sources the engine understands. A declaration naming anything
#: else cannot be honoured, so it is rejected instead of being dropped.
OWNERSHIP_SOURCES = frozenset({"database_foreign_key", "response_field"})


def _parse_grant_actions(table: str, declaration: dict[str, Any], *, strict: bool) -> frozenset[str] | None:
    """Parse the explicit action scope of a sharing declaration.

    A grant without a declared scope is not interpreted as permission for
    everything: in strict mode it is a configuration error, and in lenient mode
    the declaration is dropped (the least permissive interpretation). Unknown
    actions, non-string values and an empty list are rejected for the same
    reason - a permission the scan cannot name is a permission it cannot use.
    """
    raw = declaration.get("actions")
    if raw is None:
        if strict:
            raise RelationshipContractError(
                f"sharing declaration for {table!r} must declare 'actions' "
                f"({sorted(GRANT_ACTIONS)}); a grant without an action scope is not a grant"
            )
        return None
    if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
        if strict:
            raise RelationshipContractError(f"sharing declaration for {table!r} must declare 'actions' as a JSON array")
        return None
    actions: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            if strict:
                raise RelationshipContractError(f"sharing declaration for {table!r} has a non-string action {item!r}")
            return None
        action = item.strip().lower()
        if action not in GRANT_ACTIONS:
            if strict:
                raise RelationshipContractError(
                    f"unsupported action {item!r} for sharing declaration {table!r}; "
                    f"expected one of {sorted(GRANT_ACTIONS)}"
                )
            return None
        actions.append(action)
    if not actions:
        if strict:
            raise RelationshipContractError(f"sharing declaration for {table!r} declares an empty 'actions' list")
        return None
    # Duplicates are normalized deterministically; the scope is a set.
    return frozenset(actions)


@dataclass(frozen=True)
class RelationshipContract:
    """Explicit, trusted semantic declarations about an application.

    This is operator/application-provided metadata, not a hardcoded list of
    column names inside the inference engine. Without it, structural evidence
    stays structural: a foreign key is a reference, and an association row is
    a candidate relationship, never confirmed semantics.

    Three states are distinct and must never collapse into one another:
    no contract supplied (``None``), a valid contract, and an explicitly
    supplied contract that is invalid (``RelationshipContractError``).
    """

    version: int = 1
    identity: tuple[str, str] | None = None
    ownership: dict[str, tuple[str, str, str | None]] = field(default_factory=dict)
    #: table -> (resource_fk, principal_fk, semantics, table, actions).
    #: ``actions`` is the explicit, non-empty scope of the grant: a grant is
    #: never interpreted as permission for an operation it does not declare.
    sharing: dict[str, tuple[str, str, str, str, frozenset[str]]] = field(default_factory=dict)
    variants: dict[str, dict[str, Any]] = field(default_factory=dict)

    def _merged_data(self, name: str, override: dict[str, Any]) -> dict[str, Any]:
        """Merge one variant's explicit declarations over the base contract."""
        merged: dict[str, Any] = {
            "version": self.version,
            "identity": {"endpoint": self.identity[0], "field": self.identity[1]} if self.identity else None,
            "ownership": {
                key: {"source": value[0], "column": value[1], **({"table": value[2]} if value[2] else {})}
                for key, value in self.ownership.items()
            },
            "sharing": {
                key: {
                    "resource_fk": value[0],
                    "principal_fk": value[1],
                    "semantics": value[2],
                    "actions": sorted(value[4]),
                }
                for key, value in self.sharing.items()
            },
        }
        for section, value in override.items():
            if value is None:
                merged.pop(section, None)
            elif isinstance(value, dict) and isinstance(merged.get(section), dict):
                merged[section] = {**merged[section], **value}
            else:
                merged[section] = value
        return merged

    def for_variant(self, name: str | None, *, strict: bool = False) -> RelationshipContract:
        """Merge a variant's explicit declarations over the base contract."""
        if not name or name not in self.variants:
            return self
        return RelationshipContract.from_dict(self._merged_data(name, self.variants[name]), strict=strict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, *, strict: bool = False) -> RelationshipContract:
        """Build a contract from JSON data.

        ``strict`` is used for operator-supplied metadata: an unsupported or
        malformed declaration raises instead of being silently ignored. The
        lenient mode remains for internally composed data and older callers.
        """
        if not isinstance(data, dict):
            if strict:
                raise RelationshipContractError("a relationship contract must be a JSON object")
            return cls()
        version = data.get("version", 1)
        if strict and version != 1:
            raise RelationshipContractError(f"unsupported relationship-contract version: {version!r}")
        identity = data.get("identity")
        identity_pair = None
        if isinstance(identity, dict) and identity.get("endpoint") and identity.get("field"):
            identity_pair = (str(identity["endpoint"]), str(identity["field"]))
        elif strict and identity is not None:
            raise RelationshipContractError("identity must declare both an endpoint and a field")
        ownership: dict[str, tuple[str, str, str | None]] = {}
        ownership_data = data.get("ownership") or {}
        if strict and not isinstance(ownership_data, dict):
            raise RelationshipContractError("ownership must be an object")
        for resource_type, declaration in ownership_data.items():
            if not isinstance(declaration, dict) or not declaration.get("source"):
                if strict:
                    raise RelationshipContractError(f"ownership declaration for {resource_type!r} has no source")
                continue
            source = str(declaration["source"])
            name = declaration.get("column") or declaration.get("field")
            if not name:
                if strict:
                    raise RelationshipContractError(
                        f"ownership declaration for {resource_type!r} names neither a column nor a field"
                    )
                continue
            if strict and source not in OWNERSHIP_SOURCES:
                raise RelationshipContractError(
                    f"unsupported ownership source {source!r} for {resource_type!r}; "
                    f"expected one of {sorted(OWNERSHIP_SOURCES)}"
                )
            declared_table = declaration.get("table")
            ownership[str(resource_type)] = (
                source,
                str(name),
                str(declared_table) if declared_table else None,
            )
        sharing: dict[str, tuple[str, str, str, str, frozenset[str]]] = {}
        sharing_data = data.get("sharing") or {}
        if strict and not isinstance(sharing_data, dict):
            raise RelationshipContractError("sharing must be an object")
        for table, declaration in sharing_data.items():
            if not isinstance(declaration, dict):
                if strict:
                    raise RelationshipContractError(f"sharing declaration for {table!r} must be an object")
                continue
            semantics = declaration.get("semantics")
            if strict and semantics != "authorization_grant":
                raise RelationshipContractError(
                    f"sharing declaration for {table!r} must use semantics 'authorization_grant'"
                )
            if semantics != "authorization_grant":
                continue
            resource_fk, principal_fk = declaration.get("resource_fk"), declaration.get("principal_fk")
            if not resource_fk or not principal_fk:
                if strict:
                    raise RelationshipContractError(
                        f"sharing declaration for {table!r} must name both resource_fk and principal_fk"
                    )
                continue
            if strict and resource_fk == principal_fk:
                raise RelationshipContractError(
                    f"sharing declaration for {table!r} names the same column for both foreign keys"
                )
            actions = _parse_grant_actions(str(table), declaration, strict=strict)
            if actions is None:
                continue
            sharing[str(table)] = (
                str(resource_fk),
                str(principal_fk),
                "authorization_grant",
                str(table),
                actions,
            )
        variants_data = data.get("variants")
        variants: dict[str, dict[str, Any]] = {}
        if variants_data is None:
            pass
        elif not isinstance(variants_data, dict):
            if strict:
                raise RelationshipContractError("variants must be an object")
        else:
            for key, value in variants_data.items():
                name = str(key)
                if strict:
                    if not isinstance(key, str) or not name.strip():
                        raise RelationshipContractError("every variant must have a non-empty string name")
                    if not isinstance(value, dict):
                        raise RelationshipContractError(
                            f"variant {name!r} must be an object, got {type(value).__name__}"
                        )
                if isinstance(value, dict):
                    variants[name] = value
        contract = cls(version=1, identity=identity_pair, ownership=ownership, sharing=sharing, variants=variants)
        if strict:
            # A variant override is the same kind of declaration as the base
            # contract. Re-validate the merged result now: an invalid override
            # must fail before any security conclusion is produced, not only
            # when that variant happens to be selected later.
            for name in sorted(variants):
                merged = contract._merged_data(name, variants[name])
                cls.from_dict(merged, strict=True)
        return contract

    def validate_schema(self, schema: Any) -> None:
        """Check the declared relationships against the application's schema.

        Syntactic JSON validity is not enough: a grant that names a table or a
        column the database does not have could silently change which access
        looks legitimate. Every problem raises, with the offending name.
        """
        problems: list[str] = []
        for table, (resource_fk, principal_fk, _semantics, _name, _actions) in sorted(self.sharing.items()):
            declared = schema.get(table) if schema is not None else None
            if declared is None:
                raise RelationshipContractError(f"sharing declares unknown table {table!r}")
            resource_column = declared.column(resource_fk)
            principal_column = declared.column(principal_fk)
            if resource_column is None:
                problems.append(f"{table!r} has no resource_fk column {resource_fk!r}")
            if principal_column is None:
                problems.append(f"{table!r} has no principal_fk column {principal_fk!r}")
            if resource_column is None or principal_column is None:
                continue
            resource_target = next((fk for fk in declared.foreign_keys if fk.column == resource_fk), None)
            principal_target = next((fk for fk in declared.foreign_keys if fk.column == principal_fk), None)
            if resource_target is None:
                problems.append(f"{table}.{resource_fk} is not a declared foreign key")
            if principal_target is None:
                problems.append(f"{table}.{principal_fk} is not a declared foreign key")
            if resource_target is not None and principal_target is not None:
                if getattr(resource_target, "composite", False) or getattr(principal_target, "composite", False):
                    problems.append(
                        f"{table} declares a composite foreign key; only single-column grants are supported"
                    )
                elif resource_target.table == principal_target.table:
                    problems.append(
                        f"{table} references {resource_target.table!r} for both the resource and the principal"
                    )
                target = schema.get(resource_target.table) if schema is not None else None
                if target is None or not target.primary_key:
                    problems.append(f"{table}.{resource_fk} does not reference a table with a primary key")
                principal_entity = schema.get(principal_target.table) if schema is not None else None
                if principal_entity is None or not principal_entity.primary_key:
                    problems.append(f"{table}.{principal_fk} does not reference a table with a primary key")
        for resource_type, (source, column, declared_table) in sorted(self.ownership.items()):
            lookup = declared_table or resource_type
            try:
                declared = _resolve_declared_table(schema.tables, lookup) if schema is not None else None
            except RelationshipContractError as exc:
                problems.append(str(exc))
                continue
            if declared is None:
                # Legacy contracts name the API resource type, not the table.
                # Without an explicit table they are not a schema assertion.
                if declared_table is None:
                    continue
                problems.append(f"ownership declares unknown table {declared_table!r}")
                continue
            if declared.column(column) is None:
                problems.append(f"{resource_type!r} has no ownership column {column!r}")
        if problems:
            raise RelationshipContractError("; ".join(problems))

    @classmethod
    def load(
        cls, path: str | Path | None, variant: str | None = None, *, strict: bool = False
    ) -> RelationshipContract | None:
        """Load a contract file.

        A missing path is the "no contract supplied" state and returns
        ``None``. With ``strict``, a file that exists but cannot be read,
        parsed or validated raises ``RelationshipContractError``: an explicit
        operator decision must never degrade silently into no contract.
        """
        if path is None or not Path(path).exists():
            return None
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            if strict:
                raise RelationshipContractError(f"cannot read {path}: {exc}") from exc
            return None
        contract = cls.from_dict(data, strict=strict)
        return contract.for_variant(variant, strict=strict)


#: The conventional response fields that remain one *source* of ownership
#: evidence. They are not the only source and not an authoritative one: a
#: contradiction with data-level evidence makes the relationship ambiguous.
RESPONSE_OWNER_FIELDS = ("owner_id", "user_id", "owner", "principal_id", "account_id")


@dataclass(frozen=True)
class Observation:
    """A response observed for one principal - no token, no raw payload copy."""

    principal: str
    response: Any
    path: str | None = None


class RelationshipType(StrEnum):
    """A relationship kind. These are deliberately not interchangeable."""

    OWNS = "OWNS"
    REFERENCES = "REFERENCES"
    MEMBER_OF = "MEMBER_OF"
    SHARED_WITH = "SHARED_WITH"


class EvidenceState(StrEnum):
    """What the evidence actually establishes."""

    CONFIRMED = "CONFIRMED"
    CANDIDATE = "CANDIDATE"
    AMBIGUOUS = "AMBIGUOUS"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Evidence:
    """One stable, secret-free observation supporting a relationship."""

    source: str
    principal: str | None = None
    resource: str | None = None
    entity: str | None = None
    table: str | None = None
    column: str | None = None
    traffic_index: int | None = None
    detail: str = ""

    @property
    def id(self) -> str:
        """A stable content hash: repeating the same observation dedupes it.

        Corroboration must come from different sources, not from the same fact
        appearing twice.
        """
        raw = json.dumps(
            {
                "source": self.source,
                "principal": self.principal,
                "resource": self.resource,
                "entity": self.entity,
                "table": self.table,
                "column": self.column,
                "traffic_index": self.traffic_index,
                "detail": self.detail,
            },
            sort_keys=True,
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "principal": self.principal,
            "resource": self.resource,
            "entity": self.entity,
            "table": self.table,
            "column": self.column,
            "traffic_index": self.traffic_index,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        return cls(
            source=str(data.get("source", "")),
            principal=data.get("principal"),
            resource=data.get("resource"),
            entity=data.get("entity"),
            table=data.get("table"),
            column=data.get("column"),
            traffic_index=data.get("traffic_index"),
            detail=str(data.get("detail", "")),
        )


@dataclass
class Relationship:
    """A typed, evidenced relationship between two entities."""

    type: RelationshipType
    subject: str
    object: str
    state: EvidenceState
    evidence: tuple[str, ...] = ()
    #: For a ``SHARED_WITH`` grant, the operations it actually authorizes.
    #: An empty set means "no operation is authorized": a relationship that
    #: names no scope can never explain access.
    actions: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            "subject": self.subject,
            "object": self.object,
            "state": str(self.state),
            "evidence": list(self.evidence),
            "actions": sorted(self.actions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Relationship:
        return cls(
            type=RelationshipType(str(data["type"])),
            subject=str(data["subject"]),
            object=str(data["object"]),
            state=EvidenceState(str(data.get("state", "UNKNOWN"))),
            evidence=tuple(data.get("evidence", ())),
            actions=frozenset(str(action) for action in data.get("actions", ())),
        )


@dataclass
class OwnershipGraph:
    """The discovered entities, relationships and their evidence."""

    entities: dict[str, str] = field(default_factory=dict)
    """entity key -> kind (`principal`, `resource` or `database`)."""

    evidence: dict[str, Evidence] = field(default_factory=dict)
    """evidence id -> the observation (never a raw token or payload)."""

    relationships: list[Relationship] = field(default_factory=list)
    inconclusive: dict[str, str] = field(default_factory=dict)
    """subject key -> why the conclusion could not be established."""

    #: API resource key -> (database table, complete primary-key components).
    resource_rows: dict[str, tuple[str, tuple[str, ...]]] = field(default_factory=dict)
    #: A database row identity -> resource key, for L3 write-event resolution.
    row_resources: dict[str, str] = field(default_factory=dict)

    # -- building ----------------------------------------------------------- #

    def add_entity(self, key: str, kind: str) -> None:
        self.entities.setdefault(key, kind)

    def add_evidence(self, evidence: Evidence) -> str:
        evidence_id = evidence.id
        self.evidence.setdefault(evidence_id, evidence)
        return evidence_id

    def add_relationship(
        self,
        type_: RelationshipType,
        subject: str,
        object_: str,
        state: EvidenceState,
        evidence: Iterable[str] = (),
        *,
        actions: Iterable[str] = (),
    ) -> Relationship:
        existing = next(
            (r for r in self.relationships if r.type == type_ and r.subject == subject and r.object == object_),
            None,
        )
        # A later observation never silently replaces an earlier one. The
        # strongest state wins, and disagreement is preserved as CONTRADICTED.
        order = {
            EvidenceState.UNKNOWN: 0,
            EvidenceState.CANDIDATE: 1,
            EvidenceState.CONTRADICTED: 2,
            EvidenceState.AMBIGUOUS: 2,
            EvidenceState.CONFIRMED: 3,
        }
        if existing is None:
            existing = Relationship(type_, subject, object_, state, (), frozenset(actions))
            self.relationships.append(existing)
        elif existing.state != state and {existing.state, state} <= {EvidenceState.CONFIRMED, EvidenceState.CANDIDATE}:
            existing.state = max(existing.state, state, key=lambda s: order[s])
        elif existing.state != state:
            existing.state = EvidenceState.CONTRADICTED
        existing.actions = frozenset(set(existing.actions) | set(actions))
        ids = set(existing.evidence)
        ids.update(evidence)
        existing.evidence = tuple(sorted(ids))
        return existing

    # -- queries ------------------------------------------------------------ #

    def owner_of(self, resource_key: str) -> str | None:
        """The single confirmed owner, or ``None`` when that cannot be said."""
        owners = {
            r.subject
            for r in self.relationships
            if r.type == RelationshipType.OWNS and r.object == resource_key and r.state == EvidenceState.CONFIRMED
        }
        return owners.pop() if len(owners) == 1 else None

    def owner_state(self, resource_key: str) -> EvidenceState:
        """The strongest state among the ownership relationships for a resource."""
        relationships = [r for r in self.relationships if r.type == RelationshipType.OWNS and r.object == resource_key]
        if not relationships:
            return EvidenceState.UNKNOWN
        subjects = {r.subject for r in relationships}
        if len(subjects) > 1 or any(r.state is EvidenceState.CONTRADICTED for r in relationships):
            return EvidenceState.CONTRADICTED
        states = {r.state for r in relationships}
        return states.pop() if len(states) == 1 else EvidenceState.CONTRADICTED

    def explained_by_sharing(self, owner: str, other: str, resource_key: str, action: str) -> bool:
        """Whether a confirmed, action-scoped grant explains this access.

        ``action`` is mandatory on purpose: a permission to read is never a
        permission to write. Only a ``CONFIRMED`` ``SHARED_WITH`` relationship
        for this exact principal and resource, whose declared actions contain
        this exact action, can explain an access. Candidates, ambiguous and
        contradicted relationships and unscoped relationships explain nothing.

        ``owner`` is part of the API because callers reason about an
        owner/other pair; the decision itself binds the *other* principal and
        the resource, so a grant can never be borrowed by another identity.
        """
        if action not in GRANT_ACTIONS:
            return False
        return any(
            r.type is RelationshipType.SHARED_WITH
            and r.state is EvidenceState.CONFIRMED
            and r.subject == other
            and r.object == resource_key
            and action in r.actions
            for r in self.relationships
        )

    def counts(self) -> dict[str, int]:
        counts = {state.value: 0 for state in EvidenceState}
        for relation in self.relationships:
            counts[relation.state.value] += 1
        return counts

    def row_to_resource(self, table: str, key_components: Sequence[Any]) -> str | None:
        """Resolve a database row identity to exactly one API resource."""
        identity = (table, tuple(str(value) for value in key_components))
        return next(
            (resource for resource, mapping in self.resource_rows.items() if mapping == identity),
            None,
        )

    def report(self) -> dict[str, Any]:
        """A compact, explainable summary for reports and proof bundles."""
        principals = sum(1 for kind in self.entities.values() if kind == "principal")
        resources = sum(1 for kind in self.entities.values() if kind == "resource")
        sources: dict[str, int] = {}
        for evidence in self.evidence.values():
            sources[evidence.source] = sources.get(evidence.source, 0) + 1
        confirmed = [r for r in self.relationships if r.state is EvidenceState.CONFIRMED]
        return {
            "principals": principals,
            "resources": resources,
            "relationships": len(self.relationships),
            "by_state": self.counts(),
            "confirmed_ownership_edges": sum(1 for r in confirmed if r.type is RelationshipType.OWNS),
            "candidate_ownership_edges": sum(
                1 for r in self.relationships if r.type is RelationshipType.OWNS and r.state is EvidenceState.CANDIDATE
            ),
            "ambiguous_relationships": sum(1 for r in self.relationships if r.state is EvidenceState.AMBIGUOUS),
            "contradicted_relationships": sum(1 for r in self.relationships if r.state is EvidenceState.CONTRADICTED),
            "unattributed_resources": len(self.inconclusive),
            "resource_row_mappings": len(self.resource_rows),
            "sources": dict(sorted(sources.items())),
            "inconclusive": dict(sorted(self.inconclusive.items())),
        }

    # -- serialization ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": dict(sorted(self.entities.items())),
            "evidence": {key: self.evidence[key].to_dict() for key in sorted(self.evidence)},
            "relationships": [r.to_dict() for r in self.relationships],
            "inconclusive": dict(sorted(self.inconclusive.items())),
            "resource_rows": {
                key: [mapping[0], list(mapping[1])] for key, mapping in sorted(self.resource_rows.items())
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OwnershipGraph:
        graph = cls()
        graph.entities = dict(data.get("entities", {}))
        graph.evidence = {key: Evidence.from_dict(item) for key, item in data.get("evidence", {}).items()}
        graph.relationships = [Relationship.from_dict(item) for item in data.get("relationships", [])]
        graph.inconclusive = dict(data.get("inconclusive", {}))
        graph.resource_rows = {
            key: (str(mapping[0]), tuple(str(item) for item in mapping[1]))
            for key, mapping in data.get("resource_rows", {}).items()
        }
        graph.row_resources = {
            canonical_key([table, *values]): resource for resource, (table, values) in graph.resource_rows.items()
        }
        return graph


# --------------------------------------------------------------------------- #
# discovery helpers
# --------------------------------------------------------------------------- #


def _scalars(payload: Any, depth: int = 0) -> list[str]:
    """Scalar values from a response, bounded and never raw credentials."""
    if depth > 3:
        return []
    if isinstance(payload, dict):
        result: list[str] = []
        for value in payload.values():
            result.extend(_scalars(value, depth + 1))
        return result
    if isinstance(payload, (list, tuple)):
        result = []
        for value in payload[:10]:
            result.extend(_scalars(value, depth + 1))
        return result
    if isinstance(payload, (str, int)) and not isinstance(payload, bool):
        text = str(payload).strip()
        if text and len(text) <= 200:
            return [text]
    return []


def _find_rows(
    resource_id: str, schema: DatabaseSchema, rows: dict[str, list[dict[str, Any]]]
) -> list[tuple[str, dict[str, Any], tuple[str, ...]]]:
    """Find rows whose **complete** declared primary key is the resource id.

    A single component of a composite key never identifies a row. The caller
    passes either a scalar id or a canonical JSON array of components.
    """
    components = parse_identity(resource_id)
    if not components:
        return []
    matches: list[tuple[str, dict[str, Any], tuple[str, ...]]] = []
    for table, declared in schema.tables.items():
        columns = declared.primary_key or tuple(column.name for column in declared.columns)
        if len(columns) != len(components):
            continue  # a composite key must match the whole tuple
        for row in rows.get(table, []):
            values = tuple(str(row.get(column)) for column in columns)
            if all(row.get(column) is not None for column in columns) and values == components:
                matches.append((table, row, values))
    return matches


@dataclass
class Anchor:
    """A principal ↔ database identity record, with its evidence state."""

    principal: str
    table: str
    column: str
    value: str
    state: EvidenceState
    evidence: str = ""


def discover_anchors(
    graph: OwnershipGraph,
    records: Iterable[Any],
    schema: DatabaseSchema,
    rows: dict[str, list[dict[str, Any]]],
    contract: RelationshipContract | None = None,
) -> dict[str, Anchor]:
    """Anchor principals to database identity records using declared evidence.

    Only a response from the contract-declared identity endpoint/field may
    produce a **confirmed** anchor. Other value matches stay candidates: a
    document, assignment or task response that happens to contain a database
    value is not proof of who the caller is.
    """
    declared_values: dict[str, set[str]] = {}
    candidate_values: dict[str, set[str]] = {}
    for record in records:
        if not record.principal or record.principal == UNKNOWN_PRINCIPAL:
            continue
        endpoint, field = contract.identity if contract is not None and contract.identity else ("", "")
        if endpoint and getattr(record, "path", None) == endpoint and isinstance(record.response, dict):
            value = record.response.get(field)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                declared_values.setdefault(record.principal, set()).add(str(value))
        else:
            candidate_values.setdefault(record.principal, set()).update(_scalars(record.response))

    observed = declared_values

    matches: dict[tuple[str, str], dict[str, str]] = {}
    for (table, column), mapping in _column_matches(schema, rows, observed).items():
        if len(mapping) < 2 or len(set(mapping.values())) != len(mapping):
            continue  # one principal, or several principals with the same value: not an anchor
        matches[(table, column)] = mapping

    ranked: dict[str, list[tuple[int, str, str, dict[str, str]]]] = {}
    for (table, column), mapping in matches.items():
        declared = schema.get(table)
        column_info = declared.column(column) if declared is not None else None
        score = 0
        if column_info is not None and column_info.primary_key:
            score += 4
        score += min(_reference_count(schema, table, column), 4)
        if column_info is not None and column_info.unique:
            score += 1
        for principal, value in mapping.items():
            ranked.setdefault(principal, []).append((score, table, column, {principal: value}))

    anchors: dict[str, Anchor] = {}
    for principal, ranked_candidates in sorted(ranked.items()):
        best = max(score for score, _, _, _ in ranked_candidates)
        winners = [candidate for candidate in ranked_candidates if candidate[0] == best]
        if len(winners) != 1:
            # Preserve the ambiguity: no owner may be confirmed from it.
            for _, table, column, mapping in winners:
                evidence = graph.add_evidence(
                    Evidence(
                        source="identity_anchor",
                        principal=principal,
                        entity=f"{table}:{column}",
                        detail="ambiguous identity anchor: several equally supported columns",
                    )
                )
                graph.add_relationship(
                    RelationshipType.MEMBER_OF,
                    principal,
                    f"{table}:{column}",
                    EvidenceState.AMBIGUOUS,
                    [evidence],
                )
            continue
        _, table, column, mapping = winners[0]
        value = mapping[principal]
        evidence = graph.add_evidence(
            Evidence(
                source="identity_anchor",
                principal=principal,
                entity=f"{table}:{column}",
                table=table,
                column=column,
                detail="repeated, distinct identity values from several principals",
            )
        )
        graph.add_entity(principal, "principal")
        graph.add_relationship(
            RelationshipType.MEMBER_OF,
            principal,
            f"{table}:{column}={value}",
            EvidenceState.CONFIRMED,
            [evidence],
        )
        anchors[principal] = Anchor(principal, table, column, value, EvidenceState.CONFIRMED, evidence)

    # Undeclared value matches are kept as CANDIDATE observations and as an
    # explicit coverage reason - never promoted to an identity anchor.
    for principal, values in sorted(candidate_values.items()):
        if principal in anchors:
            continue
        for (table, column), mapping in sorted(_column_matches(schema, rows, candidate_values).items()):
            if principal not in mapping:
                continue
            evidence = graph.add_evidence(
                Evidence(
                    source="candidate_identity_observation",
                    principal=principal,
                    entity=f"{table}:{column}",
                    detail="a response value matches a database value, but no declared identity evidence exists",
                )
            )
            graph.add_relationship(
                RelationshipType.MEMBER_OF, principal, f"{table}:{column}", EvidenceState.CANDIDATE, [evidence]
            )
        graph.inconclusive.setdefault(
            f"identity:{principal}", "identity endpoint/field not declared; no confirmed anchor"
        )
    return anchors


def _column_matches(
    schema: DatabaseSchema,
    rows: dict[str, list[dict[str, Any]]],
    observed: dict[str, set[str]],
) -> dict[tuple[str, str], dict[str, str]]:
    """Map (table, column) -> {principal: value} for unambiguous value matches."""
    aligned: dict[tuple[str, str], dict[str, set[str]]] = {}
    for table in schema.tables:
        for row in rows.get(table, []):
            for column, value in row.items():
                if value is None or isinstance(value, bool) or not isinstance(value, (str, int)):
                    continue
                text = str(value)
                for principal, values in observed.items():
                    if text in values:
                        aligned.setdefault((table, column), {}).setdefault(principal, set()).add(text)
    result: dict[tuple[str, str], dict[str, str]] = {}
    for key, mapping in aligned.items():
        result[key] = {principal: next(iter(values)) for principal, values in mapping.items() if len(values) == 1}
    return result


def _reference_count(schema: DatabaseSchema, table: str, column: str) -> int:
    """How many declared foreign keys point at this column.

    A column that several tables point at is a stronger identity anchor than
    one referenced by a single association table.
    """
    return sum(
        1
        for declared in schema.tables.values()
        for fk in declared.foreign_keys
        if fk.table == table and fk.column_ref == column
    )


def discover_relationships(
    graph: OwnershipGraph,
    resources: dict[str, Resource],
    ledger: Iterable[WriteEvent],
    schema: DatabaseSchema,
    rows: dict[str, list[dict[str, Any]]],
    anchors: dict[str, Anchor],
    contract: RelationshipContract | None = None,
    known_principals: frozenset[str] = frozenset(),
) -> None:
    """Apply the conservative inference rules and fill the graph.

    Confirmed ownership needs a **semantic** signal: either the application
    declares the ownership source in the trusted relationship contract, or an
    explicit response-level owner claim names a configured principal. A
    foreign key to an anchored identity record is a reference and, at most, a
    candidate owner - never a confirmed one on its own.
    """
    anchor_by_value = {(anchor.table, anchor.column, anchor.value): anchor.principal for anchor in anchors.values()}
    writes = list(ledger)
    created: set[tuple[str, str, str]] = set()
    for event in writes:
        if event.principal and event.principal != UNKNOWN_PRINCIPAL:
            if event.row_key:
                created.add((event.table, event.row_key, event.principal))
            created.add((event.table, str(event.row_id), event.principal))

    for key, resource in sorted(resources.items()):
        graph.add_entity(key, "resource")
        if resource.id is None:
            graph.inconclusive[key] = "no public identifier"
            continue

        # Source 1: an explicit response-level ownership claim. It counts as
        # semantic evidence only when it names a principal the scan knows.
        response_owner = resource.owner if resource.owner in known_principals else None
        if resource.owner and response_owner is None:
            response_evidence = graph.add_evidence(
                Evidence(
                    source="unverified_response_claim",
                    principal=resource.owner,
                    resource=key,
                    detail="a response field names an unconfigured identity; not an ownership claim",
                )
            )
            graph.add_relationship(
                RelationshipType.OWNS, resource.owner, key, EvidenceState.CANDIDATE, [response_evidence]
            )

        try:
            declared = _resolve_declared_table(contract.ownership, resource.type) if contract is not None else None
        except RelationshipContractError as exc:
            graph.inconclusive.setdefault(resource.type, str(exc))
            declared = None
        declared_owner: str | None = None

        matches = _find_rows(resource.id, schema, rows)
        if len(matches) != 1:
            graph.inconclusive.setdefault(
                key,
                "ambiguous row mapping: the public identifier matches more than one declared primary-key row"
                if len(matches) > 1
                else "no unique database row maps to the API resource",
            )
            if response_owner is not None:
                claim = graph.add_evidence(
                    Evidence(
                        source="response_claim",
                        principal=response_owner,
                        resource=key,
                        detail="the API response names this principal as owner",
                    )
                )
                graph.add_relationship(RelationshipType.OWNS, response_owner, key, EvidenceState.CONFIRMED, [claim])
            continue
        table, row, pk_values = matches[0]
        graph.resource_rows[key] = (table, pk_values)
        graph.row_resources[canonical_key([table, *pk_values])] = key
        declared_row = schema.get(table)

        # A response claim is semantic evidence, corroborated by the row match.
        if response_owner is not None:
            claim = graph.add_evidence(
                Evidence(
                    source="response_claim",
                    principal=response_owner,
                    resource=key,
                    table=table,
                    detail="the API response names a configured principal as owner of the matched row",
                )
            )
            graph.add_relationship(RelationshipType.OWNS, response_owner, key, EvidenceState.CONFIRMED, [claim])

        if declared_row is None:
            continue
        for fk in declared_row.foreign_keys:
            local = row.get(fk.column)
            if local is None or isinstance(local, bool):
                continue  # nullable or missing references are never ownership
            target = anchor_by_value.get((fk.table, fk.column_ref, str(local)))
            reference = graph.add_evidence(
                Evidence(
                    source="sqlite_foreign_key",
                    resource=key,
                    entity=f"{fk.table}:{fk.column_ref}",
                    table=table,
                    column=fk.column,
                    detail="declared foreign key from the resource row",
                )
            )
            graph.add_relationship(
                RelationshipType.REFERENCES,
                key,
                f"{fk.table}:{fk.column_ref}={local}",
                EvidenceState.CONFIRMED,
                [reference],
            )
            if target is None:
                continue

            # The contract may declare this exact FK as the ownership signal.
            declared_table = declared[2] if declared is not None else None
            same_table = declared_table is None or (
                declared_table == table or declared_table.split(".", 1)[-1] == table.split(".", 1)[-1]
            )
            is_declared_owner = (
                declared is not None
                and declared[0] == "database_foreign_key"
                and declared[1] == fk.column
                and same_table
            )
            creation = (table, str(local), target) in created or (table, canonical_key(pk_values), target) in created
            if is_declared_owner:
                semantic = graph.add_evidence(
                    Evidence(
                        source="declared_semantics",
                        principal=target,
                        resource=key,
                        table=table,
                        column=fk.column,
                        detail="the application contract declares this foreign key as the owner",
                    )
                )
                graph.add_relationship(
                    RelationshipType.OWNS, target, key, EvidenceState.CONFIRMED, [reference, semantic]
                )
                declared_owner = target
                continue

            # Structural reference + anchor + creation is still a hypothesis.
            evidence = [reference]
            if creation:
                evidence.append(
                    graph.add_evidence(
                        Evidence(
                            source="write_ledger",
                            principal=target,
                            resource=key,
                            table=table,
                            detail="the anchored principal created the referenced row (creation is not ownership)",
                        )
                    )
                )
            graph.add_relationship(RelationshipType.OWNS, target, key, EvidenceState.CANDIDATE, evidence)

        if declared_owner is not None and response_owner is not None and declared_owner != response_owner:
            graph.inconclusive.setdefault(key, "the response claim and the declared ownership source disagree")

    discover_associations(graph, schema, rows, anchors, resources, contract)


def discover_associations(
    graph: OwnershipGraph,
    schema: DatabaseSchema,
    rows: dict[str, list[dict[str, Any]]],
    anchors: dict[str, Anchor],
    resources: dict[str, Resource],
    contract: RelationshipContract | None = None,
) -> None:
    """Structural discovery of association tables.

    Table shape is not permission. Rows create **CANDIDATE** sharing unless
    the trusted contract declares this exact association - table, resource
    foreign key **and principal foreign key** - as an authorization grant.
    A second foreign key that merely points at the same identity table never
    inherits the grant, because that could suppress a real finding.
    """
    anchor_by_value = {(anchor.table, anchor.column, anchor.value): anchor.principal for anchor in anchors.values()}
    resource_tables = {table for table, declared in schema.tables.items() if declared.primary_key}
    for table, declared in sorted(schema.tables.items()):
        resource_fks = [fk for fk in declared.foreign_keys if fk.table in resource_tables]
        identity_fks = [
            fk
            for fk in declared.foreign_keys
            if any((fk.table, fk.column_ref, value) in anchor_by_value for value in _values(anchor_by_value, fk))
        ]
        if not resource_fks or not identity_fks:
            continue
        try:
            grant = _resolve_declared_table(contract.sharing, table) if contract is not None else None
        except RelationshipContractError as exc:
            graph.inconclusive.setdefault(f"sharing:{table}", str(exc))
            grant = None
        declared_resource_fk = grant[0] if grant is not None else None
        declared_principal_fk = grant[1] if grant is not None else None
        declared_actions = grant[4] if grant is not None else frozenset()
        if grant is not None and not any(fk.column == declared_principal_fk for fk in identity_fks):
            graph.inconclusive.setdefault(
                f"sharing:{table}",
                "the declared principal foreign key has no anchored identity; no grant is confirmed",
            )
        for row in rows.get(table, []):
            principals_by_column: dict[str, str] = {}
            for fk in identity_fks:
                value = row.get(fk.column)
                if value is None:
                    continue
                principal = anchor_by_value.get((fk.table, fk.column_ref, str(value)))
                if principal:
                    principals_by_column[fk.column] = principal
            if not principals_by_column:
                continue
            for column, principal in sorted(principals_by_column.items()):
                for fk in resource_fks:
                    value = row.get(fk.column)
                    if value is None:
                        continue
                    resource_key = _resource_for_reference(graph, fk.table, str(value))
                    if resource_key is None:
                        continue
                    exact_grant = (
                        grant is not None and column == declared_principal_fk and str(fk.column) == declared_resource_fk
                    )
                    if exact_grant:
                        source, state = "declared_grant", EvidenceState.CONFIRMED
                        detail = "the application contract declares this exact association as an authorization grant"
                    else:
                        source, state = "association_table", EvidenceState.CANDIDATE
                        detail = "an association row relates the principal to the resource; semantics are unproven"
                    evidence = graph.add_evidence(
                        Evidence(
                            source=source,
                            principal=principal,
                            resource=resource_key,
                            table=table,
                            column=fk.column,
                            detail=detail,
                        )
                    )
                    graph.add_relationship(
                        RelationshipType.SHARED_WITH,
                        principal,
                        resource_key,
                        state,
                        [evidence],
                        actions=declared_actions if exact_grant else (),
                    )
                    if state is EvidenceState.CANDIDATE:
                        graph.inconclusive.setdefault(
                            f"sharing:{principal}:{resource_key}",
                            "association semantics are undeclared; sharing remains a candidate",
                        )


def _resource_for_reference(graph: OwnershipGraph, table: str, value: str) -> str | None:
    """Resolve a database reference to the API resource it actually identifies.

    The referenced table must match and the key must be the resource's complete
    primary key. Two tables holding the same identifier do not collide, and a
    coincidentally equal API id in an unrelated table is not accepted.
    """
    direct = graph.row_to_resource(table, (value,))
    if direct is not None:
        return direct
    candidates = [
        resource
        for resource, (mapped_table, values) in graph.resource_rows.items()
        if mapped_table == table and values == (str(value),)
    ]
    return candidates[0] if len(candidates) == 1 else None


def _values(anchor_by_value: dict[tuple[str, str, str], str], fk: Any) -> list[str]:
    return [value for (table, column, value) in anchor_by_value if table == fk.table and column == fk.column_ref]


def build_ownership_graph(
    *,
    resources: dict[str, Resource],
    traffic: Iterable[Any],
    ledger: Iterable[WriteEvent],
    schema: DatabaseSchema | None,
    rows: dict[str, list[dict[str, Any]]] | None,
    contract: RelationshipContract | None = None,
) -> OwnershipGraph:
    """Build the graph from independent, semantically grounded evidence.

    Without a schema, response-level claims naming a known principal remain
    usable, so older/conventional scans keep their behaviour. Database-level
    relationships require the relationship contract to be confirmed.
    """
    graph = OwnershipGraph()
    records = list(traffic)
    known = frozenset(
        record.principal for record in records if record.principal and record.principal != UNKNOWN_PRINCIPAL
    )
    for principal in known:
        graph.add_entity(principal, "principal")
    for key, resource in resources.items():
        graph.add_entity(key, "resource")
    if schema is not None and schema.tables:
        anchors = discover_anchors(graph, records, schema, rows or {}, contract)
        discover_relationships(graph, resources, ledger, schema, rows or {}, anchors, contract, known)
    else:
        for key, resource in resources.items():
            if resource.owner in known:
                evidence = graph.add_evidence(
                    Evidence(
                        source="response_claim",
                        principal=resource.owner,
                        resource=key,
                        detail="the API response names a configured principal as owner",
                    )
                )
                graph.add_relationship(RelationshipType.OWNS, resource.owner, key, EvidenceState.CONFIRMED, [evidence])
            elif resource.owner:
                graph.inconclusive.setdefault(key, "the response owner is not a configured principal")
    for key, resource in resources.items():
        if graph.owner_of(key) is None and key not in graph.inconclusive:
            graph.inconclusive[key] = "ownership cannot be established from semantic evidence"
    return graph
