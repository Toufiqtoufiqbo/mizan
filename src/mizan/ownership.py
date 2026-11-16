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
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mizan.attribution import DatabaseSchema
from mizan.core import UNKNOWN_PRINCIPAL, Resource
from mizan.taint import WriteEvent

#: The conventional response fields that remain one *source* of ownership
#: evidence. They are not the only source and not an authoritative one: a
#: contradiction with data-level evidence makes the relationship ambiguous.
RESPONSE_OWNER_FIELDS = ("owner_id", "user_id", "owner", "principal_id", "account_id")


@dataclass(frozen=True)
class Observation:
    """A principal's own identity response - no token, no raw payload copy."""

    principal: str
    response: Any


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            "subject": self.subject,
            "object": self.object,
            "state": str(self.state),
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Relationship:
        return cls(
            type=RelationshipType(str(data["type"])),
            subject=str(data["subject"]),
            object=str(data["object"]),
            state=EvidenceState(str(data.get("state", "UNKNOWN"))),
            evidence=tuple(data.get("evidence", ())),
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
    """resource key -> why ownership could not be established."""

    # -- building ----------------------------------------------------------- #

    def add_entity(self, key: str, kind: str) -> None:
        self.entities.setdefault(key, kind)

    def add_evidence(self, evidence: Evidence) -> str:
        evidence_id = evidence.id
        self.evidence.setdefault(evidence_id, evidence)
        return evidence_id

    def add_relationship(
        self, type_: RelationshipType, subject: str, object_: str, state: EvidenceState, evidence: Iterable[str] = ()
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
            existing = Relationship(type_, subject, object_, state, ())
            self.relationships.append(existing)
        elif existing.state != state and {existing.state, state} <= {EvidenceState.CONFIRMED, EvidenceState.CANDIDATE}:
            existing.state = max(existing.state, state, key=lambda s: order[s])
        elif existing.state != state:
            existing.state = EvidenceState.CONTRADICTED
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

    def explained_by_sharing(self, owner: str, other: str, resource_key: str) -> bool:
        """Whether an explicit relationship explains this principal's access.

        Sharing is an explanation for access, not permission and not
        ownership. Only confirmed associations suppress a finding.
        """
        return any(
            r.type in {RelationshipType.SHARED_WITH, RelationshipType.MEMBER_OF}
            and r.state is EvidenceState.CONFIRMED
            and r.subject == other
            and r.object == resource_key
            for r in self.relationships
        )

    def counts(self) -> dict[str, int]:
        counts = {state.value: 0 for state in EvidenceState}
        for relation in self.relationships:
            counts[relation.state.value] += 1
        return counts

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
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OwnershipGraph:
        graph = cls()
        graph.entities = dict(data.get("entities", {}))
        graph.evidence = {key: Evidence.from_dict(item) for key, item in data.get("evidence", {}).items()}
        graph.relationships = [Relationship.from_dict(item) for item in data.get("relationships", [])]
        graph.inconclusive = dict(data.get("inconclusive", {}))
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
) -> list[tuple[str, dict[str, Any]]]:
    """Find declared primary-key rows whose value is the resource's public id."""
    matches: list[tuple[str, dict[str, Any]]] = []
    for table, declared in schema.tables.items():
        columns = declared.primary_key or tuple(column.name for column in declared.columns)
        if not columns:
            continue
        for row in rows.get(table, []):
            if any(str(row.get(column)) == resource_id and row.get(column) is not None for column in columns):
                matches.append((table, row))
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
) -> dict[str, Anchor]:
    """Anchor each configured principal to a database identity record.

    A candidate must be supported by *distinct* values from at least two
    different principals (the repeatability requirement). The choice is made
    on structural grounds - primary key, then a column other tables point at,
    then uniqueness - never on a table name such as ``users``.
    """
    observed: dict[str, set[str]] = {}
    for record in records:
        if not record.principal or record.principal == UNKNOWN_PRINCIPAL:
            continue
        observed.setdefault(record.principal, set()).update(_scalars(record.response))

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
    for principal, candidates in sorted(ranked.items()):
        best = max(score for score, _, _, _ in candidates)
        winners = [candidate for candidate in candidates if candidate[0] == best]
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
) -> None:
    """Apply the conservative inference rules and fill the graph."""
    anchor_by_value = {(anchor.table, anchor.column, anchor.value): anchor.principal for anchor in anchors.values()}
    writes = list(ledger)
    created: set[tuple[str, str, str]] = set()
    for event in writes:
        if event.principal and event.principal != UNKNOWN_PRINCIPAL and event.row_key:
            created.add((event.table, event.row_key, event.principal))
        if event.principal and event.principal != UNKNOWN_PRINCIPAL:
            created.add((event.table, str(event.row_id), event.principal))

    for key, resource in sorted(resources.items()):
        graph.add_entity(key, "resource")
        if resource.id is None:
            graph.inconclusive[key] = "no public identifier"
            continue

        # Source 1: a response-level owner claim (the conventional source).
        response_owner = resource.owner
        if response_owner:
            evidence = graph.add_evidence(
                Evidence(
                    source="response_field",
                    principal=response_owner,
                    resource=key,
                    detail="the API response names this principal as owner",
                )
            )
            graph.add_relationship(RelationshipType.OWNS, response_owner, key, EvidenceState.CONFIRMED, [evidence])

        matches = _find_rows(resource.id, schema, rows)
        if len(matches) != 1:
            if not response_owner:
                graph.inconclusive[key] = "the public identifier does not match exactly one declared primary-key row"
            continue
        table, row = matches[0]
        graph.add_entity(f"{table}:{resource.id}", "database")
        declared = schema.get(table)
        if declared is None:
            continue
        for fk in declared.foreign_keys:
            local = row.get(fk.column)
            if local is None or isinstance(local, bool):
                continue  # nullable / missing references are never ownership
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
            corroboration: list[str] = []
            # The anchor is independent evidence: a repeatable, distinct
            # mapping from several principals to this exact database record.
            # A direct foreign key to an anchored principal is ownership -
            # unlike a foreign key to an intermediate entity (a workspace or
            # tenant), which stays a plain reference.
            anchor = anchors[target]
            if anchor.evidence:
                corroboration.append(anchor.evidence)
            if response_owner == target:
                corroboration.append(
                    graph.add_evidence(
                        Evidence(
                            source="response_field",
                            principal=target,
                            resource=key,
                            detail="the API response agrees with the foreign key",
                        )
                    )
                )
            if (table, str(local), target) in created or (table, resource.id, target) in created:
                corroboration.append(
                    graph.add_evidence(
                        Evidence(
                            source="write_ledger",
                            principal=target,
                            resource=key,
                            table=table,
                            detail="the anchored principal created the referenced row",
                        )
                    )
                )
            if corroboration:
                graph.add_relationship(
                    RelationshipType.OWNS, target, key, EvidenceState.CONFIRMED, [reference, *corroboration]
                )
            else:
                graph.add_relationship(RelationshipType.OWNS, target, key, EvidenceState.CANDIDATE, [reference])

    discover_associations(graph, schema, rows, anchors, resources)


def discover_associations(
    graph: OwnershipGraph,
    schema: DatabaseSchema,
    rows: dict[str, list[dict[str, Any]]],
    anchors: dict[str, Anchor],
    resources: dict[str, Resource],
) -> None:
    """Structural discovery of association tables.

    A table with foreign keys to a resource table and to an anchored identity
    table is an association table. Its rows explain access; they never create
    ownership. This is structural, not a naming convention.
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
        for row in rows.get(table, []):
            principal_values = []
            for fk in identity_fks:
                value = row.get(fk.column)
                if value is None:
                    continue
                principal = anchor_by_value.get((fk.table, fk.column_ref, str(value)))
                if principal:
                    principal_values.append(principal)
            if not principal_values:
                continue
            for principal in principal_values:
                for fk in resource_fks:
                    value = row.get(fk.column)
                    if value is None:
                        continue
                    resource_key = _resource_key_for(resources, str(value))
                    if resource_key is None:
                        continue
                    evidence = graph.add_evidence(
                        Evidence(
                            source="association_table",
                            principal=principal,
                            resource=resource_key,
                            table=table,
                            column=fk.column,
                            detail="an association row explicitly relates the principal to the resource",
                        )
                    )
                    graph.add_relationship(
                        RelationshipType.SHARED_WITH,
                        principal,
                        resource_key,
                        EvidenceState.CONFIRMED,
                        [evidence],
                    )


def _values(anchor_by_value: dict[tuple[str, str, str], str], fk: Any) -> list[str]:
    return [value for (table, column, value) in anchor_by_value if table == fk.table and column == fk.column_ref]


def _resource_key_for(resources: dict[str, Resource], value: str) -> str | None:
    """Resolve a database key to a discovered resource by its public id."""
    matches = [key for key, resource in resources.items() if resource.id is not None and str(resource.id) == value]
    return matches[0] if len(matches) == 1 else None


def build_ownership_graph(
    *,
    resources: dict[str, Resource],
    traffic: Iterable[Any],
    ledger: Iterable[WriteEvent],
    schema: DatabaseSchema | None,
    rows: dict[str, list[dict[str, Any]]] | None,
) -> OwnershipGraph:
    """Build the graph from independent evidence sources.

    With no database schema at all the graph still records response-level
    ownership, so existing scans keep their behaviour. A database is needed
    only for schema-level discovery.
    """
    graph = OwnershipGraph()
    records = list(traffic)
    for record in records:
        if record.principal and record.principal != UNKNOWN_PRINCIPAL:
            graph.add_entity(record.principal, "principal")
    for key, resource in resources.items():
        graph.add_entity(key, "resource")
    if schema is not None and schema.tables:
        anchors = discover_anchors(graph, records, schema, rows or {})
        discover_relationships(graph, resources, ledger, schema, rows or {}, anchors)
    elif any(resource.owner for resource in resources.values()):
        for key, resource in resources.items():
            if resource.owner:
                evidence = graph.add_evidence(
                    Evidence(
                        source="response_field",
                        principal=resource.owner,
                        resource=key,
                        detail="the API response names this principal as owner",
                    )
                )
                graph.add_relationship(RelationshipType.OWNS, resource.owner, key, EvidenceState.CONFIRMED, [evidence])
    for key, resource in resources.items():
        if graph.owner_of(key) is None and key not in graph.inconclusive:
            graph.inconclusive[key] = "no confirmed owner from independent evidence"
    return graph
