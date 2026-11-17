"""Write-taint: attribute every database write to the principal that caused it.

This is the part no off-the-shelf scanner does. Instead of looking at HTTP
traffic and guessing, we look at *the data* and ask: who changed this row, and
were they allowed to?
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from mizan.core import (
    OUTCOME_PRECEDENCE,
    UNKNOWN_PRINCIPAL,
    AuthorizationOutcome,
    Policy,
    Principal,
    Resource,
    Step,
    Violation,
    actions_for,
)
from mizan.tokens import mask_authorization

# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #


@dataclass
class WriteEvent:
    """A single row mutation, attributed to a principal."""

    ts: float
    request_id: str
    principal: str
    method: str
    path: str
    table: str
    row_id: str
    columns: dict[str, Any] = field(default_factory=dict)
    #: fields the client actually sent - anything else was written by the server
    source_fields: set[str] = field(default_factory=set)
    row_owner: str | None = None
    status: int = 200
    method_args: dict[str, Any] = field(default_factory=dict)
    #: The row's identity from declared primary-key metadata, when known.
    #: Older ledgers do not have it; ``resource_key`` keeps the legacy rowid.
    row_key: str | None = None

    @property
    def action(self) -> str:
        return actions_for(self.method)

    @property
    def resource_key(self) -> str:
        return f"{self.table}:{self.row_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "request_id": self.request_id,
            "principal": self.principal,
            "method": self.method,
            "path": self.path,
            "table": self.table,
            "row_id": self.row_id,
            "columns": self.columns,
            "source_fields": sorted(self.source_fields),
            "row_owner": self.row_owner,
            "status": self.status,
            "method_args": self.method_args,
            "row_key": self.row_key,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WriteEvent:
        return cls(
            ts=float(data.get("ts", 0.0)),
            request_id=str(data.get("request_id", "")),
            principal=str(data.get("principal", "")),
            method=str(data.get("method", "")),
            path=str(data.get("path", "")),
            table=str(data.get("table", "")),
            row_id=str(data.get("row_id", "")),
            columns=dict(data.get("columns", {})),
            source_fields=set(data.get("source_fields", [])),
            row_owner=data.get("row_owner"),
            status=int(data.get("status", 200)),
            method_args=dict(data.get("method_args", {})),
            row_key=data.get("row_key"),
        )


class Ledger:
    """JSONL ledger of write events."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.events: list[WriteEvent] = []

    def append(self, event: WriteEvent) -> None:
        self.events.append(event)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> Ledger:
        ledger = cls(Path(path))
        with ledger.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    ledger.events.append(WriteEvent.from_dict(json.loads(line)))
        return ledger

    def by_principal(self) -> dict[str, list[WriteEvent]]:
        grouped: dict[str, list[WriteEvent]] = {}
        for event in self.events:
            grouped.setdefault(event.principal, []).append(event)
        return grouped

    def writes_to(self, table: str, row_id: str) -> list[WriteEvent]:
        return [event for event in self.events if event.table == table and event.row_id == row_id]


# --------------------------------------------------------------------------- #
# Postgres adapter
# --------------------------------------------------------------------------- #

_STATEMENT = re.compile(r"statement:\s*(?P<sql>.*)$", re.IGNORECASE)
_APP_NAME = re.compile(r"app(?:lication)?[=:]?\s*(?P<app>[A-Za-z0-9_.:-]+)", re.IGNORECASE)
_INSERT = re.compile(
    r"INSERT\s+INTO\s+(?P<table>[\w.\"]+)\s*\((?P<columns>[^)]*)\)\s*VALUES\s*\((?P<values>[^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_UPDATE = re.compile(
    r"UPDATE\s+(?P<table>[\w.\"]+)\s+SET\s+(?P<assignments>.*?)(?:\s+WHERE\s+(?P<where>.*))?$",
    re.IGNORECASE | re.DOTALL,
)
_WHERE_ID = re.compile(r"\"?(?P<column>\w+)\"?\s*=\s*'?\"?(?P<value>[^'\s]+)", re.IGNORECASE)


def _unquote(identifier: str) -> str:
    return identifier.strip().strip('"').strip("`")


def _split_values(raw: str) -> list[str]:
    values: list[str] = []
    current = ""
    in_quote = False
    for char in raw:
        if char == "'":
            in_quote = not in_quote
            current += char
            continue
        if char == "," and not in_quote:
            values.append(current.strip())
            current = ""
            continue
        current += char
    if current.strip():
        values.append(current.strip())
    return values


class PostgresLogParser:
    """Turn Postgres statement logs into attributed write events.

    The application is expected to tag its connections with
    ``SET application_name = 'mizan:<principal>'``; the parser reads the
    application name from the log prefix and attributes the statement to that
    principal.
    """

    def __init__(self, app_name_prefix: str = "mizan:") -> None:
        self.app_name_prefix = app_name_prefix
        self._app_pattern = re.compile(rf"(?P<app>{re.escape(app_name_prefix)}[A-Za-z0-9_.-]+)")

    def principal_from_app(self, app_name: str | None) -> str | None:
        if not app_name or not app_name.startswith(self.app_name_prefix):
            return None
        return app_name[len(self.app_name_prefix) :]

    def parse(self, lines: Iterable[str]) -> list[WriteEvent]:
        events: list[WriteEvent] = []
        for index, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            app_match = self._app_pattern.search(line)
            app_name = app_match.group("app") if app_match else None
            principal = self.principal_from_app(app_name)
            statement = _STATEMENT.search(line)
            if statement is None:
                continue
            sql = statement.group("sql").strip().rstrip(";")
            event = self._parse_sql(sql, principal, request_id=f"pg-{index}")
            if event is not None:
                events.append(event)
        return events

    def _parse_sql(self, sql: str, principal: str | None, request_id: str) -> WriteEvent | None:
        insert = _INSERT.search(sql)
        if insert is not None:
            table = _unquote(insert.group("table"))
            columns = [_unquote(column) for column in insert.group("columns").split(",")]
            values = _split_values(insert.group("values"))
            row_id = values[0] if values else ""
            payload = dict(zip(columns, values))
            return WriteEvent(
                ts=0.0,
                request_id=request_id,
                principal=principal or "unknown",
                method="POST",
                path=f"/{table}",
                table=table,
                row_id=row_id,
                columns=payload,
                source_fields=set(columns),
            )
        update = _UPDATE.search(sql)
        if update is not None:
            table = _unquote(update.group("table"))
            assignments = update.group("assignments") or ""
            where = update.group("where") or ""
            columns: dict[str, Any] = {}
            for assignment in _split_values(assignments):
                if "=" not in assignment:
                    continue
                name, _, value = assignment.partition("=")
                columns[_unquote(name)] = value.strip().strip("'")
            row_id = ""
            where_match = _WHERE_ID.search(where)
            if where_match:
                row_id = where_match.group("value")
            return WriteEvent(
                ts=0.0,
                request_id=request_id,
                principal=principal or "unknown",
                method="PATCH",
                path=f"/{table}",
                table=table,
                row_id=row_id,
                columns=columns,
                source_fields=set(columns),
            )
        return None


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


class TaintAnalyzer:
    """Turn attributed write events into proven violations.

    Two modes exist, and only one of them can make a confirmed L3 claim:

    * **Legacy / no database** (``graph is None``): the historical behaviour,
      which uses ``resource.owner`` and the ``row_owner`` hint. This stays for
      ledgers without a database and for callers that never had a graph.
    * **Graph-backed** (``graph`` is an ``OwnershipGraph``): a write is an L3
      finding only when the graph maps the changed row to exactly one API
      resource and holds a *confirmed, semantically justified* owner for it.
      ``row_owner`` and the conventional owner columns are diagnostics here,
      never evidence. An unresolved case is recorded in ``inconclusive`` so
      that uncertainty stays visible instead of becoming a clean result.
    """

    def __init__(self, policy: Policy, strict: bool = False, graph: Any | None = None) -> None:
        self.policy = policy
        self.strict = strict
        self.graph = graph
        #: Writes whose author could not be established. They are evidence of
        #: a write, but not of a breach, so they are never reported as one.
        self.unattributed: list[WriteEvent] = []
        #: Writes that were attributed but could not be decided. Reported as
        #: coverage, never as a vulnerability and never as a clean result.
        self.inconclusive: list[dict[str, str]] = []
        self._inconclusive_seen: set[tuple[str, str, str]] = set()
        #: One explicit outcome per authorization check, including checks that
        #: resolved through a grant. This is the source for per-law coverage;
        #: an authorized check is never recorded as inconclusive.
        self.outcomes: list[dict[str, str]] = []
        self._outcome_index: dict[tuple[str, str, str, str], int] = {}

    def analyze(self, events: Iterable[WriteEvent]) -> list[Violation]:
        violations: list[Violation] = []
        for event in events:
            if not event.principal or event.principal == UNKNOWN_PRINCIPAL:
                # Without an author there is nobody to blame and nothing to
                # prove: the write is kept, the breach is not claimed.
                self.unattributed.append(event)
                self._record(event, "the write could not be attributed to a principal")
                self._outcome(event, event.resource_key, AuthorizationOutcome.INCONCLUSIVE)
                continue
            violations.extend(self._analyze_event(event))
        return violations

    # -- individual checks ------------------------------------------------- #

    @staticmethod
    def _check_key(event: WriteEvent, resource_key: str) -> tuple[str, str, str, str]:
        return ("L3", event.action, str(resource_key), event.principal)

    def _outcome(self, event: WriteEvent, resource_key: str, outcome: AuthorizationOutcome) -> AuthorizationOutcome:
        """Store one FINAL outcome per logical (law, action, resource, principal)."""
        key = self._check_key(event, resource_key)
        position = self._outcome_index.get(key)
        if position is None:
            self._outcome_index[key] = len(self.outcomes)
            self.outcomes.append(
                {
                    "law": "L3",
                    "action": event.action,
                    "resource": str(resource_key),
                    "principal": event.principal,
                    "outcome": outcome.value,
                }
            )
            return outcome
        previous = AuthorizationOutcome(self.outcomes[position]["outcome"])
        if OUTCOME_PRECEDENCE[outcome] <= OUTCOME_PRECEDENCE[previous]:
            return previous
        self.outcomes[position] = {
            "law": "L3",
            "action": event.action,
            "resource": str(resource_key),
            "principal": event.principal,
            "outcome": outcome.value,
        }
        if outcome is not AuthorizationOutcome.INCONCLUSIVE:
            kept = [
                item
                for item in self.inconclusive
                if (
                    str(item.get("law")),
                    str(item.get("action")),
                    str(item.get("resource")),
                    str(item.get("principal")),
                )
                != key
            ]
            if len(kept) != len(self.inconclusive):
                self.inconclusive = kept
                self._inconclusive_seen = {
                    (str(item.get("law")), str(item.get("resource")), str(item.get("reason")))
                    for item in self.inconclusive
                }
        return outcome

    def _record(self, event: WriteEvent, reason: str) -> None:
        """Keep one explicit reason per (table, row, reason)."""
        key = (event.table, str(event.row_id), reason)
        if key in self._inconclusive_seen:
            return
        self._inconclusive_seen.add(key)
        self.inconclusive.append(
            {
                "law": "L3",
                "resource": event.resource_key,
                "reason": reason,
                "action": event.action,
                "principal": event.principal,
            }
        )

    def _identity_components(self, value: str) -> tuple[str, ...]:
        """Parse a ledger row identity: a JSON array or a legacy scalar."""
        text = str(value)
        if text.startswith("[") and text.endswith("]"):
            try:
                decoded = json.loads(text)
            except ValueError:
                return (text,)
            if isinstance(decoded, list):
                return tuple(str(item) for item in decoded)
        return (text,)

    def _mapped_resource(self, event: WriteEvent) -> str | None:
        """Resolve the changed row to one API resource, or ``None``.

        The complete declared primary key is required. A legacy event without
        ``row_key`` is accepted only when exactly one resource is mapped to
        the same table and the same single-column identifier.
        """
        graph = self.graph
        components = self._identity_components(event.row_key) if event.row_key else None
        if components:
            mapped = graph.row_to_resource(event.table, components)
            if mapped is not None:
                return mapped
            return None
        candidates = [
            resource
            for resource, (table, values) in graph.resource_rows.items()
            if table == event.table and values == (str(event.row_id),)
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _resource_for(self, event: WriteEvent) -> Resource:
        known = self.policy.resource(event.resource_key)
        if known is not None:
            return known
        return Resource(type=event.table, id=event.row_id, owner=event.row_owner)

    def _analysis_resource(self, event: WriteEvent, mapped: str | None) -> Resource:
        """The resource used by checks that do not decide ownership (L4).

        In graph-backed mode the mapped API resource is preferred and no
        legacy owner hint is attached; otherwise the historical resolution is
        kept so that L4 keeps working.
        """
        if self.graph is None:
            return self._resource_for(event)
        if mapped is not None:
            known = self.policy.resource(mapped)
            if known is not None:
                return known
            resource_type, _, resource_id = mapped.partition(":")
            return Resource(type=resource_type or event.table, id=resource_id or event.row_id)
        known = self.policy.resource(event.resource_key)
        if known is not None:
            return known
        return Resource(type=event.table, id=event.row_id)

    def _graph_violation(self, event: WriteEvent, principal: Principal, owner: str, mapped: str) -> Violation:
        evidence_ids = sorted(
            {
                evidence
                for relation in self.graph.relationships
                if relation.type is not None
                and getattr(relation.type, "value", relation.type) == "OWNS"
                and relation.object in {mapped, event.resource_key}
                for evidence in relation.evidence
            }
        )
        return Violation(
            law="L3",
            title=f"{principal.id} wrote a row owned by {owner}",
            detail=(
                f"`{event.method} {event.path}` changed `{event.table}:{event.row_id}`, "
                f"which maps to `{mapped}` and belongs to `{owner}`, while the request was "
                f"authenticated as `{principal.id}`. The write is not permitted for that row."
            ),
            severity="high",
            principal=principal.id,
            resource=event.resource_key,
            action=event.action,
            evidence={
                "owner": owner,
                "event": event.to_dict(),
                "columns": sorted(event.columns),
                "resource_mapping": {
                    "database_table": event.table,
                    "database_key": event.row_key or event.row_id,
                    "api_resource": mapped,
                },
                "ownership_evidence": evidence_ids,
            },
            steps=[self._step(event, principal)],
        )

    def _step(self, event: WriteEvent, principal: Principal) -> Step:
        return Step(
            method=event.method,
            url=event.path,
            headers=mask_authorization(
                {"Authorization": f"Bearer {principal.token}"} if principal.token else {},
                principal.id,
            ),
            body=event.method_args.get("body"),
            note="the write that tainted the row",
        )

    def _legacy_l3(self, event: WriteEvent, principal: Principal, resource: Resource) -> list[Violation]:
        """The historical L3 check: only used when no graph is attached."""
        if resource.owner is None or resource.owner == principal.id:
            self._outcome(event, resource.key, AuthorizationOutcome.DECIDED)
            return []
        if self.policy.permitted(principal, resource, event.action):
            self._outcome(event, resource.key, AuthorizationOutcome.DECIDED)
            return []
        self._outcome(event, resource.key, AuthorizationOutcome.VIOLATION)
        return [
            Violation(
                law="L3",
                title=f"{principal.id} wrote a row owned by {resource.owner}",
                detail=(
                    f"`{event.method} {event.path}` changed `{event.table}:{event.row_id}` "
                    f"which is owned by `{resource.owner}`, while the request was authenticated as "
                    f"`{principal.id}`. The write is not permitted for that row."
                ),
                severity="high",
                principal=principal.id,
                resource=resource.key,
                action=event.action,
                evidence={
                    "event": event.to_dict(),
                    "row_owner": resource.owner,
                    "columns": sorted(event.columns),
                },
                steps=[self._step(event, principal)],
            )
        ]

    def _graph_l3(self, event: WriteEvent, principal: Principal, resource: Resource) -> list[Violation]:
        """L3 under graph-backed mode: confirmed ownership or no finding."""
        mapped = self._mapped_resource(event)
        if mapped is None:
            self._record(
                event,
                "the changed database row does not map uniquely to an API resource",
            )
            self._outcome(event, event.resource_key, AuthorizationOutcome.INCONCLUSIVE)
            return []
        state = self.graph.owner_state(mapped)
        state_name = getattr(state, "value", str(state))
        if state_name != "CONFIRMED":
            self._record(event, f"ownership is {state_name}; a confirmed owner is required")
            self._outcome(event, mapped, AuthorizationOutcome.INCONCLUSIVE)
            return []
        owner = self.graph.owner_of(mapped)
        if owner is None:
            self._record(event, "ownership is CONFIRMED but not unique")
            self._outcome(event, mapped, AuthorizationOutcome.INCONCLUSIVE)
            return []
        if owner == principal.id:
            self._outcome(event, mapped, AuthorizationOutcome.DECIDED)
            return []
        if self.graph.explained_by_sharing(owner, principal.id, mapped, event.action):
            # A confirmed grant for THIS action resolves the check. It is not
            # uncertainty, and it can never explain a different operation.
            self._outcome(event, mapped, AuthorizationOutcome.ALLOWED_BY_GRANT)
            return []
        resolved = self.policy.resource(mapped) or Resource(type=resource.type, id=resource.id, owner=owner)
        if self.policy.permitted(principal, replace(resolved, owner=owner), event.action):
            self._outcome(event, mapped, AuthorizationOutcome.DECIDED)
            return []
        self._outcome(event, mapped, AuthorizationOutcome.VIOLATION)
        return [self._graph_violation(event, principal, owner, mapped)]

    def _analyze_event(self, event: WriteEvent) -> list[Violation]:
        violations: list[Violation] = []
        principal = self.policy.principal(event.principal)
        mapped = self._mapped_resource(event) if self.graph is not None else None
        resource = self._analysis_resource(event, mapped)

        # L3 - the write itself must be allowed for this exact row. In
        # graph-backed mode a single standard decides: the graph.
        if self.graph is None:
            violations.extend(self._legacy_l3(event, principal, resource))
        else:
            violations.extend(self._graph_l3(event, principal, resource))

        # L4 - nobody may create authority through a request.
        #
        # The database cannot tell whether the client sent a field or the
        # server set it. A field that the client did not send is not evidence
        # of anything, so the check only looks at the fields the request
        # actually carried (`source_fields`). When those are unknown - as they
        # are for a database-only ledger - no finding is made.
        if not event.source_fields:
            return violations
        for column, value in event.columns.items():
            if column not in event.source_fields:
                continue
            if not self.policy.authority_fields or column.lower() not in {
                field.lower() for field in self.policy.authority_fields
            }:
                continue
            if principal.is_privileged():
                continue
            if not self.policy.permitted(principal, resource, "admin"):
                violations.append(
                    Violation(
                        law="L4",
                        title=f"`{principal.id}` created authority by writing `{column}`",
                        detail=(
                            f"`{event.method} {event.path}` set `{column}={value!r}` on `{resource.key}`. "
                            f"`{column}` carries authority and the request was not made by a privileged principal."
                        ),
                        severity="critical",
                        principal=principal.id,
                        resource=resource.key,
                        action=event.action,
                        evidence={
                            "event": event.to_dict(),
                            "column": column,
                            "value": value,
                            "client_supplied": column in event.source_fields,
                        },
                        steps=[self._step(event, principal)],
                    )
                )

        # L3 - unexplained writes: the server changed a field the client never sent
        # and that is not a known server-managed field. Off by default to keep
        # the signal clean.
        if self.strict:
            managed = self.policy.server_managed_fields.get(event.table, set())
            for column in event.columns:
                if column in event.source_fields or column in managed:
                    continue
                violations.append(
                    Violation(
                        law="L3",
                        title=f"Unattributed write to `{column}`",
                        detail=(
                            f"`{event.method} {event.path}` wrote `{column}` although the client never sent it "
                            f"and it is not a known server-managed field."
                        ),
                        severity="low",
                        principal=principal.id,
                        resource=resource.key,
                        action=event.action,
                        evidence={"event": event.to_dict(), "column": column},
                    )
                )
        return violations
