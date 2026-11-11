"""Traffic log: the observations Mizan learns from.

The log is a JSONL file of requests and responses observed against a *normal*
deployment (or against a local twin). It is intentionally trivial to produce -
a WSGI middleware, a reverse proxy, or the application itself can append lines.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.core import Principal, Resource, actions_for

_ID_SEGMENT = re.compile(
    r"""
    ^(
        \d+                       # numeric id
      | [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}   # uuid
      | [0-9a-f]{16,}            # long hex
      | (?=.*\d)[A-Za-z0-9_-]{2,} # short id with a digit, e.g. `o1`, `user42`
    )$
    """,
    re.VERBOSE,
)


def to_template(path: str) -> str:
    """Turn `/orders/1042/items/9` into `/orders/{id}/items/{id}`."""
    parts = path.split("/")
    out = []
    for index, part in enumerate(parts):
        if index == 0:
            out.append(part)
            continue
        if _ID_SEGMENT.match(part):
            out.append("{id}")
        else:
            out.append(part)
    return "/".join(out)


def fill_template(template: str, values: list[str]) -> str:
    """Substitute concrete values back into a template."""
    result = template
    for value in values:
        result = result.replace("{id}", value, 1)
    return result


@dataclass
class TrafficRecord:
    """One observed request/response pair."""

    method: str
    path: str
    status: int
    principal: str | None = None
    template: str | None = None
    body: Any = None
    response: Any = None
    resource_type: str | None = None
    resource_id: str | None = None
    resource_owner: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.template is None:
            self.template = to_template(self.path)

    @property
    def action(self) -> str:
        return actions_for(self.method)

    @property
    def resource(self) -> Resource | None:
        if self.resource_type is None or self.resource_id is None:
            return None
        return Resource(type=self.resource_type, id=self.resource_id, owner=self.resource_owner)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "template": self.template,
            "status": self.status,
            "principal": self.principal,
            "body": self.body,
            "response": self.response,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_owner": self.resource_owner,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrafficRecord:
        known = {
            "method",
            "path",
            "template",
            "status",
            "principal",
            "body",
            "response",
            "resource_type",
            "resource_id",
            "resource_owner",
        }
        return cls(
            method=data["method"],
            path=data["path"],
            status=int(data.get("status", 0)),
            principal=data.get("principal"),
            template=data.get("template"),
            body=data.get("body"),
            response=data.get("response"),
            resource_type=data.get("resource_type"),
            resource_id=data.get("resource_id"),
            resource_owner=data.get("resource_owner"),
            extra={k: v for k, v in data.items() if k not in known},
        )


class TrafficLog:
    """Append-only JSONL log of observed traffic."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.records: list[TrafficRecord] = []

    # -- io ---------------------------------------------------------------- #

    def append(self, record: TrafficRecord) -> None:
        self.records.append(record)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> TrafficLog:
        log = cls(Path(path))
        with log.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                log.records.append(TrafficRecord.from_dict(json.loads(line)))
        return log

    def __iter__(self) -> Iterator[TrafficRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)


def infer_resource(response: Any, template: str) -> tuple[str | None, str | None, str | None]:
    """Guess `(type, id, owner)` from a JSON response body.

    The heuristic is intentionally simple: the last non-placeholder path segment
    gives the type, an ``id`` field gives the id and an ``owner_id``/``user_id``
    field gives the owner.
    """
    if not isinstance(response, dict):
        return None, None, None
    resource_id = response.get("id")
    if not isinstance(resource_id, (str, int)):
        return None, None, None
    owner = None
    for key in ("owner_id", "user_id", "owner", "principal_id", "account_id"):
        value = response.get(key)
        if isinstance(value, (str, int)):
            owner = str(value)
            break
    segments = [segment for segment in template.split("/") if segment]
    placeholder = next((index for index, segment in enumerate(segments) if segment.startswith("{")), None)
    if placeholder is not None:
        # `/orders/{id}/approve` describes the `orders` collection.
        resource_type = segments[placeholder - 1] if placeholder > 0 else None
    else:
        resource_type = segments[-1] if segments else None
        # `/users/me` describes the `users` collection, not a `me` resource.
        while resource_type and resource_type.lower() in {"me", "self", "current", "profile"}:
            segments = segments[:-1]
            resource_type = segments[-1] if segments else None
    return resource_type, str(resource_id), owner


def principals_from_records(
    records: Iterable[TrafficRecord], tokens: dict[str, str] | None = None
) -> dict[str, Principal]:
    """Build the principal table from observed traffic."""
    principals: dict[str, Principal] = {}
    tokens = tokens or {}
    for record in records:
        if record.principal is None:
            continue
        if record.principal not in principals:
            principals[record.principal] = Principal(id=record.principal, roles=(), token=tokens.get(record.principal))
    for pid, principal in list(principals.items()):
        if principal.token is None and pid in tokens:
            principals[pid] = Principal(id=principal.id, roles=principal.roles, token=tokens[pid])
    return principals
