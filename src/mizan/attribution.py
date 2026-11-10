"""Data-level attribution: who changed this row, without changing the application.

The ledger of writes is usually the hard part of onboarding. It normally needs
a hook inside the application, a trigger in the database, or log mining.

This module takes a different route: it *watches the data*. Take a snapshot of
every table, send one request, take another snapshot, and the difference is
the write - attributed to the identity that made the request.

    attributor = SqliteAttributor(Path("app.db"))
    before = attributor.snapshot()
    session.post("/orders/1/approve")
    events = attributor.diff(before, principal="alice", method="POST", path="/orders/1/approve")

It works for any SQLite application, needs no cooperation from the code, and
turns the hardest onboarding problem into a solved one.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mizan.taint import WriteEvent

#: Columns that usually name the owner of a row.
OWNER_COLUMNS = ("owner_id", "user_id", "owner", "account_id", "tenant_id")


@dataclass
class TableSnapshot:
    """The content of one table, keyed by its primary key."""

    name: str
    rows: dict[str, dict[str, Any]]


class SqliteAttributor:
    """Derive write events by diffing the database around a request."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)

    # -- snapshots ---------------------------------------------------------- #

    def snapshot(self) -> dict[str, TableSnapshot]:
        """Read every table of the database."""
        if not Path(self.db_path).exists():
            return {}
        connection = sqlite3.connect(self.db_path, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            tables = [
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            ]
            result: dict[str, TableSnapshot] = {}
            for table in tables:
                try:
                    rows = connection.execute(f'SELECT rowid AS __rowid__, * FROM "{table}"').fetchall()
                except sqlite3.Error:
                    continue
                snapshot = TableSnapshot(name=table, rows={})
                for row in rows:
                    data = dict(row)
                    key = str(data.pop("__rowid__"))
                    snapshot.rows[key] = data
                result[table] = snapshot
            return result
        finally:
            connection.close()

    # -- diffing ------------------------------------------------------------ #

    def diff(
        self,
        before: dict[str, TableSnapshot],
        *,
        principal: str,
        method: str,
        path: str,
        request_id: str = "",
        source_fields: set[str] | None = None,
    ) -> list[WriteEvent]:
        """The writes that happened since the snapshot was taken."""
        after = self.snapshot()
        events: list[WriteEvent] = []
        for table, current in after.items():
            previous = before.get(table, TableSnapshot(name=table, rows={}))
            # Inserted rows
            for key, values in current.rows.items():
                if key in previous.rows:
                    continue
                events.append(
                    WriteEvent(
                        ts=0.0,
                        request_id=request_id,
                        principal=principal,
                        method=method,
                        path=path,
                        table=table,
                        row_id=key,
                        columns=dict(values),
                        source_fields=set(source_fields or ()),
                        row_owner=_owner(values),
                    )
                )
            # Changed rows
            for key, values in current.rows.items():
                old = previous.rows.get(key)
                if old is None:
                    continue
                changed = {
                    column: value for column, value in values.items() if old.get(column) != value
                }
                if not changed:
                    continue
                events.append(
                    WriteEvent(
                        ts=0.0,
                        request_id=request_id,
                        principal=principal,
                        method=method,
                        path=path,
                        table=table,
                        row_id=key,
                        columns=changed,
                        source_fields=set(source_fields or ()),
                        row_owner=_owner(values),
                    )
                )
            # Deleted rows
            for key, values in previous.rows.items():
                if key in current.rows:
                    continue
                events.append(
                    WriteEvent(
                        ts=0.0,
                        request_id=request_id,
                        principal=principal,
                        method=method,
                        path=path,
                        table=table,
                        row_id=key,
                        columns={column: None for column in values},
                        source_fields=set(source_fields or ()),
                        row_owner=_owner(values),
                    )
                )
        return events


def _owner(values: dict[str, Any]) -> str | None:
    for column in OWNER_COLUMNS:
        value = values.get(column)
        if isinstance(value, (str, int)):
            return str(value)
    return None


def write_events_to_jsonl(events: list[WriteEvent], path: str | Path) -> None:
    """Append events to a ledger file."""
    with Path(path).open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
