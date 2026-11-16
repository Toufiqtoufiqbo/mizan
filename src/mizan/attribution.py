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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.taint import WriteEvent

#: Columns that usually name the owner of a row.
OWNER_COLUMNS = ("owner_id", "user_id", "owner", "account_id", "tenant_id")


@dataclass(frozen=True)
class Column:
    """One declared column of a database table."""

    name: str
    type: str = ""
    primary_key: int = 0  # 1-based position in the primary key; 0 means not part of it
    not_null: bool = False
    unique: bool = False


@dataclass(frozen=True)
class ForeignKey:
    """One declared foreign key: local column -> remote table/column."""

    column: str
    table: str
    column_ref: str


@dataclass(frozen=True)
class TableSchema:
    """Declared structure of one table, from schema metadata only."""

    name: str
    columns: tuple[Column, ...] = ()
    foreign_keys: tuple[ForeignKey, ...] = ()

    @property
    def primary_key(self) -> tuple[str, ...]:
        """The primary-key columns in declaration order (may be composite)."""
        ordered = sorted((column for column in self.columns if column.primary_key), key=lambda c: c.primary_key)
        return tuple(column.name for column in ordered)

    def column(self, name: str) -> Column | None:
        return next((column for column in self.columns if column.name == name), None)


@dataclass(frozen=True)
class DatabaseSchema:
    """The declared structure of a whole database."""

    tables: dict[str, TableSchema] = field(default_factory=dict)

    def get(self, table: str) -> TableSchema | None:
        return self.tables.get(table)

    def to_dict(self) -> dict[str, Any]:
        """A compact, credential-free description for explainability."""
        return {
            name: {
                "primary_key": list(table.primary_key),
                "columns": [
                    {"name": column.name, "type": column.type, "pk": column.primary_key, "unique": column.unique}
                    for column in table.columns
                ],
                "foreign_keys": [
                    {"column": fk.column, "table": fk.table, "references": fk.column_ref} for fk in table.foreign_keys
                ],
            }
            for name, table in sorted(self.tables.items())
        }


def quote_identifier(name: str) -> str:
    """Quote an SQLite identifier so no name can escape the quoting.

    Table and column names here come from schema metadata, but quoting them
    properly is still the right default: a name with a double quote in it must
    never be able to change the statement.
    """
    return '"' + str(name).replace('"', '""') + '"'


@dataclass
class TableSnapshot:
    """The content of one table, keyed by its rowid.

    ``keys`` maps the same rowid to the row's declared primary-key values. It
    lets callers resolve a row by its real identity instead of SQLite's
    internal rowid, without changing the existing ``rows`` contract.
    """

    name: str
    rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    keys: dict[str, tuple[str, ...]] = field(default_factory=dict)


class SqliteAttributor:
    """Derive write events by diffing the database around a request."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)

    # -- schema ------------------------------------------------------------- #

    def schema(self) -> DatabaseSchema:
        """Read declared tables, columns, primary and foreign keys.

        Everything comes from ``sqlite_master`` and ``PRAGMA``; no name is
        guessed from the application's API, and no identifier is interpolated
        unquoted into a statement.
        """
        if not Path(self.db_path).exists():
            return DatabaseSchema()
        connection = sqlite3.connect(self.db_path, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            names = [
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            ]
            tables: dict[str, TableSchema] = {}
            for name in names:
                quoted = quote_identifier(name)
                columns = tuple(
                    Column(
                        name=row["name"],
                        type=str(row["type"] or ""),
                        primary_key=int(row["pk"] or 0),
                        not_null=bool(row["notnull"]),
                        unique=bool(row["pk"]),
                    )
                    for row in connection.execute(f"PRAGMA table_info({quoted})")
                )
                foreign_keys = tuple(
                    ForeignKey(column=str(row["from"]), table=str(row["table"]), column_ref=str(row["to"]))
                    for row in connection.execute(f"PRAGMA foreign_key_list({quoted})")
                )
                # A single-column UNIQUE index is also a usable row identity.
                unique_columns = {
                    str(row["name"])
                    for index in connection.execute(f"PRAGMA index_list({quoted})")
                    if index["unique"]
                    for row in connection.execute(f"PRAGMA index_info({quote_identifier(index['name'])})")
                }
                if unique_columns:
                    columns = tuple(
                        Column(c.name, c.type, c.primary_key, c.not_null, c.unique or c.name in unique_columns)
                        for c in columns
                    )
                tables[name] = TableSchema(name=name, columns=columns, foreign_keys=foreign_keys)
            return DatabaseSchema(tables=tables)
        finally:
            connection.close()

    def rows(self, table: str) -> list[dict[str, Any]]:
        """All rows of one table, with safely quoted identifiers."""
        if not Path(self.db_path).exists():
            return []
        connection = sqlite3.connect(self.db_path, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute(f"SELECT * FROM {quote_identifier(table)}")]
        except sqlite3.Error:
            return []
        finally:
            connection.close()

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
            schema = self.schema()
            result: dict[str, TableSnapshot] = {}
            for table in tables:
                quoted = quote_identifier(table)
                try:
                    rows = connection.execute(f"SELECT rowid AS __rowid__, * FROM {quoted}").fetchall()
                except sqlite3.Error:
                    continue
                declared = schema.get(table)
                pk = declared.primary_key if declared is not None else ()
                snapshot = TableSnapshot(name=table, rows={}, keys={})
                for row in rows:
                    data = dict(row)
                    key = str(data.pop("__rowid__"))
                    if pk and all(column in data for column in pk):
                        snapshot.keys[key] = tuple(str(data[column]) for column in pk)
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
                        row_key=_row_key(current, key),
                    )
                )
            # Changed rows
            for key, values in current.rows.items():
                old = previous.rows.get(key)
                if old is None:
                    continue
                changed = {column: value for column, value in values.items() if old.get(column) != value}
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
                        row_key=_row_key(current, key),
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
                        row_key=_row_key(previous, key),
                    )
                )
        return events

    def row_identity(self, table: str, rowid: str) -> str | None:
        """The declared primary-key identity of one row, when known."""
        schema = self.schema().get(table)
        if schema is None or not schema.primary_key:
            return None
        connection = sqlite3.connect(self.db_path, timeout=15)
        try:
            columns = ", ".join(quote_identifier(column) for column in schema.primary_key)
            row = connection.execute(
                f"SELECT {columns} FROM {quote_identifier(table)} WHERE rowid = ?", (int(rowid),)
            ).fetchone()
        except (sqlite3.Error, ValueError):
            return None
        finally:
            connection.close()
        return ":".join(str(value) for value in row) if row else None


def _row_key(snapshot: TableSnapshot, rowid: str) -> str | None:
    """The declared primary-key identity of a row, when metadata is available."""
    values = snapshot.keys.get(rowid)
    return ":".join(values) if values else None


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
