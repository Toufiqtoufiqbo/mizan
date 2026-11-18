"""PostgreSQL ownership-evidence provider.

This module supplies the database view required by ``build_ownership_graph()``
and by the engine's request-attribution path. It reuses the existing
``PostgresAuditor`` triggers and does **not** implement a second ownership
engine.

Security model
--------------

* A monotonic audit id, never a timestamp, is the read cursor.
* A request correlation header is propagated per HTTP request and stored in a
  transaction-local PostgreSQL setting. It is read into the audit record.
* Correlation is not identity: a write whose principal differs from the
  authenticated HTTP principal is marked ``ambiguous``, and a write without a
  request id is marked ``missing_request``. Neither can produce a confirmed L3
  violation.
* Database introspection is restricted to an explicit schema allowlist. An
  unqualified table that matches more than one configured schema is rejected.

The provider never installs triggers itself. Installation is an explicit
opt-in operation on ``PostgresAuditor``.
"""

from __future__ import annotations

import json
from typing import Any

from mizan.attribution import (
    AttributionUnavailable,
    AuditCursor,
    Column,
    DatabaseSchema,
    ForeignKey,
    TableSchema,
    _canonical_identity,
)
from mizan.core import UNKNOWN_PRINCIPAL
from mizan.postgres_audit import PostgresAuditor, qualified_name
from mizan.taint import WriteEvent

#: Header the scan proxy uses to carry a per-request correlation value.
REQUEST_HEADER = "X-Mizan-Request-Id"

ATTRIBUTION_CONFIRMED = "confirmed"
ATTRIBUTION_UNKNOWN_PRINCIPAL = "unknown_principal"
ATTRIBUTION_MISSING_REQUEST = "missing_request"
ATTRIBUTION_AMBIGUOUS = "ambiguous"


class PostgresAttributor:
    """A schema-scoped PostgreSQL provider for ownership evidence and writes."""

    request_header = REQUEST_HEADER

    def __init__(
        self,
        connection: Any,
        *,
        schemas: tuple[str, ...] | list[str],
        audit_schema: str = "public",
    ) -> None:
        self.connection = connection
        self.schemas = tuple(dict.fromkeys(str(name) for name in schemas))
        if not self.schemas:
            raise ValueError("at least one schema must be allowlisted")
        self.audit_schema = audit_schema
        self.auditor = PostgresAuditor(connection, audit_schema=audit_schema, schemas=self.schemas)
        self._table_map: dict[str, tuple[str, str]] = {}
        self._pk_columns: dict[str, tuple[str, ...]] = {}

    def rebind(self, connection: Any) -> None:
        """Point the provider at a freshly restored database connection."""
        if self.connection is not None and not self.connection.closed:
            self.connection.close()
        self.connection = connection
        self.auditor = PostgresAuditor(connection, audit_schema=self.audit_schema, schemas=self.schemas)
        self._table_map = {}
        self._pk_columns = {}

    # -- availability ------------------------------------------------------- #

    def _require_installed(self) -> None:
        """Fail closed when the audit table is missing or not configured."""
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass(%s)", (self.auditor.audit_table,))
            row = cursor.fetchone()
        if not row or row[0] is None:
            raise AttributionUnavailable(
                "the PostgreSQL audit table is not installed; run the explicit install opt-in first"
            )

    # -- schema ------------------------------------------------------------- #

    def schema(self) -> DatabaseSchema:
        """Introspect only the allowlisted schemas, with qualified table keys."""
        self._require_installed()
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT c.table_schema, c.table_name, c.column_name, c.data_type,
                       c.is_nullable, c.ordinal_position
                FROM information_schema.columns c
                JOIN information_schema.tables t
                  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
                WHERE c.table_schema = ANY(%s)
                  AND t.table_type = 'BASE TABLE'
                ORDER BY c.table_schema, c.table_name, c.ordinal_position
                """,
                (list(self.schemas),),
            )
            column_rows = cursor.fetchall()

        grouped: dict[str, list[tuple[Any, ...]]] = {}
        for row in column_rows:
            grouped.setdefault(f"{row[0]}.{row[1]}", []).append(row)

        tables: dict[str, TableSchema] = {}
        self._table_map = {}
        self._pk_columns = {}
        for key, rows in sorted(grouped.items()):
            schema_name, table_name = key.split(".", 1)
            self._table_map[key] = (schema_name, table_name)
            qualified = qualified_name(schema_name, table_name)
            primary_key = self._catalog_columns(qualified, primary=True)
            unique = self._catalog_columns(qualified, unique=True)
            self._pk_columns[key] = tuple(primary_key)
            columns = tuple(
                Column(
                    name=str(row[2]),
                    type=str(row[3] or ""),
                    primary_key=(primary_key.index(str(row[2])) + 1) if str(row[2]) in primary_key else 0,
                    not_null=str(row[4]).upper() == "NO",
                    unique=str(row[2]) in unique or str(row[2]) in primary_key,
                )
                for row in rows
            )
            foreign_keys = self._foreign_keys(qualified, primary_key)
            tables[key] = TableSchema(name=key, columns=columns, foreign_keys=foreign_keys)
        return DatabaseSchema(tables=tables)

    def _catalog_columns(self, qualified: str, *, primary: bool = False, unique: bool = False) -> list[str]:
        """Primary-key or unique-index columns in declared order."""
        condition = "i.indisprimary" if primary else "i.indisunique AND NOT i.indisprimary"
        with self.connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT a.attname
                FROM pg_index i
                CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                WHERE i.indrelid = %s::regclass AND {condition}
                GROUP BY a.attname, k.ord
                ORDER BY k.ord
                """,
                (qualified,),
            )
            return [str(row[0]) for row in cursor.fetchall()]

    def _foreign_keys(self, qualified: str, primary_key: tuple[str, ...]) -> tuple[ForeignKey, ...]:
        """Resolved foreign keys, including composite ones, from pg_constraint."""
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT con.conname,
                       array_agg(a.attname ORDER BY k.ord) AS local_columns,
                       tn.nspname,
                       tc.relname,
                       array_agg(ta.attname ORDER BY k.ord) AS target_columns
                FROM pg_constraint con
                JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
                JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
                JOIN LATERAL unnest(con.confkey) WITH ORDINALITY AS k2(attnum, ord) ON k2.ord = k.ord
                JOIN pg_attribute ta ON ta.attrelid = con.confrelid AND ta.attnum = k2.attnum
                JOIN pg_class tc ON tc.oid = con.confrelid
                JOIN pg_namespace tn ON tn.oid = tc.relnamespace
                WHERE con.conrelid = %s::regclass AND con.contype = 'f'
                GROUP BY con.conname, tn.nspname, tc.relname
                ORDER BY con.conname
                """,
                (qualified,),
            )
            rows = cursor.fetchall()
        result: list[ForeignKey] = []
        for _name, local_columns, target_schema, target_table, target_columns in rows:
            locals_ = [str(column) for column in local_columns]
            targets = [str(column) for column in target_columns]
            composite = len(locals_) > 1
            for local, target in zip(locals_, targets):
                result.append(
                    ForeignKey(
                        column=local,
                        table=f"{target_schema}.{target_table}",
                        column_ref=target,
                        composite=composite,
                    )
                )
        return tuple(result)

    # -- rows --------------------------------------------------------------- #

    def _qualified(self, table: str) -> str:
        pair = self._table_map.get(table)
        if pair is None:
            # Resolve a fresh qualified key without ever guessing an
            # ambiguous bare name.
            schema = self.schema()
            if table in schema.tables:
                pair = self._table_map[table]
            elif table.count(".") == 0:
                matches = [key for key in schema.tables if key.split(".", 1)[1] == table]
                if len(matches) != 1:
                    raise AttributionUnavailable(f"unqualified table {table!r} is ambiguous across configured schemas")
                pair = self._table_map[matches[0]]
            else:
                raise AttributionUnavailable(f"table {table!r} is outside the configured schemas")
        return qualified_name(*pair)

    def rows(self, table: str) -> list[dict[str, Any]]:
        """All rows of one allowlisted table, with their real column names."""
        self._require_installed()
        with self.connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM {self._qualified(table)}")
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    # -- snapshots and cursor ---------------------------------------------- #

    def snapshot(self, *, principal: str = "", request_id: str = "") -> AuditCursor:
        """A monotonic audit cursor taken immediately before a request."""
        self._require_installed()
        return AuditCursor(event_id=self.auditor.latest_id(), principal=principal, request_id=request_id)

    def diff(
        self,
        before: AuditCursor,
        *,
        principal: str,
        method: str,
        path: str,
        request_id: str = "",
        source_fields: set[str] | None = None,
    ) -> list[WriteEvent]:
        """Writes after ``before`` that belong to this exact request.

        A different request id is another request's work and is left alone.
        A missing request id is recorded as an inconclusive background write;
        a mismatched principal under the same request is ambiguous. Neither is
        attributed to the authenticated principal.
        """
        self._require_installed()
        if not isinstance(before, AuditCursor):
            raise AttributionUnavailable("a PostgreSQL diff requires the cursor returned by snapshot()")
        events: list[WriteEvent] = []
        for event in self.auditor.read(since_id=before.event_id):
            if event.request_id and request_id and event.request_id != request_id:
                continue  # another request; it must not be folded into this one
            if not event.request_id:
                event.attribution = ATTRIBUTION_MISSING_REQUEST
            elif event.principal != principal:
                event.attribution = ATTRIBUTION_AMBIGUOUS
            else:
                event.attribution = ATTRIBUTION_CONFIRMED
            event.table = f"{event.method_args.get('schema', '')}.{event.table}".lstrip(".")
            event.method = method.upper()
            event.path = path
            event.source_fields = set(source_fields or ())
            event.row_key = self._canonical_row_key(event.table, event.row_id, event.columns, event.method_args)
            events.append(event)
        return events

    def row_identity(self, table: str, rowid: str) -> str | None:
        """The declared primary-key identity of one row, if it still exists."""
        schema = self.schema()
        declaration = schema.get(table)
        if declaration is None or not declaration.primary_key:
            return None
        components = self._parse_identity(rowid)
        if len(components) != len(declaration.primary_key):
            return None
        conditions = " AND ".join(f"{self._quote(column)} = %s" for column in declaration.primary_key)
        with self.connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM {self._qualified(table)} WHERE {conditions}", tuple(components))
            columns = [description[0] for description in cursor.description]
            row = cursor.fetchone()
        if row is None:
            return None
        values = dict(zip(columns, row))
        return _canonical_identity(tuple(str(values[column]) for column in declaration.primary_key))

    @staticmethod
    def _quote(identifier: str) -> str:
        return '"' + str(identifier).replace('"', '""') + '"'

    @staticmethod
    def _parse_identity(value: str) -> tuple[str, ...]:
        text = str(value)
        if text.startswith("[") and text.endswith("]"):
            try:
                decoded = json.loads(text)
            except ValueError:
                return (text,)
            if isinstance(decoded, list):
                return tuple(str(item) for item in decoded)
        return (text,)

    def _canonical_row_key(
        self,
        table: str,
        row_id: str,
        columns: dict[str, Any],
        method_args: dict[str, Any],
    ) -> str | None:
        """Canonical primary-key identity of a written row, in declared order."""
        primary_key = tuple(self._pk_columns.get(table, ()))
        if not primary_key:
            return None
        row = dict(columns)
        for key in ("row", "old_row"):
            for column, value in dict(method_args.get(key) or {}).items():
                row.setdefault(column, value)
        if str(method_args.get("operation", "")).upper() == "DELETE":
            return None
        if all(column in row for column in primary_key):
            return _canonical_identity(tuple(str(row[column]) for column in primary_key))
        values = self._parse_identity(row_id)
        if len(values) == len(primary_key):
            return _canonical_identity(values)
        return None

    # -- conversion --------------------------------------------------------- #

    def event_from_audit_row(self, row: dict[str, Any] | Any) -> WriteEvent:
        """One raw audit row as a write event with explicit attribution."""
        data = dict(row) if not isinstance(row, dict) else dict(row)
        raw_principal = data.get("raw_principal")
        principal = self.auditor.principal_from(raw_principal)
        request_id = str(data.get("request_id") or "")
        schema_name = str(data.get("schema_name") or "")
        table_name = str(data.get("table_name") or "")
        row_id = str(data.get("row_id") or "")
        attribution = str(data.get("attribution") or "")
        if not attribution:
            if principal == UNKNOWN_PRINCIPAL:
                attribution = ATTRIBUTION_UNKNOWN_PRINCIPAL
            elif not request_id:
                attribution = ATTRIBUTION_MISSING_REQUEST
            else:
                attribution = ATTRIBUTION_CONFIRMED
        operation = str(data.get("operation") or "UPDATE")
        current = self._as_dict(data.get("row_data"))
        previous = self._as_dict(data.get("old_row"))
        columns = (
            dict(current)
            if operation == "INSERT"
            else dict(previous)
            if operation == "DELETE"
            else {key: value for key, value in current.items() if previous.get(key) != value}
        )
        qualified_table = f"{schema_name}.{table_name}" if schema_name else table_name
        return WriteEvent(
            ts=0.0,
            request_id=request_id,
            principal=principal,
            method={"INSERT": "POST", "UPDATE": "PATCH", "DELETE": "DELETE"}.get(operation, "POST"),
            path=f"/{qualified_table}",
            table=qualified_table,
            row_id=row_id,
            columns=columns,
            source_fields=set(),
            row_owner=None,
            row_key=self._canonical_row_key(
                qualified_table, row_id, columns, {"operation": operation, "row": current, "old_row": previous}
            ),
            attribution=attribution,
        )

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8")
        if isinstance(value, str):
            try:
                loaded = json.loads(value)
            except ValueError:
                return {}
            return dict(loaded) if isinstance(loaded, dict) else {}
        return {}
