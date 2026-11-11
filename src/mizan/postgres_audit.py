"""Postgres attribution: the write ledger for a real database.

The SQLite attributor watches the data by comparing two snapshots. Postgres
does not allow that cheaply, but it has a better tool: a trigger.

The auditor installs a small audit table and a trigger on every table of the
application. From then on, every write is recorded together with the identity
that made it.

Identity provenance
-------------------

The identity travels in ``application_name``, the standard way for a connection
to say who it is acting for::

    SET LOCAL application_name = 'mizan:' || current_user_id;

``SET LOCAL`` is transaction-scoped: the value is reset at the end of the
transaction, so a pooled connection cannot leak one user's identity into the
next user's work.

.. warning::

    ``application_name`` is **metadata, not authentication**. Anybody who can
    run SQL on that connection can claim any identity. The attribution is only
    as trustworthy as the application's ability to control its own database
    connections - which is exactly the assumption an audit of *your own*
    application rests on. Mizan never claims more than that.

.. note::

    This module needs ``psycopg`` and a reachable database. The SQL it
    generates is unit-tested without a database; the round trip is covered by
    ``tests/test_postgres_roundtrip.py``, which runs against a real server
    (a disposable one in CI, or a local one via ``pgserver``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from mizan.core import UNKNOWN_PRINCIPAL
from mizan.taint import WriteEvent

#: The table that holds the audit records.
AUDIT_TABLE = "mizan_write_audit"

#: The function that fills it. One per audit schema.
AUDIT_FUNCTION = "mizan_write_audit_fn"

#: The prefix that marks an application name as carrying an identity.
PRINCIPAL_PREFIX = "mizan:"

#: Columns that usually name the owner of a row.
OWNER_COLUMNS = ("owner_id", "user_id", "owner", "account_id", "tenant_id")

#: How the row was identified.
IDENTITY_PRIMARY_KEY = "primary_key"
IDENTITY_NONE = "none"


def quote_identifier(name: str) -> str:
    """Quote an identifier for PostgreSQL.

    Doubling the quotes is what makes an identifier safe; a name that contains
    a NUL byte is rejected outright, because PostgreSQL cannot represent it.
    """
    if not name:
        raise ValueError("an identifier cannot be empty")
    if "\x00" in name:
        raise ValueError("an identifier cannot contain a NUL byte")
    return '"' + name.replace('"', '""') + '"'


def qualified_name(schema: str, table: str) -> str:
    """A safely quoted, schema-qualified table name."""
    return f"{quote_identifier(schema)}.{quote_identifier(table)}"


@dataclass(frozen=True)
class AuditRow:
    """One raw audit record."""

    occurred_at: Any
    raw_principal: str | None
    schema_name: str
    table_name: str
    row_id: str | None
    row_identity: str
    operation: str
    row_data: dict[str, Any] = field(default_factory=dict)
    old_row: dict[str, Any] = field(default_factory=dict)

    @property
    def qualified_table(self) -> str:
        return f"{self.schema_name}.{self.table_name}"


class PostgresAuditor:
    """Records every write of a Postgres database, with its author."""

    def __init__(
        self,
        connection: Any,
        *,
        audit_schema: str = "public",
        principal_prefix: str = PRINCIPAL_PREFIX,
        schemas: Iterable[str] | None = None,
    ) -> None:
        self.connection = connection
        self.audit_schema = audit_schema
        self.principal_prefix = principal_prefix
        #: The schemas to instrument. By default only the audit schema is
        #: touched - Mizan never installs a trigger on a table it was not
        #: pointed at.
        self.schemas = tuple(schemas) if schemas is not None else (audit_schema,)

    # -- naming ------------------------------------------------------------- #

    @property
    def audit_table(self) -> str:
        return qualified_name(self.audit_schema, AUDIT_TABLE)

    @property
    def audit_function(self) -> str:
        return qualified_name(self.audit_schema, AUDIT_FUNCTION)

    # -- installation ------------------------------------------------------- #

    def install(self) -> None:
        """Create the audit table and the triggers that fill it.

        Safe to run again: the table, the function and the triggers are created
        with ``IF NOT EXISTS`` / ``OR REPLACE``, and a trigger that already
        exists is replaced rather than duplicated.
        """
        with self.connection.cursor() as cursor:
            cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {quote_identifier(self.audit_schema)}")
            cursor.execute(self.audit_table_sql())
            cursor.execute(self.audit_function_sql())
            cursor.execute(self.audit_index_sql())
            for schema, table in self.user_tables():
                cursor.execute(self.trigger_sql(schema, table))
        self.connection.commit()

    def refresh(self) -> list[tuple[str, str]]:
        """Install the trigger on the tables that were created after ``install``.

        Returns the tables that were (re)instrumented.
        """
        instrumented: list[tuple[str, str]] = []
        with self.connection.cursor() as cursor:
            for schema, table in self.user_tables():
                cursor.execute(self.trigger_sql(schema, table))
                instrumented.append((schema, table))
        self.connection.commit()
        return instrumented

    def uninstall(self) -> None:
        """Remove the triggers, the function and the audit table.

        Only objects that Mizan created are touched.
        """
        with self.connection.cursor() as cursor:
            for schema, table in self.user_tables():
                cursor.execute(
                    f"DROP TRIGGER IF EXISTS {quote_identifier(self.trigger_name(table))} "
                    f"ON {qualified_name(schema, table)}"
                )
            cursor.execute(f"DROP FUNCTION IF EXISTS {self.audit_function}()")
            cursor.execute(f"DROP TABLE IF EXISTS {self.audit_table}")
        self.connection.commit()

    # -- catalog ------------------------------------------------------------ #

    def user_tables(self, schemas: Iterable[str] | None = None) -> list[tuple[str, str]]:
        """The tables to instrument, as ``(schema, table)`` pairs.

        Only the schemas Mizan was pointed at are considered, and the audit
        table itself is excluded.
        """
        wanted = tuple(schemas) if schemas is not None else self.schemas
        if not wanted:
            return []
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE table_type = 'BASE TABLE'
                  AND table_schema = ANY(%s)
                ORDER BY table_schema, table_name
                """,
                (list(wanted),),
            )
            rows = cursor.fetchall()
        return [(schema, table) for schema, table in rows if not (schema == self.audit_schema and table == AUDIT_TABLE)]

    def primary_key_columns(self, schema: str, table: str) -> list[str]:
        """The primary key columns of a table, in key order."""
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT a.attname
                FROM pg_index i
                CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                JOIN pg_attribute a
                  ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                WHERE i.indrelid = %s::regclass AND i.indisprimary
                ORDER BY k.ord
                """,
                (f"{schema}.{table}",),
            )
            return [row[0] for row in cursor.fetchall()]

    # -- SQL ---------------------------------------------------------------- #

    def audit_table_sql(self) -> str:
        """The audit table.

        It keeps the full row before and after the change, so the changed
        columns can be computed exactly instead of guessed.
        """
        return f"""
        CREATE TABLE IF NOT EXISTS {self.audit_table} (
            id BIGSERIAL PRIMARY KEY,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            raw_principal TEXT,
            schema_name TEXT NOT NULL,
            table_name TEXT NOT NULL,
            row_id TEXT,
            row_identity TEXT NOT NULL,
            operation TEXT NOT NULL,
            row_data JSONB NOT NULL DEFAULT '{{}}'::jsonb,
            old_row JSONB NOT NULL DEFAULT '{{}}'::jsonb
        )
        """

    def audit_index_sql(self) -> str:
        return f"""
        CREATE INDEX IF NOT EXISTS {quote_identifier(AUDIT_TABLE + "_time_idx")}
        ON {self.audit_table} (occurred_at)
        """

    def audit_function_sql(self) -> str:
        """The trigger function.

        It is written once per audit schema and serves every table. The row
        identity comes from the catalog, so tables with a composite, UUID or
        text primary key work as well - and a table without a primary key is
        reported as such instead of being given a made-up identity.
        """
        return f"""
        CREATE OR REPLACE FUNCTION {self.audit_function}() RETURNS trigger AS $mizan$
        DECLARE
            pk_columns text[];
            new_id text;
            old_id text;
            identity_kind text;
        BEGIN
            SELECT array_agg(a.attname ORDER BY k.ord)
              INTO pk_columns
              FROM pg_index i
              CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
              JOIN pg_attribute a
                ON a.attrelid = i.indrelid AND a.attnum = k.attnum
             WHERE i.indrelid = TG_RELID AND i.indisprimary;

            IF pk_columns IS NULL OR array_length(pk_columns, 1) IS NULL THEN
                -- No stable identity: the row is recorded, but it is not
                -- identified. Nothing may be concluded from it.
                identity_kind := '{IDENTITY_NONE}';
                new_id := NULL;
                old_id := NULL;
            ELSE
                identity_kind := '{IDENTITY_PRIMARY_KEY}';
                SELECT string_agg(to_jsonb(NEW) ->> column_name, '|' ORDER BY column_name)
                  INTO new_id
                  FROM unnest(pk_columns) AS column_name;
                SELECT string_agg(to_jsonb(OLD) ->> column_name, '|' ORDER BY column_name)
                  INTO old_id
                  FROM unnest(pk_columns) AS column_name;
            END IF;

            INSERT INTO {self.audit_table}
                (raw_principal, schema_name, table_name, row_id, row_identity, operation, row_data, old_row)
            VALUES (
                current_setting('application_name', true),
                TG_TABLE_SCHEMA,
                TG_TABLE_NAME,
                CASE WHEN TG_OP = 'DELETE' THEN old_id ELSE new_id END,
                identity_kind,
                TG_OP,
                CASE WHEN TG_OP = 'DELETE' THEN '{{}}'::jsonb ELSE to_jsonb(NEW) END,
                CASE WHEN TG_OP = 'INSERT' THEN '{{}}'::jsonb ELSE to_jsonb(OLD) END
            );
            RETURN NULL;
        END;
        $mizan$ LANGUAGE plpgsql;
        """

    def trigger_name(self, table: str) -> str:
        """The trigger name for a table.

        PostgreSQL truncates identifiers at 63 characters, so long names are
        shortened with a hash instead of silently colliding.
        """
        import hashlib

        prefix = "mizan_write_audit_trg_"
        name = f"{prefix}{table}"
        if len(name) <= 63:
            return name
        digest = hashlib.sha1(table.encode("utf-8")).hexdigest()[:8]
        budget = 63 - len(prefix) - len(digest) - 1
        return f"{prefix}{table[:budget]}_{digest}"

    def trigger_sql(self, schema: str, table: str) -> str:
        """The trigger that records the writes of one table."""
        return f"""
        DROP TRIGGER IF EXISTS {quote_identifier(self.trigger_name(table))}
            ON {qualified_name(schema, table)};
        CREATE TRIGGER {quote_identifier(self.trigger_name(table))}
        AFTER INSERT OR UPDATE OR DELETE ON {qualified_name(schema, table)}
        FOR EACH ROW EXECUTE FUNCTION {self.audit_function}();
        """

    # -- reading ------------------------------------------------------------ #

    def read(self, *, since: Any = None) -> list[WriteEvent]:
        """The writes recorded so far, as write events."""
        with self.connection.cursor() as cursor:
            if since is None:
                cursor.execute(
                    f"""
                    SELECT occurred_at, raw_principal, schema_name, table_name, row_id,
                           row_identity, operation, row_data, old_row
                    FROM {self.audit_table}
                    ORDER BY id
                    """
                )
            else:
                cursor.execute(
                    f"""
                    SELECT occurred_at, raw_principal, schema_name, table_name, row_id,
                           row_identity, operation, row_data, old_row
                    FROM {self.audit_table}
                    WHERE occurred_at > %s
                    ORDER BY id
                    """,
                    (since,),
                )
            rows = cursor.fetchall()
        return [self.to_event(row) for row in rows]

    # -- conversion --------------------------------------------------------- #

    def to_event(self, row: Iterable[Any]) -> WriteEvent:
        """One audit record as a write event."""
        (
            occurred_at,
            raw_principal,
            schema_name,
            table_name,
            row_id,
            row_identity,
            operation,
            row_data,
            old_row,
        ) = row
        current = _as_dict(row_data)
        previous = _as_dict(old_row)
        columns = _changed_columns(current, previous, operation)
        owner = _owner(current) or _owner(previous)
        return WriteEvent(
            ts=occurred_at.timestamp() if hasattr(occurred_at, "timestamp") else 0.0,
            request_id=str(row_id or ""),
            principal=self.principal_from(raw_principal),
            method=_method_for(operation),
            path=f"/{schema_name}.{table_name}",
            table=table_name,
            row_id=str(row_id or ""),
            columns=columns,
            # The database cannot know which fields the client sent.
            source_fields=set(),
            row_owner=owner,
            method_args={
                "operation": operation,
                "row_identity": row_identity,
                "schema": schema_name,
            },
        )

    def principal_from(self, raw_principal: str | None) -> str:
        """The principal an ``application_name`` claims.

        An absent or malformed application name yields
        :data:`UNKNOWN_PRINCIPAL` - never an arbitrary identity.
        """
        if not raw_principal:
            return UNKNOWN_PRINCIPAL
        if not raw_principal.startswith(self.principal_prefix):
            return UNKNOWN_PRINCIPAL
        principal = raw_principal[len(self.principal_prefix) :].strip()
        return principal or UNKNOWN_PRINCIPAL


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _as_dict(value: Any) -> dict[str, Any]:
    """A JSONB column as a dictionary."""
    if value is None:
        return {}
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


def _changed_columns(current: dict[str, Any], previous: dict[str, Any], operation: str) -> dict[str, Any]:
    """The columns a write changed.

    An insert changed everything it wrote, an update changed what differs, and
    a delete changed the columns of the row that is gone - the old values, so
    the row can still be identified.
    """
    if operation == "INSERT":
        return dict(current)
    if operation == "DELETE":
        return dict(previous)
    changed: dict[str, Any] = {}
    for column, value in current.items():
        if previous.get(column) != value:
            changed[column] = value
    return changed


def _owner(values: dict[str, Any]) -> str | None:
    for column in OWNER_COLUMNS:
        value = values.get(column)
        if isinstance(value, (str, int)):
            return str(value)
    return None


def _method_for(operation: str) -> str:
    return {"INSERT": "POST", "UPDATE": "PATCH", "DELETE": "DELETE"}.get(operation, "POST")
