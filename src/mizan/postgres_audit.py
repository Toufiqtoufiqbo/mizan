"""Postgres attribution: the write ledger for a real database.

The SQLite attributor watches the data by comparing two snapshots. Postgres
does not allow that cheaply, but it has a better tool: a trigger.

The auditor installs a small audit table and a trigger on every table of the
application. From then on, every write is recorded together with the identity
that made it - the identity travels in ``application_name``, the standard way
for a connection pool to say who it is acting for.

.. code-block:: python

    import psycopg

    with psycopg.connect("postgresql://localhost/app") as connection:
        auditor = PostgresAuditor(connection)
        auditor.install()
        events = auditor.read()

The application needs one change: the connection must say who it is acting for.

.. code-block:: sql

    SET application_name = 'mizan:' || current_user_id;

.. note::

    This module needs ``psycopg`` and a reachable database, so it is **not**
    covered by the test suite of this repository. The SQL it generates is
    unit-tested; the round trip is not. Use the SQLite attributor, the log
    parser or the ledger file when in doubt.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from mizan.taint import WriteEvent

AUDIT_TABLE = "mizan_write_audit"


@dataclass
class PostgresAuditor:
    """Records every write of a Postgres database, with its author."""

    connection: Any

    # -- installation ------------------------------------------------------- #

    def install(self) -> None:
        """Create the audit table and the triggers that fill it."""
        with self.connection.cursor() as cursor:
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {AUDIT_TABLE} (
                    id BIGSERIAL PRIMARY KEY,
                    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    principal TEXT,
                    table_name TEXT NOT NULL,
                    row_id TEXT,
                    columns JSONB NOT NULL DEFAULT '{{}}'::jsonb,
                    operation TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                f"""
                CREATE INDEX IF NOT EXISTS {AUDIT_TABLE}_time_idx
                ON {AUDIT_TABLE} (occurred_at)
                """
            )
            for table in self.user_tables():
                cursor.execute(self.trigger_sql(table))
            self.connection.commit()

    def user_tables(self) -> list[str]:
        """Every table of the current schema, except the audit table itself."""
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
                """
            )
            return [row[0] for row in cursor.fetchall() if row[0] != AUDIT_TABLE]

    def trigger_sql(self, table: str) -> str:
        """The trigger that records the writes of one table."""
        return f"""
        CREATE OR REPLACE FUNCTION {AUDIT_TABLE}_fn() RETURNS trigger AS $$
        BEGIN
            INSERT INTO {AUDIT_TABLE} (principal, table_name, row_id, columns, operation)
            VALUES (
                current_setting('application_name', true),
                TG_TABLE_NAME,
                COALESCE(NEW.id::text, OLD.id::text),
                CASE WHEN TG_OP = 'DELETE' THEN '{{}}'::jsonb
                     ELSE to_jsonb(NEW) - to_jsonb(NEW) - 'id' END,
                TG_OP
            );
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS {AUDIT_TABLE}_trg ON "{table}";
        CREATE TRIGGER {AUDIT_TABLE}_trg
        AFTER INSERT OR UPDATE OR DELETE ON "{table}"
        FOR EACH ROW EXECUTE FUNCTION {AUDIT_TABLE}_fn();
        """

    # -- reading ------------------------------------------------------------ #

    def read(self, *, since: str | None = None) -> list[WriteEvent]:
        """The writes recorded so far."""
        query = f"""
        SELECT occurred_at, principal, table_name, row_id, columns, operation
        FROM {AUDIT_TABLE}
        {("WHERE occurred_at > %s" if since else "")}
        ORDER BY id
        """
        parameters = (since,) if since else ()
        with self.connection.cursor() as cursor:
            cursor.execute(query, parameters)
            rows = cursor.fetchall()
        return [self.to_event(row) for row in rows]

    def to_event(self, row: Any) -> WriteEvent:
        """One audit row as a write event."""
        occurred_at, principal, table_name, row_id, columns, operation = row
        payload = columns
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        payload = dict(payload or {})
        return WriteEvent(
            ts=occurred_at.timestamp() if hasattr(occurred_at, "timestamp") else 0.0,
            request_id=str(row_id or ""),
            principal=(principal or "").removeprefix("mizan:"),
            method={"INSERT": "POST", "UPDATE": "PATCH", "DELETE": "DELETE"}.get(operation, "POST"),
            path=f"/{table_name}",
            table=table_name,
            row_id=str(row_id or ""),
            columns=payload,
            source_fields=set(),
            row_owner=_owner(payload),
        )

    def uninstall(self) -> None:
        """Remove the triggers and the audit table."""
        with self.connection.cursor() as cursor:
            for table in self.user_tables():
                cursor.execute(f"DROP TRIGGER IF EXISTS {AUDIT_TABLE}_trg ON \"{table}\";")
            cursor.execute(f"DROP TABLE IF EXISTS {AUDIT_TABLE};")
            self.connection.commit()


def _owner(values: dict[str, Any]) -> str | None:
    for column in ("owner_id", "user_id", "owner", "account_id", "tenant_id"):
        value = values.get(column)
        if isinstance(value, (str, int)):
            return str(value)
    return None
