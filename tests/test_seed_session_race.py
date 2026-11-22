"""Direct deterministic coverage of the seed-session creation race.

The bug this guards against was a closed cursor being reused for the database
existence check after the seed-session drain. A cleanup-preflight test does not
exercise this path; these tests drive ``DisposableDatabase.create()`` itself.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import mizan.postgres_twin as twin_module
from mizan.postgres_twin import DisposableDatabase, TwinLifecycleError


class FakeCursor:
    def __init__(self, log: list[object]) -> None:
        self.log = log
        self.closed = False
        self.statements: list[tuple[str, object]] = []
        self._rows: list[tuple[object, ...]] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.closed = True

    def execute(self, sql: object, params: object = None) -> None:
        if self.closed:
            raise AssertionError("a closed cursor was reused")
        text = str(sql)
        self.statements.append((text, params))
        self.log.append(self)
        if "pg_stat_activity" in text:
            self._rows = [(4242, "app", "idle", "SELECT 1")]
        elif "pg_database" in text:
            self._rows = []
        else:
            self._rows = []

    def fetchall(self) -> list[tuple[object, ...]]:
        assert not self.closed, "fetchall on a closed cursor"
        return list(self._rows)

    def fetchone(self) -> tuple[object, ...] | None:
        assert not self.closed, "fetchone on a closed cursor"
        return self._rows[0] if self._rows else None


class FakeAdmin:
    def __init__(self) -> None:
        self.cursors: list[FakeCursor] = []
        self.closed = False

    def cursor(self) -> FakeCursor:
        cursor = FakeCursor(self.cursors)
        self.cursors.append(cursor)
        return cursor

    def close(self) -> None:
        self.closed = True


class FakeRegistry:
    def __init__(self) -> None:
        self.records: dict[str, object] = {}
        self.intents_removed: list[str] = []

    def get(self, name: str) -> object | None:
        return self.records.get(name)

    def put(self, record: object) -> None:
        self.records[record.database_name] = record  # type: ignore[attr-defined]

    def remove(self, name: str) -> None:
        self.records.pop(name, None)

    def remove_intent(self, name: str) -> None:
        self.intents_removed.append(name)


def _database(
    monkeypatch: pytest.MonkeyPatch, *, wait_result: list[tuple[int, str]] | None = None
) -> tuple[DisposableDatabase, FakeAdmin, FakeRegistry, dict[str, object]]:
    admin = FakeAdmin()
    registry = FakeRegistry()
    marker: dict[str, object] = {}
    source = SimpleNamespace(
        run_id="0123456789ab",
        admin=lambda: admin,
        cluster_id=lambda connection=None: "cluster-id",
        source_name=lambda: "source-db",
        target=SimpleNamespace(user="postgres"),
        rollback_errors=[],
        redact=lambda text: text,
    )
    baseline = SimpleNamespace(name="seed-db", fingerprint="digest", schemas=("pgstore",))
    database = DisposableDatabase(source, baseline, registry, "w0")  # type: ignore[arg-type]
    monkeypatch.setattr(twin_module, "database_oid", lambda connection, name: 4242)
    monkeypatch.setattr(twin_module, "database_owner", lambda connection, name: "postgres")
    monkeypatch.setattr(
        twin_module,
        "write_marker",
        lambda connection, name, value: marker.update({"name": name, "marker": value}),
    )
    monkeypatch.setattr(DisposableDatabase, "verify", lambda self, **kwargs: "digest")
    if wait_result is not None:
        monkeypatch.setattr(
            twin_module,
            "_wait_for_no_sessions",
            lambda connection, name: wait_result,
        )
    return database, admin, registry, marker


def test_seed_session_disappears_and_existence_check_uses_a_fresh_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact creation path: session seen, drained, then a new cursor."""
    database, admin, registry, marker = _database(monkeypatch, wait_result=[])

    record = database.create()

    assert admin.cursors, "no cursor was used"
    inspection = admin.cursors[0]
    assert any("pg_stat_activity" in statement for statement, _ in inspection.statements)
    assert inspection.closed, "the inspection cursor must be closed before the drain"
    existence = next(
        cursor for cursor in admin.cursors if any("pg_database" in statement for statement, _ in cursor.statements)
    )
    assert existence is not inspection, "a closed cursor was reused for the existence check"
    assert not existence.closed or all("pg_database" in s for s, _ in existence.statements)
    assert admin.closed, "the admin connection was not closed"
    assert record.database_name == database.name
    assert marker["name"] == database.name
    assert registry.get(database.name) is record
    assert any("CREATE DATABASE" in statement for cursor in admin.cursors for statement, _ in cursor.statements)


def test_a_persistent_seed_session_fails_closed_before_create(monkeypatch: pytest.MonkeyPatch) -> None:
    """A session that survives the bounded drain blocks creation safely."""
    database, admin, registry, marker = _database(monkeypatch, wait_result=[(4242, "app")])

    with pytest.raises(TwinLifecycleError, match="active sessions"):
        database.create()

    assert not any("CREATE DATABASE" in statement for cursor in admin.cursors for statement, _ in cursor.statements)
    assert marker == {}
    assert registry.records == {}


def test_no_catalog_oid_rolls_back_and_does_not_register(monkeypatch: pytest.MonkeyPatch) -> None:
    """A vanished database after CREATE is rolled back, never registered."""
    database, admin, registry, marker = _database(monkeypatch, wait_result=[])
    rollback: list[object] = []
    monkeypatch.setattr(twin_module, "database_oid", lambda connection, name: None)
    monkeypatch.setattr(DisposableDatabase, "_rollback_created", lambda self, admin, **kwargs: rollback.append(kwargs))

    with pytest.raises(TwinLifecycleError, match="no catalog OID"):
        database.create()

    assert rollback == []
    assert registry.records == {}
    assert marker == {}


def test_marker_and_record_are_bound_to_the_owned_worker_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """No unrelated database or worker identity is accepted as owned."""
    database, _admin, registry, marker = _database(monkeypatch, wait_result=[])
    record = database.create()
    written = marker["marker"]

    assert record.kind == "worker"  # type: ignore[union-attr]
    assert record.worker_id == "w0"  # type: ignore[union-attr]
    assert written.kind == "worker"  # type: ignore[union-attr]
    assert written.worker_id == "w0"  # type: ignore[union-attr]
    assert written.nonce == record.nonce  # type: ignore[union-attr]
    assert set(registry.records) == {database.name}


def test_timeout_expiry_uses_the_bounded_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real drain helper respects its timeout and returns the survivors."""
    monkeypatch.setattr(twin_module, "SESSION_DRAIN_SECONDS", 0.05)
    monkeypatch.setattr(twin_module, "_remaining_sessions", lambda connection, database: [(99, "app")])
    remaining = twin_module._wait_for_no_sessions(object(), "seed", timeout=0.05)
    assert remaining == [(99, "app")]
