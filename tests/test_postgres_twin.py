"""Phase VI.1 tests for the disposable PostgreSQL Twin lifecycle.

Unit tests pin state transitions and ownership verification without a server;
integration tests (marked ``postgres_integration``) exercise real cloning,
isolation, restoration, cleanup and L2/L3 probe execution.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import uuid
from pathlib import Path

import pytest

from mizan.postgres_twin import (
    BaselineVerificationError,
    DatabaseRegistry,
    OwnershipRecord,
    PostgresSource,
    SourceProtectionError,
    TwinLifecycleError,
    TwinState,
    cleanup_run,
    database_dsn,
    generated_name,
)

DSN_ENV = "MIZAN_V61_TEST_DSN"
FIXTURE = Path(__file__).parent / "fixtures" / "external_apps" / "postgres_store"


def _dsn() -> str:
    value = os.environ.get(DSN_ENV) or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if value:
        return (
            value
            if "connect_timeout" in value
            else value + ("&connect_timeout=5" if "?" in value else "?connect_timeout=5")
        )
    pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required for integration tests")
    return pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-v61-test-")), cleanup_mode="delete").get_uri()


# --------------------------------------------------------------------------- #
# Unit tests - no database
# --------------------------------------------------------------------------- #


def test_generated_names_are_unique_per_worker() -> None:
    first = generated_name("run1", "worker", "w0")
    second = generated_name("run1", "worker", "w1")
    assert first != second
    assert first.startswith("mizan_v61_run1_")


def test_database_dsn_replaces_only_the_database() -> None:
    dsn = "postgresql://user:secret@localhost:5432/source?sslmode=require"
    changed = database_dsn(dsn, "disposable")
    assert "/disposable?" in changed
    assert "user:secret" in changed  # only inside the in-memory string, never logged


def test_ownership_record_round_trip() -> None:
    record = OwnershipRecord("r", "w0", "db", "source", "seed", TwinState.READY, 1.0)
    assert OwnershipRecord.from_dict(json.loads(json.dumps(record.to_dict()))) == record


def test_registry_rejects_unknown_database() -> None:
    registry = DatabaseRegistry(Path(tempfile.gettempdir()) / f"registry-{uuid.uuid4().hex}.json")
    assert registry.get("unknown") is None


def test_invalid_transition_fails_closed() -> None:
    from mizan.postgres_twin import DisposableDatabase

    source = object()
    database = DisposableDatabase(source, object(), None, "w0")  # type: ignore[arg-type]
    with pytest.raises(TwinLifecycleError):
        database._transition(TwinState.RUNNING)


def test_source_requires_environment_variable(monkeypatch) -> None:
    monkeypatch.delenv(DSN_ENV, raising=False)
    with pytest.raises(SourceProtectionError):
        PostgresSource(DSN_ENV, schemas=("public",))


# --------------------------------------------------------------------------- #
# Real PostgreSQL integration
# --------------------------------------------------------------------------- #

pytestmark_integration = pytest.mark.postgres_integration


@pytest.fixture(scope="module")
def source():
    dsn = _dsn()
    os.environ[DSN_ENV] = dsn
    instance = PostgresSource(DSN_ENV, schemas=("pgstore",))
    # Initialize the independent fixture schema in the source database.
    spec = importlib.util.spec_from_file_location("pgstore_fixture", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.create_app("clean", dsn=dsn, schema="pgstore")
    return instance, dsn


@pytest.mark.postgres_integration
def test_full_lifecycle_protects_source_and_isolates_workers(source) -> None:
    from mizan.postgres_twin import PostgresTwin

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-life-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    original = instance.fingerprint()
    command = [__import__("sys").executable, str(FIXTURE / "app.py"), "--port", "{port}"]
    twins = []
    try:
        for index in range(2):
            twin = PostgresTwin(
                instance,
                baseline,
                registry,
                f"w{index}",
                command=command,
                workdir=workspace,
                env={"MIZAN_TOKEN_ALICE": "twin-alice", "MIZAN_TOKEN_BOB": "twin-bob"},
            )
            twin.start()
            twins.append(twin)
        assert twins[0].database.name != twins[1].database.name
        assert twins[0].base_url != twins[1].base_url

        with twins[0].database.connect().cursor() as cursor:
            cursor.execute('CREATE TABLE "pgstore"."isolation_probe" (id TEXT PRIMARY KEY)')
        digest0 = instance.fingerprint(twins[0].database.dsn)
        digest1 = instance.fingerprint(twins[1].database.dsn)
        assert digest0 != digest1

        twins[0].restore()
        assert instance.fingerprint(twins[0].database.dsn) == twins[0].database.expected_fingerprint
        assert instance.fingerprint() == original
        assert instance.fingerprint(twins[1].database.dsn) == digest1
    finally:
        for twin in reversed(twins):
            twin.cleanup()
            twin.cleanup()  # idempotent
        admin = instance.admin()
        with admin.cursor() as cursor:
            cursor.execute(f'DROP DATABASE IF EXISTS "{baseline.name}"')
        admin.close()
        instance.assert_unchanged()


@pytest.mark.postgres_integration
def test_l3_probe_runs_on_disposable_database(source) -> None:
    from mizan.postgres_twin import PostgresTwin, run_l2_l3_probes

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-probe-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    # Build a vulnerable baseline in a separate source-like database is not
    # allowed; instead prepare a second source with variant write.

    admin = instance.admin()
    vulnerable_name = generated_name(instance.run_id, "vulnerable")
    with admin.cursor() as cursor:
        cursor.execute(f'CREATE DATABASE "{vulnerable_name}"')
    admin.close()
    vulnerable_dsn = database_dsn(instance.dsn, vulnerable_name)
    spec = importlib.util.spec_from_file_location("pgstore_vuln", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.create_app("write", dsn=vulnerable_dsn, schema="pgstore")

    os.environ[DSN_ENV] = vulnerable_dsn
    vulnerable_source = PostgresSource(DSN_ENV, schemas=("pgstore",))
    baseline = vulnerable_source.prepare_baseline(workspace)
    twin = PostgresTwin(
        vulnerable_source,
        baseline,
        registry,
        "probe",
        command=[__import__("sys").executable, str(FIXTURE / "app.py"), "--port", "{port}", "--vulnerability", "write"],
        workdir=workspace,
        env={"MIZAN_TOKEN_ALICE": "twin-alice", "MIZAN_TOKEN_BOB": "twin-bob"},
        variant="write",
    )
    try:
        twin.start()
        result = run_l2_l3_probes(
            twin,
            schemas=("pgstore",),
            tokens={"alice": "twin-alice", "bob": "twin-bob"},
            contract_path=FIXTURE / "mizan-relationships.json",
        )
        assert result["law_types"] == ["L3"]
        assert result["coverage"]["laws"]["L3"]["findings"] == 1
        vulnerable_source.assert_unchanged()
    finally:
        twin.cleanup()
        admin = instance.admin()
        with admin.cursor() as cursor:
            cursor.execute(f'DROP DATABASE IF EXISTS "{baseline.name}"')
            cursor.execute(f'DROP DATABASE IF EXISTS "{vulnerable_name}"')
        admin.close()
        os.environ[DSN_ENV] = _dsn_value


@pytest.mark.postgres_integration
def test_cleanup_never_drops_unowned_databases(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-clean-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    record = OwnershipRecord(
        "other-run",
        "w0",
        generated_name("other-run", "worker", "w0"),
        instance.source_name(),
        generated_name("other-run", "seed"),
        TwinState.READY,
        1.0,
    )
    registry.put(record)
    assert cleanup_run(DSN_ENV, workspace, "current-run") == []


# --------------------------------------------------------------------------- #
# Failure injection - unit level, fail closed
# --------------------------------------------------------------------------- #


def _fake_source():
    return type(
        "Source",
        (),
        {
            "run_id": "run",
            "dsn": "postgresql://u:p@localhost/source",
            "schemas": ("pgstore",),
            "source_name": lambda self: "source",
            "admin": lambda self: None,
            "fingerprint": lambda self, dsn=None: "digest",
            "assert_unchanged": lambda self: None,
        },
    )()


def _fake_baseline():
    return type(
        "Baseline",
        (),
        {
            "name": "seed",
            "schemas": ("pgstore",),
            "fingerprint": "digest",
            "dsn": "postgresql://x/seed",
        },
    )()


def test_clone_failure_fails_closed(monkeypatch, tmp_path):
    from mizan.postgres_twin import DisposableDatabase, PostgresTwin

    def boom(self):
        raise TwinLifecycleError("clone failed")

    monkeypatch.setattr(DisposableDatabase, "create", boom)
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "own.json"),
        "w0",
        command=["python"],
        workdir=tmp_path,
    )
    with pytest.raises(TwinLifecycleError, match="clone failed"):
        twin.start()
    assert twin.state is TwinState.FAILED


def test_application_start_failure_fails_closed(monkeypatch, tmp_path):
    from mizan.postgres_audit import PostgresAuditor
    from mizan.postgres_twin import DisposableDatabase, PostgresTwin, Twin

    monkeypatch.setattr(PostgresAuditor, "install", lambda self: None)

    monkeypatch.setattr(
        DisposableDatabase,
        "create",
        lambda self: OwnershipRecord("run", "w0", self.name, "source", "seed", TwinState.INITIALIZED, 1.0),
    )
    monkeypatch.setattr(DisposableDatabase, "verify", lambda self: "digest")
    monkeypatch.setattr(DisposableDatabase, "connect", lambda self: object())
    monkeypatch.setattr(Twin, "start", lambda self: (_ for _ in ()).throw(RuntimeError("health failed")))
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "own.json"),
        "w0",
        command=["python"],
        workdir=tmp_path,
    )
    with pytest.raises(RuntimeError, match="health failed"):
        twin.start()
    assert twin.state is TwinState.FAILED


def test_cleanup_rejects_record_naming_the_source(tmp_path):
    record = OwnershipRecord("run", "w0", "source", "source", "seed", TwinState.READY, 1.0)
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    registry.put(record)
    with pytest.raises(SourceProtectionError):
        cleanup_run(DSN_ENV, tmp_path, "run")


@pytest.mark.postgres_integration
def test_concurrent_requests_share_worker_database(source) -> None:
    """A race experiment's concurrent requests must target one disposable DB."""
    from concurrent.futures import ThreadPoolExecutor

    import requests

    from mizan.postgres_attribution import PostgresAttributor
    from mizan.postgres_twin import PostgresTwin

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-race-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    command = [
        __import__("sys").executable,
        str(FIXTURE / "app.py"),
        "--port",
        "{port}",
        "--vulnerability",
        "clean",
    ]
    twin = PostgresTwin(
        instance,
        baseline,
        registry,
        "race",
        command=command,
        workdir=workspace,
        env={"MIZAN_TOKEN_ALICE": "race-alice", "MIZAN_TOKEN_BOB": "race-bob"},
    )
    try:
        twin.start()
        before = instance.fingerprint(twin.database.dsn)

        def put(label: str) -> int:
            session = requests.Session()
            session.headers.update({"Authorization": "Bearer race-alice"})
            response = session.put(
                twin.base_url + "/items/item-a1",
                json={"label": label},
                headers={"X-Mizan-Request-Id": "race-" + label},
                timeout=10,
            )
            return response.status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(put, ["one", "two"]))
        assert statuses == [200, 200]

        provider = PostgresAttributor(twin.database.connect(), schemas=("pgstore",), audit_schema="pgstore")
        events = provider.auditor.read()
        concurrent = [event for event in events if event.request_id.startswith("race-")]
        assert len(concurrent) >= 2
        assert {event.request_id for event in concurrent} >= {"race-one", "race-two"}
        assert all(event.attribution == "confirmed" for event in concurrent)
        assert instance.fingerprint(twin.database.dsn) != before
    finally:
        twin.cleanup()
        admin = instance.admin()
        with admin.cursor() as cursor:
            cursor.execute(f'DROP DATABASE IF EXISTS "{baseline.name}"')
        admin.close()
        instance.assert_unchanged()


def test_restore_failure_fails_closed(monkeypatch, tmp_path):
    from mizan.postgres_twin import DisposableDatabase, PostgresTwin

    def boom(self):
        raise TwinLifecycleError("restore failed")

    monkeypatch.setattr(DisposableDatabase, "drop", boom)
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "ownership.json"),
        "w0",
        command=["python"],
        workdir=tmp_path,
    )
    twin.state = TwinState.READY
    with pytest.raises(TwinLifecycleError, match="restore failed"):
        twin.restore()
    assert twin.state is TwinState.FAILED


def test_baseline_mismatch_fails_closed(monkeypatch):
    from mizan.postgres_twin import DisposableDatabase

    source = _fake_source()
    calls = {"n": 0}

    def changing(*args, **kwargs):
        calls["n"] += 1
        return "digest" if calls["n"] > 1 else "different"

    source.fingerprint = changing
    baseline = _fake_baseline()
    database = DisposableDatabase(source, baseline, None, "w0")  # type: ignore[arg-type]
    database.record = OwnershipRecord("run", "w0", database.name, "source", "seed", TwinState.INITIALIZED, 1.0)
    with pytest.raises(BaselineVerificationError):
        database.verify()


def test_audit_initialization_failure_fails_closed(monkeypatch, tmp_path):
    from mizan.postgres_audit import PostgresAuditor
    from mizan.postgres_twin import DisposableDatabase, PostgresTwin, Twin

    monkeypatch.setattr(Twin, "start", lambda self: self.base_url)

    monkeypatch.setattr(
        DisposableDatabase,
        "create",
        lambda self: OwnershipRecord("run", "w0", self.name, "source", "seed", TwinState.INITIALIZED, 1.0),
    )
    monkeypatch.setattr(DisposableDatabase, "connect", lambda self: object())
    monkeypatch.setattr(
        PostgresAuditor, "install", lambda self: (_ for _ in ()).throw(TwinLifecycleError("audit failed"))
    )
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "ownership.json"),
        "w0",
        command=["python"],
        workdir=tmp_path,
    )
    with pytest.raises(TwinLifecycleError, match="audit failed"):
        twin.start()
    assert twin.state is TwinState.FAILED


def test_cleanup_failure_fails_closed(monkeypatch, tmp_path):
    from mizan.postgres_twin import DisposableDatabase, PostgresTwin

    def boom(self):
        raise TwinLifecycleError("cleanup failed")

    monkeypatch.setattr(DisposableDatabase, "drop", boom)
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "ownership.json"),
        "w0",
        command=["python"],
        workdir=tmp_path,
    )
    twin.state = TwinState.READY
    with pytest.raises(TwinLifecycleError, match="cleanup failed"):
        twin.cleanup()
    assert twin.state is TwinState.FAILED
