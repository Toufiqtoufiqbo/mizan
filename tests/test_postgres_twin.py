"""PostgreSQL Twin tests (Phase VI.1 + VI.2 security hardening).

Unit tests pin state transitions, identifier validation, credential handling
and the cleanup boundary without a server. Integration tests (marked
``postgres_integration``) exercise real cloning, allowlist isolation,
fingerprints, pooled sessions, verified cleanup, signals and orphan recovery.
"""

from __future__ import annotations

import errno
import importlib.util
import inspect
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

import mizan.postgres_twin as twin_module
from mizan.postgres_twin import (
    DELETION_INTENTS_KEY,
    BaselineVerificationError,
    CleanupError,
    CleanupPreflightError,
    DatabaseRegistry,
    DeletionIntent,
    IntentState,
    OwnershipError,
    OwnershipRecord,
    OwnershipUnprovable,
    PartialCleanupError,
    PostgresSource,
    SourceProtectionError,
    TwinLifecycleError,
    TwinState,
    _typed,
    cleanup_run,
    database_dsn,
    database_oid,
    discover_orphan_candidates,
    expected_marker,
    expected_seed_name,
    expected_worker_name,
    generated_name,
    marker_digest,
    parse_generated_name,
    prepare_deletion_intent,
    redact,
    validate_record,
)

DSN_ENV = "MIZAN_V62_TEST_DSN"
FIXTURE = Path(__file__).parent / "fixtures" / "external_apps" / "postgres_store"
RUN = "0123456789ab"
OTHER_RUN = "ba9876543210"
CLUSTER = "7709828547954319948"
OWNER = "postgres"
NONCE = "a" * 32


def _dsn() -> str:
    value = os.environ.get(DSN_ENV) or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if value:
        return (
            value
            if "connect_timeout" in value
            else value + ("&connect_timeout=5" if "?" in value else "?connect_timeout=5")
        )
    pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required for integration tests")
    return pgserver.get_server(pgdata=Path(tempfile.mkdtemp(prefix="mizan-v62-test-")), cleanup_mode="delete").get_uri()


def _record(
    *,
    run_id: str = RUN,
    worker_id: str = "w0",
    database_name: str | None = None,
    source: str = "source",
    seed: str | None = None,
    cluster: str = CLUSTER,
    owner: str = OWNER,
    nonce: str = NONCE,
    kind: str = "worker",
    created_at: float = 1.0,
) -> OwnershipRecord:
    return OwnershipRecord(
        run_id,
        worker_id,
        database_name or expected_worker_name(run_id, worker_id),
        source,
        seed or expected_seed_name(run_id),
        TwinState.READY,
        created_at,
        kind=kind,
        cluster_id=cluster,
        owner_role=owner,
        nonce=nonce,
    )


def _build_run(instance, workspace, worker_ids=("w0", "w1")):
    """Create one seed and validly marked workers for destructive tests."""
    # The module fixture reuses one run id; remove leftovers from a prior test.
    for stale in _generated_databases(instance.dsn):
        if instance.run_id in stale:
            _drop_database(instance.dsn, stale)
    baseline = instance.prepare_baseline(workspace)
    registry = DatabaseRegistry(workspace / "ownership.json")
    admin = _admin(instance.dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
        for worker_id in worker_ids:
            name = expected_worker_name(instance.run_id, worker_id)
            _create_database(instance.dsn, name)
            with admin.cursor() as cursor:
                cursor.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s", (name,))
                owner = str(cursor.fetchone()[0])
            nonce = secrets.token_hex(16)
            created = time.time()
            twin_module.write_marker(
                admin,
                name,
                twin_module.OwnershipMarker(
                    1,
                    instance.run_id,
                    "worker",
                    worker_id,
                    instance.source_name(),
                    cluster,
                    owner,
                    nonce,
                    created,
                ),
            )
            registry.put(
                _record(
                    run_id=instance.run_id,
                    worker_id=worker_id,
                    database_name=name,
                    source=instance.source_name(),
                    seed=baseline.name,
                    cluster=cluster,
                    owner=owner,
                    nonce=nonce,
                    created_at=created,
                )
            )
    finally:
        admin.close()
    return baseline, registry


def _tamper_marker(instance, name: str) -> None:
    """Replace a valid marker with one carrying a different nonce."""
    admin = _admin(instance.dsn)
    try:
        marker = twin_module.read_marker(admin, name)
        assert marker is not None
        twin_module.write_marker(
            admin,
            name,
            twin_module.OwnershipMarker(
                marker.version,
                marker.run_id,
                marker.kind,
                marker.worker_id,
                marker.source_database,
                marker.cluster_id,
                marker.owner_role,
                "f" * 32,
                marker.created_at,
            ),
        )
    finally:
        admin.close()


# --------------------------------------------------------------------------- #
# Unit tests - no database
# --------------------------------------------------------------------------- #


def test_generated_names_are_unique_per_worker() -> None:
    first = generated_name(RUN, "worker", "w0")
    second = generated_name(RUN, "worker", "w1")
    assert first != second
    assert first.startswith("mizan_v61_" + RUN + "_")
    assert expected_seed_name(RUN) != first


def test_generated_names_reject_injection_and_bad_identifiers() -> None:
    with pytest.raises(OwnershipError):
        generated_name(RUN, "worker", 'w0"; DROP DATABASE x; --')
    with pytest.raises(OwnershipError):
        generated_name(RUN, "worker", "W0")
    with pytest.raises(OwnershipError):
        generated_name(RUN, "seed", "w0")
    with pytest.raises(OwnershipError):
        generated_name("run1", "worker", "w0")
    with pytest.raises(OwnershipError):
        generated_name(RUN, "vulnerable")


def test_parse_generated_name_rejects_similar_names() -> None:
    exact = expected_worker_name(RUN, "w0")
    assert parse_generated_name(exact) == (RUN, "worker", "w0")
    assert parse_generated_name(expected_seed_name(RUN)) == (RUN, "seed", "")
    for name in (
        exact + ".copy",
        exact.upper(),
        exact.replace(RUN, RUN.upper()),
        expected_seed_name(RUN) + "_worker_w0",
        "mizan_v61_" + RUN + "_worker_",
        "mizan_v61_" + RUN + "_evil_w0",
        "mizan_v61_" + RUN + "_worker_w0\n",
        "mizan_v61_" + RUN + '_worker_w0"; DROP DATABASE x; --',
    ):
        assert parse_generated_name(name) is None, name


def test_record_validation_rejects_every_identity_mismatch() -> None:
    validate_record(_record(), run_id=RUN, source_database="source", cluster_id=CLUSTER)

    cases = [
        {"run_id": OTHER_RUN},
        {"run_id": RUN, "database_name": "source"},
        {"run_id": RUN, "database_name": expected_seed_name(RUN)},
        {"run_id": RUN, "cluster": "1"},
        {"run_id": RUN, "source": "another"},
        {"run_id": RUN, "nonce": "short"},
        {"run_id": RUN, "owner": ""},
        {"run_id": RUN, "worker_id": 'w0"; DROP DATABASE x; --'},
    ]
    for case in cases:
        with pytest.raises(OwnershipError):
            record = _record(**case)
            validate_record(
                record,
                run_id=RUN,
                source_database="source",
                cluster_id=CLUSTER,
            )


def test_ownership_record_round_trip() -> None:
    record = _record()
    assert OwnershipRecord.from_dict(json.loads(json.dumps(record.to_dict()))) == record


def test_registry_rejects_unknown_database(tmp_path) -> None:
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    assert registry.get("unknown") is None


def test_registry_writes_atomically_and_rejects_key_mismatch(tmp_path) -> None:
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    registry.put(_record())
    assert registry.get(_record().database_name) == _record()
    assert [path.name for path in tmp_path.iterdir() if path.name.endswith(".tmp")] == []

    payload = registry.load()
    payload["different-name"] = payload[_record().database_name]
    (tmp_path / "ownership.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(OwnershipError, match="does not match"):
        registry.records()


def test_registry_rejects_malformed_json(tmp_path) -> None:
    path = tmp_path / "ownership.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(OwnershipError):
        DatabaseRegistry(path).records()


def test_invalid_transition_fails_closed() -> None:
    from mizan.postgres_twin import DisposableDatabase

    database = DisposableDatabase(object(), object(), None, "w0")  # type: ignore[arg-type]
    with pytest.raises(TwinLifecycleError):
        database._transition(TwinState.RUNNING)


def test_source_requires_environment_variable(monkeypatch) -> None:
    monkeypatch.delenv(DSN_ENV, raising=False)
    with pytest.raises(SourceProtectionError):
        PostgresSource(DSN_ENV, schemas=("public",))


def test_source_rejects_a_generated_database(monkeypatch) -> None:
    dsn = "postgresql://u:p@localhost:5432/" + expected_seed_name(RUN)
    monkeypatch.setenv(DSN_ENV, dsn)
    with pytest.raises(SourceProtectionError):
        PostgresSource(DSN_ENV, schemas=("public",))


def test_child_process_environment_never_contains_the_password() -> None:
    from mizan.postgres_twin import ConnectionTarget, password_file

    secret = "s3cr3t-value"
    target = ConnectionTarget.parse("postgresql://alice:" + secret + "@db.example:5432/source?sslmode=require")
    env = target.child_environment(database="source", passfile="C:/tmp/pgpass")
    assert "PGPASSWORD" not in env
    assert secret not in " ".join(env.values())
    assert env["PGPASSFILE"] == "C:/tmp/pgpass"
    assert env["PGSSLMODE"] == "require"
    assert secret not in target.dsn("source", include_password=False)

    with tempfile.TemporaryDirectory() as directory:
        with password_file(target, database="source", directory=Path(directory)) as path:
            assert path is not None
            assert secret in Path(path).read_text(encoding="utf-8")
            if os.name != "nt":
                assert oct(Path(path).stat().st_mode & 0o777) == "0o600"
        assert not Path(path).exists()


def test_redact_removes_dsn_passwords_and_named_secrets() -> None:
    text = "failed postgresql://alice:hunter2@db:5432/source using hunter2"
    redacted = redact(text, secrets=("hunter2",))
    assert "hunter2" not in redacted
    assert "***" in redacted


def test_typed_values_preserve_type_and_scale() -> None:
    import decimal

    assert _typed(1) != _typed("1")
    assert _typed(None) == ["null", ""]
    assert _typed(True) != _typed(1)
    assert _typed(decimal.Decimal("1.00")) != _typed(decimal.Decimal("1"))


def _fake_source():
    class Target:
        def dsn(self, database: str, *, application_name: str | None = None, include_password: bool = True) -> str:
            suffix = f"?application_name={application_name}" if application_name else ""
            return f"postgresql://u:p@localhost/{database}{suffix}"

    class Source:
        run_id = RUN
        dsn = "postgresql://u:p@localhost/source"
        schemas = ("pgstore",)
        target = Target()
        rollback_errors: list[str] = []

        def source_name(self) -> str:
            return "source"

        def admin(self):
            return None

        def cluster_id(self, connection=None) -> str:
            return CLUSTER

        def fingerprint(self, dsn=None) -> str:
            return "digest"

        def assert_unchanged(self) -> None:
            return None

        def redact(self, text: str) -> str:
            return text

    return Source()


def _fake_baseline():
    return type(
        "Baseline",
        (),
        {
            "name": expected_seed_name(RUN),
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
        lambda self: _record(database_name=self.name),
    )
    monkeypatch.setattr(DisposableDatabase, "verify", lambda self, **kwargs: "digest")
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


def test_cleanup_rejects_record_naming_the_source(monkeypatch, tmp_path):
    monkeypatch.setenv(DSN_ENV, "postgresql://u:p@127.0.0.1:1/source")
    record = _record(database_name="source")
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    registry.put(record)
    with pytest.raises(SourceProtectionError):
        cleanup_run(DSN_ENV, tmp_path, RUN)


def test_restore_failure_fails_closed(monkeypatch, tmp_path):
    from mizan.postgres_twin import DisposableDatabase, PostgresTwin

    def boom(self):
        raise TwinLifecycleError("restore failed")

    monkeypatch.setattr(DisposableDatabase, "drop", boom)
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "own.json"),
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

    monkeypatch.setattr(twin_module, "_verify_database_ownership", lambda *args, **kwargs: None)
    source = _fake_source()
    calls = {"n": 0}

    def changing(*args, **kwargs):
        calls["n"] += 1
        return "digest" if calls["n"] > 1 else "different"

    source.fingerprint = changing
    database = DisposableDatabase(source, _fake_baseline(), None, "w0")  # type: ignore[arg-type]
    database.record = _record(database_name=database.name)
    with pytest.raises(BaselineVerificationError):
        database.verify()


def test_audit_initialization_failure_fails_closed(monkeypatch, tmp_path):
    from mizan.postgres_audit import PostgresAuditor
    from mizan.postgres_twin import DisposableDatabase, PostgresTwin, Twin

    monkeypatch.setattr(Twin, "start", lambda self: self.base_url)
    monkeypatch.setattr(
        DisposableDatabase,
        "create",
        lambda self: _record(database_name=self.name),
    )
    monkeypatch.setattr(DisposableDatabase, "connect", lambda self: object())
    monkeypatch.setattr(
        PostgresAuditor, "install", lambda self: (_ for _ in ()).throw(TwinLifecycleError("audit failed"))
    )
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "own.json"),
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
        DatabaseRegistry(tmp_path / "own.json"),
        "w0",
        command=["python"],
        workdir=tmp_path,
    )
    twin.state = TwinState.READY
    with pytest.raises(TwinLifecycleError, match="cleanup failed"):
        twin.cleanup()
    assert twin.state is TwinState.FAILED


def test_stop_failure_blocks_the_destructive_drop(monkeypatch, tmp_path):
    from mizan.postgres_twin import PostgresTwin

    dropped = {"value": False}

    def failing_stop(self, *, strict):
        raise TwinLifecycleError("the application did not stop")

    monkeypatch.setattr(PostgresTwin, "_stop_application", failing_stop)
    monkeypatch.setattr(
        twin_module.DisposableDatabase,
        "drop",
        lambda self: dropped.__setitem__("value", True),
    )
    twin = PostgresTwin(
        _fake_source(),
        _fake_baseline(),
        DatabaseRegistry(tmp_path / "own.json"),
        "w0",
        command=["python"],
        workdir=tmp_path,
    )
    twin.state = TwinState.READY
    with pytest.raises(TwinLifecycleError, match="did not stop"):
        twin.cleanup()
    assert dropped["value"] is False
    assert twin.state is TwinState.FAILED


def test_cleanup_run_cli_reports_a_machine_readable_failure(monkeypatch, tmp_path):
    from click.testing import CliRunner

    from mizan.cli import main

    (tmp_path / "ownership.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        twin_module,
        "cleanup_run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OwnershipError("a forged record was refused")),
    )
    result = CliRunner().invoke(
        main,
        [
            "postgres-twin",
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--cleanup-run",
            RUN,
            "--workspace",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["status"] == "CLEANUP_FAILED"
    assert "forged" in payload["error"]


def test_no_session_termination_api_is_used() -> None:
    assert not hasattr(twin_module, "_terminate_owned_sessions")
    source = inspect.getsource(twin_module.verified_drop)
    assert "pg_terminate_backend" not in source
    assert "application_name" not in source


def test_cleanup_failures_carry_machine_readable_state() -> None:
    preflight = CleanupPreflightError(["bad marker"], categories={"db": "invalid marker"})
    assert preflight.categories == {"db": "invalid marker"}
    partial = PartialCleanupError(["w0"], ["seed"], ["drop refused"])
    assert partial.cleaned == ["w0"]
    assert partial.remaining == ["seed"]


def test_cli_reports_preflight_and_partial_cleanup_statuses(monkeypatch, tmp_path) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    (tmp_path / "ownership.json").write_text("{}", encoding="utf-8")
    cases = [
        (
            CleanupPreflightError(["bad marker"], categories={"db": "invalid marker"}),
            "PREFLIGHT_FAILED",
        ),
        (PartialCleanupError(["w0"], ["seed"], ["drop refused"]), "PARTIAL_CLEANUP"),
    ]
    for error, expected in cases:

        def failing(*args, _error=error, **kwargs):
            raise _error

        monkeypatch.setattr(twin_module, "cleanup_run", failing)
        result = CliRunner().invoke(
            main,
            [
                "postgres-twin",
                "--dsn-env",
                DSN_ENV,
                "--schema",
                "pgstore",
                "--cleanup-run",
                RUN,
                "--workspace",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 2
        payload = json.loads(result.output)
        assert payload["status"] == expected


def test_cli_never_claims_verified_before_a_successful_cleanup(monkeypatch, tmp_path):
    from click.testing import CliRunner

    from mizan.cli import main

    monkeypatch.setenv(DSN_ENV, "postgresql://u:very-secret-password@127.0.0.1:1/source")
    monkeypatch.setattr(
        twin_module.PostgresSource,
        "prepare_baseline",
        lambda self, workspace: (_ for _ in ()).throw(TwinLifecycleError("baseline failed")),
    )
    monkeypatch.setattr(
        twin_module,
        "cleanup_run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OwnershipError("cleanup failed")),
    )
    result = CliRunner().invoke(
        main,
        [
            "postgres-twin",
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--workers",
            "1",
            "--allow-disposable",
            "--workspace",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    assert "VERIFIED" not in result.output
    payload = json.loads(result.output[result.output.index("{") :])
    assert payload["status"] == "cleanup_failed"
    assert payload["cleanup_errors"]


def test_deletion_intent_round_trip_and_tamper_rejection() -> None:
    intent = DeletionIntent(
        run_id=RUN,
        database_name=expected_worker_name(RUN, "w0"),
        kind="worker",
        worker_id="w0",
        source_database="source",
        cluster_id=CLUSTER,
        owner_role=OWNER,
        nonce=NONCE,
        oid=1234,
        marker_digest="a" * 64,
        operation_id="a" * 32,
        created_at=1.0,
    )
    assert DeletionIntent.from_dict(json.loads(json.dumps(intent.to_dict()))) == intent
    assert intent.with_state(IntentState.CLEANED).state is IntentState.CLEANED
    for field, value in (
        ("run_id", OTHER_RUN),
        ("database_name", "source"),
        ("kind", "vulnerable"),
        ("nonce", "short"),
        ("oid", -1),
        ("marker_digest", "xyz"),
        ("operation_id", ""),
        ("state", "UNKNOWN"),
    ):
        data = intent.to_dict()
        data[field] = value
        with pytest.raises(OwnershipError):
            DeletionIntent.from_dict(data)


def test_journal_key_is_not_an_ownership_record(tmp_path) -> None:
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    registry.put(_record())
    assert len(registry.records()) == 1
    assert registry.intents() == {}
    intent = DeletionIntent(
        run_id=RUN,
        database_name=_record().database_name,
        kind="worker",
        worker_id="w0",
        source_database="source",
        cluster_id=CLUSTER,
        owner_role=OWNER,
        nonce=NONCE,
        oid=1234,
        marker_digest="a" * 64,
        operation_id="a" * 32,
        created_at=1.0,
    )
    registry.put_intent(intent)
    assert twin_module.DELETION_INTENTS_KEY in registry.load()
    assert len(registry.records()) == 1
    assert registry.get_intent(_record().database_name) == intent


def test_no_import_time_directory_probe() -> None:
    assert not hasattr(twin_module, "_directory_fsync_supported")
    assert not hasattr(twin_module, "DIRECTORY_FSYNC_SUPPORTED")
    # The removed VI.2.2 probe created this marker name in the system temp dir.
    marker = Path(tempfile.gettempdir()) / ".mizan-dirfsync"
    assert not marker.exists(), "an import-time filesystem probe was performed"


def test_registry_write_reports_actual_parent_sync(tmp_path) -> None:
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    registry.put(_record())
    if os.name == "posix":
        assert registry.last_directory_sync_supported is True
        assert registry.last_directory_synced is True
    else:
        assert registry.last_directory_sync_supported is False
        assert registry.last_directory_synced is False


def test_directory_fsync_failure_is_reported(tmp_path, monkeypatch) -> None:
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    calls = {"n": 0}

    def fake_fsync(fd):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise PermissionError("directory fsync is not permitted")

    monkeypatch.setattr(os, "fsync", fake_fsync)
    registry.put(_record())
    assert registry.last_directory_sync_supported is False
    assert registry.last_directory_synced is False


def test_directory_open_failure_is_reported(tmp_path, monkeypatch) -> None:
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    real_open = os.open

    def fake_open(path, flags, mode=0o777):
        if flags == os.O_RDONLY:
            raise PermissionError("directory open is not supported")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)
    registry.put(_record())
    assert registry.last_directory_sync_supported is False
    assert registry.last_directory_synced is False


def test_directory_fsync_io_error_is_raised(tmp_path, monkeypatch) -> None:
    registry = DatabaseRegistry(tmp_path / "ownership.json")
    real_open = os.open
    real_close = os.close

    def fake_open(path, flags, mode=0o777):
        if Path(path) == registry.path.parent:
            return 1
        return real_open(path, flags, mode)

    def fake_close(fd):
        if fd != 1:
            real_close(fd)

    calls = {"n": 0}

    def fake_fsync(fd):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "close", fake_close)
    monkeypatch.setattr(os, "fsync", fake_fsync)
    with pytest.raises(OwnershipError, match="directory could not be synced"):
        registry.put(_record())


def test_no_backend_termination_api_exists() -> None:
    for attribute in ("pg_terminate_backend", "_terminate_owned_sessions"):
        assert not hasattr(twin_module, attribute)


def test_cli_requires_workspace_for_cleanup_run(monkeypatch) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    monkeypatch.setenv(DSN_ENV, "postgresql://u:secret@127.0.0.1:1/source")
    result = CliRunner().invoke(
        main,
        ["postgres-twin", "--dsn-env", DSN_ENV, "--schema", "pgstore", "--cleanup-run", RUN],
    )
    assert result.exit_code != 0
    payload = json.loads(result.output)
    assert payload["status"] == "OWNERSHIP_UNPROVABLE"
    assert payload["cleaned"] == []
    assert "secret" not in result.output


# --------------------------------------------------------------------------- #
# Real PostgreSQL integration
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def source():
    dsn = _dsn()
    os.environ[DSN_ENV] = dsn
    instance = PostgresSource(DSN_ENV, schemas=("pgstore",))
    spec = importlib.util.spec_from_file_location("pgstore_fixture", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
    os.environ["MIZAN_TOKEN_ALICE"] = "twin-alice"
    os.environ["MIZAN_TOKEN_BOB"] = "twin-bob"
    try:
        module.create_app("clean", dsn=dsn, schema="pgstore")
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return instance, dsn


def _admin(dsn: str):
    import psycopg

    return psycopg.connect(dsn, autocommit=True)


def _create_database(dsn: str, name: str) -> None:
    from psycopg import sql

    admin = _admin(dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    finally:
        admin.close()


def _drop_database(dsn: str, name: str) -> None:
    from psycopg import sql

    admin = _admin(dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
    finally:
        admin.close()


def _database_exists(dsn: str, name: str) -> bool:
    admin = _admin(dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            return cursor.fetchone() is not None
    finally:
        admin.close()


@pytest.mark.postgres_integration
def test_full_lifecycle_protects_source_and_isolates_workers(source) -> None:
    from mizan.postgres_twin import PostgresTwin

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-life-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    original = instance.fingerprint()
    command = [sys.executable, str(FIXTURE / "app.py"), "--port", "{port}"]
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
        cleanup_run(DSN_ENV, workspace, instance.run_id)
        instance.assert_unchanged()
    assert not _database_exists(_dsn_value, baseline.name)
    for twin in twins:
        assert not _database_exists(_dsn_value, twin.database.name)


@pytest.mark.postgres_integration
def test_l3_probe_runs_on_disposable_database(source) -> None:
    from mizan.postgres_twin import PostgresTwin, run_l2_l3_probes

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-probe-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    vulnerable_name = "mizan_v62_source_" + uuid.uuid4().hex[:12]
    _create_database(instance.dsn, vulnerable_name)
    vulnerable_dsn = database_dsn(instance.dsn, vulnerable_name)
    spec = importlib.util.spec_from_file_location("pgstore_vuln", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
    os.environ["MIZAN_TOKEN_ALICE"] = "twin-alice"
    os.environ["MIZAN_TOKEN_BOB"] = "twin-bob"
    try:
        module.create_app("write", dsn=vulnerable_dsn, schema="pgstore")
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    os.environ[DSN_ENV] = vulnerable_dsn
    vulnerable_source = PostgresSource(DSN_ENV, schemas=("pgstore",))
    baseline = vulnerable_source.prepare_baseline(workspace)
    twin = PostgresTwin(
        vulnerable_source,
        baseline,
        registry,
        "probe",
        command=[
            sys.executable,
            str(FIXTURE / "app.py"),
            "--port",
            "{port}",
            "--vulnerability",
            "write",
        ],
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
        cleanup_run(DSN_ENV, workspace, vulnerable_source.run_id)
        _drop_database(instance.dsn, vulnerable_name)
        os.environ[DSN_ENV] = _dsn_value


@pytest.mark.postgres_integration
def test_cleanup_never_drops_unowned_databases(source) -> None:
    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-clean-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    registry.put(_record(run_id=OTHER_RUN, source=instance.source_name()))
    # A run with no local record is unprovable, never a successful no-op.
    with pytest.raises(OwnershipUnprovable):
        cleanup_run(DSN_ENV, workspace, RUN)


@pytest.mark.postgres_integration
def test_clone_does_not_contain_a_non_allowlisted_schema(source) -> None:
    instance, _dsn_value = source
    source_name = "mizan_v62_source_" + uuid.uuid4().hex[:12]
    _create_database(instance.dsn, source_name)
    source_dsn = database_dsn(instance.dsn, source_name)
    spec = importlib.util.spec_from_file_location("pgstore_allow", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.create_app("clean", dsn=source_dsn, schema="pgstore")

    import psycopg

    with psycopg.connect(source_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute("CREATE SCHEMA secret")
            cursor.execute("CREATE TABLE secret.sentinel (id INT PRIMARY KEY, note TEXT)")
            cursor.execute("INSERT INTO secret.sentinel VALUES (1, 'SENTINEL-NEVER-COPIED')")
        connection.commit()

    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-allow-"))
    os.environ[DSN_ENV] = source_dsn
    try:
        guarded = PostgresSource(DSN_ENV, schemas=("pgstore",))
        baseline = guarded.prepare_baseline(workspace)
        clone = psycopg.connect(baseline.dsn)
        try:
            with clone.cursor() as cursor:
                cursor.execute("SELECT to_regclass('secret.sentinel')")
                assert cursor.fetchone()[0] is None
                cursor.execute(
                    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'secret' AND c.relkind IN ('r','p','S','v','m','f')"
                )
                assert cursor.fetchone()[0] == 0
        finally:
            clone.close()
        cleanup_run(DSN_ENV, workspace, guarded.run_id)
        assert not _database_exists(instance.dsn, baseline.name)
    finally:
        _drop_database(instance.dsn, source_name)
        os.environ[DSN_ENV] = _dsn_value


@pytest.mark.postgres_integration
def test_cross_schema_dependency_fails_closed_and_rolls_back(source) -> None:
    instance, _dsn_value = source
    source_name = "mizan_v62_source_" + uuid.uuid4().hex[:12]
    _create_database(instance.dsn, source_name)
    source_dsn = database_dsn(instance.dsn, source_name)
    spec = importlib.util.spec_from_file_location("pgstore_cross", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.create_app("clean", dsn=source_dsn, schema="pgstore")

    import psycopg

    with psycopg.connect(source_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute("CREATE SCHEMA secret")
            cursor.execute("CREATE TABLE secret.sentinel (id INT PRIMARY KEY)")
            cursor.execute("CREATE VIEW pgstore.depends_on_secret AS SELECT id FROM secret.sentinel")
        connection.commit()

    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-cross-"))
    os.environ[DSN_ENV] = source_dsn
    try:
        guarded = PostgresSource(DSN_ENV, schemas=("pgstore",))
        with pytest.raises(TwinLifecycleError):
            guarded.prepare_baseline(workspace)
        # Baseline preparation failed: no generated seed may survive.
        assert not [
            name for name in _generated_databases(instance.dsn) if name.startswith("mizan_v61_" + guarded.run_id)
        ]
    finally:
        _drop_database(instance.dsn, source_name)
        os.environ[DSN_ENV] = _dsn_value


def _generated_databases(dsn: str) -> list[str]:
    admin = _admin(dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT datname FROM pg_database WHERE datname LIKE 'mizan_v61_%%'")
            return [str(row[0]) for row in cursor.fetchall()]
    finally:
        admin.close()


@pytest.mark.postgres_integration
def test_fingerprint_is_schema_qualified_and_sequence_aware(source) -> None:
    instance, _dsn_value = source
    admin = _admin(instance.dsn)
    name = "mizan_v62_source_" + uuid.uuid4().hex[:12]
    try:
        with admin.cursor() as cursor:
            from psycopg import sql

            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        dsn = database_dsn(instance.dsn, name)
        import psycopg

        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                for schema in ("a", "b"):
                    cursor.execute(f"CREATE SCHEMA {schema}")
                    cursor.execute(f"CREATE TABLE {schema}.same_name (id INT PRIMARY KEY)")
                    cursor.execute(f"INSERT INTO {schema}.same_name VALUES (1)")
                cursor.execute("ALTER TABLE b.same_name ADD COLUMN extra TEXT")
                cursor.execute("CREATE SEQUENCE a.seq")
            connection.commit()

        os.environ[DSN_ENV] = dsn
        guarded = PostgresSource(DSN_ENV, schemas=("a", "b"))
        first = guarded.fingerprint()
        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT nextval('a.seq')")
            connection.commit()
        second = guarded.fingerprint()
        assert first != second, "a sequence last_value/is_called change was not detected"

        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE a.same_name SET id = 2 WHERE id = 1")
            connection.commit()
        assert guarded.fingerprint() != second
    finally:
        admin.close()
        _drop_database(instance.dsn, name)
        os.environ[DSN_ENV] = _dsn_value


@pytest.mark.postgres_integration
def test_cleanup_refuses_a_forged_registry_record(source) -> None:
    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-forged-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    forged_name = "mizan_v62_forged_" + uuid.uuid4().hex[:8]
    _create_database(instance.dsn, forged_name)
    try:
        record = _record(database_name=forged_name, source=instance.source_name())
        registry.put(record)
        with pytest.raises(OwnershipError):
            cleanup_run(DSN_ENV, workspace, RUN)
        assert _database_exists(instance.dsn, forged_name)
    finally:
        _drop_database(instance.dsn, forged_name)


@pytest.mark.postgres_integration
def test_cleanup_refuses_a_foreign_marker_and_keeps_the_database(source) -> None:
    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-marker-"))
    name = expected_worker_name(RUN, "w0")
    _create_database(instance.dsn, name)
    admin = _admin(instance.dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
            cursor.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s", (name,))
            owner = str(cursor.fetchone()[0])
        twin_module.write_marker(
            admin,
            name,
            twin_module.OwnershipMarker(1, RUN, "worker", "w0", instance.source_name(), cluster, owner, "b" * 32, 1.0),
        )
        registry = DatabaseRegistry(workspace / "ownership.json")
        registry.put(_record(database_name=name, source=instance.source_name(), cluster=cluster, owner=owner))
        with pytest.raises(OwnershipError, match="nonce"):
            cleanup_run(DSN_ENV, workspace, RUN)
        assert _database_exists(instance.dsn, name)
    finally:
        _drop_database(instance.dsn, name)
        admin.close()


@pytest.mark.postgres_integration
def test_cleanup_refuses_a_record_from_another_cluster(source) -> None:
    instance, _dsn_value = source
    run = "feedfacecafe"
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-cluster-"))
    name = expected_worker_name(run, "w0")
    _create_database(instance.dsn, name)
    admin = _admin(instance.dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            live = str(cursor.fetchone()[0])
            cursor.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s", (name,))
            owner = str(cursor.fetchone()[0])
        foreign = "1" if live != "1" else "2"
        nonce = "d" * 32
        twin_module.write_marker(
            admin,
            name,
            twin_module.OwnershipMarker(1, run, "worker", "w0", instance.source_name(), foreign, owner, nonce, 1.0),
        )
        registry = DatabaseRegistry(workspace / "ownership.json")
        registry.put(
            _record(
                run_id=run,
                database_name=name,
                source=instance.source_name(),
                cluster=foreign,
                owner=owner,
                nonce=nonce,
            )
        )
        with pytest.raises(OwnershipError, match="cluster"):
            cleanup_run(DSN_ENV, workspace, run)
        assert _database_exists(instance.dsn, name)
    finally:
        _drop_database(instance.dsn, name)
        admin.close()


@pytest.mark.postgres_integration
def test_all_valid_run_cleanup_removes_seed_and_workers(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-valid-run-"))
    baseline, _registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    try:
        assert all(_database_exists(dsn, name) for name in names)
        cleaned = cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert set(cleaned) == set(names)
        assert not any(_database_exists(dsn, name) for name in names)
        assert cleanup_run(DSN_ENV, workspace, instance.run_id) == []
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_invalid_second_worker_marker_blocks_whole_run(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-bad-worker-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    names = [baseline.name, w0, w1]
    try:
        _tamper_marker(instance, w1)
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(w1) == "invalid marker"
        assert all(_database_exists(dsn, name) for name in names), "a database was deleted during preflight"
        assert {record.database_name for record in registry.records()} == set(names)
        assert all(record.state is not TwinState.CLEANED for record in registry.records())
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_invalid_seed_marker_leaves_workers_untouched(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-bad-seed-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    names = [baseline.name, w0, w1]
    try:
        _tamper_marker(instance, baseline.name)
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(baseline.name) == "invalid marker"
        assert all(_database_exists(dsn, name) for name in names)
        assert {record.database_name for record in registry.records()} == set(names)
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_session_created_during_preflight_blocks_every_drop(source, monkeypatch) -> None:
    import psycopg

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-late-session-"))
    baseline, _registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    late: list[Any] = []
    original = twin_module._wait_for_no_sessions

    def inject(*args, **kwargs):
        if not late:
            name = expected_worker_name(instance.run_id, "w1")
            late.append(
                psycopg.connect(database_dsn(instance.dsn, name, application_name="late-client"), connect_timeout=5)
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(twin_module, "_wait_for_no_sessions", inject)
    try:
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(names[2]) == "active session"
        assert all(_database_exists(dsn, name) for name in names), "a drop preceded the preflight failure"
    finally:
        for connection in late:
            connection.close()
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_session_that_disappears_during_preflight_allows_cleanup(source) -> None:
    import psycopg

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-vanish-"))
    baseline, _registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    names = [baseline.name, w0, w1]
    holder: list[Any] = []
    connected = threading.Event()

    def connect_then_close() -> None:
        holder.append(
            psycopg.connect(database_dsn(instance.dsn, w0, application_name="vanishing-client"), connect_timeout=5)
        )
        connected.set()
        time.sleep(0.2)
        holder[0].close()

    thread = threading.Thread(target=connect_then_close)
    try:
        thread.start()
        assert connected.wait(timeout=10)
        cleaned = cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert set(cleaned) == set(names)
        assert not any(_database_exists(dsn, name) for name in names)
    finally:
        thread.join(timeout=10)
        if holder and not holder[0].closed:
            holder[0].close()
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_failure_before_first_drop_is_partial_with_zero_deletions(source, monkeypatch) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-before-drop-"))
    baseline, _registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    monkeypatch.setattr(
        twin_module,
        "verified_drop",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("simulated failure")),
    )
    try:
        with pytest.raises(PartialCleanupError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.cleaned == []
        assert set(error.value.remaining) == set(names)
        assert all(_database_exists(dsn, name) for name in names)
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_failure_after_first_drop_is_recoverable(source, monkeypatch) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-after-drop-"))
    baseline, _registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    names = [baseline.name, w0, w1]
    original = twin_module.verified_drop
    calls = {"n": 0}

    def failing_drop(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return original(*args, **kwargs)
        raise RuntimeError("simulated failure after the first drop")

    monkeypatch.setattr(twin_module, "verified_drop", failing_drop)
    try:
        with pytest.raises(PartialCleanupError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.cleaned == [w0]
        assert set(error.value.remaining) == {w1, baseline.name}
        assert not _database_exists(dsn, w0)
        assert _database_exists(dsn, w1) and _database_exists(dsn, baseline.name)
    finally:
        monkeypatch.setattr(twin_module, "verified_drop", original)
        cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert not any(_database_exists(dsn, name) for name in names)


@pytest.mark.postgres_integration
def test_concurrent_cleanup_is_coordinated(source, monkeypatch) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v61-concurrent-"))
    baseline, _registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    entered = threading.Event()
    release = threading.Event()
    original = twin_module.verified_drop
    monkeypatch.setattr(twin_module, "RUN_LOCK_TIMEOUT_SECONDS", 0.5)

    def blocking_drop(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=30), "the first cleanup was never released"
        return original(*args, **kwargs)

    monkeypatch.setattr(twin_module, "verified_drop", blocking_drop)
    outcomes: dict[str, Any] = {}

    def first() -> None:
        try:
            outcomes["first"] = cleanup_run(DSN_ENV, workspace, instance.run_id)
        except Exception as exc:  # pragma: no cover - reported by the assertion
            outcomes["first_error"] = exc

    thread = threading.Thread(target=first)
    try:
        thread.start()
        assert entered.wait(timeout=30), "the first cleanup did not reach its drop"
        with pytest.raises(CleanupPreflightError, match="lock"):
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        release.set()
        thread.join(timeout=30)
        assert "first_error" not in outcomes, outcomes.get("first_error")
        assert set(outcomes["first"]) == set(names)
        assert not any(_database_exists(dsn, name) for name in names)
    finally:
        release.set()
        thread.join(timeout=30)
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_advisory_cleanup_lock_is_released_with_its_connection(source) -> None:
    instance, dsn = source
    first = _admin(instance.dsn)
    second = _admin(instance.dsn)

    key = (twin_module.RUN_LOCK_NAMESPACE << 48) + int(RUN, 16)

    def try_lock() -> bool:
        with second.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s)", (key,))
            return bool(cursor.fetchone()[0])

    try:
        with twin_module._run_cleanup_lock(first, RUN):
            assert try_lock() is False, "a concurrent cleanup could hold the same run lock"
        assert try_lock() is True, "the run lock survived its original connection"
        with second.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s)", (key,))
    finally:
        first.close()
        second.close()


@pytest.mark.postgres_integration
def test_cleanup_lock_is_released_after_process_kill(source) -> None:
    instance, dsn = source
    key = (twin_module.RUN_LOCK_NAMESPACE << 48) + int(RUN, 16)
    script = Path(tempfile.mkdtemp(prefix="mizan-v61-lock-script-")) / "holder.py"
    script.write_text(
        "import os, time\n"
        "import psycopg\n"
        "connection = psycopg.connect(os.environ['MIZAN_LOCK_DSN'], autocommit=True)\n"
        "with connection.cursor() as cursor:\n"
        f"    cursor.execute('SELECT pg_try_advisory_lock(%s)', ({key},))\n"
        "print('locked', flush=True)\n"
        "time.sleep(120)\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["MIZAN_LOCK_DSN"] = dsn
    process = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        assert process.stdout.readline().strip() == "locked"
        probe = _admin(instance.dsn)
        try:
            with probe.cursor() as cursor:
                cursor.execute("SELECT pg_try_advisory_lock(%s)", (key,))
                assert cursor.fetchone()[0] is False
        finally:
            probe.close()
        process.kill()
        process.wait(timeout=30)
        probe = _admin(instance.dsn)
        try:
            with probe.cursor() as cursor:
                cursor.execute("SELECT pg_try_advisory_lock(%s)", (key,))
                assert cursor.fetchone()[0] is True
                cursor.execute("SELECT pg_advisory_unlock(%s)", (key,))
        finally:
            probe.close()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)


@pytest.mark.postgres_integration
def test_cleanup_refuses_a_similar_name_without_failing_the_owner(source) -> None:
    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-similar-"))
    admin = _admin(instance.dsn)
    exact = expected_worker_name(RUN, "w0")
    similar = exact + "_copy"
    try:
        with admin.cursor() as cursor:
            from psycopg import sql

            for name in (exact, similar):
                cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
            owner = str(
                cursor.execute(
                    "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s",
                    (exact,),
                ).fetchone()[0]
            )
        for name in (exact, similar):
            twin_module.write_marker(
                admin,
                name,
                twin_module.OwnershipMarker(
                    1,
                    RUN,
                    "worker",
                    "w0",
                    instance.source_name(),
                    cluster,
                    owner,
                    "c" * 32,
                    1.0,
                ),
            )
        registry = DatabaseRegistry(workspace / "ownership.json")
        registry.put(
            _record(
                database_name=exact,
                source=instance.source_name(),
                cluster=cluster,
                owner=owner,
                nonce="c" * 32,
            )
        )
        cleaned = cleanup_run(DSN_ENV, workspace, RUN)
        assert cleaned == [exact]
        assert _database_exists(instance.dsn, similar)
    finally:
        _drop_database(instance.dsn, exact)
        _drop_database(instance.dsn, similar)
        admin.close()


@pytest.mark.postgres_integration
def test_cleanup_refuses_while_an_unrelated_session_is_active(source) -> None:
    import psycopg

    from mizan.postgres_twin import PostgresTwin

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-session-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    twin = PostgresTwin(
        instance,
        baseline,
        registry,
        "w0",
        command=[sys.executable, str(FIXTURE / "app.py"), "--port", "{port}"],
        workdir=workspace,
        env={"MIZAN_TOKEN_ALICE": "twin-alice", "MIZAN_TOKEN_BOB": "twin-bob"},
    )
    twin.start()
    unrelated = psycopg.connect(
        database_dsn(instance.dsn, twin.database.name, application_name="not-a-mizan-session"),
        connect_timeout=5,
    )
    try:
        with pytest.raises(CleanupError, match="session"):
            twin.cleanup()
        assert _database_exists(instance.dsn, twin.database.name)
    finally:
        unrelated.close()
        twin.cleanup()
        cleanup_run(DSN_ENV, workspace, instance.run_id)
    assert not _database_exists(instance.dsn, twin.database.name)
    assert not _database_exists(instance.dsn, baseline.name)


@pytest.mark.postgres_integration
def test_unrelated_session_spoofing_application_name_is_never_terminated(source) -> None:
    """A client-chosen label is not ownership; its backend must survive."""
    import psycopg

    from mizan.postgres_twin import PostgresTwin, app_session_identity

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-spoof-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    twin = PostgresTwin(
        instance,
        baseline,
        registry,
        "w0",
        command=[sys.executable, str(FIXTURE / "app.py"), "--port", "{port}"],
        workdir=workspace,
        env={"MIZAN_TOKEN_ALICE": "twin-alice", "MIZAN_TOKEN_BOB": "twin-bob"},
    )
    twin.start()
    identity = app_session_identity(instance.run_id, "w0")
    spoofed = psycopg.connect(
        database_dsn(instance.dsn, twin.database.name, application_name=identity),
        connect_timeout=5,
    )
    try:
        with spoofed.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            pid = int(cursor.fetchone()[0])
        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE pid = %s AND datname = %s",
                    (pid, twin.database.name),
                )
                assert cursor.fetchone()[0] == 1, "the spoofed backend was not established"
        finally:
            admin.close()

        with pytest.raises(CleanupError, match="session"):
            twin.cleanup()
        assert _database_exists(instance.dsn, twin.database.name)

        # The unrelated backend is alive and usable: it was never terminated.
        with spoofed.cursor() as cursor:
            cursor.execute("SELECT 1")
            assert cursor.fetchone() == (1,)
        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE pid = %s", (pid,))
                assert cursor.fetchone()[0] == 1, "the spoofed backend was terminated"
        finally:
            admin.close()
    finally:
        spoofed.close()
        # Retry after the unrelated session disconnects: now it can succeed.
        twin.cleanup()
        cleanup_run(DSN_ENV, workspace, instance.run_id)
    assert not _database_exists(instance.dsn, twin.database.name)
    assert not _database_exists(instance.dsn, baseline.name)


@pytest.mark.postgres_integration
def test_pooled_idle_and_active_sessions_are_released(source) -> None:
    import requests

    from mizan.postgres_twin import PostgresTwin

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-pool-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    twin = PostgresTwin(
        instance,
        baseline,
        registry,
        "w0",
        command=[sys.executable, str(FIXTURE / "app.py"), "--port", "{port}"],
        workdir=workspace,
        pool_size=4,
        env={"MIZAN_TOKEN_ALICE": "twin-alice", "MIZAN_TOKEN_BOB": "twin-bob"},
    )
    try:
        twin.start()
        status = requests.get(twin.base_url + "/pool", timeout=10).json()
        assert status["enabled"] is True
        assert status["created"] >= 4
        for _ in range(6):
            response = requests.get(
                twin.base_url + "/items",
                headers={"Authorization": "Bearer twin-alice"},
                timeout=10,
            )
            assert response.status_code == 200
        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT pid FROM pg_stat_activity WHERE datname = %s AND application_name = %s",
                    (twin.database.name, twin_module.app_session_identity(instance.run_id, "w0")),
                )
                before_pids = {int(row[0]) for row in cursor.fetchall()}
                assert len(before_pids) >= 4
        finally:
            admin.close()

        twin.restore()
        assert instance.fingerprint(twin.database.dsn) == baseline.fingerprint
        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT pid FROM pg_stat_activity WHERE datname = %s AND application_name = %s",
                    (twin.database.name, twin_module.app_session_identity(instance.run_id, "w0")),
                )
                after_pids = {int(row[0]) for row in cursor.fetchall()}
                # The old pool is gone and a new pool was established; a PID
                # cannot survive the drop, so this proves it was released.
                assert not (before_pids & after_pids), "the old pool survived the restore"
                assert len(after_pids) >= 4
        finally:
            admin.close()
    finally:
        twin.cleanup()
        cleanup_run(DSN_ENV, workspace, instance.run_id)


@pytest.mark.postgres_integration
def test_pool_leak_mode_still_releases_connections(source) -> None:
    """A pool that fails to close must not block the verified drop."""
    import requests

    from mizan.postgres_twin import PostgresTwin

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-pool-leak-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    twin = PostgresTwin(
        instance,
        baseline,
        registry,
        "w0",
        command=[sys.executable, str(FIXTURE / "app.py"), "--port", "{port}"],
        workdir=workspace,
        pool_size=3,
        env={
            "MIZAN_TOKEN_ALICE": "twin-alice",
            "MIZAN_TOKEN_BOB": "twin-bob",
            "MIZAN_PG_POOL_LEAK": "1",
        },
    )
    try:
        twin.start()
        status = requests.get(twin.base_url + "/pool", timeout=10).json()
        assert status["enabled"] is True
        assert status["leak"] is True
        assert status["created"] >= 3
        for _ in range(4):
            response = requests.get(
                twin.base_url + "/items",
                headers={"Authorization": "Bearer twin-alice"},
                timeout=10,
            )
            assert response.status_code == 200

        shutdown = requests.post(twin.base_url + "/pool/shutdown?leak=1", timeout=10).json()
        assert shutdown["closed"] is True
        assert shutdown["leak"] is True
        identity = twin_module.app_session_identity(instance.run_id, "w0")
        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = %s AND application_name = %s",
                    (twin.database.name, identity),
                )
                assert cursor.fetchone()[0] >= 3, "a failed pool shutdown must leave its sessions open"
        finally:
            admin.close()

        # The leaked pool's connections are released explicitly; MÃ„Â«zÃ„Ân does not
        # terminate them by label. Cleanup then succeeds on retry.
        released = requests.post(twin.base_url + "/pool/release", timeout=10).json()
        assert released["released"] >= 3
        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = %s AND application_name = %s",
                    (twin.database.name, identity),
                )
                assert cursor.fetchone()[0] == 0
        finally:
            admin.close()

        twin.cleanup()
        assert not _database_exists(instance.dsn, twin.database.name)
    finally:
        twin.cleanup()
        cleanup_run(DSN_ENV, workspace, instance.run_id)
    assert not _database_exists(instance.dsn, baseline.name)


@pytest.mark.postgres_integration
def test_concurrent_requests_share_worker_database(source) -> None:
    """A race experiment's concurrent requests must target one disposable DB."""
    from concurrent.futures import ThreadPoolExecutor

    import requests

    from mizan.postgres_attribution import PostgresAttributor
    from mizan.postgres_twin import PostgresTwin

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-race-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    baseline = instance.prepare_baseline(workspace)
    twin = PostgresTwin(
        instance,
        baseline,
        registry,
        "race",
        command=[sys.executable, str(FIXTURE / "app.py"), "--port", "{port}", "--vulnerability", "clean"],
        workdir=workspace,
        pool_size=2,
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
        cleanup_run(DSN_ENV, workspace, instance.run_id)
        instance.assert_unchanged()


# --------------------------------------------------------------------------- #
# Signals and abrupt termination
# --------------------------------------------------------------------------- #


@pytest.mark.postgres_integration
def test_interruption_is_cleaned_up_even_without_a_real_signal(source, monkeypatch) -> None:
    from click.testing import CliRunner

    from mizan.cli import main
    from mizan.postgres_twin import RunInterrupted

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-interrupt-"))

    def interrupted(*args, **kwargs):
        raise RunInterrupted("the run was interrupted by signal 2")

    monkeypatch.setattr(twin_module, "run_l2_l3_probes", interrupted)
    result = CliRunner().invoke(
        main,
        [
            "postgres-twin",
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--workers",
            "1",
            "--allow-disposable",
            "--exercise",
            "--workspace",
            str(workspace),
        ],
    )
    assert result.exit_code == 2
    payload = json.loads(result.output[result.output.index("{") :])
    assert payload["status"] == "FAILED"
    run_id = payload["run_id"]
    assert not [name for name in _generated_databases(dsn) if run_id in name]


@pytest.mark.postgres_integration
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_signal_during_probes_cleans_up_and_exits_nonzero(source, monkeypatch, signum) -> None:
    if os.name == "nt":
        pytest.skip("POSIX signal delivery is required; Windows has no catchable SIGTERM")
    from click.testing import CliRunner

    from mizan.cli import main

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-signal-"))

    def interrupted(*args, **kwargs):
        os.kill(os.getpid(), signum)
        raise AssertionError("the signal handler did not interrupt the probe call")

    monkeypatch.setattr(twin_module, "run_l2_l3_probes", interrupted)
    result = CliRunner().invoke(
        main,
        [
            "postgres-twin",
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--workers",
            "1",
            "--allow-disposable",
            "--exercise",
            "--workspace",
            str(workspace),
        ],
    )
    assert result.exit_code != 0
    payload = json.loads(result.output[result.output.index("{") :])
    assert payload["status"] in {"FAILED", "cleanup_failed"}
    run_id = payload["run_id"]
    assert not [name for name in _generated_databases(dsn) if run_id in name]
    assert workspace.joinpath("ownership.json").exists()


@pytest.mark.postgres_integration
def test_signal_during_restore_cleans_up(source, monkeypatch) -> None:
    if os.name == "nt":
        pytest.skip("POSIX signal delivery is required")
    from click.testing import CliRunner

    from mizan.cli import main
    from mizan.postgres_twin import PostgresTwin

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-restore-signal-"))
    original = PostgresTwin.restore

    def interrupted_restore(self):
        os.kill(os.getpid(), signal.SIGINT)
        return original(self)

    monkeypatch.setattr(PostgresTwin, "restore", interrupted_restore)
    result = CliRunner().invoke(
        main,
        [
            "postgres-twin",
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--workers",
            "1",
            "--allow-disposable",
            "--workspace",
            str(workspace),
        ],
    )
    assert result.exit_code == 2
    payload = json.loads(result.output[result.output.index("{") :])
    assert payload["status"] in {"FAILED", "cleanup_failed"}
    run_id = payload["run_id"]
    assert not [name for name in _generated_databases(dsn) if run_id in name]


@pytest.mark.postgres_integration
def test_sigkill_then_cleanup_run_recovers_the_orphan(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-kill-"))
    script = Path(tempfile.mkdtemp(prefix="mizan-v62-kill-script-")) / "orphan.py"
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    script.write_text(
        "import json, os, sys, time\n"
        f"sys.path.insert(0, {source_root!r})\n"
        "from mizan.postgres_twin import PostgresSource\n"
        f"os.environ[{DSN_ENV!r}] = os.environ['MIZAN_ORPHAN_DSN']\n"
        f"source = PostgresSource({DSN_ENV!r}, schemas=('pgstore',))\n"
        f"baseline = source.prepare_baseline({str(workspace)!r})\n"
        "print(json.dumps({'run_id': source.run_id, 'seed': baseline.name}), flush=True)\n"
        "time.sleep(120)\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["MIZAN_ORPHAN_DSN"] = dsn
    process = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        line = process.stdout.readline()
        payload = json.loads(line)
        seed = payload["seed"]
        assert _database_exists(dsn, seed)
        if os.name == "nt":
            process.kill()
        else:
            os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=30)
        # SIGKILL leaves the registry and marker behind: recovery is explicit.
        from click.testing import CliRunner

        from mizan.cli import main

        result = CliRunner().invoke(
            main,
            [
                "postgres-twin",
                "--dsn-env",
                DSN_ENV,
                "--schema",
                "pgstore",
                "--cleanup-run",
                payload["run_id"],
                "--workspace",
                str(workspace),
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["status"] == "CLEANED"
        assert not _database_exists(dsn, seed)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)


@pytest.mark.postgres_integration
def test_cleanup_run_requires_explicit_workspace(source) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-req-workspace-"))
    baseline, _registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    try:
        result = CliRunner().invoke(
            main,
            ["postgres-twin", "--dsn-env", DSN_ENV, "--schema", "pgstore", "--cleanup-run", instance.run_id],
        )
        assert result.exit_code != 0
        payload = json.loads(result.output)
        assert payload["status"] == "OWNERSHIP_UNPROVABLE"
        assert payload["cleaned"] == []
        assert all(_database_exists(dsn, name) for name in names)
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_missing_registry_never_reports_cleaned(source) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-no-registry-"))
    baseline, _registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    (workspace / "ownership.json").unlink()
    try:
        result = CliRunner().invoke(
            main,
            [
                "postgres-twin",
                "--dsn-env",
                DSN_ENV,
                "--schema",
                "pgstore",
                "--cleanup-run",
                instance.run_id,
                "--workspace",
                str(workspace),
            ],
        )
        assert result.exit_code != 0
        payload = json.loads(result.output)
        assert payload["status"] == "OWNERSHIP_UNPROVABLE"
        assert payload["cleaned"] == []
        assert payload["reasons"]
        assert {c["database_name"] for c in payload["orphan_candidates"]} >= set(names)
        assert all(_database_exists(dsn, name) for name in names)
        assert not (workspace / "ownership.json").exists(), "recovery must not create a registry"
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_empty_registry_never_reports_cleaned(source) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-empty-registry-"))
    baseline, _registry = _build_run(instance, workspace)
    (workspace / "ownership.json").write_text("{}", encoding="utf-8")
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    try:
        result = CliRunner().invoke(
            main,
            [
                "postgres-twin",
                "--dsn-env",
                DSN_ENV,
                "--schema",
                "pgstore",
                "--cleanup-run",
                instance.run_id,
                "--workspace",
                str(workspace),
            ],
        )
        assert result.exit_code != 0
        assert json.loads(result.output)["status"] == "OWNERSHIP_UNPROVABLE"
        assert all(_database_exists(dsn, name) for name in names)
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_orphan_marker_discovery_is_read_only(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-orphan-"))
    baseline, _registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    (workspace / "ownership.json").unlink()

    def snapshot() -> dict[str, str]:
        admin = _admin(dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT datname, coalesce(shobj_description(oid, 'pg_database'), '') "
                    "FROM pg_database WHERE datname = ANY(%s) ORDER BY datname",
                    (names,),
                )
                return {str(row[0]): str(row[1]) for row in cursor.fetchall()}
        finally:
            admin.close()

    before = snapshot()
    try:
        admin = _admin(instance.dsn)
        try:
            candidates = discover_orphan_candidates(admin, instance.run_id, source_database=instance.source_name())
        finally:
            admin.close()
        assert {c["database_name"] for c in candidates} >= set(names)
        assert all(c["reason"] == "matching server marker" for c in candidates)
        with pytest.raises(OwnershipUnprovable) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.candidates
        assert snapshot() == before, "read-only diagnostics changed database state"
        assert all(_database_exists(dsn, name) for name in names)
        assert not (workspace / "ownership.json").exists()
    finally:
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_delete_intent_is_durable_before_drop(source, monkeypatch) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-intent-before-"))
    baseline, registry = _build_run(instance, workspace)
    names = [baseline.name, expected_worker_name(instance.run_id, "w0"), expected_worker_name(instance.run_id, "w1")]
    observed: list[str] = []

    def hook(name: str) -> None:
        admin = _admin(instance.dsn)
        try:
            assert _database_exists(instance.dsn, name), "the database was dropped before intent persistence"
            intent = registry.get_intent(name)
            assert intent is not None and intent.state is IntentState.DELETE_PENDING
            record = registry.get(name)
            assert record is not None
            assert intent.oid == database_oid(admin, name)
            assert intent.marker_digest == marker_digest(expected_marker(record, intent.cluster_id))
        finally:
            admin.close()
        observed.append(name)

    monkeypatch.setattr(twin_module, "INTENT_TEST_HOOK", hook)
    try:
        cleaned = cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert set(cleaned) == set(names)
        assert observed == [
            expected_worker_name(instance.run_id, "w0"),
            expected_worker_name(instance.run_id, "w1"),
            baseline.name,
        ]
        assert all(intent.state is IntentState.CLEANED for intent in registry.intents().values())
    finally:
        monkeypatch.setattr(twin_module, "INTENT_TEST_HOOK", None)
        for name in names:
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_crash_after_intent_before_drop_recovers(source) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-crash-intent-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    ready = workspace / "intent.ready"
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    script = workspace / "crash_before_drop.py"
    script.write_text(
        "import os, sys, time\n"
        f"sys.path.insert(0, {source_root!r})\n"
        "import mizan.postgres_twin as twin\n"
        f"os.environ[{DSN_ENV!r}] = {dsn!r}\n"
        f"workspace = {str(workspace)!r}\n"
        f"name = {w0!r}\n"
        f"ready = {str(ready)!r}\n"
        "def hook(database):\n"
        "    if database == name:\n"
        "        open(ready, 'w').close()\n"
        "        time.sleep(120)\n"
        "twin.INTENT_TEST_HOOK = hook\n"
        f"twin.cleanup_run({DSN_ENV!r}, workspace, {instance.run_id!r})\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["MIZAN_ORPHAN_DSN"] = dsn
    process = subprocess.Popen(
        [sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment
    )
    try:
        deadline = time.monotonic() + 60
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert ready.exists(), "the child never persisted its deletion intent"
        assert _database_exists(dsn, w0), "the child dropped the database too early"
        pending = registry.get_intent(w0)
        assert pending is not None and pending.state is IntentState.DELETE_PENDING
        operation_id = pending.operation_id
        process.kill()
        process.wait(timeout=30)

        result = CliRunner().invoke(
            main,
            [
                "postgres-twin",
                "--dsn-env",
                DSN_ENV,
                "--schema",
                "pgstore",
                "--cleanup-run",
                instance.run_id,
                "--workspace",
                str(workspace),
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["status"] == "CLEANED"
        reconciled = registry.get_intent(w0)
        assert reconciled is not None
        assert reconciled.state is IntentState.CLEANED
        assert reconciled.operation_id == operation_id, "the pending operation was not resumed"
        assert not _database_exists(dsn, w0)
        assert not _database_exists(dsn, baseline.name)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_crash_after_drop_before_registry_completion_recovers(source) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-crash-drop-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    ready = workspace / "dropped.ready"
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    script = workspace / "crash_after_drop.py"
    script.write_text(
        "import sys, time\n"
        f"sys.path.insert(0, {source_root!r})\n"
        "import mizan.postgres_twin as twin\n"
        f"os_dsn = {dsn!r}\n"
        "import os\n"
        f"os.environ[{DSN_ENV!r}] = os_dsn\n"
        f"workspace = {str(workspace)!r}\n"
        f"name = {w0!r}\n"
        f"ready = {str(ready)!r}\n"
        "def hook(database):\n"
        "    if database == name:\n"
        "        open(ready, 'w').close()\n"
        "        time.sleep(120)\n"
        "twin.DELETION_TEST_HOOK = hook\n"
        f"twin.cleanup_run({DSN_ENV!r}, workspace, {instance.run_id!r})\n",
        encoding="utf-8",
    )
    process = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 60
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert ready.exists(), "the child never reached the post-DROP window"
        assert not _database_exists(dsn, w0), "PostgreSQL did not confirm the deletion"
        pending = registry.get_intent(w0)
        assert pending is not None and pending.state is IntentState.DELETE_PENDING
        assert registry.get(w0) is not None
        assert registry.get(w0).state is not TwinState.CLEANED
        process.kill()
        process.wait(timeout=30)

        result = CliRunner().invoke(
            main,
            [
                "postgres-twin",
                "--dsn-env",
                DSN_ENV,
                "--schema",
                "pgstore",
                "--cleanup-run",
                instance.run_id,
                "--workspace",
                str(workspace),
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "CLEANED"
        assert set(payload["cleaned"]) == {w0, w1, baseline.name}
        assert not any(_database_exists(dsn, name) for name in (w1, baseline.name))
        assert registry.get_intent(w0).state is IntentState.CLEANED
        assert registry.get(w0).state is TwinState.CLEANED
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_pending_intent_rejects_recreated_database_oid(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-recreated-oid-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    admin = _admin(instance.dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
        prepare_deletion_intent(
            admin, registry, registry.get(w0), cluster_id=cluster, source_database=instance.source_name()
        )
        original_oid = database_oid(admin, w0)
    finally:
        admin.close()
    _drop_database(dsn, w0)
    _create_database(dsn, w0)
    admin = _admin(instance.dsn)
    try:
        twin_module.write_marker(admin, w0, expected_marker(registry.get(w0), cluster))
        assert database_oid(admin, w0) != original_oid
    finally:
        admin.close()
    try:
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(w0) == "invalid deletion intent"
        assert _database_exists(dsn, w0), "the replacement database was deleted"
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_tampered_deletion_intent_fails_closed(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-tampered-intent-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    admin = _admin(instance.dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
        prepare_deletion_intent(
            admin, registry, registry.get(w0), cluster_id=cluster, source_database=instance.source_name()
        )
    finally:
        admin.close()
    payload = registry.load()
    payload[DELETION_INTENTS_KEY][w0]["nonce"] = "f" * 32
    registry._write(payload)
    try:
        with pytest.raises(OwnershipError):
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert registry.load()[DELETION_INTENTS_KEY][w0]["nonce"] == "f" * 32
        assert _database_exists(dsn, w0)
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_cleaned_record_with_existing_database_fails_closed(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-cleaned-present-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    registry.update_state(w0, TwinState.CLEANED)
    try:
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(w0) == "cleaned but present"
        assert _database_exists(dsn, w0)
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_pending_intent_with_existing_original_database_resumes(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-resume-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    admin = _admin(instance.dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
        intent = prepare_deletion_intent(
            admin, registry, registry.get(w0), cluster_id=cluster, source_database=instance.source_name()
        )
    finally:
        admin.close()
    try:
        assert _database_exists(dsn, w0)
        assert cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert not _database_exists(dsn, w0)
        resumed = registry.get_intent(w0)
        assert resumed is not None and resumed.state is IntentState.CLEANED
        assert resumed.operation_id == intent.operation_id
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_registry_durable_replace_and_directory_sync(source) -> None:
    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-durable-registry-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    registry.put(_record())
    assert registry.path.read_text(encoding="utf-8").startswith("{")
    assert [p.name for p in workspace.iterdir() if p.name.endswith(".tmp")] == []
    assert registry.last_directory_sync_supported == (os.name == "posix")
    assert [p.name for p in workspace.iterdir() if p.name.endswith(".tmp")] == []
    (workspace / "ownership.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(OwnershipError):
        registry.records()


@pytest.mark.postgres_integration
def test_missing_intent_absent_database_fails_even_when_record_cleaned(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-missing-cleaned-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    _drop_database(dsn, w0)
    registry.update_state(w0, TwinState.CLEANED)
    assert registry.get_intent(w0) is None
    try:
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(w0) == "missing without deletion intent"
        assert registry.get(w0).state is TwinState.CLEANED, "the record was silently repaired"
        assert _database_exists(dsn, w1) and _database_exists(dsn, baseline.name)
    finally:
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_missing_intent_absent_database_fails_when_record_not_cleaned(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-missing-ready-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    _drop_database(dsn, w0)
    assert registry.get_intent(w0) is None
    try:
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(w0) == "missing without deletion intent"
        assert _database_exists(dsn, w1) and _database_exists(dsn, baseline.name)
    finally:
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


def _intent_for(instance, registry, name):
    admin = _admin(instance.dsn)
    try:
        with admin.cursor() as cursor:
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster = str(cursor.fetchone()[0])
        return prepare_deletion_intent(
            admin, registry, registry.get(name), cluster_id=cluster, source_database=instance.source_name()
        )
    finally:
        admin.close()


@pytest.mark.postgres_integration
def test_valid_pending_intent_absent_database_reconciles_both_states(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-pending-absent-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    try:
        intent = _intent_for(instance, registry, w0)
        _drop_database(dsn, w0)
        assert cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert registry.get_intent(w0).state is IntentState.CLEANED
        assert registry.get_intent(w0).operation_id == intent.operation_id
        assert registry.get(w0).state is TwinState.CLEANED
        assert not _database_exists(dsn, baseline.name)
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_valid_cleaned_intent_and_cleaned_record_are_idempotent(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-idempotent-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    try:
        intent = _intent_for(instance, registry, w0)
        _drop_database(dsn, w0)
        registry.complete_deletion(registry.get(w0), intent)
        first = cleanup_run(DSN_ENV, workspace, instance.run_id)
        second = cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert w0 not in first and second == []
        assert registry.get_intent(w0).operation_id == intent.operation_id
        assert registry.get(w0).state is TwinState.CLEANED
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


def _historical_vi22_intent(
    *,
    run_id: str,
    database_name: str,
    kind: str,
    worker_id: str,
    source_database: str,
    cluster_id: str,
    owner_role: str,
    nonce: str,
    oid: int,
    marker_digest: str,
    operation_id: str,
    created_at: float,
    state: str,
) -> dict[str, Any]:
    """Serialize the exact VI.2.2 ``DeletionIntent.to_dict()`` format.

    Source of truth: ``git show f3f6c00:src/mizan/postgres_twin.py`` lines 1045-1078.
    VI.2.2 intents have no ``integrity`` field and used a float ``created_at``.
    """
    return {
        "run_id": run_id,
        "database_name": database_name,
        "kind": kind,
        "worker_id": worker_id,
        "source_database": source_database,
        "cluster_id": cluster_id,
        "owner_role": owner_role,
        "nonce": nonce,
        "oid": oid,
        "marker_digest": marker_digest,
        "operation_id": operation_id,
        "created_at": created_at,
        "state": state,
    }


@pytest.mark.postgres_integration
def test_vi22_historical_registry_without_integrity_reconciles(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-vi22-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    try:
        intent = _intent_for(instance, registry, w0)
        record = registry.get(w0)
        assert record is not None
        _drop_database(dsn, w0)

        historical = _historical_vi22_intent(
            run_id=intent.run_id,
            database_name=intent.database_name,
            kind=intent.kind,
            worker_id=intent.worker_id,
            source_database=intent.source_database,
            cluster_id=intent.cluster_id,
            owner_role=intent.owner_role,
            nonce=intent.nonce,
            oid=intent.oid,
            marker_digest=intent.marker_digest,
            operation_id=intent.operation_id,
            created_at=intent.created_at,
            state=str(IntentState.CLEANED),
        )
        assert "integrity" not in historical
        payload = registry.load()
        payload[DELETION_INTENTS_KEY][w0] = historical
        registry._write(payload)
        assert "integrity" not in registry.load()[DELETION_INTENTS_KEY][w0]
        assert registry.get(w0).state is not TwinState.CLEANED

        cleaned = cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert w0 in cleaned
        reconciled = registry.get_intent(w0)
        assert reconciled is not None
        assert reconciled.state is IntentState.CLEANED
        assert reconciled.operation_id == intent.operation_id
        assert reconciled.nonce == intent.nonce
        assert reconciled.oid == intent.oid
        assert reconciled.marker_digest == intent.marker_digest
        assert reconciled.run_id == intent.run_id
        assert reconciled.database_name == intent.database_name
        assert reconciled.kind == intent.kind
        assert reconciled.worker_id == intent.worker_id
        assert reconciled.source_database == intent.source_database
        assert reconciled.cluster_id == intent.cluster_id
        assert reconciled.owner_role == intent.owner_role
        assert reconciled.created_at == intent.created_at
        assert reconciled.integrity, "the upgraded intent must carry a valid integrity digest"
        assert DeletionIntent.from_dict(reconciled.to_dict()) == reconciled
        assert registry.get(w0).state is TwinState.CLEANED
        assert not _database_exists(dsn, w0)
        assert cleanup_run(DSN_ENV, workspace, instance.run_id) == []
        assert not _database_exists(dsn, w1) and not _database_exists(dsn, baseline.name)
    finally:
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_vi22_legacy_intent_without_integrity_cannot_delete_an_existing_database(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-legacy-present-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    intent = _intent_for(instance, registry, w0)
    historical = _historical_vi22_intent(
        run_id=intent.run_id,
        database_name=intent.database_name,
        kind=intent.kind,
        worker_id=intent.worker_id,
        source_database=intent.source_database,
        cluster_id=intent.cluster_id,
        owner_role=intent.owner_role,
        nonce=intent.nonce,
        oid=intent.oid,
        marker_digest=intent.marker_digest,
        operation_id=intent.operation_id,
        created_at=intent.created_at,
        state="DELETE_PENDING",
    )
    payload = registry.load()
    payload[DELETION_INTENTS_KEY][w0] = historical
    registry._write(payload)
    try:
        with pytest.raises(CleanupPreflightError):
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert _database_exists(dsn, w0)
        assert _database_exists(dsn, w1) and _database_exists(dsn, baseline.name)
    finally:
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_vi22_legacy_intent_tampered_marker_is_rejected(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-legacy-tampered-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    intent = _intent_for(instance, registry, w0)
    _drop_database(dsn, w0)
    historical = _historical_vi22_intent(
        run_id=intent.run_id,
        database_name=intent.database_name,
        kind=intent.kind,
        worker_id=intent.worker_id,
        source_database=intent.source_database,
        cluster_id=intent.cluster_id,
        owner_role=intent.owner_role,
        nonce=intent.nonce,
        oid=intent.oid,
        marker_digest="0" * 64,
        operation_id=intent.operation_id,
        created_at=intent.created_at,
        state="CLEANED",
    )
    payload = registry.load()
    payload[DELETION_INTENTS_KEY][w0] = historical
    registry._write(payload)
    try:
        with pytest.raises(OwnershipError):
            cleanup_run(DSN_ENV, workspace, instance.run_id)
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_current_intent_bad_integrity_remains_rejected(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-bad-integrity-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    _intent_for(instance, registry, w0)
    payload = registry.load()
    payload[DELETION_INTENTS_KEY][w0]["integrity"] = "0" * 64
    registry._write(payload)
    try:
        with pytest.raises(OwnershipError):
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert _database_exists(dsn, w0)
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_existing_database_with_cleaned_intent_fails_closed(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-present-cleaned-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    intent = _intent_for(instance, registry, w0)
    registry.put_intent(intent.with_state(IntentState.CLEANED))
    try:
        with pytest.raises(CleanupPreflightError) as error:
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert error.value.categories.get(w0) == "invalid deletion intent"
        assert _database_exists(dsn, w0)
        assert _database_exists(dsn, w1) and _database_exists(dsn, baseline.name)
    finally:
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_absent_database_with_tampered_intent_fails_closed(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-tampered-absent-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    _intent_for(instance, registry, w0)
    _drop_database(dsn, w0)
    payload = registry.load()
    payload[DELETION_INTENTS_KEY][w0]["operation_id"] = "tampered-operation"
    registry._write(payload)
    try:
        with pytest.raises(OwnershipError):
            cleanup_run(DSN_ENV, workspace, instance.run_id)
        assert _database_exists(dsn, w1) and _database_exists(dsn, baseline.name)
        assert registry.load()[DELETION_INTENTS_KEY][w0]["operation_id"] == "tampered-operation"
    finally:
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_complete_deletion_updates_intent_and_record_in_one_write(source, monkeypatch) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-one-write-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    try:
        intent = _intent_for(instance, registry, w0)
        record = registry.get(w0)
        writes: list[dict[str, Any]] = []
        original = registry._write

        def counting(snapshot):
            writes.append(json.loads(json.dumps(snapshot)))
            return original(snapshot)

        monkeypatch.setattr(registry, "_write", counting)
        registry.complete_deletion(record, intent)
        assert len(writes) == 1
        saved = writes[0]
        assert saved[DELETION_INTENTS_KEY][w0]["state"] == str(IntentState.CLEANED)
        assert saved[w0]["state"] == str(TwinState.CLEANED)
    finally:
        monkeypatch.setattr(registry, "_write", registry._write)
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_complete_deletion_rejects_stale_registry_snapshot(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-stale-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    try:
        intent = _intent_for(instance, registry, w0)
        record = registry.get(w0)
        other = DatabaseRegistry(registry.path)
        tampered = record.to_dict()
        tampered["nonce"] = "f" * 32
        payload = other.load()
        payload[w0] = tampered
        other._write(payload)
        with pytest.raises(OwnershipError, match="changed since it was loaded"):
            registry.complete_deletion(record, intent)
        assert registry.get_intent(w0).state is IntentState.DELETE_PENDING
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_complete_deletion_rejects_operation_id_mismatch(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-opid-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    try:
        intent = _intent_for(instance, registry, w0)
        data = intent.to_dict()
        data["operation_id"] = "b" * 32
        data["integrity"] = twin_module._intent_integrity(data)
        wrong = DeletionIntent.from_dict(data)
        with pytest.raises(OwnershipError, match="changed since it was loaded"):
            registry.complete_deletion(registry.get(w0), wrong)
        assert registry.get_intent(w0).operation_id == intent.operation_id
        assert registry.get(w0).state is not TwinState.CLEANED
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_complete_deletion_rejects_invalid_transition(source) -> None:
    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-bad-transition-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    try:
        intent = _intent_for(instance, registry, w0)
        registry.complete_deletion(registry.get(w0), intent)
        with pytest.raises(OwnershipError):
            registry.complete_deletion(registry.get(w0), registry.get_intent(w0))
        with pytest.raises(OwnershipError):
            registry.complete_deletion(registry.get(w0), registry.get_intent(w0), allow_legacy=True)
    finally:
        for name in (baseline.name, w0, expected_worker_name(instance.run_id, "w1")):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
@pytest.mark.parametrize("phase", ["before", "after"])
def test_process_crash_during_completion_leaves_consistent_registry(source, phase) -> None:
    from click.testing import CliRunner

    from mizan.cli import main

    instance, dsn = source
    workspace = Path(tempfile.mkdtemp(prefix=f"mizan-v63-crash-{phase}-"))
    baseline, registry = _build_run(instance, workspace)
    w0 = expected_worker_name(instance.run_id, "w0")
    w1 = expected_worker_name(instance.run_id, "w1")
    expected_opid = _intent_for(instance, registry, w0).operation_id
    ready = workspace / f"{phase}-replace.ready"
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    script = workspace / f"crash_{phase}_replace.py"
    script.write_text(
        "import json, os, sys, time\n"
        "import psycopg\n"
        "from psycopg import sql\n"
        f"sys.path.insert(0, {source_root!r})\n"
        "import mizan.postgres_twin as twin\n"
        f"dsn = {dsn!r}\n"
        f"workspace = {str(workspace)!r}\n"
        f"name = {w0!r}\n"
        f"ready = {str(ready)!r}\n"
        f"phase = {phase!r}\n"
        "connection = psycopg.connect(dsn, autocommit=True)\n"
        "with connection.cursor() as cursor:\n"
        "    cursor.execute(sql.SQL('DROP DATABASE IF EXISTS {}').format(sql.Identifier(name)))\n"
        "connection.close()\n"
        "admin = twin._admin(twin.ConnectionTarget.parse(dsn))\n"
        "assert not twin.database_exists(admin, name)\n"
        "admin.close()\n"
        "registry = twin.DatabaseRegistry(os.path.join(workspace, 'ownership.json'))\n"
        "record = registry.get(name)\n"
        "intent = registry.get_intent(name)\n"
        "def hook():\n"
        "    open(ready, 'w').close()\n"
        "    time.sleep(120)\n"
        "if phase == 'before':\n"
        "    twin.REGISTRY_BEFORE_REPLACE_HOOK = hook\n"
        "else:\n"
        "    twin.REGISTRY_AFTER_REPLACE_HOOK = hook\n"
        "registry.complete_deletion(record, intent)\n",
        encoding="utf-8",
    )
    process = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 90
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert ready.exists(), f"the child never reached the {phase}-replace window"
        assert not _database_exists(dsn, w0)
        fresh = DatabaseRegistry(registry.path)
        intent_state = fresh.get_intent(w0).state
        record_state = fresh.get(w0).state
        split = (intent_state is IntentState.CLEANED and record_state is not TwinState.CLEANED) or (
            intent_state is IntentState.DELETE_PENDING and record_state is TwinState.CLEANED
        )
        assert not split, f"a split registry state is visible after {phase}-replace"
        expected = IntentState.CLEANED if phase == "after" else IntentState.DELETE_PENDING
        assert intent_state is expected
        process.kill()
        process.wait(timeout=30)
        lock = registry.lock_path
        for _ in range(20):
            try:
                lock.unlink(missing_ok=True)
                break
            except PermissionError:  # the killed child's handle can linger briefly
                time.sleep(0.1)

        result = CliRunner().invoke(
            main,
            [
                "postgres-twin",
                "--dsn-env",
                DSN_ENV,
                "--schema",
                "pgstore",
                "--cleanup-run",
                instance.run_id,
                "--workspace",
                str(workspace),
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["status"] == "CLEANED"
        final = DatabaseRegistry(registry.path)
        assert final.get_intent(w0).state is IntentState.CLEANED
        assert final.get(w0).state is TwinState.CLEANED
        assert final.get_intent(w0).operation_id == expected_opid
        assert not _database_exists(dsn, w1) and not _database_exists(dsn, baseline.name)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        for name in (baseline.name, w0, w1):
            _drop_database(dsn, name)


@pytest.mark.postgres_integration
def test_registry_permissions_and_durability_report(source) -> None:
    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v63-permissions-"))
    registry = DatabaseRegistry(workspace / "ownership.json")
    assert registry.put(_record()) is None
    assert registry.path.is_file()
    if os.name != "posix":
        assert registry.last_directory_synced is False
    else:
        assert isinstance(registry.last_directory_synced, bool)
        assert registry.last_directory_sync_supported is True
    assert [path.name for path in workspace.iterdir() if path.name.endswith(".tmp")] == []
