"""PostgreSQL Twin tests (Phase VI.1 + VI.2 security hardening).

Unit tests pin state transitions, identifier validation, credential handling
and the cleanup boundary without a server. Integration tests (marked
``postgres_integration``) exercise real cloning, allowlist isolation,
fingerprints, pooled sessions, verified cleanup, signals and orphan recovery.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

import mizan.postgres_twin as twin_module
from mizan.postgres_twin import (
    BaselineVerificationError,
    CleanupError,
    DatabaseRegistry,
    OwnershipError,
    OwnershipRecord,
    PostgresSource,
    SourceProtectionError,
    TwinLifecycleError,
    TwinState,
    _typed,
    cleanup_run,
    database_dsn,
    expected_seed_name,
    expected_worker_name,
    generated_name,
    parse_generated_name,
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
) -> OwnershipRecord:
    return OwnershipRecord(
        run_id,
        worker_id,
        database_name or expected_worker_name(run_id, worker_id),
        source,
        seed or expected_seed_name(run_id),
        TwinState.READY,
        1.0,
        kind=kind,
        cluster_id=cluster,
        owner_role=owner,
        nonce=nonce,
    )


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
    assert payload["status"] == "cleanup_failed"
    assert "forged" in payload["error"]


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
    assert cleanup_run(DSN_ENV, workspace, RUN) == []


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
        with pytest.raises(CleanupError, match="unrelated"):
            twin.cleanup()
        assert _database_exists(instance.dsn, twin.database.name)
    finally:
        unrelated.close()
        twin.cleanup()
        cleanup_run(DSN_ENV, workspace, instance.run_id)
    assert not _database_exists(instance.dsn, twin.database.name)
    assert not _database_exists(instance.dsn, baseline.name)


@pytest.mark.postgres_integration
def test_cleanup_terminates_only_the_exact_owned_session(source) -> None:
    """A stale Mīzān session is terminated; an unrelated one is preserved."""
    import time

    import psycopg

    from mizan.postgres_twin import PostgresTwin, app_session_identity

    instance, _dsn_value = source
    workspace = Path(tempfile.mkdtemp(prefix="mizan-v62-owned-session-"))
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
    owned = psycopg.connect(
        database_dsn(instance.dsn, twin.database.name, application_name=identity),
        connect_timeout=5,
    )
    unrelated = psycopg.connect(
        database_dsn(instance.dsn, twin.database.name, application_name="unrelated-app"),
        connect_timeout=5,
    )

    def sessions() -> dict[str, int]:
        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT application_name, pid FROM pg_stat_activity WHERE datname = %s",
                    (twin.database.name,),
                )
                return {str(name): int(pid) for name, pid in cursor.fetchall()}
        finally:
            admin.close()

    try:
        before = sessions()
        assert before.get(identity), "the stale owned session was not established"
        assert before.get("unrelated-app"), "the unrelated session was not established"

        with pytest.raises(CleanupError, match="unrelated"):
            twin.cleanup()
        assert _database_exists(instance.dsn, twin.database.name)

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and identity in sessions():
            time.sleep(0.1)
        after = sessions()
        assert identity not in after, "the exact owned session was not terminated"
        assert after.get("unrelated-app") == before["unrelated-app"], "the unrelated session was terminated"
    finally:
        unrelated.close()
        owned.close()
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

        admin = _admin(instance.dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = %s AND application_name = %s",
                    (twin.database.name, twin_module.app_session_identity(instance.run_id, "w0")),
                )
                assert cursor.fetchone()[0] >= 3
        finally:
            admin.close()

        # Cleanup stops the application and must still release its sessions.
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
