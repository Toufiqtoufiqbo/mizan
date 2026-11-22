"""PostgreSQL L4/L6 law expansion: real database-state evidence."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

from mizan.postgres_twin import PostgresSource

FIXTURE = Path(__file__).parent / "fixtures" / "external_apps" / "postgres_store"
DSN_ENV = "MIZAN_VIII_TEST_DSN"
TOKENS = {"alice": "twin-alice", "bob": "twin-bob"}


@pytest.fixture(scope="module")
def dsn():
    value = os.environ.get(DSN_ENV) or os.environ.get("MIZAN_TEST_POSTGRES_DSN")
    if value:
        dsn_value = value if "connect_timeout" in value else value + "?connect_timeout=5"
    else:
        pgserver = pytest.importorskip("pgserver", reason="a real PostgreSQL is required")
        dsn_value = pgserver.get_server(
            pgdata=Path(tempfile.mkdtemp(prefix="mizan-viii-pg-")), cleanup_mode="delete"
        ).get_uri()
    os.environ[DSN_ENV] = dsn_value
    module_spec = importlib.util.spec_from_file_location("pgstore_viii", FIXTURE / "app.py")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    previous = {key: os.environ.get(key) for key in ("MIZAN_TOKEN_ALICE", "MIZAN_TOKEN_BOB")}
    os.environ["MIZAN_TOKEN_ALICE"] = TOKENS["alice"]
    os.environ["MIZAN_TOKEN_BOB"] = TOKENS["bob"]
    try:
        module.create_app("clean", dsn=dsn_value, schema="pgstore")
    finally:
        for key, original in previous.items():
            if original is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original
    return dsn_value


@pytest.fixture
def source(dsn):
    return PostgresSource(DSN_ENV, schemas=("pgstore",))


def _run(variant: str) -> tuple[object, Path]:
    from click.testing import CliRunner

    from mizan.cli import main

    workspace = Path(tempfile.mkdtemp(prefix=f"mizan-viii-{variant}-"))
    out = workspace / "out"
    result = CliRunner().invoke(
        main,
        [
            "twin",
            "--backend",
            "postgres",
            "--command",
            f'"{sys.executable}" "{FIXTURE / "app.py"}" --port {{port}} --vulnerability {variant}',
            "--dsn-env",
            DSN_ENV,
            "--schema",
            "pgstore",
            "--allow-disposable",
            "--spec",
            str(FIXTURE / "openapi-laws.json"),
            "--relationship-contract",
            str(FIXTURE / "mizan-laws.json"),
            "--token",
            f"alice={TOKENS['alice']}",
            "--token",
            f"bob={TOKENS['bob']}",
            "--workdir",
            str(workspace),
            "--out",
            str(out),
        ],
    )
    return result, out


def _status(result) -> dict:
    for line in result.output.splitlines():
        if line.startswith("postgres backend status:"):
            return json.loads(line.split("postgres backend status:", 1)[1])
    raise AssertionError(result.output)


def _bundles(out: Path) -> dict[str, dict]:
    found: dict[str, dict] = {}
    if not out.exists():
        return found
    for directory in out.iterdir():
        if not directory.is_dir():
            continue
        payload = json.loads((directory / "replay.json").read_text(encoding="utf-8"))
        found.setdefault(payload["law"], payload)
    return found


@pytest.mark.postgres_integration
def test_l4_detects_unauthorized_persisted_role_change(source, dsn) -> None:
    result, out = _run("l4_vulnerable")
    assert result.exit_code == 0, result.output
    bundles = _bundles(out)
    assert "L4" in bundles
    evidence = bundles["L4"]["evidence"]
    assert evidence["field"] == "role"
    assert evidence["attempted_value"].startswith("mizan-probe-")
    assert evidence["persisted_value"] == evidence["attempted_value"]
    assert evidence["original_value"] == "user"
    assert evidence["attribution"] == "confirmed"
    assert evidence["state_verification"] == "attributed database write"
    assert evidence["confidence"] == "confirmed"
    assert "L4" in _status(result)["laws_executed"]
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_l4_secure_blocks_the_same_mutation(source, dsn) -> None:
    result, out = _run("l4_secure")
    assert result.exit_code == 0, result.output
    assert "L4" not in _bundles(out)
    status = _status(result)
    assert status["confirmed_findings"] == 0 or all(law != "L4" for law in _bundles(out))
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_l6_detects_collection_and_single_use_violations(source, dsn) -> None:
    result, out = _run("l6_vulnerable")
    assert result.exit_code == 0, result.output
    bundles = _bundles(out)
    assert "L6" in bundles
    evidence = bundles["L6"]["evidence"]
    assert evidence["bound"] >= 1
    assert evidence["initial_count"] >= 0
    assert evidence["final_count"] > evidence["bound"] or evidence["operations"] > 1
    assert evidence["verification"] == "database row count"
    assert "L6" in _status(result)["laws_executed"]
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_l6_secure_accepts_boundary_behavior(source, dsn) -> None:
    result, out = _run("l6_secure")
    assert result.exit_code == 0, result.output
    assert "L6" not in _bundles(out)
    assert "L4" not in _bundles(out)
    source.assert_unchanged()


@pytest.mark.postgres_integration
def test_l4_and_l6_have_independent_execution_records(source, dsn) -> None:
    result, _out = _run("l4_vulnerable")
    assert result.exit_code == 0, result.output
    status = _status(result)
    assert "L4" in status["laws_executed"]
    assert "L6" in status["laws_executed"]
    assert status["laws_by_status"]["L4"] == "executed"
    assert status["laws_by_status"]["L6"] == "executed"
