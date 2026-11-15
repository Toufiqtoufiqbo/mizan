"""The real CLI workflow against an independent opaque-token application.

The application (`tests/fixtures/external_apps/flask_store`) knows nothing
about Mizan: its own authentication with opaque random tokens, its own SQLite
database, its own OpenAPI document. The only contact is ordinary HTTP plus
the database file for attribution.

Everything here runs through `mizan twin --identity-map` - the real command,
the real proxy, the real recorder, the real learning and attack phases. The
identity map is a file of environment-variable names; the tokens themselves
travel only through the environment.

The tokens deployed here are canaries: distinctive strings that must never
appear in anything Mizan writes - not the traffic log, not the proof bundles,
not the CLI output. Their absence from every artifact is the evidence that
the identity pipeline moves *attribution*, never secrets.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests
from click.testing import CliRunner

from mizan.cli import main

APP_DIR = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "flask_store"
SPEC_PATH = APP_DIR / "openapi.json"

#: The mission's canary tokens. Deployed to the application out-of-band;
#: searched for in every artifact Mizan produces.
CANARY_ALICE = "MIZAN_SECRET_CANARY_ALICE_7F31"
CANARY_BOB = "MIZAN_SECRET_CANARY_BOB_9C42"


@pytest.fixture()
def deployed_tokens() -> tuple[str, str]:
    """Put the canary tokens in the environment, like an operator would."""
    os.environ["MIZAN_TOKEN_ALICE"] = CANARY_ALICE
    os.environ["MIZAN_TOKEN_BOB"] = CANARY_BOB
    yield CANARY_ALICE, CANARY_BOB
    os.environ.pop("MIZAN_TOKEN_ALICE", None)
    os.environ.pop("MIZAN_TOKEN_BOB", None)


def _write_identity_map(tmp_path: Path) -> Path:
    map_path = tmp_path / "identity-map.json"
    map_path.write_text(
        json.dumps(
            {
                "version": 1,
                "principals": {
                    "alice": {"token_env": "MIZAN_TOKEN_ALICE", "roles": ["user"]},
                    "bob": {"token_env": "MIZAN_TOKEN_BOB", "roles": ["user"]},
                },
            }
        ),
        encoding="utf-8",
    )
    return map_path


def _run_twin(tmp_path: Path, variant: str):
    """Run `mizan twin` with an identity map against one variant.

    The caller must have activated the ``deployed_tokens`` fixture.
    """
    map_path = _write_identity_map(tmp_path)
    database = tmp_path / "store.sqlite"
    out_path = tmp_path / "proofs"
    traffic_path = tmp_path / "traffic.jsonl"
    command = (
        f'"{Path(sys.executable).as_posix()}" "{(APP_DIR / "app.py").as_posix()}"'
        f' --db "{database.as_posix()}" --port {{port}} --vulnerability {variant}'
    )
    result = CliRunner().invoke(
        main,
        [
            "twin",
            "--command",
            command,
            "--data",
            str(database),
            "--spec",
            str(SPEC_PATH),
            "--identity-map",
            str(map_path),
            "--out",
            str(out_path),
            "--traffic",
            str(traffic_path),
            "--workdir",
            str(tmp_path),
        ],
        catch_exceptions=False,
    )
    return result, out_path, traffic_path


def _findings(out_path: Path) -> list[dict]:
    """The recorded findings from the proof bundles."""
    bundles = sorted(path for path in out_path.iterdir() if path.is_dir()) if out_path.exists() else []
    findings = []
    for bundle in bundles:
        for meta in bundle.glob("*.json"):
            data = json.loads(meta.read_text(encoding="utf-8"))
            if data.get("law") or data.get("violation"):
                findings.append(data)
    return findings


def _assert_no_token_leakage(text: str, *tokens: str) -> None:
    for token in tokens:
        assert token not in text, "a bearer token leaked into a generated artifact"


def _assert_artifacts_are_clean(tmp_path: Path, output: str, alice: str, bob: str) -> None:
    """Every file Mizan wrote, plus its own output, is free of the tokens."""
    scanned: list[str] = []
    for artifact in tmp_path.rglob("*"):
        if artifact.is_file() and artifact.suffix in {".jsonl", ".json", ".md", ".sarif"}:
            scanned.append(artifact.name)
            _assert_no_token_leakage(artifact.read_text(encoding="utf-8", errors="replace"), alice, bob)
    assert scanned, "no artifacts were produced to scan"
    _assert_no_token_leakage(output, alice, bob)


def test_the_clean_variant_produces_no_finding(tmp_path: Path, deployed_tokens) -> None:
    alice, bob = deployed_tokens
    result, out_path, traffic_path = _run_twin(tmp_path, "clean")
    assert result.exit_code == 0, result.output
    findings = _findings(out_path)
    assert findings == [], f"the clean application produced findings: {findings}"
    _assert_artifacts_are_clean(tmp_path, result.output, alice, bob)


def test_the_read_variant_produces_only_a_read_finding(tmp_path: Path, deployed_tokens) -> None:
    alice, bob = deployed_tokens
    result, out_path, traffic_path = _run_twin(tmp_path, "read")
    assert result.exit_code == 0, result.output
    laws = sorted({finding.get("law") for finding in _findings(out_path)})
    assert laws == ["L2"], f"expected exactly one L2 finding, got {laws}"
    _assert_artifacts_are_clean(tmp_path, result.output, alice, bob)


def test_the_write_variant_produces_only_a_write_finding(tmp_path: Path, deployed_tokens) -> None:
    alice, bob = deployed_tokens
    result, out_path, traffic_path = _run_twin(tmp_path, "write")
    assert result.exit_code == 0, result.output
    laws = sorted({finding.get("law") for finding in _findings(out_path)})
    assert laws == ["L3"], f"expected exactly one L3 finding, got {laws}"
    _assert_artifacts_are_clean(tmp_path, result.output, alice, bob)


def test_the_combined_variant_produces_both_findings(tmp_path: Path, deployed_tokens) -> None:
    alice, bob = deployed_tokens
    result, out_path, traffic_path = _run_twin(tmp_path, "both")
    assert result.exit_code == 0, result.output
    laws = sorted({finding.get("law") for finding in _findings(out_path)})
    assert laws == ["L2", "L3"], f"expected L2 and L3, got {laws}"
    _assert_artifacts_are_clean(tmp_path, result.output, alice, bob)


def test_every_learned_request_is_attributed_to_a_configured_principal(tmp_path: Path, deployed_tokens) -> None:
    """The identity map, not a fallback, decides who the traffic belongs to."""
    result, out_path, traffic_path = _run_twin(tmp_path, "clean")
    assert result.exit_code == 0, result.output
    principals = {
        json.loads(line)["principal"] for line in traffic_path.read_text(encoding="utf-8").splitlines() if line
    }
    assert principals == {"alice", "bob"}, f"unexpected principals in the traffic log: {principals}"
    # The canaries were the tokens: their values must not be in the log even
    # though their attributions are.
    _assert_no_token_leakage(traffic_path.read_text(encoding="utf-8"), CANARY_ALICE, CANARY_BOB)


def test_the_traffic_log_records_no_canary_token_anywhere(tmp_path: Path, deployed_tokens) -> None:
    result, out_path, traffic_path = _run_twin(tmp_path, "both")
    assert result.exit_code == 0, result.output
    _assert_artifacts_are_clean(tmp_path, result.output, CANARY_ALICE, CANARY_BOB)


def test_the_sarif_export_is_also_canary_free(tmp_path: Path, deployed_tokens) -> None:
    """SARIF is the artifact that leaves the machine: no token may reach it."""
    alice, bob = deployed_tokens
    result, out_path, traffic_path = _run_twin(tmp_path, "both")
    assert result.exit_code == 0, result.output
    sarif_path = tmp_path / "findings.sarif"
    export = CliRunner().invoke(main, ["export-sarif", str(out_path), "--out", str(sarif_path)])
    assert export.exit_code == 0, export.output
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif.get("version") == "2.1.0", "the SARIF export did not produce a SARIF document"
    _assert_no_token_leakage(sarif_path.read_text(encoding="utf-8"), alice, bob)
    _assert_no_token_leakage(export.output, alice, bob)


def test_a_forged_user_header_cannot_access_or_attribute(tmp_path: Path, deployed_tokens) -> None:
    """X-User-Id is not an identity: the app refuses it as authentication."""
    alice, _ = deployed_tokens
    from mizan.twin import free_port

    port = free_port()
    database = tmp_path / "store.sqlite"
    process = subprocess.Popen(
        [
            sys.executable,
            str(APP_DIR / "app.py"),
            "--db",
            str(database),
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                if requests.get(f"{base_url}/health", timeout=2).status_code == 200:
                    break
            except requests.RequestException:
                time.sleep(0.2)
        # 1. A forged X-User-Id with an unknown token: the app refuses it.
        response = requests.get(
            f"{base_url}/me",
            headers={"Authorization": "Bearer not-a-known-token", "X-User-Id": "alice"},
            timeout=5,
        )
        assert response.status_code == 401, "a forged user header authenticated an unknown token"
        # 2. Without any token: same refusal.
        response = requests.get(f"{base_url}/me", headers={"X-User-Id": "alice"}, timeout=5)
        assert response.status_code == 401, "a user header authenticated an anonymous caller"
        # 3. The deployed opaque token works without any user header.
        response = requests.get(f"{base_url}/me", headers={"Authorization": f"Bearer {alice}"}, timeout=5)
        assert response.status_code == 200
        assert response.json()["id"] == "alice"
    finally:
        process.terminate()
        process.wait(timeout=10)
