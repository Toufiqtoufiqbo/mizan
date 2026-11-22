"""Packaging and documentation consistency for the optional PostgreSQL backend."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_base_install_does_not_require_the_postgres_driver() -> None:
    project = _project()
    assert not any("psycopg" in dependency.lower() for dependency in project["project"]["dependencies"])


def test_optional_postgres_group_declares_the_driver() -> None:
    extras = _project()["project"]["optional-dependencies"]
    assert any(dependency.startswith("psycopg") for dependency in extras["postgres"])


def test_version_matches_the_documented_release_history() -> None:
    # reports/MIZAN_0.2.2_EXTERNAL_VALIDATION.md is the actual release record.
    assert (ROOT / "reports" / "MIZAN_0.2.2_EXTERNAL_VALIDATION.md").exists()
    assert _project()["project"]["version"] == "0.2.2"


def test_missing_driver_produces_an_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from mizan.postgres_twin import TwinLifecycleError, _conninfo

    monkeypatch.setitem(sys.modules, "psycopg", None)
    with pytest.raises(TwinLifecycleError, match=r"\[postgres\]"):
        _conninfo("postgresql://user@localhost/db")


def test_readme_documents_install_backend_and_capability_matrix() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "pip install -e '.[postgres]'" in readme
    assert "mizan.principal" in readme
    assert "not trusted authentication evidence" in readme
    assert "| L4 | PARTIAL | SUPPORTED |" in readme
    assert "| L6 | PARTIAL | SUPPORTED |" in readme
    assert "PHASE_VIII_L7_FEASIBILITY.md" in readme
    assert "replicated" in readme
