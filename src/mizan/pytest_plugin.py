"""Pytest plugin: makes Mizan's law checks available to Schemathesis runs."""

from __future__ import annotations


def pytest_configure(config: object) -> None:
    from mizan.schemathesis_plugin import register

    register()
