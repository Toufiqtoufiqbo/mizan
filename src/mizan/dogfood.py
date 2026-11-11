"""Mīzān scanning itself.

The first user of Mīzān is Mīzān. This module starts the project's own control
plane, records its traffic through the proxy, learns its laws and attacks it.

The self-scan runs twice:

* against the real API, where it must find nothing - a clean bill of health and
  a measurement of the false-positive rate on a real application;
* against a deliberately weakened twin, where it must find something - proof
  that the check still bites and that the self-test would catch a regression.

That second half is what makes the first half meaningful.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.learning import learn_from_spec
from mizan.proxy import RecordingProxy
from mizan.tokens import make_token
from mizan.twin import Twin, TwinSpec, python_command

#: The identities the self-scan uses. The server knows them by token.
SELF_IDENTITIES = ("alice", "bob", "root")


@dataclass
class SelfScanResult:
    """What the self-scan found."""

    variant: str
    laws: list[str] = field(default_factory=list)
    requests: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def clean(self) -> bool:
        return not self.laws and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant": self.variant,
            "laws": self.laws,
            "requests": self.requests,
            "findings": self.findings,
            "error": self.error,
            "clean": self.clean,
        }


def _server_spec(base_url: str) -> dict[str, Any]:
    import requests

    response = requests.get(f"{base_url}/openapi.json", timeout=15)
    response.raise_for_status()
    return response.json()


def scan_server(
    *,
    variant: str = "clean",
    vulnerable: bool = False,
    workspace: str | Path | None = None,
    budget: int = 60,
) -> SelfScanResult:
    """Start the server and attack it."""
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="mizan-selfscan-"))
    root.mkdir(parents=True, exist_ok=True)
    database = root / "server.sqlite"
    traffic_path = root / "traffic.jsonl"

    command = python_command(
        "mizan.server",
        "--db",
        str(database),
        "--port",
        "{port}",
    )
    if vulnerable:
        command.append("--vulnerable")

    spec = TwinSpec(
        command=command,
        workdir=root,
        data_paths=[database],
        health_path="/health",
        health_timeout=60.0,
    )
    twin = Twin(spec, workspace=root / "twin")
    proxy = RecordingProxy("http://127.0.0.1:1", traffic_path)
    try:
        twin.start()
        proxy = RecordingProxy(twin.base_url, traffic_path)
        proxy.start()

        document = _server_spec(twin.base_url)
        spec_path = root / "openapi.json"
        spec_path.write_text(json.dumps(document, indent=2), encoding="utf-8")

        tokens = {name: make_token(name, "admin" if name == "root" else "user") for name in SELF_IDENTITIES}
        learn_from_spec(spec_path, proxy.base_url, tokens=list(tokens.values()))

        principals = [
            Principal(id=name, roles=("admin" if name == "root" else "user",), token=token)
            for name, token in tokens.items()
        ]
        engine = Mizan(
            Target(base_url=proxy.base_url, principals=principals),
            traffic_path=traffic_path,
            spec_path=spec_path,
            twin=twin,
            attributor=_attributor(database),
        )
        engine.learn()
        violations = engine.attack()
        return SelfScanResult(
            variant=variant,
            laws=sorted({violation.law for violation in violations}),
            requests=engine.requests,
            findings=[violation.to_dict() for violation in violations],
        )
    except Exception as exc:  # pragma: no cover - reported, never hidden
        return SelfScanResult(variant=variant, error=f"{type(exc).__name__}: {exc}")
    finally:
        proxy.stop()
        twin.stop()


def _attributor(database: Path):
    from mizan.attribution import SqliteAttributor

    return SqliteAttributor(database)


def run_self_check(*, workspace: str | Path | None = None, budget: int = 60) -> dict[str, Any]:
    """Scan the real API and the weakened twin.

    Returns the two results and whether the self-check passed: the real API
    must be clean, and the weakened twin must not be.
    """
    clean = scan_server(variant="clean", vulnerable=False, workspace=workspace, budget=budget)
    weakened = scan_server(variant="weakened", vulnerable=True, workspace=workspace, budget=budget)
    passed = clean.clean and not weakened.clean and weakened.error is None
    return {
        "passed": passed,
        "clean": clean.to_dict(),
        "weakened": weakened.to_dict(),
    }
