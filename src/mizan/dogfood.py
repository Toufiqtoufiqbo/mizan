"""Mīzān scanning itself - and an application that knows nothing about Mīzān.

Mīzān has a small control plane of its own (`mizan.server`). That API is the
project's first user, and the self-scan is what keeps it honest:

* the **clean** variant must produce no finding at all;
* the **weakened** variant - the same code with one ownership check removed -
  must produce one.

The second half is what makes the first half meaningful: "no findings" is only
evidence if the check is known to bite.

The scan is deliberately **fail-closed**. A scanner that crashed, a server that
did not start, a scan that sent no request and a finding without a principal
are all failures - never an empty result.
"""

from __future__ import annotations

import json
import secrets
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.learning import learn_from_spec
from mizan.proxy import RecordingProxy
from mizan.twin import Twin, TwinSpec, python_command

#: The identities the self-scan uses. The server knows them by token.
SELF_IDENTITIES = ("alice", "bob", "root")

#: The law the weakened variant is expected to break.
WEAKENED_EXPECTED_LAW = "L2"


@dataclass
class SelfScanResult:
    """What one self-scan found."""

    variant: str
    finding_count: int = 0
    law_types: list[str] = field(default_factory=list)
    request_count: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    workspace: str | None = None

    @property
    def clean(self) -> bool:
        """No finding, no error, and the scan really ran."""
        return self.error is None and self.finding_count == 0 and self.request_count > 0

    @property
    def evidence_complete(self) -> bool:
        """Every finding names a principal and the resource it touched."""
        return all(finding.get("principal") and finding.get("resource") for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant": self.variant,
            "finding_count": self.finding_count,
            "law_types": list(self.law_types),
            "request_count": self.request_count,
            "findings": self.findings,
            "error": self.error,
            "clean": self.clean,
            "evidence_complete": self.evidence_complete,
            "workspace": self.workspace,
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
    """Start the server in its own workspace and attack it.

    The workspace holds everything this variant needs - database, traffic log,
    twin directory - and nothing else. Two variants never share one.
    """
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix=f"mizan-selfscan-{variant}-"))
    root.mkdir(parents=True, exist_ok=True)
    database = root / "server.sqlite"
    traffic_path = root / "traffic.jsonl"
    traffic_path.unlink(missing_ok=True)

    command = python_command("mizan.server", "--db", str(database), "--port", "{port}")
    if vulnerable:
        command.append("--vulnerable")

    # The credentials are generated for this run and injected explicitly:
    # there is no default account, and the tokens are random.
    tokens = {name: secrets.token_urlsafe(32) for name in SELF_IDENTITIES}
    users = ",".join(f"{name}={token}" + (":admin" if name == "root" else "") for name, token in tokens.items())

    spec = TwinSpec(
        command=command,
        workdir=root,
        env={"MIZAN_SERVER_USERS": users},
        data_paths=[database],
        health_path="/health",
        health_timeout=60.0,
    )
    twin = Twin(spec, workspace=root / "twin")
    proxy = RecordingProxy("http://127.0.0.1:1", traffic_path)
    result = SelfScanResult(variant=variant, workspace=str(root))
    try:
        twin.start()
        proxy = RecordingProxy(twin.base_url, traffic_path)
        proxy.start()

        document = _server_spec(twin.base_url)
        spec_path = root / "openapi.json"
        spec_path.write_text(json.dumps(document, indent=2), encoding="utf-8")

        # The tokens are opaque: the proxy is told who owns what.
        proxy.identity_map = {token: name for name, token in tokens.items()}
        learn_from_spec(
            spec_path,
            proxy.base_url,
            identities=tokens,
        )

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
            request_budget=budget,
        )
        engine.learn()
        violations = engine.attack()
        result.finding_count = len(violations)
        result.law_types = sorted({violation.law for violation in violations})
        result.request_count = engine.requests
        result.findings = [violation.to_dict() for violation in violations]
    except Exception as exc:  # pragma: no cover - reported, never hidden
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        proxy.stop()
        twin.stop()
    return result


def _attributor(database: Path):
    from mizan.attribution import SqliteAttributor

    return SqliteAttributor(database)


@dataclass
class SelfCheck:
    """The result of the whole self-check, with every check spelled out."""

    passed: bool = False
    checks: list[dict[str, Any]] = field(default_factory=list)
    clean: SelfScanResult | None = None
    weakened: SelfScanResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checks": self.checks,
            "clean": self.clean.to_dict() if self.clean else None,
            "weakened": self.weakened.to_dict() if self.weakened else None,
        }


def run_self_check(
    *,
    workspace: str | Path | None = None,
    budget: int = 60,
    keep: bool = False,
) -> SelfCheck:
    """Scan the real API and the weakened twin, and judge the result.

    The two variants get separate workspaces, so neither can benefit from what
    the other did.
    """
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="mizan-selfcheck-"))
    root.mkdir(parents=True, exist_ok=True)
    check = SelfCheck()
    try:
        clean = scan_server(variant="clean", vulnerable=False, workspace=root / "clean", budget=budget)
        weakened = scan_server(variant="weakened", vulnerable=True, workspace=root / "weakened", budget=budget)
        check.clean = clean
        check.weakened = weakened

        def record(name: str, ok: bool, detail: str) -> None:
            check.checks.append({"check": name, "passed": bool(ok), "detail": detail})

        record(
            "clean: no execution error",
            clean.error is None,
            clean.error or "the clean scan ran",
        )
        record(
            "clean: the scan sent requests",
            clean.request_count > 0,
            f"{clean.request_count} requests",
        )
        record(
            "clean: no findings",
            clean.finding_count == 0,
            f"{clean.finding_count} findings {clean.law_types}",
        )
        record(
            "weakened: no execution error",
            weakened.error is None,
            weakened.error or "the weakened scan ran",
        )
        record(
            "weakened: the scan sent requests",
            weakened.request_count > 0,
            f"{weakened.request_count} requests",
        )
        record(
            "weakened: the removed check is detected",
            WEAKENED_EXPECTED_LAW in weakened.law_types,
            f"law types {weakened.law_types}",
        )
        record(
            "weakened: every finding carries its evidence",
            weakened.evidence_complete,
            f"{weakened.finding_count} findings",
        )
        record(
            "the two variants are isolated",
            _isolated(clean, weakened),
            "separate workspaces, databases, traffic logs and processes",
        )
        check.passed = all(item["passed"] for item in check.checks)
    finally:
        if not keep and workspace is None:
            shutil.rmtree(root, ignore_errors=True)
    return check


def _isolated(clean: SelfScanResult, weakened: SelfScanResult) -> bool:
    """The two variants must not have shared anything."""
    if not clean.workspace or not weakened.workspace:
        return False
    return Path(clean.workspace) != Path(weakened.workspace)
