"""Independent validation: test an application that knows nothing about Mīzān.

The self-scan proves that Mīzān can test Mīzān. That is necessary and not
sufficient - an application that was written with the same assumptions can hide
the same mistakes.

This module runs the same engine against an application that has its own
authentication, its own database and its own OpenAPI document. The only thing
Mīzān uses is ordinary HTTP plus the database file for attribution.

    from mizan.validation import scan_application

    result = scan_application("tests/fixtures/external_apps/flask_store")
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.learning import learn_from_spec
from mizan.proxy import RecordingProxy
from mizan.twin import Twin, TwinSpec, script_command


@dataclass
class ValidationResult:
    """What the scan of an independent application found."""

    application: str
    variant: str
    finding_count: int = 0
    law_types: list[str] = field(default_factory=list)
    request_count: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    traffic_lines: int = 0

    @property
    def clean(self) -> bool:
        return self.error is None and self.finding_count == 0 and self.request_count > 0

    @property
    def evidence_complete(self) -> bool:
        """Every finding identifies a principal, an endpoint and a resource."""
        for finding in self.findings:
            steps = finding.get("steps") or []
            if not finding.get("principal") or not finding.get("resource") or not steps:
                return False
            if not steps[0].get("method") or not steps[0].get("url"):
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "application": self.application,
            "variant": self.variant,
            "finding_count": self.finding_count,
            "law_types": list(self.law_types),
            "request_count": self.request_count,
            "findings": self.findings,
            "error": self.error,
            "clean": self.clean,
            "evidence_complete": self.evidence_complete,
            "traffic_lines": self.traffic_lines,
        }


def _login(base_url: str, username: str, password: str) -> str | None:
    """Get a token from the application's own login endpoint."""
    import requests

    try:
        response = requests.post(f"{base_url}/login", json={"username": username, "password": password}, timeout=15)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    try:
        return response.json().get("token")
    except Exception:
        return None


def scan_application(
    application: str | Path,
    *,
    variant: str = "clean",
    vulnerable: bool = False,
    workspace: str | Path | None = None,
    budget: int = 60,
    credentials: dict[str, tuple[str, str]] | None = None,
    spec_name: str = "openapi.json",
) -> ValidationResult:
    """Start an independent application and attack it.

    ``credentials`` maps a principal to ``(username, password)``. The
    application issues the tokens; Mīzān never invents them.
    """
    app_dir = Path(application).resolve()
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix=f"mizan-validate-{variant}-"))
    root.mkdir(parents=True, exist_ok=True)
    database = root / "application.sqlite"
    traffic_path = root / "traffic.jsonl"
    traffic_path.unlink(missing_ok=True)

    environment = dict(os.environ)
    if vulnerable:
        environment["STORE_VULNERABLE"] = "1"
    else:
        environment.pop("STORE_VULNERABLE", None)

    spec = TwinSpec(
        command=script_command(app_dir / "app.py", "--db", str(database), "--port", "{port}"),
        workdir=root,
        env=environment,
        data_paths=[database],
        health_path="/health",
        health_timeout=60.0,
    )
    twin = Twin(spec, workspace=root / "twin")
    proxy = RecordingProxy("http://127.0.0.1:1", traffic_path)
    result = ValidationResult(application=str(app_dir), variant=variant)
    try:
        twin.start()
        proxy = RecordingProxy(twin.base_url, traffic_path)
        proxy.start()

        credentials = credentials or {
            "alice": ("alice", "alice-secret"),
            "bob": ("bob", "bob-secret"),
            "root": ("root", "root-secret"),
        }
        tokens: dict[str, str] = {}
        for principal, (username, password) in credentials.items():
            token = _login(twin.base_url, username, password)
            if token:
                tokens[principal] = token
        if not tokens:
            raise RuntimeError("the application issued no token: the credentials are wrong")

        spec_path = app_dir / spec_name
        if not spec_path.exists():
            raise RuntimeError(f"the application has no OpenAPI document at {spec_path}")
        # The application issued opaque tokens: the proxy is told who owns what
        # *before* the traffic is recorded, otherwise the learning phase would
        # produce anonymous requests.
        proxy.identity_map = {token: name for name, token in tokens.items()}
        learn_from_spec(spec_path, proxy.base_url, identities=tokens)

        principals = [
            Principal(id=name, roles=("admin" if name == "root" else "user",), token=token)
            for name, token in tokens.items()
        ]
        from mizan.attribution import SqliteAttributor

        engine = Mizan(
            Target(base_url=proxy.base_url, principals=principals),
            traffic_path=traffic_path,
            spec_path=spec_path,
            twin=twin,
            attributor=SqliteAttributor(database),
            request_budget=budget,
        )
        engine.learn()
        violations = engine.attack()
        result.finding_count = len(violations)
        result.law_types = sorted({violation.law for violation in violations})
        result.request_count = engine.requests
        result.findings = [violation.to_dict() for violation in violations]
        result.traffic_lines = (
            len(traffic_path.read_text(encoding="utf-8").splitlines()) if traffic_path.exists() else 0
        )
    except Exception as exc:  # pragma: no cover - reported, never hidden
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        proxy.stop()
        twin.stop()
    return result


def validate_application(
    application: str | Path,
    *,
    workspace: str | Path | None = None,
    budget: int = 60,
    expected_laws: tuple[str, ...] = ("L2",),
) -> dict[str, Any]:
    """Scan the clean and the vulnerable variant and judge both."""
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="mizan-validate-"))
    root.mkdir(parents=True, exist_ok=True)
    try:
        clean = scan_application(
            application, variant="clean", vulnerable=False, workspace=root / "clean", budget=budget
        )
        vulnerable = scan_application(
            application,
            variant="vulnerable",
            vulnerable=True,
            workspace=root / "vulnerable",
            budget=budget,
        )
        checks = [
            {
                "check": "clean: no execution error",
                "passed": clean.error is None,
                "detail": clean.error or "the clean scan ran",
            },
            {
                "check": "clean: the scan sent requests",
                "passed": clean.request_count > 0,
                "detail": f"{clean.request_count} requests",
            },
            {
                "check": "clean: no findings",
                "passed": clean.finding_count == 0,
                "detail": f"{clean.finding_count} findings {clean.law_types}",
            },
            {
                "check": "vulnerable: no execution error",
                "passed": vulnerable.error is None,
                "detail": vulnerable.error or "the vulnerable scan ran",
            },
            {
                "check": "vulnerable: the scan sent requests",
                "passed": vulnerable.request_count > 0,
                "detail": f"{vulnerable.request_count} requests",
            },
            {
                "check": "vulnerable: the expected laws are detected",
                "passed": all(law in vulnerable.law_types for law in expected_laws),
                "detail": f"law types {vulnerable.law_types}, expected {list(expected_laws)}",
            },
            {
                "check": "vulnerable: every finding carries its evidence",
                "passed": vulnerable.evidence_complete,
                "detail": f"{vulnerable.finding_count} findings",
            },
        ]
        return {
            "passed": all(item["passed"] for item in checks),
            "checks": checks,
            "clean": clean.to_dict(),
            "vulnerable": vulnerable.to_dict(),
        }
    finally:
        if workspace is None:
            shutil.rmtree(root, ignore_errors=True)


def _spec_path_hint() -> str:  # pragma: no cover - documentation helper
    return json.dumps({"openapi": "3.0.3"})
