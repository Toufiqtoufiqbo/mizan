"""Independent validation: test an application that knows nothing about Mīzān.

The self-scan proves that Mīzān can test Mīzān. That is necessary and not
sufficient - an application that was written with the same assumptions can hide
the same mistakes.

This module runs the same engine against an application that has its own
authentication, its own database and its own OpenAPI document. The only things
Mīzān uses are ordinary HTTP, the tokens the application issues, and the
database file for attribution.

The validation is **fail-closed**:

* every expected identity must authenticate, or the scan is a setup error -
  never a clean result;
* the request budget covers the learning traffic *and* the attack traffic, and
  the accounting says which is which;
* a finding is only counted when its evidence is complete and consistent.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.core import Principal
from mizan.engine import Mizan, Target
from mizan.learning import learn_from_spec
from mizan.proxy import RecordingProxy
from mizan.twin import Twin, TwinSpec, script_command

#: The variants of an application, and the laws each of them must produce.
VARIANTS: dict[str, tuple[str, ...]] = {
    "clean": (),
    "read": ("L2",),
    "write": ("L3",),
    "both": ("L2", "L3"),
}


@dataclass
class LaunchSpec:
    """Specification for launching an independent application under test."""

    command: list[str]
    environment: dict[str, str] | None = None

    def with_environment(self, extra: dict[str, str]) -> LaunchSpec:
        """Return a new ``LaunchSpec`` with extra environment variables merged in."""
        return LaunchSpec(
            command=self.command,
            environment={**(self.environment or {}), **extra},
        )


#: The launch specification for the FastAPI fixture.
LAUNCH_FASTAPI = LaunchSpec(
    command=[sys.executable, "app.py"],
    environment=None,
)

#: The launch specification for the Express fixture.
LAUNCH_EXPRESS = LaunchSpec(
    command=["node", "server.js"],
    environment=None,
)

#: The launch specification for the Flask fixture.
LAUNCH_FLASK = LaunchSpec(
    command=[sys.executable, "app.py"],
    environment=None,
)


def launch_for(fixture_dir: Path) -> LaunchSpec | None:
    """Return the ``LaunchSpec`` for a fixture directory, or ``None`` if unknown."""
    _FIXTURE_LAUNCH: dict[str, LaunchSpec] = {
        "fastapi_store": LAUNCH_FASTAPI,
        "express_store": LAUNCH_EXPRESS,
        "flask_store": LAUNCH_FLASK,
    }
    return _FIXTURE_LAUNCH.get(fixture_dir.name)


def resolve_launch(fixture_dir: Path, explicit: LaunchSpec | None = None) -> LaunchSpec | None:
    """Resolve the launch specification for a fixture directory.

    If ``explicit`` is given it is always returned (the specification always wins
    over the fixture convention).  Otherwise the fixture convention is used, and
    ``None`` is returned for unknown directories.
    """
    if explicit is not None:
        return explicit
    result = launch_for(fixture_dir)
    return result


def environment_for(launch: LaunchSpec) -> dict[str, str]:
    """Return the environment dict from a ``LaunchSpec`` (defaulting to ``{}), merged with os.environ.

    The ``LaunchSpec``'s environment takes precedence over ambient variables,
    but ambient variables fill in any gaps where the specification does not set a value.
    """
    result = dict(os.environ)
    result.update(launch.environment or {})
    return result


def build_command(
    launch: LaunchSpec,
    fixture_dir: Path,
    db_path: Path,
    variant: str,
) -> list[str]:
    """Build the launch command for a fixture with the given vulnerability variant."""
    cmd: list[str] = list(launch.command)

    entry_point = "server.js" if fixture_dir.name == "express_store" else "app.py"
    cmd = [str(fixture_dir / part) if Path(part).name == entry_point else part for part in cmd]
    if not any(Path(part).name == entry_point for part in cmd):
        cmd.append(str(fixture_dir / entry_point))

    # Common placeholders: ``{port}`` and ``{workspace}``.
    cmd += ["--db", str(db_path), "--port", "{port}", "--vulnerability", variant]

    return cmd


@dataclass
class RequestAccounting:
    """Where every request went."""

    bootstrap: int = 0
    """The requests that obtained the tokens."""
    learning: int = 0
    """The requests of the learning phase."""
    attack: int = 0
    """The requests of the probes."""
    budget: int | None = None
    budget_exhausted: bool = False

    @property
    def total(self) -> int:
        return self.bootstrap + self.learning + self.attack

    def to_dict(self) -> dict[str, Any]:
        return {
            "bootstrap": self.bootstrap,
            "learning": self.learning,
            "attack": self.attack,
            "total": self.total,
            "budget": self.budget,
            "budget_exhausted": self.budget_exhausted,
        }


@dataclass
class ValidationResult:
    """What the scan of an independent application found."""

    application: str
    variant: str
    finding_count: int = 0
    law_types: list[str] = field(default_factory=list)
    requests: RequestAccounting = field(default_factory=RequestAccounting)
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    setup_error: str | None = None
    traffic_lines: int = 0
    missing_identities: list[str] = field(default_factory=list)
    workspace: str | None = None

    @property
    def clean(self) -> bool:
        """A clean result: the scan ran, it sent requests, and it found nothing."""
        return self.error is None and self.setup_error is None and self.finding_count == 0 and self.requests.total > 0

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
            "requests": self.requests.to_dict(),
            "findings": self.findings,
            "error": self.error,
            "setup_error": self.setup_error,
            "clean": self.clean,
            "evidence_complete": self.evidence_complete,
            "traffic_lines": self.traffic_lines,
            "missing_identities": list(self.missing_identities),
            "workspace": self.workspace,
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
        token = response.json().get("token")
    except Exception:
        return None
    if not isinstance(token, str) or not token.strip():
        return None
    return token


def _authenticate(
    base_url: str, credentials: dict[str, tuple[str, str]], required: list[str]
) -> tuple[dict[str, str], list[str]]:
    """Log in as every expected identity.

    Returns the tokens and the identities that could not be authenticated. A
    missing identity is a setup error, not a result.
    """
    tokens: dict[str, str] = {}
    missing: list[str] = []
    for principal in required:
        entry = credentials.get(principal)
        if entry is None:
            missing.append(principal)
            continue
        username, password = entry
        token = _login(base_url, username, password)
        if not token:
            missing.append(principal)
            continue
        tokens[principal] = token
    return tokens, missing


def scan_application(
    application: str | Path,
    *,
    variant: str = "clean",
    vulnerable: bool = False,
    workspace: str | Path | None = None,
    keep_workspace: bool | None = None,
    budget: int = 60,
    credentials: dict[str, tuple[str, str]] | None = None,
    spec_name: str = "openapi.json",
    observer: Any | None = None,
    launch: LaunchSpec | None = None,
) -> ValidationResult:
    """Start an independent application and attack it.

    ``credentials`` maps a principal to ``(username, password)``. The
    application issues the tokens; Mīzān never invents them.

    ``keep_workspace``: if True, the temporary workspace directory is retained
    after the scan for replay purposes.

    ``observer``: an optional callable that is called with the running Twin.

    ``launch``: an optional LaunchSpec whose environment overrides the
    ambient environment variables.
    """
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}; expected one of {sorted(VARIANTS)}")
    app_dir = Path(application).resolve()
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix=f"mizan-validate-{variant}-"))
    root.mkdir(parents=True, exist_ok=True)

    database = root / "application.sqlite"
    traffic_path = root / "traffic.jsonl"
    traffic_path.unlink(missing_ok=True)

    # Build the environment, merging the LaunchSpec environment with os.environ.
    env = dict(os.environ)
    if launch is not None:
        env.update(environment_for(launch))
    elif launch is None and vulnerable:
        env["STORE_VULNERABLE"] = "1"
    else:
        env.pop("STORE_VULNERABLE", None)

    resolved_launch = resolve_launch(app_dir, launch)
    if resolved_launch is not None:
        command = build_command(resolved_launch, app_dir, database, variant)
    else:
        command = script_command(
            app_dir / "app.py", "--db", str(database), "--port", "{port}", "--vulnerability", variant
        )
    spec = TwinSpec(
        command=command,
        workdir=root,
        env=env,
        data_paths=[database],
        health_path="/health",
        health_timeout=60.0,
    )

    twin = Twin(spec, workspace=root / "twin")
    proxy = RecordingProxy("http://127.0.0.1:1", traffic_path)
    accounting = RequestAccounting(budget=budget)
    result = ValidationResult(
        application=str(app_dir),
        variant=variant,
        requests=accounting,
        workspace=str(root) if keep_workspace else None,
    )

    try:
        twin.start()

        if observer is not None:
            try:
                observer(twin)
            except Exception as exc:
                raise RuntimeError(f"the observer failed: {exc}") from exc

        proxy = RecordingProxy(twin.base_url, traffic_path)
        proxy.start()

        credentials = credentials or {
            "alice": ("alice", "alice-secret"),
            "bob": ("bob", "bob-secret"),
            "root": ("root", "root-secret"),
        }

        required = ["alice", "bob"]
        tokens, missing = _authenticate(twin.base_url, credentials, required)
        accounting.bootstrap = len(required)
        result.missing_identities = missing
        if missing:
            result.setup_error = f"could not authenticate: {', '.join(missing)}"
            return result

        spec_path = app_dir / spec_name
        if not spec_path.exists():
            result.setup_error = f"the application has no OpenAPI document at {spec_path}"
            return result

        # The application issued opaque tokens: the proxy is told who owns what
        # *before* the traffic is recorded, otherwise the learning phase would
        # produce anonymous requests.
        proxy.identity_map = {token: name for name, token in tokens.items()}

        learning_budget = max(0, budget - accounting.bootstrap)
        learned = learn_from_spec(spec_path, proxy.base_url, identities=tokens, max_requests=learning_budget)
        accounting.learning = len(learned)
        if accounting.learning >= learning_budget and learning_budget > 0:
            accounting.budget_exhausted = True

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
            request_budget=max(0, budget - accounting.bootstrap - accounting.learning),
        )

        engine.learn()
        violations = engine.attack()
        accounting.attack = engine.requests
        accounting.budget_exhausted = accounting.budget_exhausted or engine.budget_exhausted

        result.finding_count = len(violations)
        result.law_types = sorted({violation.law for violation in violations})
        result.findings = [violation.to_dict() for violation in violations]

        result.traffic_lines = (
            len(traffic_path.read_text(encoding="utf-8").splitlines()) if traffic_path.exists() else 0
        )
    except Exception as exc:  # pragma: no cover - reported, never hidden
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        proxy.stop()
        twin.stop()
        if not keep_workspace:
            shutil.rmtree(root, ignore_errors=True)

    return result


def validate_application(
    application: str | Path,
    *,
    budget: int = 60,
    expected: dict[str, tuple[str, ...]] | None = None,
    credentials: dict[str, tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Scan every variant of an application and judge the results.

    ``expected`` maps a variant to the laws it must produce. A variant that
    produces a law it should not produce fails the gate as well - that is how a
    "vulnerable" application that is vulnerable in more ways than intended is
    caught.
    """
    expected = expected or {"clean": (), "read": ("L2",), "write": ("L3",), "both": ("L2", "L3")}
    root = Path(tempfile.mkdtemp(prefix="mizan-validate-"))
    checks: list[dict[str, Any]] = []
    variants: dict[str, Any] = {}
    try:
        for variant, expected_laws in expected.items():
            result = scan_application(
                application,
                variant=variant,
                budget=budget,
                credentials=credentials,
            )
            variants[variant] = result.to_dict()

            def record(name: str, ok: bool, detail: str) -> None:
                checks.append({"check": f"{variant}: {name}", "passed": bool(ok), "detail": detail})

            record("no setup error", result.setup_error is None, result.setup_error or "the setup worked")
            record("no execution error", result.error is None, result.error or "the scan ran")
            record("the scan sent requests", result.requests.total > 0, f"{result.requests.total} requests")
            record(
                "the expected laws are detected",
                all(law in result.law_types for law in expected_laws),
                f"law types {result.law_types}, expected {list(expected_laws)}",
            )
            record(
                "no unexpected laws are reported",
                all(law in expected_laws for law in result.law_types),
                f"law types {result.law_types}",
            )
            record(
                "every finding carries its evidence",
                all(not validate_finding(finding) for finding in result.findings),
                "; ".join(problem for finding in result.findings for problem in validate_finding(finding))
                or f"{result.finding_count} findings",
            )
        return {
            "passed": all(item["passed"] for item in checks),
            "checks": checks,
            "variants": variants,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def validate_finding(finding: dict[str, Any]) -> list[str]:
    """Check that one finding is complete and internally consistent.

    Returns the problems; an empty list means the finding is sound.
    """
    problems: list[str] = []
    law = finding.get("law")
    if not isinstance(law, str) or not law.startswith("L"):
        problems.append(f"the law identifier is missing or malformed: {law!r}")
    if not finding.get("principal"):
        problems.append("the finding does not name a principal")
    if not finding.get("resource"):
        problems.append("the finding does not name the affected resource")
    if not finding.get("action"):
        problems.append("the finding does not name the action")
    steps = finding.get("steps") or []
    if not steps:
        problems.append("the finding has no reproduction steps")
        return problems
    first = steps[0]
    if not first.get("method"):
        problems.append("the reproduction step has no method")
    if not first.get("url"):
        problems.append("the reproduction step has no endpoint")
    evidence = finding.get("evidence") or {}
    if not evidence:
        problems.append("the finding has no evidence")
    # The laws that are about ownership must say whose object it was.
    if law in {"L2", "L3"}:
        owner = evidence.get("owner") or evidence.get("row_owner")
        if not owner:
            owner = (evidence.get("event") or {}).get("row_owner")
        if not owner:
            problems.append(f"{law} does not say who owns the affected object")
        elif owner == finding.get("principal"):
            problems.append(f"{law} blames the owner of the object")
    return problems
