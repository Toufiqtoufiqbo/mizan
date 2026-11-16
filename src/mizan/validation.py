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

The launch is **framework-neutral**. A ``LaunchSpec`` is the single source of
truth for how an application starts: which executable, which entry point,
which arguments, which database, which port, which health endpoint, which
startup timeout and where the OpenAPI document comes from. The same engine
starts Flask, FastAPI and Express with it - no framework branch exists in the
engine itself.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.core import Principal, ScanCoverage, Verdict
from mizan.engine import Mizan, Target
from mizan.learning import learn_from_spec
from mizan.proxy import RecordingProxy
from mizan.twin import Twin, TwinSpec, script_command

#: The variants of an application, and the laws each of them must produce.
#: The default variants of a fixture. A fixture with additional variants
#: declares them in its own ``variants.json``; production code never names a
#: particular fixture or guesses which variants it implements.
DEFAULT_EXPECTED: dict[str, tuple[str, ...]] = {
    "clean": (),
    "read": ("L2",),
    "write": ("L3",),
    "both": ("L2", "L3"),
}


def expected_variants(application: str | Path) -> dict[str, tuple[str, ...]]:
    """The variants a fixture declares, or the standard contract by default."""
    manifest = Path(application) / "variants.json"
    if not manifest.exists():
        return dict(DEFAULT_EXPECTED)
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULT_EXPECTED)
    if not isinstance(data, dict):
        return dict(DEFAULT_EXPECTED)
    return {str(name): tuple(str(law) for law in laws) for name, laws in data.items()}

#: The principals that L2 and L3 validation require. Cross-user testing is
#: meaningless with fewer than two unprivileged identities, so a scan that
#: cannot authenticate both of them is a setup error - never a clean result.
REQUIRED_IDENTITIES: tuple[str, ...] = ("alice", "bob")


# --------------------------------------------------------------------------- #
# The OpenAPI source
# --------------------------------------------------------------------------- #


class SpecResolutionError(RuntimeError):
    """The OpenAPI document could not be resolved - never a clean result."""


@dataclass(frozen=True)
class SpecSource:
    """Where an application's OpenAPI document comes from.

    Applications differ:

    * a Flask fixture commits its document to disk;
    * a FastAPI application generates it at runtime and serves it on
      ``/openapi.json``;
    * an Express fixture commits its document to disk.

    The engine must not assume that every target has a physical
    ``openapi.json`` file. The document is resolved through the configured
    source, validated, and only then handed to the engine.
    """

    kind: str
    """``"file"`` - a document on disk.  ``"url"`` - a document served at runtime."""

    path: str | None = None
    """For ``kind="file"``: the file path. ``{fixture}`` resolves to the fixture directory."""

    url: str | None = None
    """For ``kind="url"``: an absolute URL, or a path relative to the base URL."""

    timeout: float = 15.0
    """How long to wait for the document (also retries while the app starts)."""

    @classmethod
    def from_file(cls, path: str, timeout: float = 15.0) -> SpecSource:
        return cls(kind="file", path=path)

    @classmethod
    def from_url(cls, url: str, timeout: float = 15.0) -> SpecSource:
        return cls(kind="url", url=url)


def _resolve_fixture(part: str, fixture_dir: Path) -> str:
    """Replace the ``{fixture}`` placeholder and normalize the separators."""
    if "{fixture}" not in part:
        return part
    tail = part.split("{fixture}", 1)[1].lstrip("/\\")
    if not tail:
        return str(fixture_dir)
    return str(fixture_dir / tail)


def resolve_spec(
    source: SpecSource | None,
    *,
    fixture_dir: Path | None = None,
    base_url: str | None = None,
    fallback_path: Path | None = None,
) -> dict[str, Any]:
    """Fetch, parse and validate the OpenAPI document of a configured source.

    Raises ``SpecResolutionError`` for every failure mode: a missing file, an
    unreachable endpoint, invalid JSON, a document that is not OpenAPI. A
    missing document is a **setup error** - it must never be reported as a
    clean security result.
    """
    if source is None:
        # No configured source: fall back to a static file next to the code,
        # which is the convention the Flask and Express fixtures follow.
        if fallback_path is not None and fallback_path.exists():
            source = SpecSource.from_file(str(fallback_path))
        else:
            raise SpecResolutionError(f"the application has no OpenAPI document at {fallback_path}")

    if source.kind == "file":
        if source.path is None:
            raise SpecResolutionError("the file source does not name a path")
        path = Path(_resolve_fixture(source.path, fixture_dir)) if fixture_dir else Path(source.path)
        if not path.exists():
            raise SpecResolutionError(f"the application has no OpenAPI document at {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SpecResolutionError(f"the OpenAPI document at {path} is not valid JSON: {exc}") from exc
        return _validate_document(document, path)

    if source.kind == "url":
        import time as _time
        import urllib.error
        import urllib.request

        if source.url is None:
            raise SpecResolutionError("the url source does not name a URL")
        url = (
            source.url if source.url.startswith("http") else f"{(base_url or '').rstrip('/')}/{source.url.lstrip('/')}"
        )
        if not url.startswith("http"):
            raise SpecResolutionError(f"no base URL is available to resolve {source.url!r}")

        deadline = _time.time() + source.timeout
        last_error: Exception | None = None
        while _time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    body = response.read().decode("utf-8", errors="replace")
                try:
                    document = json.loads(body)
                except ValueError as exc:
                    raise SpecResolutionError(f"the OpenAPI document at {url} is not valid JSON: {exc}") from exc
                return _validate_document(document, url)
            except SpecResolutionError:
                raise
            except (urllib.error.URLError, OSError) as exc:
                last_error = exc
            _time.sleep(0.2)
        raise SpecResolutionError(
            f"the OpenAPI document at {url} was not reachable within {source.timeout}s: {last_error}"
        )

    raise SpecResolutionError(f"unknown OpenAPI source kind: {source.kind!r}")


def _validate_document(document: Any, origin: Any) -> dict[str, Any]:
    """Whether a parsed document is a usable OpenAPI document."""
    if not isinstance(document, dict):
        raise SpecResolutionError(f"the document at {origin} is not a JSON object")
    if "openapi" not in document and "swagger" not in document:
        raise SpecResolutionError(f"the document at {origin} does not declare an OpenAPI version")
    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise SpecResolutionError(f"the document at {origin} declares no paths")
    return document


# --------------------------------------------------------------------------- #
# The launch contract
# --------------------------------------------------------------------------- #


@dataclass
class LaunchSpec:
    """How to start, wait for and describe an application under test.

    This is the single source of truth for launching a target. It carries:

    * ``command`` - the executable, entry point and static arguments. The
      ``{fixture}`` placeholder resolves to the fixture directory, so the same
      specification works from any working directory;
    * ``environment`` - variables that override the ambient environment;
    * ``health_path`` - the endpoint that answers when the app is ready;
    * ``health_timeout`` - how long to wait for that endpoint;
    * ``database`` - the database *file name* inside the workspace, so replay
      can reopen the state a scan left behind;
    * ``spec_source`` - where the OpenAPI document comes from.

    Nothing here is framework-specific. Flask, FastAPI and Express are three
    values of this one contract, not three code paths.
    """

    command: list[str]
    environment: dict[str, str] | None = None
    health_path: str = "/health"
    health_timeout: float = 60.0
    database: str = "application.sqlite"
    spec_source: SpecSource | None = None

    def with_environment(self, extra: dict[str, str]) -> LaunchSpec:
        """Return a new ``LaunchSpec`` with extra environment variables merged in."""
        return LaunchSpec(
            command=self.command,
            environment={**(self.environment or {}), **extra},
            health_path=self.health_path,
            health_timeout=self.health_timeout,
            database=self.database,
            spec_source=self.spec_source,
        )


#: The launch specification for the FastAPI fixture. FastAPI generates its
#: OpenAPI document at runtime and serves it on ``/openapi.json``.
LAUNCH_FASTAPI = LaunchSpec(
    command=[sys.executable, "{fixture}/app.py"],
    spec_source=SpecSource.from_url("/openapi.json"),
)

#: The launch specification for the Express fixture. The document is committed
#: to disk; the application runs on Node.js.
LAUNCH_EXPRESS = LaunchSpec(
    command=["node", "{fixture}/server.js"],
    spec_source=SpecSource.from_file("{fixture}/openapi.json"),
)

#: The launch specification for the Flask fixture.
LAUNCH_FLASK = LaunchSpec(
    command=[sys.executable, "{fixture}/app.py"],
    spec_source=SpecSource.from_file("{fixture}/openapi.json"),
)

#: The launch specification for the nonstandard-ownership fixture (Phase V).
LAUNCH_LINKED = LaunchSpec(
    command=[sys.executable, "{fixture}/app.py"],
    spec_source=SpecSource.from_file("{fixture}/openapi.json"),
)


def launch_for(fixture_dir: Path) -> LaunchSpec | None:
    """Return the ``LaunchSpec`` for a fixture directory, or ``None`` if unknown."""
    _FIXTURE_LAUNCH: dict[str, LaunchSpec] = {
        "fastapi_store": LAUNCH_FASTAPI,
        "express_store": LAUNCH_EXPRESS,
        "flask_store": LAUNCH_FLASK,
        "linked_store": LAUNCH_LINKED,
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
    return launch_for(fixture_dir)


def environment_for(launch: LaunchSpec) -> dict[str, str]:
    """The environment a launch runs in: ambient variables, overridden by the spec.

    The ``LaunchSpec``'s environment takes precedence over ambient variables,
    but ambient variables fill in any gaps where the specification does not set
    a value.
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
    """Build the launch command for a fixture with the given vulnerability variant.

    The ``{fixture}`` placeholder in the specification's command resolves to
    the fixture directory - the entry point comes from the specification, never
    from a guess about which framework the directory belongs to.
    """
    command: list[str] = [_resolve_fixture(part, fixture_dir) for part in launch.command]
    # The standard contract every fixture implements.
    command += ["--db", str(db_path), "--port", "{port}", "--vulnerability", variant]
    return command


# --------------------------------------------------------------------------- #
# Accounting and results
# --------------------------------------------------------------------------- #


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
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    setup_error: str | None = None
    traffic_lines: int = 0
    missing_identities: list[str] = field(default_factory=list)
    workspace: str | None = None
    requests: RequestAccounting = field(default_factory=RequestAccounting)
    coverage: ScanCoverage = field(default_factory=ScanCoverage)
    #: Phase V: the ownership graph report for this scan (explainability).
    ownership: dict[str, Any] = field(default_factory=dict)

    @property
    def verdict(self) -> Verdict:
        """What the scan concluded.

        The order matters. A failed setup is ``ERROR`` even when nothing was
        found, because a scan that could not start proved nothing. A proven
        finding is ``FINDINGS`` even when the coverage was incomplete - the
        finding is real, and the missing coverage stays visible in
        ``coverage``. Only a scan that both ran its checks *and* found nothing
        is ``CLEAN``; anything else is ``INCONCLUSIVE``.
        """
        if self.error is not None or self.setup_error is not None:
            return Verdict.ERROR
        if self.finding_count > 0:
            return Verdict.FINDINGS
        if self.coverage.meaningful:
            return Verdict.CLEAN
        return Verdict.INCONCLUSIVE

    @property
    def clean(self) -> bool:
        """Whether the scan is entitled to say it found nothing.

        This is deliberately **not** "the scan found no findings". A scan that
        never learned anything, never discovered a resource, never identified a
        check or never ran one has no standing to make that claim - it must
        report ``INCONCLUSIVE``, and this property says so by staying False.
        """
        return self.verdict is Verdict.CLEAN

    @property
    def inconclusive(self) -> bool:
        """Whether the scan could not establish enough coverage."""
        return self.verdict is Verdict.INCONCLUSIVE

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
            "verdict": self.verdict.value,
            "clean": self.clean,
            "inconclusive": self.inconclusive,
            "coverage": self.coverage.to_dict(),
            "ownership": self.ownership,
            "evidence_complete": self.evidence_complete,
            "traffic_lines": self.traffic_lines,
            "missing_identities": list(self.missing_identities),
            "workspace": self.workspace,
        }


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


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
) -> tuple[dict[str, str], list[str], int]:
    """Log in as every expected identity.

    Returns the tokens, the identities that could not be authenticated, and
    the number of login requests that were actually sent. A missing identity is
    a setup error, not a result - and the accounting counts the requests that
    were really made, not the ones that were planned.
    """
    tokens: dict[str, str] = {}
    missing: list[str] = []
    attempted = 0
    for principal in required:
        entry = credentials.get(principal)
        if entry is None:
            # No credentials were configured: no request was made.
            missing.append(principal)
            continue
        username, password = entry
        attempted += 1
        token = _login(base_url, username, password)
        if not token:
            missing.append(principal)
            continue
        tokens[principal] = token
    return tokens, missing, attempted


# --------------------------------------------------------------------------- #
# The scan
# --------------------------------------------------------------------------- #


def scan_application(
    application: str | Path,
    *,
    variant: str = "clean",
    vulnerable: bool = False,
    workspace: str | Path | None = None,
    keep_workspace: bool | None = None,
    budget: int = 60,
    credentials: dict[str, tuple[str, str]] | None = None,
    required_identities: list[str] | None = None,
    observer: Any | None = None,
    launch: LaunchSpec | None = None,
) -> ValidationResult:
    """Start an independent application and attack it.

    ``credentials`` maps a principal to ``(username, password)``. The
    application issues the tokens; Mīzān never invents them.

    ``required_identities`` names the principals the scan must be able to
    authenticate. It defaults to ``REQUIRED_IDENTITIES`` - the two unprivileged
    identities that L2 and L3 need. A scan that cannot authenticate all of
    them is a setup error.

    ``keep_workspace``: if True, the temporary workspace directory is retained
    after the scan for replay purposes.

    ``observer``: an optional callable that is called with the running Twin.

    ``launch``: the launch contract. When given, it overrides the fixture
    convention entirely.
    """
    application_path = Path(application).resolve()
    if variant not in expected_variants(application_path):
        raise ValueError(
            f"unknown variant {variant!r} for this fixture; expected one of "
            f"{sorted(expected_variants(application_path))}"
        )
    app_dir = application_path
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix=f"mizan-validate-{variant}-"))
    root.mkdir(parents=True, exist_ok=True)

    required = list(required_identities) if required_identities else list(REQUIRED_IDENTITIES)
    resolved_launch = resolve_launch(app_dir, launch)
    # The database name comes from the launch contract, so the replay - which
    # reopens the scan's state through the same contract - finds the same
    # file. Two different names would silently break the replay.
    database_name = resolved_launch.database if resolved_launch is not None else "application.sqlite"
    database = root / database_name
    traffic_path = root / "traffic.jsonl"
    traffic_path.unlink(missing_ok=True)

    # Build the environment, merging the LaunchSpec environment with os.environ.
    env = dict(os.environ)
    if launch is not None:
        env.update(launch.environment or {})
    elif vulnerable:
        env["STORE_VULNERABLE"] = "1"
    else:
        env.pop("STORE_VULNERABLE", None)

    if resolved_launch is not None:
        command = build_command(resolved_launch, app_dir, database, variant)
    else:
        # No specification at all: the fallback is the Python convention, and
        # it is explicit here so a Node.js target without a specification fails
        # loudly instead of being started with the wrong interpreter.
        command = script_command(
            app_dir / "app.py", "--db", str(database), "--port", "{port}", "--vulnerability", variant
        )
    health_path = resolved_launch.health_path if resolved_launch else "/health"
    health_timeout = resolved_launch.health_timeout if resolved_launch else 60.0
    spec = TwinSpec(
        command=command,
        workdir=root,
        env=env,
        data_paths=[database],
        health_path=health_path,
        health_timeout=health_timeout,
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

        tokens, missing, bootstrap_requests = _authenticate(twin.base_url, credentials, required)
        accounting.bootstrap = bootstrap_requests
        result.missing_identities = missing
        if missing:
            result.setup_error = f"could not authenticate: {', '.join(missing)}"
            return result

        # The application issued opaque tokens: the proxy is told who owns what
        # *before* the traffic is recorded, otherwise the learning phase would
        # produce anonymous requests.
        proxy.identity_map = {token: name for name, token in tokens.items()}

        # Resolve the OpenAPI document through the configured source. A missing
        # or malformed document is a setup error - never a clean result.
        try:
            document = resolve_spec(
                resolved_launch.spec_source if resolved_launch else None,
                fixture_dir=app_dir,
                base_url=twin.base_url,
                fallback_path=app_dir / "openapi.json",
            )
        except SpecResolutionError as exc:
            result.setup_error = str(exc)
            return result

        learning_budget = max(0, budget - accounting.bootstrap)
        if learning_budget == 0 and budget > 0:
            # The bootstrap used the whole budget: the learning phase cannot run.
            accounting.budget_exhausted = True
        # /login is how the identities were obtained; exercising it again
        # would mint fresh tokens and write them into the traffic log.
        learned = learn_from_spec(
            document, proxy.base_url, identities=tokens, max_requests=learning_budget, exclude_paths=("/login",)
        )
        accounting.learning = len(learned)
        if learning_budget > 0 and accounting.learning >= learning_budget:
            accounting.budget_exhausted = True

        principals = [
            Principal(id=name, roles=("admin" if name == "root" else "user",), token=token)
            for name, token in tokens.items()
        ]

        from mizan.attribution import SqliteAttributor

        engine = Mizan(
            Target(base_url=proxy.base_url, principals=principals),
            traffic_path=traffic_path,
            spec_document=document,
            twin=twin,
            attributor=SqliteAttributor(database),
            request_budget=max(0, budget - accounting.bootstrap - accounting.learning),
        )

        engine.learn()
        violations = engine.attack()
        accounting.attack = engine.requests
        accounting.budget_exhausted = accounting.budget_exhausted or engine.budget_exhausted

        # The coverage counters are what a clean claim is made of. They come
        # from the engine's own view of the attack - not from the request
        # total, which a login and a health check can satisfy on their own.
        coverage = engine.coverage()
        coverage.learning_operations = len(learned)
        coverage.budget_exhausted = accounting.budget_exhausted
        result.coverage = coverage
        result.ownership = engine.graph.report() if engine.graph is not None else {}
        result.ownership["inconclusive_checks"] = list(engine.inconclusive_checks)

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
    launch: LaunchSpec | None = None,
) -> dict[str, Any]:
    """Scan every variant of an application and judge the results.

    ``expected`` maps a variant to the laws it must produce. A variant that
    produces a law it should not produce fails the gate as well - that is how a
    "vulnerable" application that is vulnerable in more ways than intended is
    caught.
    """
    expected = expected or expected_variants(application)
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
                launch=launch,
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
    # The laws that are about ownership must say whose object it was, and the
    # owner must not be the attacker: an ownership finding against the owner's
    # own object is not a breach, it is a detector defect.
    if law in {"L2", "L3"}:
        owner = evidence.get("owner") or evidence.get("row_owner")
        if not owner:
            owner = (evidence.get("event") or {}).get("row_owner")
        if not owner:
            problems.append(f"{law} does not say who owns the affected object")
        elif owner == finding.get("principal"):
            problems.append(f"{law} blames the owner of the object")
    return problems
