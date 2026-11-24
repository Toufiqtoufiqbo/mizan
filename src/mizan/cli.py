"""The ``mizan`` command line interface."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import click
import requests

from mizan.core import LAWS, Principal, Step
from mizan.engine import Mizan, Target
from mizan.proof import ProofBundle
from mizan.tokens import TokenResolver, make_token

SPEC_PATH = Path(__file__).parent / "demo" / "openapi.json"

#: The probes, in the order they run. The parallel mode splits them between the
#: isolated copies.
PROBE_GROUPS = ("L5", "L1", "L2", "L3", "L4", "T")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="mizan", prog_name="mizan")
def main() -> None:
    """Mizan - break the security laws of your API, and prove it."""


# --------------------------------------------------------------------------- #
# laws
# --------------------------------------------------------------------------- #


@main.command()
def laws() -> None:
    """List the security laws Mizan checks."""
    click.echo(f"{'ID':<5} {'SEVERITY':<9} NAME")
    for law in LAWS.values():
        click.echo(f"{law.id:<5} {law.severity:<9} {law.name}")
        click.echo(f"{'':<5} {'':<9} {law.description}")


# --------------------------------------------------------------------------- #
# learn
# --------------------------------------------------------------------------- #


@main.command()
@click.option("--traffic", "traffic_path", required=True, type=click.Path(exists=True), help="Traffic log (JSONL).")
@click.option("--ledger", "ledger_path", type=click.Path(exists=True), help="Write ledger (JSONL).")
@click.option("--target", default="http://127.0.0.1:8000", help="Base URL of the API.")
@click.option("--out", "out_path", default="mizan-policy.json", type=click.Path(), help="Where to write the policy.")
def learn(traffic_path: str, ledger_path: str | None, target: str, out_path: str) -> None:
    """Learn the application's security laws from observed traffic."""
    principals = _principals_from_traffic(traffic_path)
    engine = Mizan(
        Target(base_url=target, principals=principals),
        traffic_path=traffic_path,
        ledger_path=ledger_path,
    )
    policy = engine.learn()
    Path(out_path).write_text(json.dumps(policy.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    click.echo(f"Learned {len(policy.resources)} resources and {len(policy.rules)} rules -> {out_path}")
    for rule in policy.rules:
        click.echo(f"  {rule.kind:<9} {rule.action:<6} {rule.resource_type or '*'}")


# --------------------------------------------------------------------------- #
# attack
# --------------------------------------------------------------------------- #


@main.command()
@click.option("--target", default="http://127.0.0.1:8000", help="Base URL of the API.")
@click.option("--traffic", "traffic_path", required=True, type=click.Path(exists=True), help="Traffic log (JSONL).")
@click.option("--ledger", "ledger_path", type=click.Path(exists=True), help="Write ledger (JSONL).")
@click.option("--spec", "spec_path", type=click.Path(exists=True), help="OpenAPI document.")
@click.option("--out", "out_path", default="mizan-proofs", type=click.Path(), help="Directory for proof bundles.")
@click.option("--guided", is_flag=True, help="Search for the request sequence that breaks a law.")
@click.option("--budget", default=40, show_default=True, help="How many actions the guided search may try.")
def attack(
    target: str,
    traffic_path: str,
    ledger_path: str | None,
    spec_path: str | None,
    out_path: str,
    guided: bool,
    budget: int,
) -> None:
    """Attack the learned laws and write a proof bundle per finding."""
    principals = _principals_from_traffic(traffic_path)
    engine = Mizan(
        Target(base_url=target, principals=principals),
        traffic_path=traffic_path,
        ledger_path=ledger_path,
        spec_path=spec_path,
    )
    engine.learn()
    violations = _guided_attack(engine, budget) if guided else engine.attack()
    directories = engine.write_bundles(violations, out_path)
    _print_report(engine, violations, directories)


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


@main.command()
@click.option(
    "--backend",
    type=click.Choice(["sqlite", "postgres"]),
    default="sqlite",
    show_default=True,
    help="Evidence backend: sqlite (filesystem) or postgres (disposable Twin).",
)
@click.option(
    "--command", "command", required=True, help="How to start the application, e.g. 'python -m app --port {port}'."
)
@click.option(
    "--data", "data_paths", multiple=True, type=click.Path(), help="File or directory holding the state (repeatable)."
)
@click.option(
    "--spec",
    "spec_path",
    default=None,
    type=click.Path(exists=True),
    help="OpenAPI document (optional if the traffic log is already filled).",
)
@click.option(
    "--token", "tokens", multiple=True, help="Bearer token of an identity, in the form name=token (repeatable)."
)
@click.option(
    "--identity-map",
    "identity_map_path",
    default=None,
    type=click.Path(exists=True),
    help="JSON identity-map file for opaque tokens: environment-variable names, never tokens.",
)
@click.option(
    "--relationship-contract",
    "relationship_contract_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Trusted JSON declarations of identity endpoints, ownership columns and authorization grants.",
)
@click.option("--workdir", default=".", type=click.Path(), help="Where the application runs.")
@click.option("--out", "out_path", default="mizan-proofs", type=click.Path(), help="Directory for proof bundles.")
@click.option(
    "--traffic",
    "traffic_path",
    default=None,
    type=click.Path(),
    help="Traffic log to write (default: next to the proof bundles).",
)
@click.option("--workers", default=1, show_default=True, help="How many isolated copies to attack in parallel.")
@click.option(
    "--dsn-env",
    "dsn_env",
    default="MIZAN_DATABASE_URL",
    show_default=True,
    help="Environment variable holding the PostgreSQL DSN (postgres backend).",
)
@click.option(
    "--schema",
    "schemas",
    multiple=True,
    help="Schema allowlist (repeatable; required for the postgres backend).",
)
@click.option("--pool-size", default=2, show_default=True, help="Pool size for PostgreSQL workers.")
@click.option("--allow-disposable", is_flag=True, help="Authorize creation of disposable PostgreSQL databases.")
@click.option(
    "--guided",
    is_flag=True,
    help="Search for the request sequence that breaks a law, instead of running fixed probes.",
)
@click.option("--budget", default=40, show_default=True, help="How many actions the guided search may try.")
@click.option("--keep", is_flag=True, help="Keep the twin workspace.")
def twin(
    backend: str,
    command: str,
    data_paths: tuple[str, ...],
    spec_path: str,
    tokens: tuple[str, ...],
    identity_map_path: str | None,
    relationship_contract_path: str | None,
    workdir: str,
    out_path: str,
    traffic_path: str | None,
    workers: int,
    dsn_env: str,
    schemas: tuple[str, ...],
    pool_size: int,
    allow_disposable: bool,
    guided: bool,
    budget: int,
    keep: bool,
) -> None:
    """Run the whole thing against a local copy of an application.

    No Docker, no changes to the application: Mizan starts it, records the
    traffic through a proxy, learns the laws from the database itself, and
    attacks them - restoring the state between probes.

    With ``--backend postgres``, the same engine runs against an isolated,
    verified disposable PostgreSQL Twin instead of a filesystem copy.
    """
    if backend == "postgres":
        _run_postgres_cli(
            command=command,
            workdir=workdir,
            out_path=out_path,
            traffic_path=traffic_path,
            workers=workers,
            dsn_env=dsn_env,
            schemas=schemas,
            pool_size=pool_size,
            allow_disposable=allow_disposable,
            tokens=tokens,
            relationship_contract_path=relationship_contract_path,
            spec_path=spec_path,
            guided=guided,
            budget=budget,
        )
        return
    from mizan.attribution import SqliteAttributor
    from mizan.identity import IdentityMapError, load_identity_map, resolve_identity_map
    from mizan.learning import learn_from_spec
    from mizan.ownership import RelationshipContract, RelationshipContractError
    from mizan.proxy import RecordingProxy
    from mizan.twin import Twin, TwinSpec

    # Three states, kept distinct: no contract (None), a valid contract, and an
    # invalid contract, which is a configuration error - never a silent
    # downgrade to weaker semantics.
    try:
        contract = RelationshipContract.load(relationship_contract_path, strict=True)
    except RelationshipContractError as exc:
        click.echo(f"relationship contract error: {exc}", err=True)
        raise SystemExit(2) from None

    identities: list[Principal] = []
    token_values: list[str] = []
    for entry in tokens:
        name, _, token = entry.partition("=")
        identities.append(Principal(id=name, roles=("user",), token=token))
        token_values.append(token)

    # The identity map resolves opaque tokens: the file names environment
    # variables, the environment holds the tokens, and the proxy records who
    # each token belongs to. A missing or empty variable is a setup error.
    identity_map: dict[str, str] = {}
    if identity_map_path:
        if tokens:
            raise click.UsageError("use --token or --identity-map, not both")
        try:
            config = load_identity_map(identity_map_path)
            mapped_principals, identity_map = resolve_identity_map(config)
        except IdentityMapError as exc:
            click.echo(f"identity map error: {exc}", err=True)
            raise SystemExit(2) from None
        identities.extend(mapped_principals)
        token_values.extend(identity_map)

    workspace = Path(workdir) / ".mizan-twin"
    resolved_data = [Path(workdir) / path if not Path(path).is_absolute() else Path(path) for path in data_paths]
    spec = TwinSpec(
        command=_split_command(command),
        workdir=Path(workdir),
        data_paths=resolved_data,
        data_dir=Path(workdir),
        health_path="/",
    )
    log_path = Path(traffic_path) if traffic_path else Path(out_path).parent / "mizan-traffic.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if traffic_path is None:
        # A run starts with an empty traffic log.
        log_path.write_text("", encoding="utf-8")
    engine_instance = Twin(spec, workspace=workspace)
    try:
        engine_instance.start()
        click.echo(f"application started on {engine_instance.base_url}")
        # The pristine state is taken before anything runs, so every probe
        # starts from the same place - including the ones that need an object
        # in a state that only exists before the first request.
        engine_instance.snapshot()
        proxy = RecordingProxy(engine_instance.base_url, log_path, identity_map=identity_map or None)
        proxy.start()
        try:
            if spec_path:
                # /login is not exercised here even when the document lists
                # it: the learning phase already holds the identities, and
                # minting fresh tokens would write them into the traffic log.
                learn_from_spec(spec_path, proxy.base_url, tokens=token_values or None, exclude_paths=("/login",))
            recorded = len(list(log_path.read_text(encoding="utf-8").splitlines())) if log_path.exists() else 0
            click.echo(f"recorded {recorded} requests")
            if not recorded:
                click.echo("no traffic was recorded - use --spec, or browse the application through the proxy first")
                raise SystemExit(2)

            def build_engine(base_url: str, data: list[Path], worker_twin: Any = None) -> Mizan:
                attributor = None
                for path in data:
                    if str(path).lower().endswith((".sqlite", ".sqlite3", ".db")):
                        attributor = SqliteAttributor(path)
                        break
                return Mizan(
                    Target(base_url=base_url, principals=identities),
                    traffic_path=log_path,
                    spec_path=spec_path,
                    twin=worker_twin,
                    attributor=attributor,
                    relationship_contract=contract,
                )

            engine = build_engine(proxy.base_url, resolved_data)
            try:
                policy = engine.learn()
            except RelationshipContractError as exc:
                click.echo(f"relationship contract error: {exc}", err=True)
                raise SystemExit(2) from None
            click.echo(f"learned {len(policy.resources)} resources and {len(policy.rules)} rules")

            if guided:
                violations = _guided_attack(engine, budget)
            elif workers > 1:
                # The workers start from the pristine snapshot, not from the
                # state the learning phase left behind.
                pristine = engine_instance.snapshot_files() or resolved_data
                try:
                    violations = _attack_parallel(spec, workers, workspace, pristine, build_engine, out_path)
                except RelationshipContractError as exc:
                    click.echo(f"relationship contract error: {exc}", err=True)
                    raise SystemExit(2) from None
            else:
                violations = engine.attack()
            directories = engine.write_bundles(violations, out_path)
            _print_report(engine, violations, directories)
        finally:
            proxy.stop()
    finally:
        engine_instance.stop()
        if not keep:
            shutil.rmtree(workspace, ignore_errors=True)


def _attack_parallel(
    spec: Any,
    workers: int,
    workspace: Path,
    data_paths: list[Path],
    build_engine: Any,
    out_path: str,
) -> list[Any]:
    """Attack several isolated copies of the application at the same time.

    The same probes as the serial run - they are split between the copies, so
    the result does not depend on the number of workers.
    """
    from mizan.parallel import run_parallel

    findings, executed = run_parallel(
        spec,
        workers=workers,
        workspace=workspace.parent / f"{workspace.name}-pool",
        data_paths=data_paths,
        build_engine=build_engine,
        groups=PROBE_GROUPS,
    )
    click.echo(f"attacked with {workers} isolated copies: {', '.join(executed)}")
    return findings


def postgres_backend_status(engine: Any, violations: list[Any], workers: int) -> dict[str, Any]:
    """Derive the backend status from real engine execution records.

    Kept as a pure function so the reporting contract can be tested without a
    live PostgreSQL cluster. No law name is hardcoded here.
    """
    coverage = engine.coverage()
    law_details = coverage.to_dict()["laws"]
    return {
        "backend": "postgres",
        "laws_executed": coverage.executed_laws,
        "laws_by_status": {law: details["state"] for law, details in law_details.items()},
        "laws_unsupported": sorted(law for law, details in law_details.items() if details["state"] == "unsupported"),
        "laws_skipped": sorted(law for law, details in law_details.items() if details["state"] == "skipped"),
        "l7_categories": coverage.to_dict().get("l7_categories", {}),
        "probe_candidates": engine.probe_candidates,
        "probes_executed": engine.probes_executed,
        "requests": engine.requests,
        "attributed_writes": len(engine._attributed_events),
        "confirmed_findings": len(violations),
        "inconclusive": len(engine.inconclusive_checks),
        "workers": workers,
    }


def _run_postgres_cli(
    *,
    command: str,
    workdir: str,
    out_path: str,
    traffic_path: str | None,
    workers: int,
    dsn_env: str,
    schemas: tuple[str, ...],
    pool_size: int,
    allow_disposable: bool,
    tokens: tuple[str, ...],
    relationship_contract_path: str | None,
    spec_path: str | None,
    guided: bool,
    budget: int,
) -> None:
    """Generic engine run against the PostgreSQL disposable Twin."""
    from mizan.ownership import RelationshipContract
    from mizan.postgres_engine import PostgresRun, dedupe_findings, findings_equivalent, normalize_finding
    from mizan.postgres_twin import DatabaseRegistry, PostgresSource

    if not allow_disposable:
        raise click.UsageError("pass --allow-disposable to authorize disposable PostgreSQL databases")
    if workers < 1:
        raise click.UsageError("at least one worker is required")
    if not schemas:
        raise click.UsageError("the postgres backend requires --schema (repeatable)")

    contract = (
        RelationshipContract.load(relationship_contract_path, strict=True) if relationship_contract_path else None
    )
    token_map: dict[str, str] = {}
    for entry in tokens:
        name, _, token = entry.partition("=")
        token_map[name] = token

    workspace = Path(workdir) / ".mizan-postgres"
    workspace.mkdir(parents=True, exist_ok=True)
    traffic = Path(traffic_path) if traffic_path else Path(out_path).parent / "mizan-postgres-traffic.jsonl"
    traffic.parent.mkdir(parents=True, exist_ok=True)
    if not traffic_path:
        traffic.write_text("", encoding="utf-8")

    source = PostgresSource(dsn_env, schemas=schemas)
    baseline = source.prepare_baseline(workspace)
    registry = DatabaseRegistry(workspace / "ownership.json")
    run = PostgresRun(
        source,
        baseline,
        registry,
        workspace,
        _split_command(command),
        tokens=token_map,
        relationship_contract=contract,
        traffic_path=traffic,
        pool_size=pool_size,
    )
    try:
        twin = run.start_worker("w0")
        if spec_path:
            from mizan.learning import learn_from_spec
            from mizan.proxy import RecordingProxy

            # Every --token entry is an explicit name -> token declaration. The
            # proxy needs the reverse map to attribute recorded traffic; without
            # it the engine learns zero resources and cannot prove anything.
            proxy = RecordingProxy(
                twin.base_url, traffic, identity_map={token: name for name, token in token_map.items()}
            )
            proxy.start()
            try:
                learn_from_spec(
                    spec_path,
                    proxy.base_url,
                    # identities maps a principal name to a *token value*; the
                    # learner must send the token itself, never "name=token".
                    identities=token_map,
                    exclude_paths=("/login",),
                )
            finally:
                proxy.stop()
        engine = run.build_engine(twin, Path(out_path))
        policy = engine.learn()
        click.echo(f"learned {len(policy.resources)} resources and {len(policy.rules)} rules")
        if guided:
            click.echo("guided attack is not supported for the postgres backend")
            raise SystemExit(2)
        serial = engine.attack()
        click.echo(f"serial run on worker w0: {len(serial)} finding(s)")
        violations = serial
        if workers > 1:
            parallel_by_worker = run.parallel_attack(workers)
            parallel = dedupe_findings([v for _, vs in parallel_by_worker for v in vs])
            click.echo(f"parallel run on {workers} worker(s): {len(parallel)} finding(s)")
            click.echo("serial: " + json.dumps([normalize_finding(v) for v in serial], sort_keys=True))
            click.echo("parallel: " + json.dumps([normalize_finding(v) for v in parallel], sort_keys=True))
            equivalence = findings_equivalent(serial, parallel)
            click.echo(f"serial/parallel normalized finding equivalence: {equivalence}")
            if not equivalence:
                raise SystemExit(2)
        directories = engine.write_bundles(violations, out_path)
        _print_report(engine, violations, directories)
        status = postgres_backend_status(engine, violations, workers)
        click.echo("postgres backend status: " + json.dumps(status, sort_keys=True))
        source.assert_unchanged()
    finally:
        cleaned = run.cleanup()
        source.assert_unchanged()
        click.echo(f"cleanup: {len(cleaned)} database(s) removed")


@main.command()
@click.argument("bundles", type=click.Path(exists=True))
@click.option("--out", "out_path", required=True, type=click.Path(), help="The SARIF file to write.")
def export_sarif(bundles: str, out_path: str) -> None:
    """Export the proof bundles as SARIF 2.1.0."""
    from mizan.sarif import export_sarif as _export
    from mizan.sarif import validate_sarif

    result = _export(bundles, out_path)
    for warning in result.warnings:
        click.echo(f"  ! {warning}")
    problems = validate_sarif(result.document)
    if problems:
        for problem in problems:
            click.echo(f"  ! {problem}")
        raise SystemExit(1)
    click.echo(f"{result.results} finding(s) from {result.bundles} bundle(s) -> {out_path}")


@main.command()
@click.argument("bundles", type=click.Path(exists=True))
@click.option("--target", default="http://127.0.0.1:8000", help="Base URL of the API.")
@click.option("--token", "token", default=None, help="Bearer token of the attacker.")
def replay(bundles: str, target: str, token: str | None) -> None:
    """Replay a directory of proof bundles - the CI gate.

    Exits with a non-zero status when an attack still works, so a pull request
    that reintroduces a fixed vulnerability fails the build.
    """
    from mizan.core import Step, Violation
    from mizan.regression import attack_succeeds, build_attack

    resolver = TokenResolver.from_env()
    directories = sorted(path for path in Path(bundles).iterdir() if path.is_dir())
    if not directories:
        click.echo("no proof bundles found")
        return
    reproduced = 0
    unreachable = 0
    for directory in directories:
        payload = json.loads((directory / "replay.json").read_text(encoding="utf-8"))
        steps = payload.get("steps") or []
        if not steps:
            continue
        if payload.get("law") == "L7":
            from mizan.confidentiality import replay_l7

            still_works, reason = replay_l7(payload.get("evidence") or {}, target)
            if reason.startswith("missing_consumer_token") or reason.startswith("replay_failed"):
                click.echo(f"  ! L7 replay could not run: {reason}")
                unreachable += 1
                continue
            if still_works:
                reproduced += 1
                click.echo(f"  ✗ {payload['law']} {payload['title']} - STILL REPRODUCIBLE")
            else:
                click.echo(f"  ✓ {payload['law']} {payload['title']} - fixed")
            continue
        principal = payload.get("principal") or "attacker"
        bearer = token or resolver.token_for(principal)
        if not bearer:
            raise click.ClickException(
                f'no token for principal {principal!r}. Set MIZAN_TOKENS=\'{{"{principal}": "..."}}\' '
                f"or MIZAN_TOKEN_{principal.upper()}. The replay cannot be trusted without it."
            )
        violation = Violation(
            law=payload["law"],
            title=payload["title"],
            detail=payload.get("detail", ""),
            severity=payload.get("severity", "high"),
            principal=principal,
            resource=payload.get("resource"),
            action=payload.get("action"),
            evidence=payload.get("evidence") or {},
            steps=[Step(**item) for item in steps],
        )
        attack = build_attack(violation)
        if attack is None:
            continue
        try:
            still_works = attack_succeeds(attack, bearer, target)
        except Exception as exc:
            click.echo(f"  ! {payload['law']} {payload['title']} - target unreachable: {type(exc).__name__}")
            unreachable += 1
            continue
        if still_works:
            reproduced += 1
            click.echo(f"  ✗ {payload['law']} {payload['title']} - STILL REPRODUCIBLE")
        else:
            click.echo(f"  ✓ {payload['law']} {payload['title']} - fixed")
    if unreachable:
        raise SystemExit(2)
    if reproduced:
        raise SystemExit(1)
    click.echo(f"all {len(directories)} attacks are blocked")


def _guided_attack(engine: Mizan, budget: int) -> list[Any]:
    """Search for the request sequence that breaks a law."""
    from mizan.search import GuidedSearch

    search = GuidedSearch(engine, budget=budget)
    result = search.run()
    click.echo(f"guided search: {result.requests} requests, laws {sorted(result.laws) or 'none'}")
    return result.violations


def _split_command(command: str) -> list[str]:
    import shlex

    return shlex.split(command)


@main.command()
@click.option("--out", "out_path", default=None, type=click.Path(), help="Where to write the proof bundles.")
@click.option("--budget", default=60, show_default=True, help="How many requests a variant may send.")
def self_scan(out_path: str | None, budget: int) -> None:
    """Scan Mizan's own control plane with Mizan.

    The clean API must produce no finding, and a deliberately weakened twin
    must produce one - otherwise the check is not known to bite. The scan is
    fail-closed: a crash, an empty scan or a finding without evidence is a
    failure, not an empty result.
    """
    from mizan.dogfood import run_self_check

    check = run_self_check(budget=budget)
    for variant in (check.clean, check.weakened):
        if variant is None:
            continue
        click.echo(f"{variant.variant}:")
        click.echo(f"  findings: {variant.finding_count}")
        click.echo(f"  law types: {variant.law_types}")
        click.echo(f"  requests: {variant.request_count}")
        if variant.error:
            click.echo(f"  error: {variant.error}")
        for finding in variant.findings:
            click.echo(f"    - {finding['law']} {finding['title']}")
            click.echo(
                f"      principal={finding.get('principal')} resource={finding.get('resource')} "
                f"severity={finding.get('severity')}"
            )
            if out_path:
                bundles = _write_bundles(finding, out_path)
                click.echo(f"      bundle: {bundles}")
    click.echo("")
    for item in check.checks:
        click.echo(f"  [{'PASS' if item['passed'] else 'FAIL'}] {item['check']} - {item['detail']}")
    if not check.passed:
        click.echo("self-scan FAILED")
        raise SystemExit(1)
    click.echo("self-scan OK: the real API is clean, the weakened one is not")


def _write_bundles(finding: dict[str, Any], out_path: str) -> str:
    """Write a proof bundle for one finding."""
    from mizan.core import Step, Violation
    from mizan.proof import ProofBundle

    violation = Violation(
        law=finding["law"],
        title=finding["title"],
        detail=finding.get("detail", ""),
        severity=finding.get("severity", "high"),
        principal=finding.get("principal"),
        resource=finding.get("resource"),
        action=finding.get("action"),
        steps=[Step(**step) for step in finding.get("steps", [])],
    )
    directory = ProofBundle.create(out_path, violation, evidence=finding.get("evidence", {}))
    return str(directory)


@main.command()
@click.argument("application", type=click.Path(exists=True))
@click.option("--budget", default=60, show_default=True, help="How many requests a variant may send.")
def validate(application: str, budget: int) -> None:
    """Validate an application that does not depend on Mizan.

    The clean variant must produce no finding, and the vulnerable variant must
    produce the expected one. This is how Mizan is checked against code it did
    not write.
    """
    from mizan.validation import validate_application

    result = validate_application(application, budget=budget)
    for variant, data in result["variants"].items():
        click.echo(f"{variant}:")
        click.echo(f"  findings: {data['finding_count']}")
        click.echo(f"  law types: {data['law_types']}")
        click.echo(
            f"  requests: {data['requests']['total']} "
            f"(bootstrap {data['requests']['bootstrap']}, "
            f"learning {data['requests']['learning']}, "
            f"attack {data['requests']['attack']})"
        )
        if data["setup_error"]:
            click.echo(f"  setup error: {data['setup_error']}")
        if data["error"]:
            click.echo(f"  error: {data['error']}")
    click.echo("")
    for item in result["checks"]:
        click.echo(f"  [{'PASS' if item['passed'] else 'FAIL'}] {item['check']} - {item['detail']}")
    if not result["passed"]:
        click.echo("validation FAILED")
        raise SystemExit(1)
    click.echo("validation OK")


@main.command()
@click.option("--size", default=10, show_default=True, help="How many applications to compare.")
def compare(size: int) -> None:
    """Compare the fixed probes with the guided search."""
    from mizan.benchmark.evaluate import compare_modes

    result = compare_modes(size)
    click.echo(f"{result['applications']} applications")
    click.echo("")
    click.echo("| mode | average requests | breaches found |")
    click.echo("|---|---|---|")
    for mode in ("probes", "guided"):
        data = result[mode]
        click.echo(f"| {mode} | {data['average_requests']} | {data['detected']} |")
    click.echo("")
    for row in result["rows"]:
        click.echo(
            f"  {row['application']}: expected {','.join(row['expected'])} | "
            f"probes {','.join(row['probes']['laws']) or '-'} ({row['probes']['requests']}) | "
            f"guided {','.join(row['guided']['laws']) or '-'} ({row['guided']['requests']})"
        )


@main.command()
@click.option("--size", default=50, show_default=True, help="Number of labelled applications.")
@click.option("--controls", default=5, show_default=True, help="Number of patched control applications.")
@click.option("--limit", default=None, type=int, help="Run only the first N applications (for a quick check).")
@click.option("--out", "out_path", default="authzbugs-report", type=click.Path(), help="Where to write the report.")
def benchmark(size: int, controls: int, limit: int | None, out_path: str) -> None:
    """Run the AuthzBugs benchmark and report detection rate and false positives."""
    from mizan.benchmark import build_suite, describe, run_suite

    suite = build_suite(size, controls=controls)
    click.echo(describe(suite))
    click.echo("")
    report = run_suite(suite, limit=limit)
    report.write(out_path)
    click.echo(
        f"Detection rate: {report.detection_rate:.0%} "
        f"({report.total_detected}/{report.total_expected}) | "
        f"false positives on patched apps: {report.false_positives}/{report.control_count}"
    )
    click.echo(f"Report written to {out_path}")


@main.command()
@click.argument("bundle", type=click.Path(exists=True))
@click.option("--out", "out_path", default="tests", type=click.Path(), help="Where to write the test.")
def regress(bundle: str, out_path: str) -> None:
    """Turn a proof bundle into a regression test."""
    import json as json_module

    from mizan.core import Violation
    from mizan.regression import render_test

    payload = json_module.loads((Path(bundle) / "replay.json").read_text(encoding="utf-8"))
    violation = Violation(
        law=payload["law"],
        title=payload["title"],
        detail=payload.get("detail", ""),
        severity=payload.get("severity", "high"),
        principal=payload.get("principal"),
        resource=payload.get("resource"),
        action=payload.get("action"),
        evidence=payload.get("evidence") or {},
        steps=[Step(**step) for step in payload.get("steps", [])],
    )
    directory = Path(out_path)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"test_mizan_{violation.law.lower()}.py"
    target.write_text(render_test(violation), encoding="utf-8")
    click.echo(f"Regression test written to {target}")
    click.echo("Run it with:")
    click.echo(f"  MIZAN_TARGET=https://your-target MIZAN_TOKEN_{violation.principal.upper()}=... pytest {target}")


@main.command()
@click.argument("bundle", type=click.Path(exists=True))
@click.option("--target", default="http://127.0.0.1:8000", help="Base URL of the API.")
@click.option("--token", "token", default=None, help="Bearer token of the attacker.")
@click.option("--expect-fixed", is_flag=True, help="Fail unless the attack is now rejected.")
def verify(bundle: str, target: str, token: str | None, expect_fixed: bool) -> None:
    """Replay a proof bundle against a live target."""
    proof = ProofBundle.load(bundle)
    resolver = TokenResolver.from_env()
    if expect_fixed:
        _verify_fixed(bundle, target, token, resolver)
        return
    session = requests.Session()
    result = proof.verify(session, resolver=resolver)
    click.echo(json.dumps(result, indent=2, ensure_ascii=False, default=str))


def _verify_fixed(bundle: str, target: str, token: str | None, resolver: TokenResolver) -> None:
    """Check that the attack behind a bundle no longer works."""
    from mizan.core import Step, Violation
    from mizan.regression import attack_succeeds, build_attack

    payload = json.loads((Path(bundle) / "replay.json").read_text(encoding="utf-8"))
    steps = payload.get("steps") or []
    if not steps:
        click.echo("the bundle has no reproduction steps")
        raise SystemExit(2)
    principal = payload.get("principal") or "attacker"
    token = token or resolver.token_for(principal) or ""
    violation = Violation(
        law=payload["law"],
        title=payload["title"],
        detail=payload.get("detail", ""),
        severity=payload.get("severity", "high"),
        principal=principal,
        resource=payload.get("resource"),
        action=payload.get("action"),
        evidence=payload.get("evidence") or {},
        steps=[Step(**item) for item in steps],
    )
    attack = build_attack(violation)
    if attack is None:
        raise SystemExit(2)
    if not token:
        click.echo(f"no token given: set --token or MIZAN_TOKEN_{principal.upper()}")
        raise SystemExit(2)
    if attack_succeeds(attack, token, target):
        click.echo(f"STILL VULNERABLE - {payload['law']} {payload['title']}")
        raise SystemExit(1)
    click.echo(f"fix confirmed - {payload['law']} {payload['title']} is no longer reproducible")


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #


@main.command()
@click.option("--out", "out_path", default="mizan-proofs", type=click.Path(), help="Directory for proof bundles.")
@click.option("--keep", is_flag=True, help="Keep the temporary workspace.")
def demo(out_path: str, keep: bool) -> None:
    """Run Mizan against the bundled vulnerable application."""
    from mizan.demo.app import DemoApp, serve

    workspace = Path(tempfile.mkdtemp(prefix="mizan-demo-"))
    db_path = workspace / "demo.sqlite"
    traffic_path = workspace / "traffic.jsonl"
    ledger_path = workspace / "ledger.jsonl"

    app = DemoApp(db_path, ledger_path=ledger_path, traffic_path=traffic_path)
    server, port, _thread = serve(app)
    base_url = f"http://127.0.0.1:{port}"
    click.echo(f"Demo API listening on {base_url}")

    try:
        _generate_normal_traffic(base_url)
        principals = [
            Principal(id="alice", roles=("user",), token=make_token("alice")),
            Principal(id="bob", roles=("user",), token=make_token("bob")),
            Principal(id="root", roles=("admin",), token=make_token("root", "admin")),
        ]
        engine = Mizan(
            Target(base_url=base_url, principals=principals),
            traffic_path=traffic_path,
            ledger_path=ledger_path,
            spec_path=SPEC_PATH,
        )
        policy = engine.learn()
        click.echo(
            f"Learned {len(policy.resources)} resources, {len(policy.rules)} rules "
            f"from {len(engine.traffic)} traffic records and {len(engine.ledger.events)} writes"
        )
        violations = engine.attack()
        directories = engine.write_bundles(violations, out_path)
        _print_report(engine, violations, directories)
    finally:
        server.shutdown()
        if keep:
            click.echo(f"Workspace kept at {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _principals_from_traffic(traffic_path: str) -> list[Principal]:
    from mizan.traffic import TrafficLog

    log = TrafficLog.load(traffic_path)
    principals: dict[str, Principal] = {}
    for record in log:
        if record.principal and record.principal not in principals:
            principals[record.principal] = Principal(id=record.principal)
    return list(principals.values())


def _generate_normal_traffic(base_url: str) -> None:
    """Produce the kind of traffic a real application sees in normal use."""
    alice = requests.Session()
    alice.headers["Authorization"] = f"Bearer {make_token('alice')}"
    alice.get(f"{base_url}/me")
    alice.get(f"{base_url}/orders/o1")
    alice.post(f"{base_url}/orders/o1/approve")
    alice.put(f"{base_url}/orders/o1", json={"status": "paid"})
    alice.patch(f"{base_url}/users/me", json={"name": "Alice Updated"})

    bob = requests.Session()
    bob.headers["Authorization"] = f"Bearer {make_token('bob')}"
    bob.get(f"{base_url}/me")
    bob.get(f"{base_url}/orders/o2")


def _print_report(engine: Mizan, violations: list[Any], directories: list[Path]) -> None:
    click.echo("")
    click.echo(f"Found {len(violations)} proven violation(s):")
    for violation, directory in zip(violations, directories):
        click.echo(f"  [{violation.severity:<8}] {violation.law} {violation.title}")
        click.echo(f"             {directory}")
    report = engine.report()
    click.echo("")
    click.echo(
        f"Access matrix: {report['observed_cells']} observed cells, "
        f"{report['residual_cells']} outside the permitted space, "
        f"residual norm {report['residual_norm']}"
    )


@main.command("postgres-evidence")
@click.option(
    "--dsn-env",
    default="MIZAN_DATABASE_URL",
    show_default=True,
    help="Name of the environment variable holding the DSN.",
)
@click.option("--schema", "schemas", multiple=True, required=True, help="Schema to inspect (repeatable allowlist).")
@click.option(
    "--audit-schema", default=None, help="Schema holding the audit table (default: first allowlisted schema)."
)
@click.option("--install-audit", is_flag=True, help="Explicit opt-in: create audit table, function and triggers.")
@click.option("--relationship-contract", "contract_path", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_path", default=None, type=click.Path())
def postgres_evidence(
    dsn_env: str,
    schemas: tuple[str, ...],
    audit_schema: str | None,
    install_audit: bool,
    contract_path: str | None,
    out_path: str | None,
) -> None:
    """Build ownership evidence from a PostgreSQL database (read-only).

    This command does NOT attack the database. PostgreSQL attack/twin mode
    fails closed because filesystem snapshots cannot restore a live database.
    """
    import os

    from mizan.attribution import AttributionUnavailable
    from mizan.ownership import RelationshipContract, RelationshipContractError, build_ownership_graph
    from mizan.postgres_attribution import PostgresAttributor

    dsn = os.environ.get(dsn_env)
    if not dsn:
        raise click.ClickException(f"environment variable {dsn_env} is not set")
    allowlist = tuple(dict.fromkeys(schemas))
    audit = audit_schema or allowlist[0]
    from mizan.postgres_twin import TwinLifecycleError, require_psycopg

    try:
        psycopg = require_psycopg()
    except TwinLifecycleError as exc:
        raise click.ClickException(str(exc)) from exc
    try:
        connection = psycopg.connect(dsn, connect_timeout=5)
    except Exception:
        # Never echo a DSN: passwords and hosts must not reach logs.
        raise click.ClickException("cannot connect to PostgreSQL (check the DSN environment variable)")
    try:
        provider = PostgresAttributor(connection, schemas=allowlist, audit_schema=audit)
        if install_audit:
            provider.auditor.install()
        try:
            declared = provider.schema()
        except AttributionUnavailable:
            raise click.ClickException(
                "the audit table is not installed; pass --install-audit explicitly to allow schema changes"
            )
        rows = {name: provider.rows(name) for name in declared.tables}
        contract = None
        if contract_path:
            try:
                contract = RelationshipContract.load(contract_path, strict=True)
            except RelationshipContractError as exc:
                raise click.ClickException(f"relationship contract error: {exc}")
            if contract is not None:
                try:
                    contract.validate_schema(declared)
                except RelationshipContractError as exc:
                    raise click.ClickException(f"relationship contract error: {exc}")
        graph = build_ownership_graph(
            resources={}, traffic=[], ledger=[], schema=declared, rows=rows, contract=contract
        )
        report = graph.report()
        report["schemas"] = list(allowlist)
        report["verdict"] = "INCONCLUSIVE"
        report["verdict_reason"] = "evidence only: no authorization probes were executed"
        report["attack_mode"] = "unsupported: PostgreSQL has no verified disposable-target restoration"
        rendered = json.dumps(report, indent=2, sort_keys=True)
        if out_path:
            Path(out_path).write_text(rendered + "\n", encoding="utf-8")
        click.echo(rendered)
    finally:
        connection.close()


@main.command("postgres-twin")
@click.option(
    "--dsn-env", default="MIZAN_DATABASE_URL", show_default=True, help="Environment variable holding the DSN."
)
@click.option("--schema", "schemas", multiple=True, required=True, help="Schema allowlist (repeatable).")
@click.option(
    "--fixture", default=None, type=click.Path(exists=True, file_okay=False), help="Independent fixture directory."
)
@click.option("--variant", default="clean", show_default=True)
@click.option(
    "--workers",
    default=2,
    show_default=True,
    help="Provision this many isolated worker databases; --exercise probes w0 only.",
)
@click.option("--pool-size", default=2, show_default=True, help="Connections each fixture worker keeps pooled.")
@click.option(
    "--allow-disposable", is_flag=True, help="Explicit authorization to create and drop disposable databases."
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Validate the DSN, tools, allowlist and fingerprint without creating any database.",
)
@click.option("--cleanup-run", default=None, help="Drop only databases owned by this run id.")
@click.option("--exercise", is_flag=True, help="Execute L2/L3 probes against worker w0.")
@click.option(
    "--workspace",
    default=None,
    type=click.Path(),
    help="Run workspace; mandatory with --cleanup-run, which never creates a new one.",
)
def postgres_twin(
    dsn_env: str,
    schemas: tuple[str, ...],
    fixture: str | None,
    variant: str,
    workers: int,
    pool_size: int,
    allow_disposable: bool,
    dry_run: bool,
    cleanup_run: str | None,
    exercise: bool,
    workspace: str | None,
) -> None:
    """Prepare and exercise a disposable PostgreSQL Twin lifecycle.

    The status is emitted only after cleanup has been verified. A cleanup
    failure exits non-zero and reports ``cleanup_failed``; the local records
    and the server-side ownership markers are preserved so ``--cleanup-run``
    can recover them.
    """
    import time

    from mizan.postgres_twin import (
        CancellationToken,
        CleanupPreflightError,
        DatabaseRegistry,
        OwnershipUnprovable,
        PartialCleanupError,
        PostgresSource,
        PostgresTwin,
        SourceProtectionError,
        TwinLifecycleError,
        redact,
    )
    from mizan.postgres_twin import (
        cleanup_run as drop_run,
    )

    def emit(payload: dict[str, Any], *, code: int = 0) -> None:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        if code:
            raise SystemExit(code)

    if cleanup_run and not workspace:
        emit(
            {
                "run_id": cleanup_run,
                "status": "OWNERSHIP_UNPROVABLE",
                "cleaned": [],
                "remaining": [],
                "reasons": ["--workspace is mandatory with --cleanup-run; no temporary workspace is created"],
                "category": "missing workspace",
                "error": "an explicit existing workspace is required for recovery",
            },
            code=2,
        )
        return
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="mizan-v62-"))
    if cleanup_run:
        if not root.is_dir():
            emit(
                {
                    "run_id": cleanup_run,
                    "status": "OWNERSHIP_UNPROVABLE",
                    "cleaned": [],
                    "remaining": [],
                    "reasons": ["the requested workspace does not exist"],
                    "category": "missing workspace",
                    "error": "the recovery workspace must already exist",
                },
                code=2,
            )
            return
        registry_file = root / "ownership.json"
        if registry_file.is_symlink():
            emit(
                {
                    "run_id": cleanup_run,
                    "status": "OWNERSHIP_UNPROVABLE",
                    "cleaned": [],
                    "remaining": [],
                    "reasons": ["the ownership registry must be a regular file, not a symlink"],
                    "category": "unsafe registry path",
                    "error": "a symlinked registry is never read during recovery",
                },
                code=2,
            )
            return
    else:
        root.mkdir(parents=True, exist_ok=True)
    registry = DatabaseRegistry(root / "ownership.json")

    if cleanup_run:
        try:
            cleaned = drop_run(dsn_env, root, cleanup_run)
        except OwnershipUnprovable as exc:
            emit(
                {
                    "run_id": cleanup_run,
                    "status": "OWNERSHIP_UNPROVABLE",
                    "cleaned": [],
                    "remaining": [],
                    "reasons": [exc.reason],
                    "category": "unprovable local ownership",
                    "orphan_candidates": exc.candidates,
                    "error": redact(str(exc)),
                },
                code=2,
            )
            return
        except CleanupPreflightError as exc:
            emit(
                {
                    "run_id": cleanup_run,
                    "status": "PREFLIGHT_FAILED",
                    "cleaned": [],
                    "remaining": sorted(exc.categories),
                    "category": "ownership preflight",
                    "categories": exc.categories,
                    "reasons": exc.reasons,
                    "error": redact(str(exc)),
                },
                code=2,
            )
            return
        except PartialCleanupError as exc:
            emit(
                {
                    "run_id": cleanup_run,
                    "status": "PARTIAL_CLEANUP",
                    "cleaned": exc.cleaned,
                    "remaining": exc.remaining,
                    "category": "operational failure during sequential deletion",
                    "reasons": exc.reasons,
                    "error": redact(str(exc)),
                },
                code=2,
            )
            return
        except Exception as exc:
            emit(
                {
                    "run_id": cleanup_run,
                    "status": "CLEANUP_FAILED",
                    "cleaned": [],
                    "remaining": [],
                    "category": "cleanup error",
                    "reasons": [redact(str(exc))],
                    "error": redact(str(exc)),
                },
                code=2,
            )
            return
        emit({"run_id": cleanup_run, "cleaned": cleaned, "remaining": [], "status": "CLEANED"})
        return

    if not allow_disposable:
        raise click.ClickException("pass --allow-disposable to authorize disposable database creation")
    if workers < 1:
        raise click.ClickException("at least one worker is required")

    fixture_dir = (
        Path(fixture)
        if fixture
        else Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "external_apps" / "postgres_store"
    )
    app = fixture_dir / "app.py"
    if not app.exists():
        raise click.ClickException("the fixture application was not found")
    command = [
        sys.executable,
        str(app),
        "--port",
        "{port}",
        "--vulnerability",
        variant,
    ]

    try:
        source = PostgresSource(dsn_env, schemas=tuple(schemas))
    except SourceProtectionError as exc:
        emit({"status": "FAILED", "error": redact(str(exc))}, code=2)
        return

    evidence: dict[str, Any] = {
        "run_id": source.run_id,
        "source_database": source.source_name(),
        "schemas": list(schemas),
        "workers": workers,
        "pool_size": pool_size,
        "dry_run": dry_run,
        "probe_worker": "w0" if exercise else None,
    }
    timings: dict[str, float] = {}
    started: list[PostgresTwin] = []
    baseline = None
    failure: str | None = None
    cleanup_errors: list[str] = []
    token = CancellationToken()

    try:
        token.install()
        if dry_run:
            before = time.monotonic()
            tools = source.preflight()
            timings["preflight_seconds"] = round(time.monotonic() - before, 3)
            evidence.update(
                {
                    # A dry run creates nothing, so there is no cleanup to
                    # verify; it must not use the word VERIFIED.
                    "status": "DRY_RUN_OK",
                    "baseline_fingerprint": tools["fingerprint"],
                    "tools": tools["tools"],
                    "timings": timings,
                }
            )
        else:
            begin = time.monotonic()
            baseline = source.prepare_baseline(root)
            timings["baseline_seconds"] = round(time.monotonic() - begin, 3)
            evidence["seed_database"] = baseline.name
            evidence["baseline_fingerprint"] = baseline.fingerprint

            for index in range(workers):
                begin = time.monotonic()
                twin = PostgresTwin(
                    source,
                    baseline,
                    registry,
                    f"w{index}",
                    command=command,
                    workdir=root,
                    variant=variant,
                    pool_size=pool_size,
                    env={"MIZAN_TOKEN_ALICE": "twin-alice", "MIZAN_TOKEN_BOB": "twin-bob"},
                )
                twin.start()
                timings[f"worker_{index}_start_seconds"] = round(time.monotonic() - begin, 3)
                started.append(twin)

            # Isolation proof: mutate worker 0 and verify worker 1 is unaffected.
            first = started[0]
            from psycopg import sql

            mutator = first.database.connect()
            with mutator.cursor() as cursor:
                cursor.execute(
                    "SELECT table_schema, table_name FROM information_schema.tables "
                    "WHERE table_schema = ANY(%s) AND table_type = 'BASE TABLE'",
                    (list(schemas),),
                )
                tables = cursor.fetchall()
            if tables:
                schema, table = tables[0]
                cursor_sql = sql.SQL("CREATE TABLE {}.{} (id TEXT PRIMARY KEY)").format(
                    sql.Identifier(schema), sql.Identifier("mizan_twin_proof")
                )
                with mutator.cursor() as cursor:
                    cursor.execute(cursor_sql)
                    cursor.execute(
                        sql.SQL("INSERT INTO {}.{} VALUES (%s)").format(
                            sql.Identifier(schema), sql.Identifier("mizan_twin_proof")
                        ),
                        ("proof",),
                    )
            fingerprints = {twin.worker_id: source.fingerprint(twin.database.dsn) for twin in started}
            if len(set(fingerprints.values())) != len(started):
                raise TwinLifecycleError("worker databases are not isolated")

            begin = time.monotonic()
            first.restore()
            timings["restore_seconds"] = round(time.monotonic() - begin, 3)
            source.assert_unchanged()
            evidence["source_unchanged"] = True
            if exercise:
                from mizan.postgres_twin import run_l2_l3_probes

                begin = time.monotonic()
                evidence["probe_results"] = run_l2_l3_probes(
                    first,
                    schemas=tuple(schemas),
                    tokens={"alice": "twin-alice", "bob": "twin-bob"},
                    contract_path=fixture_dir / "mizan-relationships.json",
                    cancel=token.check,
                )
                timings["probe_seconds"] = round(time.monotonic() - begin, 3)
                source.assert_unchanged()
            evidence.update(
                {
                    "status": "VERIFIED",
                    "worker_fingerprints_after_mutation": fingerprints,
                    "restored_fingerprint": source.fingerprint(first.database.dsn),
                    "timings": timings,
                }
            )
    except (SourceProtectionError, TwinLifecycleError) as exc:
        failure = source.redact(str(exc))
    except KeyboardInterrupt:
        failure = "the run was interrupted"
    finally:
        token.disarm()
        stop_failed = False
        for twin in reversed(started):
            try:
                twin.stop(strict=True)
            except Exception as exc:
                stop_failed = True
                cleanup_errors.append(source.redact(f"worker {twin.worker_id}: {exc}"))
        if not stop_failed:
            try:
                drop_run(dsn_env, root, source.run_id)
            except CleanupPreflightError as exc:
                evidence["cleanup_status"] = "PREFLIGHT_FAILED"
                cleanup_errors.append(source.redact("cleanup preflight: " + str(exc)))
            except PartialCleanupError as exc:
                evidence["cleanup_status"] = "PARTIAL_CLEANUP"
                evidence["cleanup_completed"] = exc.cleaned
                evidence["cleanup_remaining"] = exc.remaining
                cleanup_errors.append(source.redact("partial cleanup: " + str(exc)))
            except Exception as exc:
                cleanup_errors.append(source.redact(f"run cleanup: {exc}"))
        else:
            cleanup_errors.append("destructive cleanup was blocked because a worker did not stop")
        cleanup_errors.extend(source.rollback_errors)
        if cleanup_errors:
            for message in cleanup_errors:
                click.echo(f"cleanup error: {message}", err=True)

    if failure is not None or cleanup_errors:
        evidence["status"] = "cleanup_failed" if cleanup_errors else "FAILED"
        if failure is not None:
            evidence["error"] = failure
        if cleanup_errors:
            evidence["cleanup_errors"] = cleanup_errors
        emit(evidence, code=2)
        return
    emit(evidence)


if __name__ == "__main__":  # pragma: no cover
    main()
