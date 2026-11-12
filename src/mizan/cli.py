"""The ``mizan`` command line interface."""

from __future__ import annotations

import json
import shutil
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
    "--guided", is_flag=True, help="Search for the request sequence that breaks a law, instead of running fixed probes."
)
@click.option("--budget", default=40, show_default=True, help="How many actions the guided search may try.")
@click.option("--keep", is_flag=True, help="Keep the twin workspace.")
def twin(
    command: str,
    data_paths: tuple[str, ...],
    spec_path: str,
    tokens: tuple[str, ...],
    workdir: str,
    out_path: str,
    traffic_path: str | None,
    workers: int,
    guided: bool,
    budget: int,
    keep: bool,
) -> None:
    """Run the whole thing against a local copy of an application.

    No Docker, no changes to the application: Mizan starts it, records the
    traffic through a proxy, learns the laws from the database itself, and
    attacks them - restoring the state between probes.
    """
    from mizan.attribution import SqliteAttributor
    from mizan.learning import learn_from_spec
    from mizan.proxy import RecordingProxy
    from mizan.twin import Twin, TwinSpec

    identities: list[Principal] = []
    token_values: list[str] = []
    for entry in tokens:
        name, _, token = entry.partition("=")
        identities.append(Principal(id=name, roles=("user",), token=token))
        token_values.append(token)

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
        proxy = RecordingProxy(engine_instance.base_url, log_path)
        proxy.start()
        try:
            if spec_path:
                learn_from_spec(spec_path, proxy.base_url, tokens=token_values or None)
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
                )

            engine = build_engine(proxy.base_url, resolved_data)
            policy = engine.learn()
            click.echo(f"learned {len(policy.resources)} resources and {len(policy.rules)} rules")

            if guided:
                violations = _guided_attack(engine, budget)
            elif workers > 1:
                # The workers start from the pristine snapshot, not from the
                # state the learning phase left behind.
                pristine = engine_instance.snapshot_files() or resolved_data
                violations = _attack_parallel(spec, workers, workspace, pristine, build_engine, out_path)
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
    from urllib.parse import urlsplit

    from mizan.regression import Attack, attack_succeeds

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
        step = steps[0]
        principal = payload.get("principal") or "attacker"
        bearer = token or resolver.token_for(principal)
        if not bearer:
            raise click.ClickException(
                f'no token for principal {principal!r}. Set MIZAN_TOKENS=\'{{"{principal}": "..."}}\' '
                f"or MIZAN_TOKEN_{principal.upper()}. The replay cannot be trusted without it."
            )
        attack = Attack(
            law=payload["law"],
            title=payload["title"],
            method=step["method"],
            path=urlsplit(step["url"]).path or "/",
            token_var=f"MIZAN_TOKEN_{principal.upper()}",
            headers=step.get("headers") or {},
            body=step.get("body"),
            expectation="the request is rejected",
            principal=principal,
        )
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
        click.echo(f"  requests: {data['requests']['total']} "
                   f"(bootstrap {data['requests']['bootstrap']}, "
                   f"learning {data['requests']['learning']}, "
                   f"attack {data['requests']['attack']})")
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
    from urllib.parse import urlsplit

    from mizan.regression import Attack, attack_succeeds

    payload = json.loads((Path(bundle) / "replay.json").read_text(encoding="utf-8"))
    steps = payload.get("steps") or []
    if not steps:
        click.echo("the bundle has no reproduction steps")
        raise SystemExit(2)
    step = steps[0]
    principal = payload.get("principal") or "attacker"
    token = token or resolver.token_for(principal) or ""
    attack = Attack(
        law=payload["law"],
        title=payload["title"],
        method=step["method"],
        path=urlsplit(step["url"]).path or "/",
        token_var=f"MIZAN_TOKEN_{principal.upper()}",
        headers=step.get("headers") or {},
        body=step.get("body"),
        expectation="the request is rejected",
        principal=principal,
    )
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


if __name__ == "__main__":  # pragma: no cover
    main()
