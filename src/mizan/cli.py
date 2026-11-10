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

SPEC_PATH = Path(__file__).parent / "demo" / "openapi.json"


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
def attack(
    target: str,
    traffic_path: str,
    ledger_path: str | None,
    spec_path: str | None,
    out_path: str,
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
    violations = engine.attack()
    directories = engine.write_bundles(violations, out_path)
    _print_report(engine, violations, directories)


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


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
        steps=[
            Step(**step) for step in payload.get("steps", [])
        ],
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
    if expect_fixed:
        _verify_fixed(bundle, target, token)
        return
    session = requests.Session()
    result = proof.verify(session)
    click.echo(json.dumps(result, indent=2, ensure_ascii=False, default=str))


def _verify_fixed(bundle: str, target: str, token: str | None) -> None:
    """Check that the attack behind a bundle no longer works."""
    import os
    from urllib.parse import urlsplit

    from mizan.regression import Attack, attack_succeeds

    payload = json.loads((Path(bundle) / "replay.json").read_text(encoding="utf-8"))
    steps = payload.get("steps") or []
    if not steps:
        click.echo("the bundle has no reproduction steps")
        raise SystemExit(2)
    step = steps[0]
    principal = payload.get("principal") or "attacker"
    token = token or os.environ.get(f"MIZAN_TOKEN_{principal.upper()}", "")
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
            Principal(id="alice", roles=("user",), token="tok-alice"),
            Principal(id="bob", roles=("user",), token="tok-bob"),
            Principal(id="root", roles=("admin",), token="tok-admin"),
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
    alice.headers["Authorization"] = "Bearer tok-alice"
    alice.get(f"{base_url}/me")
    alice.get(f"{base_url}/orders/o1")
    alice.post(f"{base_url}/orders/o1/approve")
    alice.put(f"{base_url}/orders/o1", json={"status": "paid"})
    alice.patch(f"{base_url}/users/me", json={"name": "Alice Updated"})

    bob = requests.Session()
    bob.headers["Authorization"] = "Bearer tok-bob"
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
