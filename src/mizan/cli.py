"""The ``mizan`` command line interface."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

import click
import requests

from mizan.core import LAWS, Principal
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
@click.argument("bundle", type=click.Path(exists=True))
@click.option("--target", default="http://127.0.0.1:8000", help="Base URL of the API.")
def verify(bundle: str, target: str) -> None:
    """Replay a proof bundle against a live target."""
    proof = ProofBundle.load(bundle)
    session = requests.Session()
    result = proof.verify(session)
    click.echo(json.dumps(result, indent=2, ensure_ascii=False, default=str))


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
