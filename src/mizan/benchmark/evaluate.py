"""Run Mizan over the benchmark and measure what matters.

Two numbers decide whether the engine is useful:

* **detection rate** - of the planted bugs, how many does Mizan find?
* **false positives** - of the patched twins, how many findings does Mizan
  invent? A scanner that reports a clean application as broken gets ignored.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from mizan.benchmark.apps import BUGS, AppSpec, BenchmarkApp, serve
from mizan.benchmark.generator import BENCHMARK_NAME, Suite, build_suite
from mizan.engine import Mizan, Target
from mizan.core import Principal
from mizan.regression import Attack, attack_succeeds, build_attack

#: The OpenAPI document of the benchmark applications.
SPEC_PATH = Path(__file__).resolve().parents[1] / "demo" / "openapi.json"


@dataclass
class AppResult:
    """What Mizan found in one application."""

    name: str
    expected: tuple[str, ...]
    detected: tuple[str, ...]
    missing: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()
    findings: list[dict[str, Any]] = field(default_factory=list)
    #: The attacks behind the findings, ready to be replayed.
    attacks: list[dict[str, Any]] = field(default_factory=list)
    #: Attacks that still work against this application.
    attacks_reproduced: int = 0
    #: Attacks that a fixed application is expected to block.
    attacks_blocked: int = 0

    @property
    def ok(self) -> bool:
        return not self.missing and not self.unexpected

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "expected": list(self.expected),
            "detected": list(self.detected),
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "ok": self.ok,
            "attacks_reproduced": self.attacks_reproduced,
            "attacks_blocked": self.attacks_blocked,
            "findings": self.findings,
        }


@dataclass
class Report:
    """The result of a benchmark run."""

    applications: list[AppResult] = field(default_factory=list)
    #: The patched twin of every application: the same code with the bug fixed.
    twins: list[AppResult] = field(default_factory=list)
    #: Applications that never had a bug: they must stay completely silent.
    controls: list[AppResult] = field(default_factory=list)

    # -- metrics ------------------------------------------------------------ #

    @property
    def total_expected(self) -> int:
        return sum(len(result.expected) for result in self.applications)

    @property
    def total_detected(self) -> int:
        return sum(len(set(result.detected) & set(result.expected)) for result in self.applications)

    @property
    def detection_rate(self) -> float:
        total = self.total_expected
        return self.total_detected / total if total else 0.0

    @property
    def false_positives(self) -> int:
        return sum(len(result.detected) for result in self.twins) + sum(
            len(result.detected) for result in self.controls
        )

    @property
    def control_count(self) -> int:
        return len(self.controls)

    @property
    def unexpected_in_buggy_apps(self) -> int:
        return sum(len(result.unexpected) for result in self.applications)

    @property
    def attacks_total(self) -> int:
        return sum(len(result.attacks) for result in self.applications)

    @property
    def attacks_reproduced(self) -> int:
        """Attacks that still worked on the vulnerable application."""
        return sum(result.attacks_reproduced for result in self.applications)

    @property
    def attacks_blocked(self) -> int:
        """Attacks that the patched twin rejected."""
        return sum(result.attacks_blocked for result in self.twins)

    @property
    def regression_validity(self) -> float:
        """How many generated regression tests are trustworthy.

        A test is trustworthy when it fails on the vulnerable application and
        passes on the patched one.
        """
        total = self.attacks_total
        if not total:
            return 0.0
        return min(self.attacks_reproduced, self.attacks_blocked) / total

    def by_law(self) -> dict[str, dict[str, int]]:
        table: dict[str, dict[str, int]] = {}
        for result in self.applications:
            for law in result.expected:
                entry = table.setdefault(law, {"expected": 0, "detected": 0})
                entry["expected"] += 1
                if law in result.detected:
                    entry["detected"] += 1
        return dict(sorted(table.items()))

    # -- output ------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": BENCHMARK_NAME,
            "metrics": {
                "detection_rate": round(self.detection_rate, 4),
                "expected": self.total_expected,
                "detected": self.total_detected,
                "false_positives_on_patched_apps": self.false_positives,
                "controls": self.control_count,
                "unexpected_findings_on_buggy_apps": self.unexpected_in_buggy_apps,
                "attacks_total": self.attacks_total,
                "attacks_reproduced": self.attacks_reproduced,
                "attacks_blocked_after_fix": self.attacks_blocked,
                "regression_test_validity": round(self.regression_validity, 4),
            },
            "by_law": self.by_law(),
            "applications": [result.to_dict() for result in self.applications],
            "twins": [result.to_dict() for result in self.twins],
            "controls": [result.to_dict() for result in self.controls],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# {BENCHMARK_NAME} - results",
            "",
            "| metric | value |",
            "|---|---|",
            f"| detection rate | **{self.detection_rate:.0%}** ({self.total_detected}/{self.total_expected}) |",
            f"| false positives on patched apps | **{self.false_positives}** / {self.control_count} apps |",
            f"| unexpected findings on buggy apps | {self.unexpected_in_buggy_apps} |",
            f"| regression tests valid | **{self.regression_validity:.0%}** "
            f"({self.attacks_reproduced} reproduce, {self.attacks_blocked} blocked after the fix) |",
            "",
            "| law | expected | detected |",
            "|---|---|---|",
        ]
        for law, entry in self.by_law().items():
            lines.append(f"| {law} {BUGS_BY_LAW.get(law, '')} | {entry['expected']} | {entry['detected']} |")
        lines.append("")
        lines.append("## Applications")
        lines.append("")
        lines.append("| application | expected | detected | missing | unexpected |")
        lines.append("|---|---|---|---|---|")
        for result in self.applications:
            lines.append(
                f"| {result.name} | {','.join(result.expected) or '-'} | {','.join(result.detected) or '-'} | "
                f"{','.join(result.missing) or '-'} | {','.join(result.unexpected) or '-'} |"
            )
        return "\n".join(lines)

    def write(self, directory: str | Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "report.json").write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        (directory / "report.md").write_text(self.to_markdown(), encoding="utf-8")
        return directory / "report.json"


BUGS_BY_LAW = {bug.law: f"({kind})" for kind, bug in BUGS.items()}


# --------------------------------------------------------------------------- #
# Running one application
# --------------------------------------------------------------------------- #


def generate_traffic(base_url: str, tokens: dict[str, str], users: tuple[str, ...], orders: int = 6) -> None:
    """Produce the traffic of a normal, healthy application."""
    sessions = {}
    for user in users:
        session = requests.Session()
        session.headers["Authorization"] = f"Bearer {tokens[user]}"
        sessions[user] = session

    # Every user identifies itself.
    for user in users:
        sessions[user].get(f"{base_url}/me")

    # Every user walks through the orders they own.
    for index in range(orders):
        user = users[index % len(users)]
        order = f"ord{index}"
        sessions[user].get(f"{base_url}/orders/{order}")

    # Each user updates and approves one of their own orders. The rest stay
    # pending, so a race probe still has something to race on.
    for position, user in enumerate(users):
        order = f"ord{position}"
        sessions[user].put(f"{base_url}/orders/{order}", json={"status": "paid"})
        sessions[user].patch(f"{base_url}/users/me", json={"name": f"{user.title()} Updated"})
        sessions[user].post(f"{base_url}/orders/{order}/approve")


def run_application(
    spec: AppSpec,
    workspace: Path,
    *,
    patched: bool = False,
    attacks: list[Any] | None = None,
) -> AppResult:
    """Run Mizan against one application and return what it found.

    ``attacks`` replays known attacks against the application. That is how the
    benchmark checks that a *fixed* application really blocks them.
    """
    db_path = workspace / f"{spec.name}{'-patched' if patched else ''}.sqlite"
    traffic_path = workspace / f"{spec.name}{'-patched' if patched else ''}-traffic.jsonl"
    ledger_path = workspace / f"{spec.name}{'-patched' if patched else ''}-ledger.jsonl"
    for path in (traffic_path, ledger_path):
        path.unlink(missing_ok=True)

    app = BenchmarkApp(
        db_path,
        bugs=() if patched else spec.bugs,
        users=spec.users,
        orders=spec.orders,
        traffic_path=traffic_path,
        ledger_path=ledger_path,
    )
    server, port, _thread = serve(app)
    base_url = f"http://127.0.0.1:{port}"
    reproduced = 0
    blocked = 0
    built_attacks: list[Attack] = []
    try:
        tokens = app.tokens()
        generate_traffic(base_url, tokens, spec.users, spec.orders)
        principals = [
            Principal(id=user, roles=("user",), token=tokens[user]) for user in spec.users
        ] + [Principal(id="admin", roles=("admin",), token=tokens["admin"])]
        engine = Mizan(
            Target(base_url=base_url, principals=principals),
            traffic_path=traffic_path,
            ledger_path=ledger_path,
            spec_path=SPEC_PATH,
        )
        engine.learn()
        violations = engine.attack()

        if attacks:
            # The fixed application must block every attack.
            for attack in attacks:
                token = tokens.get(attack.principal or "", "")
                if not token:
                    continue
                if attack_succeeds(attack, token, base_url):
                    reproduced += 1
                else:
                    blocked += 1
        else:
            # On the vulnerable application every finding must reproduce.
            for violation in violations:
                attack = build_attack(violation)
                if attack is None:
                    continue
                built_attacks.append(attack)
    finally:
        server.shutdown()

    detected = tuple(sorted({violation.law for violation in violations}))
    expected = () if patched else spec.expected_laws
    return AppResult(
        name=spec.name if not patched else f"{spec.name}-patched",
        expected=tuple(sorted(expected)),
        detected=detected,
        missing=tuple(sorted(set(expected) - set(detected))),
        unexpected=tuple(sorted(set(detected) - set(expected))),
        findings=[violation.to_dict() for violation in violations],
        attacks=[attack.to_dict() for attack in built_attacks],
        attacks_reproduced=reproduced,
        attacks_blocked=blocked,
    )


# --------------------------------------------------------------------------- #
# The whole benchmark
# --------------------------------------------------------------------------- #


def replay_attacks(
    spec: AppSpec,
    attacks: list[Attack],
    *,
    patched: bool,
    workspace: Path,
) -> tuple[int, int]:
    """Replay attacks against a *fresh* application.

    A fresh instance matters: an attack that was already triggered once would
    otherwise be blocked by the state it left behind, and the measurement would
    be about the leftover state instead of about the vulnerability.
    """
    if not attacks:
        return (0, 0)
    suffix = "replay-patched" if patched else "replay"
    db_path = workspace / f"{spec.name}-{suffix}.sqlite"
    db_path.unlink(missing_ok=True)
    app = BenchmarkApp(
        db_path,
        bugs=() if patched else spec.bugs,
        users=spec.users,
        orders=spec.orders,
    )
    server, port, _thread = serve(app)
    base_url = f"http://127.0.0.1:{port}"
    tokens = app.tokens()
    reproduced = 0
    blocked = 0
    try:
        for attack in attacks:
            token = tokens.get(attack.principal or "", "")
            if not token:
                continue
            if attack_succeeds(attack, token, base_url):
                reproduced += 1
            else:
                blocked += 1
    finally:
        server.shutdown()
    return (reproduced, blocked)


def run_suite(
    suite: Suite | None = None,
    *,
    limit: int | None = None,
    workspace: str | Path | None = None,
) -> Report:
    """Run the whole benchmark: the applications, their patched twins and the controls."""
    suite = suite or build_suite()
    root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="authzbugs-"))
    root.mkdir(parents=True, exist_ok=True)
    report = Report()
    applications = suite.applications[:limit] if limit else suite.applications
    for spec in applications:
        vulnerable = run_application(spec, root)
        attacks = [Attack(**data) for data in vulnerable.attacks]
        vulnerable.attacks_reproduced, _ = replay_attacks(spec, attacks, patched=False, workspace=root)
        report.applications.append(vulnerable)

        twin = run_application(spec, root, patched=True)
        _, twin.attacks_blocked = replay_attacks(spec, attacks, patched=True, workspace=root)
        report.twins.append(twin)

    controls = suite.controls[: max(1, (limit // 10))] if limit else suite.controls
    for spec in controls:
        report.controls.append(run_application(spec, root, patched=True))
    if workspace is None:
        shutil.rmtree(root, ignore_errors=True)
    return report


def main() -> None:  # pragma: no cover - CLI helper
    import argparse

    parser = argparse.ArgumentParser(description="Run the AuthzBugs benchmark")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--out", default="authzbugs-report")
    arguments = parser.parse_args()
    report = run_suite(limit=arguments.limit)
    report.write(arguments.out)
    print(report.to_markdown())


if __name__ == "__main__":  # pragma: no cover
    main()
