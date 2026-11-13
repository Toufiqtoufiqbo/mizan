"""The cross-framework benchmark: Mīzān against two independent applications.

Run it from the repository root:

    python -m benchmarks.cross_framework.run --repetitions 3

It writes ``results.json`` and ``results.md`` into the output directory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import aggregate, environment_report, render_json, render_markdown
from .runner import DEFAULT_BUDGET, run_scenario
from .scenarios import FRAMEWORKS, VARIANTS

#: Where the results are written when no other directory is given.
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "results"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the Mizan cross-framework validation benchmark.",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=3,
        help="how many independent repetitions of the whole matrix to run (default: 3)",
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=DEFAULT_BUDGET,
        help=f"the request budget of one scenario (default: {DEFAULT_BUDGET})",
    )
    parser.add_argument(
        "--framework",
        action="append",
        choices=sorted(FRAMEWORKS),
        help="restrict the run to one framework (may be repeated)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"where to write results.json and results.md (default: {DEFAULT_OUTPUT})",
    )
    arguments = parser.parse_args(argv)

    if arguments.repetitions < 1:
        parser.error("--repetitions must be at least 1")

    frameworks = arguments.framework or sorted(FRAMEWORKS)
    scenarios = []
    for repetition in range(1, arguments.repetitions + 1):
        for name in frameworks:
            framework = FRAMEWORKS[name]
            for variant in VARIANTS:
                print(f"[{repetition}/{arguments.repetitions}] {name} / {variant} ...", flush=True)
                scenario = run_scenario(
                    framework,
                    variant,
                    repetition,
                    budget=arguments.budget,
                )
                scenarios.append(scenario)
                print(
                    "    outcome={outcome} observed={observed} requests={requests}".format(
                        outcome=scenario["outcome"],
                        observed=scenario["observed_findings"] or "none",
                        requests=scenario["requests"]["total"],
                    ),
                    flush=True,
                )

    results = {
        "benchmark": "cross_framework",
        "repetitions": arguments.repetitions,
        "budget": arguments.budget,
        "frameworks": frameworks,
        "variants": list(VARIANTS),
        "environment": environment_report(),
        "scenarios": scenarios,
        "totals": aggregate(scenarios),
    }

    output = arguments.output
    output.mkdir(parents=True, exist_ok=True)
    (output / "results.json").write_text(render_json(results), encoding="utf-8")
    (output / "results.md").write_text(render_markdown(results), encoding="utf-8")

    totals = results["totals"]
    print("")
    print(f"scenarios as expected : {totals['scenarios_expected']}/{totals['scenarios']}")
    print(f"true positives        : {totals['true_positives']}")
    print(f"false positives       : {totals['false_positives']}")
    print(f"false negatives       : {totals['false_negatives']}")
    print(f"reproductions         : {totals['reproduction_succeeded']}/{totals['reproduction_attempted']}")
    print(f"results               : {output / 'results.json'}")
    print(f"                       {output / 'results.md'}")

    return 0 if totals["scenarios_unexpected"] == 0 and totals["scenarios_error"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
