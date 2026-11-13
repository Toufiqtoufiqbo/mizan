"""The cross-framework benchmark itself.

It runs the same scenarios against two independently implemented applications
and measures what Mīzān found. The numbers are produced by the benchmark and
checked by `check.py`, which did not produce them.

    python -m benchmarks.cross_framework.run --repetitions 3
    python -m benchmarks.cross_framework.check benchmarks/cross_framework/results/results.json
"""

from __future__ import annotations

import sys

from .runner import generate_credentials, run_scenario
from .scenarios import EXPECTED, FRAMEWORKS, VARIANTS

__all__ = ["EXPECTED", "FRAMEWORKS", "VARIANTS", "generate_credentials", "run_scenario"]


def main(argv: list[str] | None = None) -> int:
    from .run import main as run_main

    return run_main(argv)


if __name__ == "__main__":
    sys.exit(main())
