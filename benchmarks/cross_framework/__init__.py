"""The Mīzān cross-framework validation benchmark.

Two independently implemented applications - FastAPI and Express - implement the
same behavioral contract. The benchmark runs the same scenarios against both,
measures what Mīzān found, and replays every finding.

    python -m benchmarks.cross_framework.run --repetitions 3
"""

from __future__ import annotations

__all__ = ["runner", "report", "scenarios"]
