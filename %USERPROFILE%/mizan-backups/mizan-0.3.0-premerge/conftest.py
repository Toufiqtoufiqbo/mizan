"""Make the repository root importable.

The benchmark harness lives in `benchmarks/` next to the package rather than
inside it, so a test that imports it needs the repository root on the path.
`python -m pytest` already puts it there; this makes `pytest` behave the same.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
