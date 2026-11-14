"""Make the repository root importable.

The benchmark harness lives in `benchmarks/` next to the package rather than
inside it, so a test that imports it needs the repository root on the path.
`python -m pytest` already puts it there; this makes `pytest` behave the same.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "src"
for directory in (SOURCE, ROOT):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

# A Twin starts a fresh interpreter from a temporary working directory. Propagate
# the source checkout so tests do not require an editable installation.
paths = os.environ.get("PYTHONPATH", "").split(os.pathsep)
for directory in (SOURCE, ROOT):
    if str(directory) not in paths:
        paths.insert(0, str(directory))
os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, paths))
