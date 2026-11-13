"""The scenarios the cross-framework benchmark runs.

The two applications implement the same behavioral contract
(``tests/fixtures/external_apps/contract/CONTRACT.md``), so the same scenario
definitions apply to both. The benchmark never asks a framework-specific
question: it starts an application, attacks it with Mīzān, and checks whether
the expected laws were found.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mizan.validation import LAUNCH_EXPRESS, LAUNCH_FASTAPI, LaunchSpec

#: The root of the repository.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

#: The directory the fixtures live in.
FIXTURES = REPOSITORY_ROOT / "tests" / "fixtures" / "external_apps"


@dataclass(frozen=True)
class Framework:
    """One independently implemented application."""

    name: str
    directory: Path
    launch: LaunchSpec
    runtime: str
    """The runtime the application needs, for the report."""


#: The frameworks under test. Both are controlled fixtures, not deployments.
FRAMEWORKS: dict[str, Framework] = {
    "fastapi": Framework(
        name="fastapi",
        directory=FIXTURES / "fastapi_store",
        launch=LAUNCH_FASTAPI,
        runtime="python",
    ),
    "express": Framework(
        name="express",
        directory=FIXTURES / "express_store",
        launch=LAUNCH_EXPRESS,
        runtime="node",
    ),
}

#: The four independently controlled security variants.
VARIANTS = ("clean", "read", "write", "both")

#: The laws each variant must produce - and nothing else.
EXPECTED: dict[str, tuple[str, ...]] = {
    "clean": (),
    "read": ("L2",),
    "write": ("L3",),
    "both": ("L2", "L3"),
}

#: The principals a scenario uses. ``root`` is privileged and never attacked.
PRINCIPALS = ("alice", "bob", "root")

#: The environment variable each principal's password is read from.
CREDENTIAL_ENV = {
    "alice": "MIZAN_TEST_ALICE",
    "bob": "MIZAN_TEST_BOB",
    "root": "MIZAN_TEST_ROOT",
}
