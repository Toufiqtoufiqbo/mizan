"""The AuthzBugs benchmark: 50 labelled authorization bugs plus controls.

Every application in the benchmark is the same skeleton with exactly one
vulnerability injected, and there is a patched twin of every application. The
twins are the measurement instrument: Mizan must be silent about them.
"""

from __future__ import annotations

from dataclasses import dataclass

from mizan.benchmark.apps import BUGS, AppSpec

#: The benchmark's identifier.
BENCHMARK_NAME = "AuthzBugs-50"


@dataclass(frozen=True)
class Suite:
    """The full benchmark: labelled applications plus clean controls."""

    applications: tuple[AppSpec, ...]
    controls: tuple[AppSpec, ...]

    @property
    def size(self) -> int:
        return len(self.applications)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": BENCHMARK_NAME,
            "applications": [spec.to_dict() for spec in self.applications],
            "controls": [spec.to_dict() for spec in self.controls],
        }


def build_suite(size: int = 50, controls: int = 5) -> Suite:
    """Build the benchmark deterministically.

    The bug kinds are rotated, so every kind appears the same number of times.
    """
    kinds = list(BUGS)
    applications: list[AppSpec] = []
    for index in range(size):
        kind = kinds[index % len(kinds)]
        applications.append(
            AppSpec(
                name=f"{BENCHMARK_NAME.lower()}-{index:02d}-{kind}",
                bugs=(kind,),
                users=("alice", "bob", "carol"),
                orders=6,
            )
        )
    control_specs = tuple(
        AppSpec(
            name=f"{BENCHMARK_NAME.lower()}-control-{index:02d}",
            bugs=(),
            users=("alice", "bob", "carol"),
            orders=6,
        )
        for index in range(controls)
    )
    return Suite(applications=tuple(applications), controls=control_specs)


def describe(suite: Suite) -> str:
    """A human-readable summary of the suite."""
    lines = [f"{BENCHMARK_NAME}: {suite.size} applications, {len(suite.controls)} controls"]
    for kind, bug in BUGS.items():
        count = sum(1 for spec in suite.applications if kind in spec.bugs)
        lines.append(f"  {bug.law}  {kind:<18} x{count:<3} {bug.title}")
    return "\n".join(lines)
