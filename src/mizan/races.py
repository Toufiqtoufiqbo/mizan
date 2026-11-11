"""Concurrency harness: make TOCTOU bugs reproducible instead of accidental.

Two identical requests are released at the same instant through a barrier. If
both of them mutate the same row, the application performed a non-atomic
check-then-act and the race is now a deterministic artifact.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from mizan.core import SINGLE_USE_HINTS, Violation


@dataclass
class RaceOutcome:
    """What happened when two identical actions ran concurrently."""

    url: str
    method: str
    statuses: list[int | None] = field(default_factory=list)
    bodies: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def successes(self) -> int:
        return sum(1 for status in self.statuses if status is not None and 200 <= status < 300)

    @property
    def failed(self) -> bool:
        return self.successes < 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "statuses": self.statuses,
            "bodies": self.bodies,
            "errors": self.errors,
            "successes": self.successes,
        }


def run_concurrently(calls: list[Callable[[], Any]], timeout: float = 15.0) -> list[Any]:
    """Run every callable at the same time.

    A barrier guarantees the requests are released together, which is what turns
    a rare race into a reliable one.
    """
    if not calls:
        return []
    barrier = threading.Barrier(len(calls))

    def wrapped(fn: Callable[[], Any]) -> Callable[[], Any]:
        def inner() -> Any:
            barrier.wait(timeout=timeout)
            return fn()

        return inner

    with ThreadPoolExecutor(max_workers=len(calls)) as executor:
        futures = [executor.submit(wrapped(fn)) for fn in calls]
        results: list[Any] = []
        for future in futures:
            try:
                results.append(future.result(timeout=timeout))
            except Exception as exc:  # pragma: no cover - defensive
                results.append(exc)
        return results


def looks_single_use(path: str) -> bool:
    """Whether the operation's semantics are naturally one-shot.

    The hints are matched on word boundaries: `/users/me` is not a single-use
    operation, even though it contains the letters of `use`.
    """
    lowered = path.lower()
    for hint in SINGLE_USE_HINTS:
        if re.search(rf"(^|[/_.\-]){re.escape(hint)}($|[/_.\-])", lowered):
            return True
    return False


def detect_race(
    *,
    outcome: RaceOutcome,
    before: list[Any],
    after: list[Any],
    row_id: str | None = None,
    principal: str | None = None,
) -> Violation | None:
    """Turn a race outcome into a violation, or `None` when it was benign."""
    if outcome.failed:
        return None

    new_events = after[len(before) :]
    if not new_events:
        # Both requests were accepted. Under concurrency the data-level
        # attribution is not decisive - two writes can be attributed to one
        # request - so for a single-use operation the two accepted responses
        # are evidence enough.
        if looks_single_use(outcome.url):
            return Violation(
                law="L6",
                title="A single-use operation succeeded twice",
                detail=(
                    f"Two concurrent `{outcome.method} {outcome.url}` requests were both accepted, and the "
                    f"operation looks single-use. The resource was consumed more than once."
                ),
                severity="high",
                principal=principal,
                resource=None,
                action="write",
                evidence={"race": outcome.to_dict(), "applied_changes": []},
            )
        return None

    by_row: dict[str, list[Any]] = {}
    for event in new_events:
        key = getattr(event, "resource_key", None) or getattr(event, "row_id", "?")
        by_row.setdefault(key, []).append(event)

    for key, events in by_row.items():
        if row_id is not None and key != f"{getattr(events[0], 'table', '')}:{row_id}":
            continue
        if len(events) < 2:
            continue
        # The same one-shot transition applied twice is the strongest signal of a
        # missing atomic guard (check-then-act).
        signatures = []
        for event in events:
            columns = getattr(event, "columns", {}) or {}
            signatures.append(tuple(sorted((k, str(v)) for k, v in columns.items())))
        if len(set(signatures)) == 1 and len(signatures) > 1:
            return Violation(
                law="L5",
                title="The same state transition was applied twice",
                detail=(
                    f"Two concurrent `{outcome.method} {outcome.url}` requests were both accepted and both "
                    f"applied the identical change to `{key}`. A check-then-act sequence without an atomic "
                    f"guard lets both requests through."
                ),
                severity="high",
                principal=principal,
                resource=key,
                action="write",
                evidence={
                    "race": outcome.to_dict(),
                    "applied_changes": [event.to_dict() for event in events],
                    "single_use_hint": looks_single_use(outcome.url),
                },
            )
        if looks_single_use(outcome.url):
            return Violation(
                law="L6",
                title="A single-use operation succeeded twice",
                detail=(
                    f"Two concurrent `{outcome.method} {outcome.url}` requests were both accepted, and the "
                    f"operation looks single-use. The resource was consumed more than once."
                ),
                severity="high",
                principal=principal,
                resource=key,
                action="write",
                evidence={"race": outcome.to_dict(), "applied_changes": [event.to_dict() for event in events]},
            )
    return None
