"""Mizan - law-driven API security testing.

The engine learns the security laws of an application from its own normal
behaviour and then tries to break them. Every finding ships with a proof
bundle that a reviewer can replay.

Public API::

    from mizan import Mizan, Target, Principal

    mizan = Mizan(Target(base_url="http://127.0.0.1:8000", principals=[...]))
    policy = mizan.learn()
    violations = mizan.attack()
"""

from __future__ import annotations

from mizan.core import (
    LAWS,
    AccessMatrix,
    Law,
    Policy,
    Principal,
    Resource,
    Rule,
    Step,
    Violation,
    actions_for,
    is_authority_field,
)
from mizan.engine import Mizan, Target
from mizan.identity import TokenClaims, decode_token, subject_of
from mizan.patching import PatchSuggestion, suggest
from mizan.proof import ProofBundle
from mizan.races import RaceOutcome, detect_race, run_concurrently
from mizan.regression import Attack, attack_succeeds, build_attack, render_test
from mizan.taint import Ledger, PostgresLogParser, TaintAnalyzer, WriteEvent
from mizan.traffic import TrafficLog, TrafficRecord

__version__ = "0.2.0"

__all__ = [
    "LAWS",
    "AccessMatrix",
    "Attack",
    "Law",
    "Ledger",
    "Mizan",
    "PatchSuggestion",
    "Policy",
    "PostgresLogParser",
    "Principal",
    "ProofBundle",
    "RaceOutcome",
    "Resource",
    "Rule",
    "Step",
    "TaintAnalyzer",
    "Target",
    "TokenClaims",
    "TrafficLog",
    "TrafficRecord",
    "Violation",
    "WriteEvent",
    "actions_for",
    "attack_succeeds",
    "build_attack",
    "decode_token",
    "detect_race",
    "is_authority_field",
    "render_test",
    "run_concurrently",
    "subject_of",
    "suggest",
    "register",
    "__version__",
]


def register() -> None:
    """Install Mizan's checks into Schemathesis.

    Call this once (or use the ``mizan`` pytest plugin) to make the law checks
    available to ``schemathesis run``.
    """
    from mizan.schemathesis_plugin import register as _register

    _register()
