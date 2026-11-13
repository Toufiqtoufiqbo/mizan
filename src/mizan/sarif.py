"""SARIF 2.1.0 export.

Findings should be readable by the tools a team already uses, so Mīzān can
write SARIF - the format GitHub code scanning, GitLab and many others read.

    mizan export-sarif mizan-proofs --out findings.sarif

The export is deliberately conservative:

* a rule per law, with a stable identifier, so the same finding keeps the same
  identity between runs;
* the evidence travels as properties, not as invented source locations - Mīzān
  does not know where in your code the flaw is, and it will not pretend to;
* a missing or incomplete bundle produces a warning, never a crash.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

TOOL_NAME = "Mizan"
TOOL_URL = "https://github.com/Toufiqtoufiqbo/mizan"

#: How a severity maps onto the SARIF levels.
LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

#: The rules, one per law. The identifiers are stable: the same law always
#: produces the same rule id.
RULES: dict[str, dict[str, Any]] = {
    "L1": {
        "name": "AuthenticationCoherence",
        "shortDescription": {"text": "The server acts as a different identity than the token claims."},
        "fullDescription": {
            "text": (
                "The identity a request is served as is not the identity the token claims. "
                "A session, a cache or a mapping resolves the token to another account."
            )
        },
        "tags": ["security", "authentication"],
    },
    "L2": {
        "name": "ReadAuthorization",
        "shortDescription": {"text": "An object is readable by somebody who does not own it."},
        "fullDescription": {
            "text": (
                "A read returned an object to an identity that does not own it and is not "
                "entitled to it. The response crosses an ownership boundary."
            )
        },
        "tags": ["security", "authorization", "idor"],
    },
    "L3": {
        "name": "WriteAuthorization",
        "shortDescription": {"text": "A write lands in a row owned by somebody else."},
        "fullDescription": {
            "text": (
                "A write changed a row that belongs to another identity. The write was "
                "accepted and persisted, not rejected."
            )
        },
        "tags": ["security", "authorization", "idor"],
    },
    "L4": {
        "name": "AuthorityCreation",
        "shortDescription": {"text": "A caller created authority for itself."},
        "fullDescription": {
            "text": (
                "A request set a field that carries authority - a role, an owner, a tenant - "
                "and the server persisted it."
            )
        },
        "tags": ["security", "mass-assignment"],
    },
    "L5": {
        "name": "NonAtomicTransition",
        "shortDescription": {"text": "Two concurrent requests applied the same transition."},
        "fullDescription": {
            "text": (
                "A check and the action that follows it are not atomic. Two identical "
                "requests were both accepted, so the second one was not prevented."
            )
        },
        "tags": ["security", "race-condition", "toctou"],
    },
    "L6": {
        "name": "CardinalityViolation",
        "shortDescription": {"text": "A single-use resource was used more than once."},
        "fullDescription": {"text": "An operation that may happen once happened twice."},
        "tags": ["security", "business-logic"],
    },
    "L7": {
        "name": "PathConfidentiality",
        "shortDescription": {"text": "Data left the system outside the caller's authority."},
        "fullDescription": {"text": "A field or an object reached a caller that may not see it."},
        "tags": ["security", "confidentiality"],
    },
}


@dataclass
class ExportResult:
    """The outcome of an export."""

    document: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    bundles: int = 0
    results: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundles": self.bundles,
            "results": self.results,
            "warnings": list(self.warnings),
        }


def rule_id(law: str) -> str:
    """The stable identifier of a law's rule."""
    return f"MIZAN-{law}"


def _level(severity: str) -> str:
    return LEVELS.get((severity or "").lower(), "warning")


def _rule(law: str, severity: str) -> dict[str, Any]:
    definition = RULES.get(law, {})
    return {
        "id": rule_id(law),
        "name": definition.get("name", f"Law{law}"),
        "shortDescription": definition.get("shortDescription", {"text": f"Violation of law {law}."}),
        "fullDescription": definition.get("fullDescription", {"text": f"Violation of law {law}."}),
        "defaultConfiguration": {"level": _level(severity)},
        "properties": {"tags": definition.get("tags", ["security"])},
    }


def _fingerprint(payload: dict[str, Any]) -> str:
    """A stable identity for a finding, so it can be tracked over time."""
    import hashlib

    parts = [
        str(payload.get("law", "")),
        str(payload.get("principal", "")),
        str(payload.get("resource", "")),
        str(payload.get("title", "")),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _result(payload: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    law = str(payload.get("law", "L0"))
    severity = str(payload.get("severity", "medium"))
    steps = payload.get("steps") or []
    endpoint = ""
    method = ""
    if steps:
        first = steps[0]
        method = str(first.get("method", ""))
        endpoint = str(first.get("url", ""))
    message = payload.get("title") or f"Violation of law {law}."
    details = payload.get("detail") or ""

    properties: dict[str, Any] = {
        "law": law,
        "principal": payload.get("principal"),
        "resource": payload.get("resource"),
        "action": payload.get("action"),
        "severity": severity,
    }
    if endpoint:
        properties["endpoint"] = endpoint
    if method:
        properties["httpMethod"] = method
    if evidence:
        properties["evidence"] = evidence
    if steps:
        properties["reproduction"] = [
            {
                "method": step.get("method"),
                "url": step.get("url"),
                "note": step.get("note"),
            }
            for step in steps
        ]

    result: dict[str, Any] = {
        "ruleId": rule_id(law),
        "level": _level(severity),
        "message": {"text": message},
        "properties": properties,
        "partialFingerprints": {"mizanFindingId": _fingerprint(payload)},
    }
    if details:
        result["message"]["markdown"] = f"{message}\n\n{details}"
    return result


def to_sarif(bundles: list[Path], *, warnings: list[str] | None = None) -> ExportResult:
    """Build the SARIF document for a list of proof bundles."""
    warnings = warnings if warnings is not None else []
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    count = 0
    for bundle in bundles:
        replay = bundle / "replay.json"
        if not replay.exists():
            warnings.append(f"{bundle.name}: no replay.json, skipped")
            continue
        try:
            payload = json.loads(replay.read_text(encoding="utf-8"))
        except ValueError as exc:
            warnings.append(f"{bundle.name}: replay.json is not valid JSON ({exc}), skipped")
            continue
        evidence: dict[str, Any] = {}
        evidence_file = bundle / "evidence.json"
        if evidence_file.exists():
            try:
                evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
            except ValueError:
                warnings.append(f"{bundle.name}: evidence.json is not valid JSON, ignored")
        law = str(payload.get("law", "L0"))
        severity = str(payload.get("severity", "medium"))
        rules.setdefault(law, _rule(law, severity))
        results.append(_result(payload, evidence))
        count += 1

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URL,
                        "rules": [rules[law] for law in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }
    return ExportResult(document=document, warnings=warnings, bundles=count, results=len(results))


def export_sarif(directory: str | Path, out_path: str | Path) -> ExportResult:
    """Export every proof bundle in a directory to a SARIF file."""
    root = Path(directory)
    bundles = sorted(path for path in root.iterdir() if path.is_dir()) if root.is_dir() else []
    result = to_sarif(bundles)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.document, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def validate_sarif(document: dict[str, Any]) -> list[str]:
    """Check the document against the parts of SARIF 2.1.0 that matter here.

    This is not a full schema validation - it checks the structure the format
    requires: the version, the runs, the tool driver and the shape of a result.
    """
    problems: list[str] = []
    if document.get("version") != SARIF_VERSION:
        problems.append(f"version must be {SARIF_VERSION}")
    if "$schema" not in document:
        problems.append("the document has no $schema")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("the document has no runs")
        return problems
    for index, run in enumerate(runs):
        driver = (run.get("tool") or {}).get("driver") or {}
        if not driver.get("name"):
            problems.append(f"run {index}: the tool driver has no name")
        rule_ids = {rule.get("id") for rule in driver.get("rules", [])}
        for result_index, result in enumerate(run.get("results", [])):
            if not result.get("ruleId"):
                problems.append(f"run {index}, result {result_index}: no ruleId")
            elif rule_ids and result["ruleId"] not in rule_ids:
                problems.append(f"run {index}, result {result_index}: unknown rule {result['ruleId']}")
            if not (result.get("message") or {}).get("text"):
                problems.append(f"run {index}, result {result_index}: no message")
            if result.get("level") not in {"error", "warning", "note", "none"}:
                problems.append(f"run {index}, result {result_index}: invalid level")
    return problems
