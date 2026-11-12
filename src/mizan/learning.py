"""Learn an application by exercising it.

Before Mizan can attack an application it needs to know what a normal request
looks like. Often that knowledge exists only inside the running system, so the
twin simply *asks*: it walks the OpenAPI document and sends the smallest
possible request for every operation it can.

    learn_from_spec("openapi.json", base_url, tokens=["eyJ..."])

What comes out is ordinary traffic - and that traffic is what the law learner
consumes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests

#: Values used to fill a request body. Small, harmless and recognisable.
SAMPLE_VALUES: dict[str, Any] = {
    "string": "mizan",
    "integer": 1,
    "number": 1,
    "boolean": False,
    "array": [],
    "object": {},
}


def load_spec(path: str | Path) -> dict[str, Any]:
    """Read an OpenAPI document (JSON or YAML)."""
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if file.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml

            return yaml.safe_load(text)
        except ImportError:  # pragma: no cover - optional dependency
            raise RuntimeError("PyYAML is needed to read YAML specifications")
    return json.loads(text)


def _resolve(schema: dict[str, Any], document: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    if depth > 6 or not isinstance(schema, dict):
        return {}
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        target = document.get("components", {}).get("schemas", {}).get(name, {})
        return _resolve(target, document, depth + 1)
    return schema


def sample_body(schema: dict[str, Any], document: dict[str, Any], depth: int = 0) -> Any:
    """A minimal body for a request schema.

    An example from the specification wins over a generated value: a real
    specification usually knows what a valid request looks like, and a
    generated string is often rejected by the application.
    """
    schema = _resolve(schema, document, depth)
    if not schema:
        return None
    for key in ("example", "default"):
        if key in schema and schema[key] is not None:
            return schema[key]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        body: dict[str, Any] = {}
        for name, definition in properties.items():
            resolved = _resolve(definition, document, depth + 1)
            # A field may carry its own example - that is often the only value
            # the application will accept.
            value = sample_body(resolved, document, depth + 1)
            for key in ("example", "default"):
                if isinstance(resolved, dict) and key in resolved and resolved[key] is not None:
                    value = resolved[key]
                    break
            examples = resolved.get("examples") if isinstance(resolved, dict) else None
            if isinstance(examples, list) and examples:
                value = examples[0]
            body[name] = value
        return body
    if kind == "array":
        return []
    if kind in SAMPLE_VALUES:
        return SAMPLE_VALUES[kind]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    return "mizan"


def operations(document: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """`(method, path, operation)` for every operation in the document."""
    result: list[tuple[str, str, dict[str, Any]]] = []
    for path, item in (document.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head"}:
                continue
            if not isinstance(operation, dict):
                continue
            result.append((method.upper(), path, operation))
    return result


def learn_from_spec(
    spec_path: str | Path,
    base_url: str,
    *,
    tokens: list[str] | None = None,
    identities: dict[str, str] | None = None,
    timeout: float = 15.0,
    session: requests.Session | None = None,
    discover_ids: bool = True,
    max_discovered_ids: int = 5,
    include_destructive: bool = False,
    max_requests: int | None = None,
) -> list[dict[str, Any]]:
    """Send the smallest possible request for every operation.

    The learning runs in two passes. The first one exercises the operations
    without path parameters - creates, listings, identity - and collects the
    identifiers from the responses. The second one uses those identifiers for
    the operations that need them.

    When the identifiers are known per identity, the second pass acts as *the
    identity that created the object*: a client reads back what it created,
    not what somebody else created.

    Destructive operations are skipped by default: a learning run must not
    destroy the objects the attack phase is going to look at.

    ``max_requests`` bounds the number of requests the learning phase may send.
    """
    document = load_spec(spec_path)
    session = session or requests.Session()
    results: list[dict[str, Any]] = []
    pending: list[tuple[str, str, dict[str, Any]]] = []
    discovered: dict[str, list[str]] = {}

    principals = list((identities or {}).items())
    if not principals:
        principals = [(f"identity-{index}", token) for index, token in enumerate(tokens or [])]

    for index, (method, path, operation) in enumerate(operations(document)):
        if method == "DELETE" and not include_destructive:
            continue
        if _has_required_path_parameter(operation):
            pending.append((method, path, operation))
            continue
        principal, token = _pick(principals, index)
        if max_requests is not None and len(results) >= max_requests:
            break
        result = _send(session, method, base_url, path, operation, document, token, timeout)
        results.append(result)
        for identifier in _identifiers_in(result.get("response")):
            if identifier not in discovered.setdefault(principal, []):
                discovered[principal].append(identifier)

    if discover_ids and pending and discovered:
        for principal, identifiers in discovered.items():
            token = dict(principals).get(principal)
            if token is None:
                continue
            # Writes first: a listing that is read before the object exists
            # is empty, and an empty listing teaches the engine nothing.
            ordered = sorted(
                pending,
                key=lambda item: 0 if item[0] in {"POST", "PUT", "PATCH"} else 1,
            )
            for method, path, operation in ordered:
                for candidate in identifiers[:max_discovered_ids]:
                    if max_requests is not None and len(results) >= max_requests:
                        break
                    concrete = _fill_path(path, operation, candidate)
                    if concrete is None:
                        continue
                    result = _send(session, method, base_url, concrete, operation, document, token, timeout)
                    results.append(result)
                    for found in _identifiers_in(result.get("response")):
                        if found not in discovered[principal]:
                            discovered[principal].append(found)
    return results


def _pick(principals: list[tuple[str, str]], index: int) -> tuple[str, str]:
    """The identity to act as for the n-th request."""
    if not principals:
        return ("anonymous", "")
    return principals[index % len(principals)]


def _send(
    session: requests.Session,
    method: str,
    base_url: str,
    path: str,
    operation: dict[str, Any],
    document: dict[str, Any],
    token: str,
    timeout: float,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    content = operation.get("requestBody", {})
    for media in (content or {}).get("content", {}).values():
        schema = media.get("schema", {})
        body = sample_body(schema, document)
        break
    try:
        if method in {"GET", "HEAD", "DELETE"}:
            response = session.request(method, url, headers=headers, timeout=timeout)
        else:
            response = session.request(method, url, headers=headers, json=body, timeout=timeout)
        payload = None
        try:
            payload = response.json()
        except Exception:
            payload = response.text[:500]
        return {
            "method": method,
            "path": path,
            "status": response.status_code,
            "body": body,
            "response": payload,
        }
    except Exception as exc:  # pragma: no cover - network dependent
        return {"method": method, "path": path, "error": str(exc)}


def _identifiers_in(payload: Any, depth: int = 0) -> list[str]:
    """Identifiers found in a response body."""
    if depth > 4:
        return []
    found: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in {"id", "order_id", "user_id", "uuid"} and isinstance(value, (str, int)):
                found.append(str(value))
            else:
                found.extend(_identifiers_in(value, depth + 1))
    elif isinstance(payload, list):
        for item in payload[:20]:
            found.extend(_identifiers_in(item, depth + 1))
    return found


def _fill_path(path: str, operation: dict[str, Any], candidate: str) -> str | None:
    """Put a discovered identifier into the path parameters."""
    parameters = [
        parameter
        for parameter in operation.get("parameters", []) or []
        if isinstance(parameter, dict) and parameter.get("in") == "path"
    ]
    if not parameters:
        return None
    concrete = path
    for parameter in parameters:
        name = parameter.get("name")
        if not name:
            return None
        concrete = concrete.replace("{" + name + "}", candidate)
    if "{" in concrete:
        return None
    return concrete


def _has_required_path_parameter(operation: dict[str, Any]) -> bool:
    for parameter in operation.get("parameters", []) or []:
        if isinstance(parameter, dict) and parameter.get("in") == "path" and parameter.get("required"):
            return True
    return False
