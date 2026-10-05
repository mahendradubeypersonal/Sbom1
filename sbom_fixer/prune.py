"""Schema-guided pruner (Guide Step 12): remove keys the current version's schema does not allow."""

from __future__ import annotations

import re
from typing import Any

from .changes import DATA_LOSS, ChangeLog
from .jsonutil import esc
from .schemas import load_schema, resolve_local

_JSON_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
}


def _matches_type(instance: Any, t: Any) -> bool:
    types = t if isinstance(t, list) else [t]
    for ty in types:
        if ty in ("integer", "number"):
            if isinstance(instance, (int, float)) and not isinstance(instance, bool):
                return True
        elif ty == "null":
            if instance is None:
                return True
        elif ty in _JSON_TYPES and isinstance(instance, _JSON_TYPES[ty]):
            return True
    return False


def _required_ok(instance: Any, schema: Any, root: dict[str, Any]) -> bool:
    s = resolve_local(schema, root) if isinstance(schema, dict) else None
    if s is None:
        return True
    return not isinstance(instance, dict) or all(k in instance for k in s.get("required", []))


def _shape_ok(instance: Any, branch: dict[str, Any], root: dict[str, Any]) -> bool:
    if isinstance(instance, dict):
        return _required_ok(instance, branch, root)
    if isinstance(instance, list):
        items = branch.get("items")
        if isinstance(items, dict):
            return all(_required_ok(x, items, root) for x in instance)
        if isinstance(items, list):
            if len(instance) > len(items) and branch.get("additionalItems") is False:
                return False
            return all(_required_ok(x, s, root) for x, s in zip(instance, items, strict=False))
    return True


def _branch_for(instance: Any, branches: list[Any], root: dict[str, Any]) -> dict[str, Any] | None:
    """Pick the single branch that fits the instance (by type, then by required keys); None if ambiguous."""
    candidates = []
    for b in branches:
        rb = resolve_local(b, root)
        if rb is None or "type" not in rb:
            return None
        if _matches_type(instance, rb["type"]):
            candidates.append(rb)
    if len(candidates) > 1:
        candidates = [c for c in candidates if _shape_ok(instance, c, root)]
    return candidates[0] if len(candidates) == 1 else None


def _prune(node: Any, schema: Any, root: dict[str, Any], path: str, log: ChangeLog, depth: int = 0) -> None:
    if depth > 200 or not isinstance(schema, dict):
        return
    schema = resolve_local(schema, root)
    if schema is None:
        return
    for sub in schema.get("allOf", []):
        _prune(node, sub, root, path, log, depth + 1)
    for key in ("oneOf", "anyOf"):
        if key in schema:
            branch = _branch_for(node, schema[key], root)
            if branch is not None:
                _prune(node, branch, root, path, log, depth + 1)
    if isinstance(node, dict) and ("properties" in schema or "additionalProperties" in schema):
        props = schema.get("properties") or {}
        patterns = schema.get("patternProperties") or {}
        addl = schema.get("additionalProperties", True)
        for k in list(node.keys()):
            if k in props:
                _prune(node[k], props[k], root, f"{path}/{esc(k)}", log, depth + 1)
                continue
            matched = [p for p in patterns if re.search(p, k)]
            if matched:
                _prune(node[k], patterns[matched[0]], root, f"{path}/{esc(k)}", log, depth + 1)
                continue
            if addl is False:
                removed = node.pop(k)
                log.add("PRUNE-001", f"{path}/{esc(k)}", "removed", removed, None, DATA_LOSS,
                        "Field is not allowed by the schema of the current version")
            elif isinstance(addl, dict):
                _prune(node[k], addl, root, f"{path}/{esc(k)}", log, depth + 1)
    elif isinstance(node, list) and isinstance(schema.get("items"), dict):
        for i, item in enumerate(node):
            _prune(item, schema["items"], root, f"{path}/{i}", log, depth + 1)
    elif isinstance(node, list) and isinstance(schema.get("items"), list):
        for i, (item, sub) in enumerate(zip(node, schema["items"], strict=False)):
            _prune(item, sub, root, f"{path}/{i}", log, depth + 1)


def prune_to(doc: Any, spec: str, version: str, log: ChangeLog) -> int:
    root = load_schema(spec, version)
    before = len(log)
    _prune(doc, root, root, "", log)
    return len(log) - before
