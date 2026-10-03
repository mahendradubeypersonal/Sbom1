"""Machine diff (RFC 6902 JSON Patch) and human diff (Guide Step 15)."""

from __future__ import annotations

import difflib
import json
from typing import Any

import jsonpatch

from .changes import ChangeLog

UNIFIED_DIFF_LIMIT_BYTES = 400_000  # difflib slows down sharply on large, repetitive JSON


def machine_diff(original: Any, fixed: Any) -> list[dict[str, Any]]:
    return list(jsonpatch.make_patch(original, fixed).patch)


def apply_patch(original: Any, patch: list[dict[str, Any]]) -> Any:
    return jsonpatch.apply_patch(original, patch, in_place=False)


def _short(value: Any, limit: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def patch_listing(patch: list[dict[str, Any]], original: Any, name: str) -> str:
    """Readable listing of a JSON Patch: one line per operation, linear in the number of changes."""
    out = [f"{name}: {len(patch)} change(s), listed as JSON Patch operations", ""]
    for op in patch:
        path = op.get("path", "")
        if op["op"] in ("replace", "remove"):
            try:
                old = jsonpatch.JsonPointer(path).resolve(original)
            except (jsonpatch.JsonPointerException, KeyError, IndexError, TypeError):
                old = None
        else:
            old = None
        if op["op"] == "replace":
            out.append(f"~ {path}\n    - {_short(old)}\n    + {_short(op.get('value'))}")
        elif op["op"] == "remove":
            out.append(f"- {path}\n    - {_short(old)}")
        elif op["op"] == "add":
            out.append(f"+ {path}\n    + {_short(op.get('value'))}")
        else:
            out.append(f"{op['op']} {op.get('from', '')} -> {path}")
    return "\n".join(out) + "\n"


def human_diff(original: Any, fixed: Any, name: str, log: ChangeLog | None = None,
               patch: list[dict[str, Any]] | None = None) -> str:
    a = json.dumps(original, indent=2, sort_keys=True, ensure_ascii=False)
    b = json.dumps(fixed, indent=2, sort_keys=True, ensure_ascii=False)
    if len(a) + len(b) > UNIFIED_DIFF_LIMIT_BYTES:
        if patch is not None and len(patch) <= 20_000:
            return patch_listing(patch, original, name)
        if log is not None:
            return summary_by_rule(log, name)
    lines = difflib.unified_diff(a.splitlines(), b.splitlines(), f"{name} (original)", f"{name} (fixed)", lineterm="", n=2)
    return "\n".join(lines) + "\n"


def summary_by_rule(log: ChangeLog, name: str) -> str:
    out = [f"{name}: document too large for a line diff; changes grouped by rule", ""]
    for rule_id, changes in log.by_rule().items():
        out.append(f"{rule_id}  {len(changes)} change(s)")
        for c in changes[:5]:
            out.append(f"    {c.action:9} {c.path}")
        if len(changes) > 5:
            out.append(f"    ... {len(changes) - 5} more")
    return "\n".join(out) + "\n"
