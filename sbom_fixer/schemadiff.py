"""First-level diff between two vendored schema versions (Guide Step 09)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .schemas import load_schema, resolve_local


@dataclass
class DefinitionDiff:
    name: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    enum_added: dict[str, list[str]] = field(default_factory=dict)
    enum_removed: dict[str, list[str]] = field(default_factory=dict)
    type_changed: dict[str, tuple[str, str]] = field(default_factory=dict)
    new_definition: bool = False


def _defs(root: dict[str, Any]) -> dict[str, Any]:
    return root.get("definitions") or root.get("$defs") or {}


def _props(d: dict[str, Any]) -> dict[str, Any]:
    return d.get("properties") or {}


def _enum(p: dict[str, Any], root: dict[str, Any]) -> set[str]:
    p = resolve_local(p, root) or {}
    if "enum" in p:
        return set(p["enum"])
    if p.get("type") == "array" and isinstance(p.get("items"), dict):
        return _enum(p["items"], root)
    return set()


def _type(p: dict[str, Any], root: dict[str, Any]) -> str:
    p = resolve_local(p, root) or {}
    if "type" in p:
        return str(p["type"])
    for key in ("oneOf", "anyOf"):
        if key in p:
            return key + "[" + ",".join(_type(b, root) for b in p[key]) + "]"
    return "?"


def schema_diff(spec: str, old_v: str, new_v: str) -> list[DefinitionDiff]:
    old, new = load_schema(spec, old_v), load_schema(spec, new_v)
    out: list[DefinitionDiff] = []
    pairs: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = [("(root)", new, old)]
    for name, prop in _props(new).items():
        item = resolve_local(prop.get("items", {}), new) if isinstance(prop.get("items"), dict) else None
        if item and "properties" in item:
            oitem_src = _props(old).get(name, {}).get("items")
            oitem = resolve_local(oitem_src, old) if isinstance(oitem_src, dict) else None
            if not (prop.get("items", {}).get("$ref") and oitem_src and oitem_src.get("$ref")):
                pairs.append((f"(root).{name}[]", item, oitem))
    pairs += [(n, d, _defs(old).get(n)) for n, d in _defs(new).items()]
    for name, ndef, odef in pairs:
        dd = DefinitionDiff(name)
        if odef is None:
            dd.new_definition = True
            dd.added = sorted(_props(ndef))
            out.append(dd)
            continue
        np_, op_ = _props(ndef), _props(odef)
        dd.added = sorted(set(np_) - set(op_))
        dd.removed = sorted(set(op_) - set(np_))
        for prop in set(np_) & set(op_):
            ne, oe = _enum(np_[prop], new), _enum(op_[prop], old)
            if ne - oe:
                dd.enum_added[prop] = sorted(ne - oe)
            if oe - ne:
                dd.enum_removed[prop] = sorted(oe - ne)
            nt, ot = _type(np_[prop], new), _type(op_[prop], old)
            if nt != ot:
                dd.type_changed[prop] = (ot, nt)
        if dd.added or dd.removed or dd.enum_added or dd.enum_removed or dd.type_changed:
            out.append(dd)
    return out


def format_diff(spec: str, old_v: str, new_v: str) -> str:
    lines = [f"Schema diff {spec} {old_v} -> {new_v}", "=" * 40]
    for d in schema_diff(spec, old_v, new_v):
        head = f"[{d.name}]" + (" NEW DEFINITION" if d.new_definition else "")
        lines.append(head)
        if d.added:
            lines.append(f"  added properties   : {', '.join(d.added)}")
        if d.removed:
            lines.append(f"  removed properties : {', '.join(d.removed)}")
        for p, vals in sorted(d.enum_added.items()):
            lines.append(f"  enum added   {p}: {', '.join(vals)}")
        for p, vals in sorted(d.enum_removed.items()):
            lines.append(f"  enum removed {p}: {', '.join(vals)}")
        for p, (o, n) in sorted(d.type_changed.items()):
            lines.append(f"  type changed {p}: {o} -> {n}")
    return "\n".join(lines) + "\n"
