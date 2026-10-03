"""Small helpers for JSON Pointer paths and document walking."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from typing import Any


def esc(token: Any) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def pointer(parts: Iterable[Any]) -> str:
    return "".join("/" + esc(p) for p in parts)


def parse_pointer(ptr: str) -> list[str | int]:
    if not ptr:
        return []
    out: list[str | int] = []
    for raw in ptr.lstrip("/").split("/"):
        tok = raw.replace("~1", "/").replace("~0", "~")
        out.append(int(tok) if tok.isdigit() else tok)
    return out


def get_at(doc: Any, parts: Iterable[Any]) -> Any:
    node = doc
    for p in parts:
        node = node[p]
    return node


def parent_of(doc: Any, parts: list[Any]) -> tuple[Any, Any]:
    """Return (container, key) for the node at parts. Raises KeyError/IndexError if missing."""
    if not parts:
        raise KeyError("root has no parent")
    return get_at(doc, parts[:-1]), parts[-1]


def exists(doc: Any, parts: list[Any]) -> bool:
    try:
        get_at(doc, parts)
        return True
    except (KeyError, IndexError, TypeError):
        return False


def walk(node: Any, path: str = "") -> Iterator[tuple[str, Any, Any, Any]]:
    """Yield (parent_path, parent, key, value) for every key/index in the tree, parents before children."""
    if isinstance(node, dict):
        for k in list(node.keys()):
            if k not in node:
                continue
            v = node[k]
            yield path, node, k, v
            yield from walk(v, f"{path}/{esc(k)}")
    elif isinstance(node, list):
        for i, v in enumerate(list(node)):
            yield path, node, i, v
            yield from walk(v, f"{path}/{i}")


def iter_components(doc: dict[str, Any], include_metadata: bool = False) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (pointer, component) for top-level and nested components."""

    def rec(comps: Any, base: str) -> Iterator[tuple[str, dict[str, Any]]]:
        if not isinstance(comps, list):
            return
        for i, c in enumerate(comps):
            if isinstance(c, dict):
                p = f"{base}/{i}"
                yield p, c
                yield from rec(c.get("components"), p + "/components")

    if include_metadata:
        mc = (doc.get("metadata") or {}).get("component")
        if isinstance(mc, dict):
            yield "/metadata/component", mc
            yield from rec(mc.get("components"), "/metadata/component/components")
    yield from rec(doc.get("components"), "/components")


def canonical_json(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_of(doc: Any) -> str:
    return hashlib.sha256(canonical_json(doc).encode("utf-8")).hexdigest()


def add_property(target: dict[str, Any], name: str, value: Any) -> None:
    props = target.setdefault("properties", [])
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    props.append({"name": name, "value": text})
