"""Helpers shared by the version hop rules."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..changes import INFO, ChangeLog
from ..jsonutil import add_property, esc, iter_components
from ..schemas import enum_of


def iter_services(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    def rec(svcs: Any, base: str) -> Iterator[tuple[str, dict[str, Any]]]:
        if isinstance(svcs, list):
            for i, s in enumerate(svcs):
                if isinstance(s, dict):
                    yield f"{base}/{i}", s
                    yield from rec(s.get("services"), f"{base}/{i}/services")

    yield from rec(doc.get("services"), "/services")


def iter_objects_with(doc: Any, key: str, path: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    """Every dict anywhere in the document that has `key`."""
    if isinstance(doc, dict):
        if key in doc:
            yield path, doc
        for k, v in list(doc.items()):
            yield from iter_objects_with(v, key, f"{path}/{esc(k)}")
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from iter_objects_with(v, key, f"{path}/{i}")


def all_components(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return list(iter_components(doc, include_metadata=True))


def move_to_property(obj: dict[str, Any], key: str, prop_name: str, path: str, log: ChangeLog, rule_id: str, reason: str) -> None:
    value = obj.pop(key)
    add_property(obj, prop_name, value)
    log.add(rule_id, f"{path}/{esc(key)}", "moved", value, f"properties[{prop_name}]", INFO, reason)


def external_ref_types_to_other(doc: dict[str, Any], target_version: str, log: ChangeLog, rule_id: str) -> None:
    allowed = set(enum_of("cyclonedx", target_version, "externalReference", "type"))
    if not allowed:
        return
    for path, obj in iter_objects_with(doc, "externalReferences"):
        refs = obj.get("externalReferences")
        if not isinstance(refs, list):
            continue
        for i, ref in enumerate(refs):
            if isinstance(ref, dict) and isinstance(ref.get("type"), str) and ref["type"] not in allowed:
                old = ref["type"]
                ref["type"] = "other"
                note = f"original type: {old}"
                ref["comment"] = f"{ref['comment']} ({note})" if ref.get("comment") else note
                log.add(rule_id, f"{path}/externalReferences/{i}/type", "replaced", old, "other", INFO,
                        f"External reference type '{old}' does not exist in {target_version}; kept in comment")


def hashes_not_in(doc: dict[str, Any], target_version: str, log: ChangeLog, rule_id: str) -> None:
    allowed = set(enum_of("cyclonedx", target_version, "hash", "alg"))
    if not allowed:
        return
    for path, obj in iter_objects_with(doc, "hashes"):
        hs = obj.get("hashes")
        if not isinstance(hs, list):
            continue
        keep = []
        for i, h in enumerate(hs):
            if isinstance(h, dict) and isinstance(h.get("alg"), str) and h["alg"] not in allowed:
                log.add(rule_id, f"{path}/hashes/{i}", "removed", h, None, "DATA_LOSS",
                        f"Hash algorithm {h['alg']} does not exist in {target_version}")
            else:
                keep.append(h)
        obj["hashes"] = keep
