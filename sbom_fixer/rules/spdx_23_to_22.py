"""Hop rules SPDX 2.3 -> 2.2, confirmed against the vendored 2.2.2 and 2.3 schemas.

SPDX 2.2.2 already accepts both PACKAGE-MANAGER and PACKAGE_MANAGER, so no category rename is needed.
"""

from __future__ import annotations

from typing import Any

from ..changes import INFO
from .base import HOP, Ctx, Rule, register

HOP_23 = ("2.3", "2.2")
_PKG_FIELDS = ("primaryPackagePurpose", "releaseDate", "builtDate", "validUntilDate")
_NEW_REL = {"REQUIREMENT_DESCRIPTION_FOR", "SPECIFICATION_FOR"}


def _append_comment(obj: dict[str, Any], text: str) -> None:
    obj["comment"] = f"{obj['comment']}\n{text}" if obj.get("comment") else text


@register
class PackageFields23(Rule):
    id = "SPDX23-001"
    title = "2.3-only package fields to comment"
    description = "Package fields added in SPDX 2.3 (primaryPackagePurpose, releaseDate, builtDate, validUntilDate) were moved into the package comment."
    case, kind, hop, specs = "B", HOP, HOP_23, ("spdx",)

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for i, pkg in enumerate(doc.get("packages") or []):
            if not isinstance(pkg, dict):
                continue
            for key in _PKG_FIELDS:
                if key in pkg:
                    value = pkg.pop(key)
                    _append_comment(pkg, f"{key}: {value}")
                    ctx.log.add(self.id, f"/packages/{i}/{key}", "moved", value, "comment", INFO, f"{key} does not exist in SPDX 2.2")


@register
class RelationshipTypes23(Rule):
    id = "SPDX23-002"
    title = "2.3-only relationship types to OTHER"
    description = "Relationship types added in SPDX 2.3 (REQUIREMENT_DESCRIPTION_FOR, SPECIFICATION_FOR) became OTHER with the original type in the comment."
    case, kind, hop, specs = "B", HOP, HOP_23, ("spdx",)

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for i, rel in enumerate(doc.get("relationships") or []):
            if isinstance(rel, dict) and rel.get("relationshipType") in _NEW_REL:
                old = rel["relationshipType"]
                rel["relationshipType"] = "OTHER"
                _append_comment(rel, f"original relationshipType: {old}")
                ctx.log.add(self.id, f"/relationships/{i}/relationshipType", "replaced", old, "OTHER", INFO,
                            f"{old} does not exist in SPDX 2.2")
