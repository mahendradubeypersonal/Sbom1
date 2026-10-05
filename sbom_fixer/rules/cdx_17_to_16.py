"""Hop rules CycloneDX 1.7 -> 1.6. Fields removed by the pruner are logged as PRUNE-001."""

from __future__ import annotations

from typing import Any

from ..changes import DATA_LOSS
from .base import HOP, Ctx, Rule, register
from .hop_common import (
    all_components,
    external_ref_types_to_other,
    hashes_not_in,
    iter_services,
    move_to_property,
)


@register
class VersionRangeAndExternal(Rule):
    id = "CDX17-001"
    title = "component.versionRange and isExternal to properties"
    description = "CycloneDX 1.7 component fields versionRange and isExternal do not exist in 1.6; they were kept as properties."
    case, kind, hop = "B", HOP, ("1.7", "1.6")

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            for key, prop in (("versionRange", "sbom-fixer:versionRange"), ("isExternal", "sbom-fixer:isExternal")):
                if key in c:
                    move_to_property(c, key, prop, path, ctx.log, self.id, f"{key} does not exist in 1.6")


@register
class PatentsAndCitations(Rule):
    id = "CDX17-002"
    title = "Remove patent assertions, citations and distribution constraints"
    description = "CycloneDX 1.7 patent assertions, citations and metadata.distributionConstraints have no 1.6 equivalent and were removed."
    case, kind, hop = "B", HOP, ("1.7", "1.6")

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for key in ("citations",):
            if key in doc:
                ctx.log.add(self.id, f"/{key}", "removed", doc.pop(key), None, DATA_LOSS, f"{key} does not exist in 1.6")
        meta = doc.get("metadata")
        if isinstance(meta, dict) and "distributionConstraints" in meta:
            ctx.log.add(self.id, "/metadata/distributionConstraints", "removed", meta.pop("distributionConstraints"), None,
                        DATA_LOSS, "distributionConstraints does not exist in 1.6")
        for path, obj in all_components(doc) + list(iter_services(doc)):
            if "patentAssertions" in obj:
                ctx.log.add(self.id, f"{path}/patentAssertions", "removed", obj.pop("patentAssertions"), None, DATA_LOSS,
                            "patentAssertions does not exist in 1.6")


@register
class Enums17(Rule):
    id = "CDX17-ENUM"
    title = "1.7-only enum values"
    description = "Enum values that exist only in CycloneDX 1.7 were mapped: new external reference types became 'other' (original kept in comment); Streebog hashes were removed."
    case, kind, hop = "B", HOP, ("1.7", "1.6")

    def apply(self, doc: Any, ctx: Ctx) -> None:
        external_ref_types_to_other(doc, "1.6", ctx.log, self.id)
        hashes_not_in(doc, "1.6", ctx.log, self.id)
