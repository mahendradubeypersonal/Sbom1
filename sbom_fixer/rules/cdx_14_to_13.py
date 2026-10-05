"""Hop rules CycloneDX 1.4 -> 1.3 (CDX14-001..004)."""

from __future__ import annotations

from typing import Any

from packageurl import PackageURL

from ..changes import DATA_LOSS, INFO, WARN
from .base import HOP, Ctx, Rule, register
from .hop_common import all_components, external_ref_types_to_other, iter_objects_with

HOP_14 = ("1.4", "1.3")


@register
class ComponentVersionRequired(Rule):
    id = "CDX14-001"
    title = "component.version is required in 1.3"
    description = "CycloneDX 1.3 requires a component version; it was taken from the purl, or set to 'unknown' and reported."
    case, kind, hop = "B", HOP, HOP_14

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            if c.get("version"):
                continue
            ver = None
            if isinstance(c.get("purl"), str):
                try:
                    ver = PackageURL.from_string(c["purl"]).version
                except ValueError:
                    ver = None
            c["version"] = ver or "unknown"
            ctx.log.add(self.id, f"{path}/version", "added", None, c["version"], INFO if ver else WARN,
                        "Version taken from the purl" if ver else "Version required in 1.3 and unknown")


@register
class Vulnerabilities(Rule):
    id = "CDX14-002"
    title = "Remove vulnerabilities"
    description = "CycloneDX 1.3 has no vulnerabilities section; it was removed (the scanner computes its own findings)."
    case, kind, hop = "B", HOP, HOP_14

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if "vulnerabilities" in doc:
            ctx.log.add(self.id, "/vulnerabilities", "removed", doc.pop("vulnerabilities"), None, INFO, "Not in 1.3")


@register
class SignatureReleaseNotes(Rule):
    id = "CDX14-003"
    title = "Remove signatures and release notes"
    description = "signature and releaseNotes (1.4) do not exist in 1.3 and were removed."
    case, kind, hop = "B", HOP, HOP_14

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for key in ("signature", "releaseNotes"):
            for path, obj in list(iter_objects_with(doc, key)):
                ctx.log.add(self.id, f"{path}/{key}", "removed", obj.pop(key), None, DATA_LOSS, f"{key} does not exist in 1.3")


@register
class ToolExternalRefs(Rule):
    id = "CDX14-004"
    title = "1.4-only values"
    description = "Values added in 1.4 were mapped: the external reference type release-notes became other; tool externalReferences were removed."
    case, kind, hop = "B", HOP, HOP_14

    def apply(self, doc: Any, ctx: Ctx) -> None:
        external_ref_types_to_other(doc, "1.3", ctx.log, self.id)
        tools = (doc.get("metadata") or {}).get("tools")
        if isinstance(tools, list):
            for i, t in enumerate(tools):
                if isinstance(t, dict) and "externalReferences" in t:
                    ctx.log.add(self.id, f"/metadata/tools/{i}/externalReferences", "removed", t.pop("externalReferences"),
                                None, INFO, "Tool externalReferences do not exist in 1.3")
