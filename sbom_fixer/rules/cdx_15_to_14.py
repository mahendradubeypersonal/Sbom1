"""Hop rules CycloneDX 1.5 -> 1.4 (CDX15-001..011) and the importer-specific CDX15-001P."""

from __future__ import annotations

from typing import Any

from ..changes import DATA_LOSS, INFO, WARN
from ..jsonutil import add_property
from .base import HOP, SANITIZE, Ctx, Rule, register
from .hop_common import all_components, external_ref_types_to_other, iter_services, move_to_property

HOP_15 = ("1.5", "1.4")
_LEGACY_TOOL_KEYS = ("vendor", "name", "version", "hashes", "externalReferences")


def tools_object_to_array(tools: dict[str, Any], path: str, ctx: Ctx, rule_id: str) -> list[dict[str, Any]]:
    legacy: list[dict[str, Any]] = []
    for c in tools.get("components") or []:
        if not isinstance(c, dict):
            continue
        vendor = (c.get("supplier") or {}).get("name") or (c.get("manufacturer") or {}).get("name") or c.get("group") or c.get("publisher")
        entry = {"vendor": vendor, "name": c.get("name"), "version": c.get("version"),
                 "hashes": c.get("hashes"), "externalReferences": c.get("externalReferences")}
        legacy.append({k: v for k, v in entry.items() if v})
    services = tools.get("services") or []
    for s in services:
        if isinstance(s, dict) and s.get("name"):
            legacy.append({k: v for k, v in {"vendor": (s.get("provider") or {}).get("name"), "name": s.get("name"),
                                             "version": s.get("version")}.items() if v})
    ctx.log.add(rule_id, path, "converted", tools, legacy, INFO,
                "CycloneDX 1.4 expects tools as an array of {vendor, name, version}")
    return legacy


@register
class ToolsObjectToArray(Rule):
    id = "CDX15-001"
    title = "metadata.tools object to legacy array"
    description = "metadata.tools (and vulnerabilities[].tools) in the 1.5 object form {components, services} were converted to the 1.4 array of {vendor, name, version}."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        meta = doc.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("tools"), dict):
            meta["tools"] = tools_object_to_array(meta["tools"], "/metadata/tools", ctx, self.id)
        for i, v in enumerate(doc.get("vulnerabilities") or []):
            if isinstance(v, dict) and isinstance(v.get("tools"), dict):
                v["tools"] = tools_object_to_array(v["tools"], f"/vulnerabilities/{i}/tools", ctx, self.id)


@register
class ToolsLegacyArrayAtTarget(Rule):
    id = "CDX15-001P"
    title = "metadata.tools as legacy array for importers that need it"
    description = "The profile sets tools_form: legacy-array, so metadata.tools was written in the legacy array form even though this version also accepts the object form."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if ctx.profile.tools_form != "legacy-array":
            return
        meta = doc.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("tools"), dict):
            meta["tools"] = tools_object_to_array(meta["tools"], "/metadata/tools", ctx, self.id)


@register
class Lifecycles(Rule):
    id = "CDX15-002"
    title = "metadata.lifecycles to property"
    description = "metadata.lifecycles (1.5) was kept as the property sbom-fixer:lifecycles."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        meta = doc.get("metadata")
        if isinstance(meta, dict) and "lifecycles" in meta:
            move_to_property(meta, "lifecycles", "sbom-fixer:lifecycles", "/metadata", ctx.log, self.id,
                             "lifecycles does not exist in 1.4")


@register
class FormulationAnnotations(Rule):
    id = "CDX15-003"
    title = "Remove formulation and annotations"
    description = "Top-level formulation and annotations (1.5) have no 1.4 equivalent and were removed."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for key in ("formulation", "annotations"):
            if key in doc:
                ctx.log.add(self.id, f"/{key}", "removed", doc.pop(key), None, DATA_LOSS, f"{key} does not exist in 1.4")


_TYPE_MAP_14 = {"device-driver": "device", "data": "file", "platform": "application", "machine-learning-model": "application"}


@register
class ComponentTypes15(Rule):
    id = "CDX15-004"
    title = "1.5-only component types"
    description = "Component types added in 1.5 were mapped to their nearest 1.4 type (device-driver to device, data to file, platform and machine-learning-model to application); the original type is kept in a property."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            t = c.get("type")
            if t in _TYPE_MAP_14:
                c["type"] = _TYPE_MAP_14[t]
                add_property(c, "sbom-fixer:originalType", t)
                ctx.log.add(self.id, f"{path}/type", "replaced", t, c["type"], WARN, f"Type '{t}' does not exist in 1.4")


@register
class ModelCardData(Rule):
    id = "CDX15-005"
    title = "Remove modelCard and component data"
    description = "component.modelCard and component.data (1.5) were removed."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            for key in ("modelCard", "data"):
                if key in c:
                    ctx.log.add(self.id, f"{path}/{key}", "removed", c.pop(key), None, DATA_LOSS, f"{key} does not exist in 1.4")


@register
class EvidenceExtras(Rule):
    id = "CDX15-006"
    title = "Remove evidence identity, occurrences and callstack"
    description = "evidence.identity, occurrences and callstack (1.5) were removed; evidence.licenses and copyright were kept."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            ev = c.get("evidence")
            if not isinstance(ev, dict):
                continue
            for key in ("identity", "occurrences", "callstack"):
                if key in ev:
                    ctx.log.add(self.id, f"{path}/evidence/{key}", "removed", ev.pop(key), None, WARN, f"evidence.{key} does not exist in 1.4")
            if not ev:
                c.pop("evidence")


@register
class VulnerabilityFields(Rule):
    id = "CDX15-007"
    title = "Remove 1.5-only vulnerability fields"
    description = "Vulnerability fields rejected, proofOfConcept and workaround (1.5) were removed."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for i, v in enumerate(doc.get("vulnerabilities") or []):
            if not isinstance(v, dict):
                continue
            for key in ("rejected", "proofOfConcept", "workaround"):
                if key in v:
                    ctx.log.add(self.id, f"/vulnerabilities/{i}/{key}", "removed", v.pop(key), None, INFO, f"{key} does not exist in 1.4")


@register
class ExternalRefTypes15(Rule):
    id = "CDX15-008"
    title = "1.5-only external reference types to other"
    description = "External reference types added in 1.5 became 'other'; the original type is kept in comment."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        external_ref_types_to_other(doc, "1.4", ctx.log, self.id)


@register
class RootProperties(Rule):
    id = "CDX15-009"
    title = "Root properties to metadata.properties"
    description = "CycloneDX 1.4 has no root-level properties; they were moved to metadata.properties."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if "properties" in doc:
            props = doc.pop("properties")
            meta = doc.setdefault("metadata", {})
            meta.setdefault("properties", []).extend(props if isinstance(props, list) else [])
            ctx.log.add(self.id, "/properties", "moved", props, "metadata.properties", INFO, "1.4 has no root properties")


@register
class BomVersionRequired(Rule):
    id = "CDX15-010"
    title = "BOM version is required"
    description = "CycloneDX 1.4 and older require the root field version (the BOM revision); it was set to 1."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if "version" not in doc:
            doc["version"] = 1
            ctx.log.add(self.id, "/version", "added", None, 1, INFO, "version is required in 1.4")


@register
class Enums15(Rule):
    id = "CDX15-011"
    title = "1.5-only enum values"
    description = "Enum values added in 1.5 were mapped: composition aggregate incomplete_* became incomplete, rating methods CVSSv4 and SSVC became other."
    case, kind, hop = "B", HOP, HOP_15

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for i, comp in enumerate(doc.get("compositions") or []):
            agg = comp.get("aggregate") if isinstance(comp, dict) else None
            if isinstance(agg, str) and agg.startswith("incomplete_"):
                comp["aggregate"] = "incomplete"
                ctx.log.add(self.id, f"/compositions/{i}/aggregate", "replaced", agg, "incomplete", INFO, f"'{agg}' does not exist in 1.4")
        for i, v in enumerate(doc.get("vulnerabilities") or []):
            for j, r in enumerate((v or {}).get("ratings") or []):
                if isinstance(r, dict) and r.get("method") in ("CVSSv4", "SSVC"):
                    old = r["method"]
                    r["method"] = "other"
                    ctx.log.add(self.id, f"/vulnerabilities/{i}/ratings/{j}/method", "replaced", old, "other", INFO,
                                f"Rating method {old} does not exist in 1.4")
        for path, s in iter_services(doc):
            if "trustZone" in s:
                move_to_property(s, "trustZone", "sbom-fixer:trustZone", path, ctx.log, self.id, "trustZone does not exist in 1.4")
