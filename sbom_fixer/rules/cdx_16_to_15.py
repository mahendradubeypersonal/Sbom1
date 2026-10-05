"""Hop rules CycloneDX 1.6 -> 1.5 (CDX16-001..011), confirmed against the 1.5/1.6 schema diff."""

from __future__ import annotations

from typing import Any

from ..changes import DATA_LOSS, INFO, WARN
from .base import HOP, Ctx, Rule, register
from .hop_common import (
    all_components,
    external_ref_types_to_other,
    iter_objects_with,
    iter_services,
    move_to_property,
)

HOP_16 = ("1.6", "1.5")


@register
class MetadataManufacturer(Rule):
    id = "CDX16-001"
    title = "metadata.manufacturer to metadata.manufacture"
    description = "metadata.manufacturer (1.6) was renamed to metadata.manufacture, its 1.5 equivalent."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        meta = doc.get("metadata")
        if isinstance(meta, dict) and "manufacturer" in meta:
            value = meta.pop("manufacturer")
            if "manufacture" in meta:
                ctx.log.add(self.id, "/metadata/manufacturer", "removed", value, None, WARN,
                            "metadata.manufacture already present; 1.6 manufacturer dropped")
            else:
                meta["manufacture"] = value
                ctx.log.add(self.id, "/metadata/manufacturer", "renamed", value, "metadata.manufacture", INFO,
                            "1.5 calls this field manufacture")


@register
class ComponentManufacturer(Rule):
    id = "CDX16-002"
    title = "component.manufacturer to supplier"
    description = "component.manufacturer (1.6) was moved to supplier when supplier was empty, otherwise dropped."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            if "manufacturer" not in c:
                continue
            value = c.pop("manufacturer")
            if not c.get("supplier"):
                c["supplier"] = value
                ctx.log.add(self.id, f"{path}/manufacturer", "moved", value, "supplier", INFO, "1.5 has no component manufacturer")
            else:
                ctx.log.add(self.id, f"{path}/manufacturer", "removed", value, None, WARN,
                            "Supplier already set; 1.5 has no component manufacturer")


@register
class ComponentAuthors(Rule):
    id = "CDX16-003"
    title = "component.authors to author"
    description = "component.authors (1.6, a list of contacts) was joined into the 1.5 string field author."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            if "authors" not in c:
                continue
            authors = c.pop("authors")
            names = [a.get("name") or a.get("email") for a in authors if isinstance(a, dict)] if isinstance(authors, list) else []
            joined = ", ".join(n for n in names if n)
            if joined and not c.get("author"):
                c["author"] = joined
                ctx.log.add(self.id, f"{path}/authors", "converted", authors, joined, INFO, "Joined into author")
            else:
                ctx.log.add(self.id, f"{path}/authors", "removed", authors, None, WARN,
                            "author already set or no names; 1.5 has no authors list")


@register
class EvidenceIdentityArray(Rule):
    id = "CDX16-004"
    title = "evidence.identity array to single object"
    description = "evidence.identity was an array (1.6 form); the entry with the highest confidence was kept as the single 1.5 object."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            ev = c.get("evidence")
            if not isinstance(ev, dict) or not isinstance(ev.get("identity"), list):
                continue
            items = [x for x in ev["identity"] if isinstance(x, dict)]
            if not items:
                ctx.log.add(self.id, f"{path}/evidence/identity", "removed", ev.pop("identity"), None, INFO, "Empty identity list")
                continue
            best = max(items, key=lambda x: float(x.get("confidence", 0) or 0))
            old = ev["identity"]
            ev["identity"] = best
            sev = WARN if len(items) > 1 else INFO
            ctx.log.add(self.id, f"{path}/evidence/identity", "converted", old, best, sev,
                        f"Kept the highest-confidence entry of {len(items)}")


@register
class LicenseAcknowledgement(Rule):
    id = "CDX16-005"
    title = "Remove license acknowledgement"
    description = "license acknowledgement (declared/concluded, 1.6) does not exist in 1.5 and was removed."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, obj in iter_objects_with(doc, "licenses"):
            lics = obj.get("licenses")
            if not isinstance(lics, list):
                continue
            for i, entry in enumerate(lics):
                if not isinstance(entry, dict):
                    continue
                targets = [(f"{path}/licenses/{i}", entry)]
                if isinstance(entry.get("license"), dict):
                    targets.append((f"{path}/licenses/{i}/license", entry["license"]))
                for p, t in targets:
                    if "acknowledgement" in t:
                        ctx.log.add(self.id, f"{p}/acknowledgement", "removed", t.pop("acknowledgement"), None, INFO,
                                    "acknowledgement does not exist in 1.5")


@register
class OmniborSwhid(Rule):
    id = "CDX16-006"
    title = "omniborId and swhid to properties"
    description = "component.omniborId and swhid (1.6) were kept as properties sbom-fixer:omniborId / sbom-fixer:swhid."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in all_components(doc):
            for key in ("omniborId", "swhid"):
                if key in c:
                    move_to_property(c, key, f"sbom-fixer:{key}", path, ctx.log, self.id, f"{key} does not exist in 1.5")


@register
class Tags(Rule):
    id = "CDX16-007"
    title = "tags to property"
    description = "tags (1.6) on components and services were kept as one property sbom-fixer:tags."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, obj in all_components(doc) + list(iter_services(doc)):
            if "tags" in obj:
                tags = obj.pop("tags")
                text = ", ".join(map(str, tags)) if isinstance(tags, list) else str(tags)
                obj.setdefault("properties", []).append({"name": "sbom-fixer:tags", "value": text})
                ctx.log.add(self.id, f"{path}/tags", "moved", tags, "properties[sbom-fixer:tags]", INFO, "tags does not exist in 1.5")


@register
class DeclarationsDefinitions(Rule):
    id = "CDX16-008"
    title = "Remove declarations and definitions"
    description = "Top-level declarations and definitions (1.6 attestations and standards) have no 1.5 equivalent and were removed."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for key in ("declarations", "definitions"):
            if key in doc:
                ctx.log.add(self.id, f"/{key}", "removed", doc.pop(key), None, DATA_LOSS, f"{key} does not exist in 1.5")


@register
class DependencyProvides(Rule):
    id = "CDX16-009"
    title = "Remove dependencies[].provides"
    description = "dependencies[].provides (1.6) does not exist in 1.5 and was removed."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for i, d in enumerate(doc.get("dependencies") or []):
            if isinstance(d, dict) and "provides" in d:
                ctx.log.add(self.id, f"/dependencies/{i}/provides", "removed", d.pop("provides"), None, DATA_LOSS,
                            "provides does not exist in 1.5")


@register
class CryptoAssets(Rule):
    id = "CDX16-010"
    title = "Remove cryptographic-asset components"
    description = "Components of type cryptographic-asset (1.6) are not packages a scanner can match and were removed with their dependency edges."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        removed_refs: set[str] = set()

        def strip(comps: Any, base: str) -> Any:
            if not isinstance(comps, list):
                return comps
            keep = []
            for i, c in enumerate(comps):
                if isinstance(c, dict) and c.get("type") == "cryptographic-asset":
                    if c.get("bom-ref"):
                        removed_refs.add(c["bom-ref"])
                    ctx.log.add(self.id, f"{base}/{i}", "removed", c, None, DATA_LOSS,
                                "cryptographic-asset components do not exist in 1.5")
                    continue
                if isinstance(c, dict) and "components" in c:
                    c["components"] = strip(c["components"], f"{base}/{i}/components")
                keep.append(c)
            return keep

        if "components" in doc:
            doc["components"] = strip(doc["components"], "/components")
        for path, c in all_components(doc):
            if "cryptoProperties" in c:
                ctx.log.add(self.id, f"{path}/cryptoProperties", "removed", c.pop("cryptoProperties"), None, DATA_LOSS,
                            "cryptoProperties does not exist in 1.5")
        if removed_refs and isinstance(doc.get("dependencies"), list):
            deps = []
            for d in doc["dependencies"]:
                if isinstance(d, dict) and d.get("ref") in removed_refs:
                    continue
                if isinstance(d, dict) and isinstance(d.get("dependsOn"), list):
                    d["dependsOn"] = [r for r in d["dependsOn"] if r not in removed_refs]
                deps.append(d)
            doc["dependencies"] = deps


@register
class ExternalRefTypes16(Rule):
    id = "CDX16-011"
    title = "1.6-only external reference types to other"
    description = "External reference types added in 1.6 (source-distribution, digital-signature, electronic-signature, rfc-9116) became 'other'; the original type is kept in comment."
    case, kind, hop = "B", HOP, HOP_16

    def apply(self, doc: Any, ctx: Ctx) -> None:
        external_ref_types_to_other(doc, "1.5", ctx.log, self.id)
