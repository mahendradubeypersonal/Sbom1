"""Sanitizers (case C): fixes the importer needs at every level, plus final rules (SAN-060, SAN-090)."""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import quote

from packageurl import PackageURL

from .. import __version__
from ..changes import INFO, WARN
from ..jsonutil import iter_components
from ..licenses import canonical_id, looks_like_expression, normalize_expression, spdx_ids
from ..purlmap import URL_RE, purl_from_url, slots
from .base import FINAL, SANITIZE, Ctx, Rule, register
from .repair import format_utc, parse_datetime

_KEEP_EMPTY = {"dependsOn", "components"}


@register
class Nulls(Rule):
    id = "SAN-001"
    title = "Remove null values"
    description = "null values are invalid in every SBOM schema; they were removed."
    case, kind, specs = "C", SANITIZE, ("cyclonedx", "spdx")

    def apply(self, doc: Any, ctx: Ctx) -> None:
        def rec(node: Any, path: str) -> None:
            if isinstance(node, dict):
                for k in list(node):
                    if node[k] is None:
                        node.pop(k)
                        ctx.log.add(self.id, f"{path}/{k}", "removed", None, None, INFO, "null value")
                    else:
                        rec(node[k], f"{path}/{k}")
            elif isinstance(node, list):
                for i in range(len(node) - 1, -1, -1):
                    if node[i] is None:
                        node.pop(i)
                        ctx.log.add(self.id, f"{path}/{i}", "removed", None, None, INFO, "null value in array")
                    else:
                        rec(node[i], f"{path}/{i}")

        rec(doc, "")


@register
class EmptyContainers(Rule):
    id = "SAN-002"
    title = "Remove empty arrays and objects"
    description = "Empty arrays and objects in optional fields were removed (dependsOn is kept, because an empty dependsOn means 'no dependencies')."
    case, kind, specs = "C", SANITIZE, ("cyclonedx",)

    def apply(self, doc: Any, ctx: Ctx) -> None:
        def rec(node: Any, path: str) -> None:
            if isinstance(node, dict):
                for k in list(node):
                    v = node[k]
                    rec(v, f"{path}/{k}")
                    if (v == [] or v == {}) and k not in _KEEP_EMPTY:
                        node.pop(k)
                        ctx.log.add(self.id, f"{path}/{k}", "removed", v, None, INFO, "empty value")
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    rec(v, f"{path}/{i}")

        rec(doc, "")


@register
class SerialNumberMissing(Rule):
    id = "SAN-003"
    title = "Add a serialNumber"
    description = "The BOM had no serialNumber; a deterministic urn:uuid derived from the input was added."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if not doc.get("serialNumber"):
            new = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "sbom-fixer:" + ctx.source_sha256))
            doc["serialNumber"] = new
            ctx.log.add(self.id, "/serialNumber", "added", None, new, INFO, "serialNumber identifies this BOM")


@register
class TimestampUtc(Rule):
    id = "SAN-004"
    title = "Timestamp in UTC"
    description = "metadata.timestamp had a timezone offset; it was normalized to UTC 'Z' form. A missing timestamp is reported, never invented."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        meta = doc.get("metadata")
        ts = meta.get("timestamp") if isinstance(meta, dict) else None
        if ts is None:
            ctx.log.note(self.id, "/metadata/timestamp", "No timestamp; NTIA requires one. Set it at the source.")
            return
        if isinstance(ts, str) and not ts.endswith("Z"):
            dt, assumed = parse_datetime(ts)
            if dt is not None and not assumed:
                new = format_utc(dt)
                if new != ts:
                    meta["timestamp"] = new
                    ctx.log.add(self.id, "/metadata/timestamp", "replaced", ts, new, INFO, "Normalized to UTC")


def _try_purl(text: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(text)
    except ValueError:
        return None


_VCS_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")


@register
class PurlIsUrl(Rule):
    id = "SAN-009"
    title = "purl written as a URL"
    description = ("The purl field held a web URL (https://...), which is not a purl. A registry URL was converted to the exact "
                   "purl; any other URL was moved to externalReferences and the component reported as not scannable.")
    source_fix = "Write a package URL (pkg:type/namespace/name@version) in the purl field; put web links in externalReferences."
    case, kind, specs = "C", SANITIZE, ("cyclonedx", "spdx")

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for slot in slots(doc, ctx.spec):
            url = slot.purl
            if url is None or not URL_RE.match(url.strip()):
                continue
            new = purl_from_url(url, slot.version)
            if new is not None:
                text = new.to_string()
                slot.set_purl(text)
                ctx.log.add(self.id, slot.purl_path, "replaced", url, text, INFO, "Registry URL converted to its purl")
            elif ctx.spec == "cyclonedx":
                c = slot.package
                c.pop("purl")
                kind = "vcs" if any(h in url.lower() for h in _VCS_HOSTS) else "distribution"
                refs = c.setdefault("externalReferences", [])
                if not any(isinstance(r, dict) and r.get("url") == url for r in refs):
                    refs.append({"type": kind, "url": url})
                ctx.log.add(self.id, slot.purl_path, "moved", url, f"{slot.path}/externalReferences ({kind})", WARN,
                            "URL is not a purl; moved to externalReferences, component will not be scanned")
            else:
                ctx.log.note(self.id, slot.purl_path, f"purl '{url}' is a URL, not a purl; package will not be scanned")


@register
class PurlParse(Rule):
    id = "SAN-010"
    title = "purls parse"
    description = "A purl did not parse; characters were percent-encoded where that made it valid, otherwise the purl was removed and the component reported as not scannable."
    source_fix = "Report the generator bug; purls must follow the package-url specification."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in iter_components(doc, include_metadata=True):
            p = c.get("purl")
            if not isinstance(p, str) or _try_purl(p) is not None:
                continue
            fixed = quote(p.strip(), safe=":/@?=&#%+")
            if _try_purl(fixed) is not None:
                c["purl"] = fixed
                ctx.log.add(self.id, f"{path}/purl", "replaced", p, fixed, INFO, "purl characters percent-encoded")
            else:
                c.pop("purl")
                ctx.log.add(self.id, f"{path}/purl", "removed", p, None, WARN, "purl does not parse; component will not be scanned")


_ECOSYSTEM_HINTS = {
    "java-archive": "maven", "jar": "maven", "pom": "maven", "gradle": "maven", "maven": "maven",
    "npm": "npm", "node-pkg": "npm", "yarn": "npm", "pnpm": "npm",
    "python": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "wheel": "pypi",
    "go-module": "golang", "gomod": "golang", "gobinary": "golang",
    "nuget": "nuget", "dotnet-core": "nuget", "gem": "gem", "bundler": "gem", "cargo": "cargo", "composer": "composer",
}
_HINT_PROPS = ("syft:package:type", "aquasecurity:trivy:PkgType", "cdx:npm:package:type", "type")


def _ecosystem(c: dict[str, Any]) -> str | None:
    ref = c.get("bom-ref")
    if isinstance(ref, str) and ref.startswith("pkg:") and _try_purl(ref):
        return "from-bom-ref"
    for prop in c.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") in _HINT_PROPS:
            eco = _ECOSYSTEM_HINTS.get(str(prop.get("value", "")).lower())
            if eco:
                return eco
    return None


@register
class PurlMissing(Rule):
    id = "SAN-011"
    title = "Build missing purls when the ecosystem is certain"
    description = "A component had no purl. One was built when the ecosystem was certain (bom-ref is a purl, or a generator property names the package type); otherwise the component is reported as not scannable."
    source_fix = "Use a generator that writes purls for every package component."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, c in iter_components(doc):
            if c.get("purl") or c.get("type") not in (None, "library", "framework", "application"):
                continue
            eco = _ecosystem(c)
            name, version = c.get("name"), c.get("version")
            new: str | None = None
            if eco == "from-bom-ref":
                new = c["bom-ref"]
            elif eco and name and version:
                ns = c.get("group") or None
                if eco == "maven" and not ns:
                    eco = None
                if eco:
                    new = PackageURL(type=eco, namespace=ns, name=name, version=str(version)).to_string()
            if new:
                c["purl"] = new
                ctx.log.add(self.id, f"{path}/purl", "added", None, new, INFO, "purl built from verified component data")
            else:
                ctx.log.note(self.id, path, f"Component '{name}' has no purl and will not be scanned")


_UNSCANNED_TYPES = {"generic", "github", "docker", "oci", "swid", "bitbucket"}


@register
class PurlTypesNotScanned(Rule):
    id = "SAN-012"
    title = "Report purl types scanners usually ignore"
    description = "Components with purl types such as generic or github are kept but counted separately, because SCA scanners usually do not match them."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if ctx.profile.purl is not None:
            return  # the profile lists the consumer's purl types; CXP-020/021 report them instead
        for path, c in iter_components(doc):
            p = _try_purl(c["purl"]) if isinstance(c.get("purl"), str) else None
            if p is not None and p.type in _UNSCANNED_TYPES:
                ctx.log.note(self.id, path, f"purl type '{p.type}' is usually not matched by SCA scanners", INFO)


def _tool_entry(ctx: Ctx) -> tuple[Any, str]:
    """metadata.tools in the form the current version (and profile) expects, plus a short description."""
    if _version_at_least(ctx.version, "1.5") and ctx.profile.tools_form != "legacy-array":
        return {"components": [{"type": "application", "name": "sbom-fixer", "version": __version__}]}, "object form"
    return [{"vendor": "sbom-fixer", "name": "sbom-fixer", "version": __version__}], "array form"


def _has_tool(tools: Any) -> bool:
    if isinstance(tools, dict):
        return bool(tools.get("components") or tools.get("services"))
    return isinstance(tools, list) and bool(tools)


@register
class ToolsMissing(Rule):
    id = "SAN-013"
    title = "Add a default tool when none is named"
    description = ("The SBOM named no generating tool (CycloneDX metadata.tools, SPDX creationInfo creators 'Tool:'); "
                   "sbom-fixer was added as the default tool, because some importers expect at least one.")
    source_fix = "Let the generator record itself in metadata.tools (CycloneDX) or creationInfo.creators (SPDX)."
    case, kind, specs = "C", SANITIZE, ("cyclonedx", "spdx")

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if not ctx.profile.ensure_tools:
            return
        if ctx.spec == "spdx":
            info = doc.get("creationInfo")
            if not isinstance(info, dict):
                return
            creators = info.get("creators")
            if isinstance(creators, list) and any(isinstance(c, str) and c.startswith("Tool:") for c in creators):
                return
            new = f"Tool: sbom-fixer-{__version__}"
            if isinstance(creators, list):
                creators.append(new)
                ctx.log.add(self.id, f"/creationInfo/creators/{len(creators) - 1}", "added", None, new, INFO,
                            "No 'Tool:' creator; sbom-fixer added as the default tool")
            else:
                info["creators"] = [new]
                ctx.log.add(self.id, "/creationInfo/creators", "added", creators, [new], INFO,
                            "No creators; sbom-fixer added as the default tool")
            return
        meta = doc.setdefault("metadata", {})
        if not isinstance(meta, dict) or _has_tool(meta.get("tools")):
            return
        tools, form = _tool_entry(ctx)
        old = meta.get("tools")
        meta["tools"] = tools
        ctx.log.add(self.id, "/metadata/tools", "added", old, tools, INFO, f"No tool named; sbom-fixer added as the default tool ({form})")


def _all_refs(doc: dict[str, Any]) -> set[str]:
    refs = {c["bom-ref"] for _, c in iter_components(doc, include_metadata=True) if isinstance(c.get("bom-ref"), str)}

    def svc(s: Any) -> None:
        for x in s or []:
            if isinstance(x, dict):
                if isinstance(x.get("bom-ref"), str):
                    refs.add(x["bom-ref"])
                svc(x.get("services"))

    svc(doc.get("services"))
    return refs


@register
class DuplicateRefs(Rule):
    id = "SAN-020"
    title = "Unique bom-refs"
    description = "Several components shared one bom-ref; duplicates were renamed with a #2, #3 suffix (dependencies keep pointing to the first)."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        seen: dict[str, int] = {}
        for path, c in iter_components(doc, include_metadata=True):
            ref = c.get("bom-ref")
            if not isinstance(ref, str):
                continue
            if ref in seen:
                seen[ref] += 1
                new = f"{ref}#{seen[ref]}"
                c["bom-ref"] = new
                ctx.log.add(self.id, f"{path}/bom-ref", "replaced", ref, new, WARN, "bom-ref must be unique")
            else:
                seen[ref] = 1


@register
class DanglingDependencies(Rule):
    id = "SAN-021"
    title = "Remove dependency edges that point to nothing"
    description = "Dependency entries referred to bom-refs that do not exist in the document; those edges were removed."
    source_fix = "The generator writes dependency refs for components it does not list; report it upstream."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        deps = doc.get("dependencies")
        if not isinstance(deps, list):
            return
        refs = _all_refs(doc)
        keep = []
        for i, d in enumerate(deps):
            if not isinstance(d, dict):
                keep.append(d)
                continue
            if d.get("ref") not in refs:
                ctx.log.add(self.id, f"/dependencies/{i}", "removed", d, None, WARN, f"ref '{d.get('ref')}' does not exist")
                continue
            if isinstance(d.get("dependsOn"), list):
                good = []
                for j, r in enumerate(d["dependsOn"]):
                    if r in refs:
                        good.append(r)
                    else:
                        ctx.log.add(self.id, f"/dependencies/{i}/dependsOn/{j}", "removed", r, None, WARN, f"'{r}' does not exist")
                d["dependsOn"] = list(dict.fromkeys(good))
            keep.append(d)
        doc["dependencies"] = keep


@register
class DuplicatePurls(Rule):
    id = "SAN-022"
    title = "Merge components with the same purl"
    description = "Top-level components with an identical purl were merged into the first one; dependency references were rewritten to it."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        comps = doc.get("components")
        if not isinstance(comps, list):
            return
        first: dict[str, dict[str, Any]] = {}
        rewrite: dict[str, str] = {}
        keep = []
        for i, c in enumerate(comps):
            p = c.get("purl") if isinstance(c, dict) else None
            if isinstance(p, str) and p in first and not c.get("components"):
                target = first[p]
                if isinstance(c.get("bom-ref"), str) and isinstance(target.get("bom-ref"), str):
                    rewrite[c["bom-ref"]] = target["bom-ref"]
                ctx.log.add(self.id, f"/components/{i}", "removed", c, f"merged into {target.get('bom-ref') or p}", INFO,
                            "Duplicate component with the same purl")
                continue
            if isinstance(p, str):
                first.setdefault(p, c)
            keep.append(c)
        doc["components"] = keep
        if rewrite and isinstance(doc.get("dependencies"), list):
            merged: dict[str, dict[str, Any]] = {}
            for d in doc["dependencies"]:
                if not isinstance(d, dict) or not isinstance(d.get("ref"), str):
                    continue
                ref = str(rewrite.get(d["ref"]) or d["ref"])
                on = [rewrite.get(r, r) for r in d.get("dependsOn") or []]
                if ref in merged:
                    merged[ref]["dependsOn"] = list(dict.fromkeys(merged[ref].get("dependsOn", []) + on))
                else:
                    nd = dict(d, ref=ref)
                    if "dependsOn" in d:
                        nd["dependsOn"] = list(dict.fromkeys(on))
                    merged[ref] = nd
            doc["dependencies"] = list(merged.values())


@register
class LicenseIds(Rule):
    id = "SAN-030"
    title = "License names that are really SPDX IDs"
    description = "A license name was an SPDX ID or an unambiguous alias of one (for example 'Apache 2.0'); it was written as the SPDX id."
    source_fix = "Use SPDX license IDs in package metadata."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, _entry, lic in _license_objects(doc):
            name = lic.get("name")
            if "id" in lic or not isinstance(name, str):
                continue
            cid = canonical_id(name)
            if cid and cid in spdx_ids():
                lic.pop("name")
                lic["id"] = cid
                ctx.log.add(self.id, f"{path}/license", "converted", {"name": name}, {"id": cid}, INFO, f"'{name}' is SPDX license {cid}")


@register
class LicenseExpressions(Rule):
    id = "SAN-031"
    title = "License expressions parse"
    description = "A license expression did not parse as SPDX; it was normalized when every license in it is known, otherwise kept as a license name."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for path, obj in _licenses_arrays(doc):
            lics = obj["licenses"]
            for i, entry in enumerate(lics):
                if not isinstance(entry, dict) or not isinstance(entry.get("expression"), str):
                    continue
                expr = entry["expression"]
                norm = normalize_expression(expr)
                if norm is None:
                    if len(lics) == 1 or not looks_like_expression(expr):
                        new = {"license": {"name": expr}}
                        lics[i] = new
                        ctx.log.add(self.id, f"{path}/licenses/{i}", "converted", entry, new, INFO,
                                    "Expression is not valid SPDX; kept as a license name")
                elif norm != expr:
                    entry["expression"] = norm
                    ctx.log.add(self.id, f"{path}/licenses/{i}/expression", "replaced", expr, norm, INFO, "Normalized SPDX expression")


def _licenses_arrays(doc: Any, path: str = "") -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []

    def rec(node: Any, p: str) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("licenses"), list):
                out.append((p, node))
            for k, v in node.items():
                rec(v, f"{p}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                rec(v, f"{p}/{i}")

    rec(doc, path)
    return out


def _license_objects(doc: Any) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    out = []
    for path, obj in _licenses_arrays(doc):
        for i, entry in enumerate(obj["licenses"]):
            if isinstance(entry, dict) and isinstance(entry.get("license"), dict):
                out.append((f"{path}/licenses/{i}", entry, entry["license"]))
    return out


@register
class FlattenNested(Rule):
    id = "SAN-050"
    title = "Flatten nested components"
    description = "Nested components were moved to the top-level components list, which the profile requires."
    case, kind = "C", SANITIZE

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if not ctx.profile.flatten_nested_components or not isinstance(doc.get("components"), list):
            return
        flat: list[Any] = []

        def rec(comps: list[Any], base: str) -> None:
            for i, c in enumerate(comps):
                flat.append(c)
                if isinstance(c, dict) and isinstance(c.get("components"), list) and c["components"]:
                    children = c.pop("components")
                    ctx.log.add(self.id, f"{base}/{i}/components", "moved", f"{len(children)} components", "/components", INFO,
                                "Nested components moved to the top level")
                    rec(children, f"{base}/{i}/components")

        rec(list(doc["components"]), "/components")
        doc["components"] = flat


@register
class SignatureRemoved(Rule):
    id = "SAN-060"
    title = "Remove an invalidated signature"
    description = "The document carried a signature; any change invalidates it, so it was removed. Re-sign the output if signatures are required."
    case, kind = "C", FINAL

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if "signature" in doc and len(ctx.log) > 0:
            ctx.log.add(self.id, "/signature", "removed", doc.pop("signature"), None, WARN, "Signature no longer matches the content")


@register
class Provenance(Rule):
    id = "SAN-090"
    title = "Record sbom-fixer provenance"
    description = "sbom-fixer was added to metadata.tools and metadata.properties record the source version and hash, so the output can be traced to its original."
    case, kind = "C", FINAL

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if not ctx.profile.provenance or len(ctx.log) == 0:
            return
        meta = doc.setdefault("metadata", {})
        tool = {"name": "sbom-fixer", "version": __version__}
        tools = meta.get("tools")
        listed = tools.get("components") if isinstance(tools, dict) else tools
        if isinstance(listed, list) and any(isinstance(t, dict) and t.get("name") == "sbom-fixer" for t in listed):
            pass  # already named, for example by SAN-013
        elif isinstance(tools, dict):
            tools.setdefault("components", []).append({"type": "application", "name": "sbom-fixer", "version": __version__})
        elif isinstance(tools, list):
            tools.append(tool)
        elif _version_at_least(ctx.version, "1.5") and ctx.profile.tools_form != "legacy-array":
            meta["tools"] = {"components": [{"type": "application", "name": "sbom-fixer", "version": __version__}]}
        else:
            meta["tools"] = [tool]
        props = meta.setdefault("properties", [])
        props.extend([
            {"name": "sbom-fixer:version", "value": __version__},
            {"name": "sbom-fixer:sourceSpecVersion", "value": ctx.declared},
            {"name": "sbom-fixer:sourceSha256", "value": ctx.source_sha256},
            {"name": "sbom-fixer:profile", "value": ctx.profile.name},
        ])
        ctx.log.add(self.id, "/metadata", "added", None, "sbom-fixer provenance", INFO, "Output records how it was produced")


def _version_at_least(v: str, minimum: str) -> bool:
    return tuple(map(int, v.split("."))) >= tuple(map(int, minimum.split(".")))
