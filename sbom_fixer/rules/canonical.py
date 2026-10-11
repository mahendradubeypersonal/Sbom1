"""Checkmarx canonical form (CXN-*): reduce a repaired CycloneDX SBOM to the shape Checkmarx One SCA ingests reliably.

A schema-valid SBOM is not always ingested by Checkmarx: extra fields (hashes with SHA3 algorithms, evidence,
properties, externalReferences, services, vulnerabilities, the 1.5+ tools object, purl qualifiers, ...) make some
uploads fail or come back with 0 packages. The form below is the one that imports reliably (the cyclonedx-dotnet
layout): every component is {bom-ref, type, name, version, purl, licenses}, metadata is {timestamp, tools, component},
dependencies only point at components that exist.

These rules run once, after the repair and the Checkmarx purl rules (CXP-*), at the final version and only when the
profile has a `canonical:` section. Execution order is registration order. The spec version is never changed.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from packageurl import PackageURL

from ..changes import INFO, WARN
from ..ecosystem import detect_ecosystem
from ..purlmap import URL_RE, try_purl
from .base import Ctx, Rule, register
from .sanitize import _ECOSYSTEM_HINTS, _HINT_PROPS, _version_at_least
from .sanitize_purl import _build

CANONICAL = "canonical"

TOP_LEVEL = ("bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "dependencies")
_MISSING = object()


class CanonicalRule(Rule):
    case, kind, specs = "C", CANONICAL, ("cyclonedx",)

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if ctx.profile.canonical is None or not isinstance(doc, dict):
            return
        self.run(doc, ctx)

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        raise NotImplementedError


def _components(doc: dict[str, Any]) -> list[dict[str, Any]]:
    comps = doc.get("components")
    return [c for c in comps if isinstance(c, dict)] if isinstance(comps, list) else []


def _str(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = str(value).strip()
    return text or None


@register
class FlattenAll(CanonicalRule):
    id = "CXN-001"
    title = "All components at the top level"
    description = ("Components nested inside other components (or inside metadata.component) were moved to the "
                   "top-level components list; Checkmarx reads only the top level.")

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        flat: list[Any] = []

        def rec(comps: list[Any], base: str) -> None:
            for i, c in enumerate(comps):
                if not isinstance(c, dict):
                    continue
                flat.append(c)
                children = c.pop("components", None)
                if isinstance(children, list) and children:
                    ctx.log.add(self.id, f"{base}/{i}/components", "moved", f"{len(children)} components",
                                "/components", INFO, "Nested components moved to the top level")
                    rec(children, f"{base}/{i}/components")

        meta = doc.get("metadata")
        root = meta.get("component") if isinstance(meta, dict) else None
        if isinstance(root, dict) and isinstance(root.get("components"), list):
            children = root.pop("components")
            if children:
                ctx.log.add(self.id, "/metadata/component/components", "moved", f"{len(children)} components",
                            "/components", INFO, "Components nested in metadata.component moved to the top level")
            rec(children, "/metadata/component/components")
        if isinstance(doc.get("components"), list):
            rec(list(doc["components"]), "/components")
        if flat or "components" in doc:
            doc["components"] = flat


def _ecosystem(c: dict[str, Any]) -> str | None:
    """Package ecosystem when the component data says so; None when it is a guess."""
    for prop in c.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") in _HINT_PROPS:
            eco = _ECOSYSTEM_HINTS.get(str(prop.get("value", "")).lower())
            if eco:
                return eco
    name = c.get("name")
    if isinstance(name, str) and name.startswith("@") and "/" in name:
        return "npm"
    return None


_URL_IN_PURL = re.compile(r"https?(:|%3a)", re.IGNORECASE)


def has_url(purl: str) -> bool:
    """True when a purl carries a web URL anywhere (type, namespace, name, qualifiers), also percent-encoded."""
    return bool(_URL_IN_PURL.search(purl))


def _dashes(name: str) -> str:
    """Package name for a purl: a URL becomes its last path segment (or host), whitespace becomes dashes."""
    text = name.strip()
    if URL_RE.match(text):
        parts = urlsplit(text)
        segs = [x for x in parts.path.split("/") if x]
        text = unquote(segs[-1]) if segs else (parts.hostname or "package")
    return re.sub(r"\s+", "-", text) or "package"


def canonical_purl(c: dict[str, Any], keep_qualifiers: bool, fallback: str) -> tuple[str | None, str]:
    """(purl, how) for a component. how: kept | normalized | from-bom-ref | built | generic | none.

    The result never contains a web URL (http/https, also percent-encoded): Checkmarx cannot match such a purl.
    """
    purl, how = _canonical_purl(c, keep_qualifiers, fallback)
    if purl is not None and has_url(purl):
        p = try_purl(purl)
        if p is not None and not has_url(PackageURL(type=p.type, namespace=p.namespace, name=p.name,
                                                    version=p.version).to_string()):
            return PackageURL(type=p.type, namespace=p.namespace, name=p.name, version=p.version).to_string(), "normalized"
        name = _str(c.get("name")) or (p.name if p else "package")
        if fallback != "generic":
            return None, "none"
        return PackageURL(type="generic", name=_dashes(name), version=_str(c.get("version"))).to_string(), "generic"
    return purl, how


def _canonical_purl(c: dict[str, Any], keep_qualifiers: bool, fallback: str) -> tuple[str | None, str]:
    version = _str(c.get("version"))
    original = c.get("purl")
    source, p = "purl", try_purl(original) if isinstance(original, str) else None
    if p is None:
        ref = c.get("bom-ref")
        if isinstance(ref, str) and ref.lower().startswith("pkg:"):
            source, p = "bom-ref", try_purl(ref)
    if p is not None and has_url(p.to_string().split("?", 1)[0]):
        p = None  # a URL inside namespace or name: not a usable purl, rebuilt below
    if p is not None:
        new = PackageURL(type=p.type.lower(), namespace=p.namespace, name=p.name, version=p.version or version,
                         qualifiers=p.qualifiers if keep_qualifiers else None,
                         subpath=p.subpath if keep_qualifiers else None).to_string()
        if source == "bom-ref":
            return new, "from-bom-ref"
        return new, "kept" if new == original else "normalized"
    name = _str(c.get("name"))
    if not name:
        return None, "none"
    eco = _ecosystem(c)
    if eco:
        try:
            built = _build(eco, _dashes(name), version, _str(c.get("group")))
        except ValueError:
            built = None
        if built is not None:
            return built.to_string(), "built"
    if fallback != "generic":
        return None, "none"
    return PackageURL(type="generic", namespace=_str(c.get("group")), name=_dashes(name), version=version).to_string(), "generic"


@register
class PurlCanonical(CanonicalRule):
    id = "CXN-020"
    title = "purl in the form Checkmarx matches"
    description = ("Every component got a purl of the form pkg:type/[namespace/]name@version: the type in lower case, "
                   "qualifiers and subpath removed (Checkmarx does not use them), the version filled from the component. "
                   "A missing purl was built from the bom-ref or the ecosystem named by the generator, otherwise as "
                   "pkg:generic/<name>@<version> (Checkmarx skips generic components but no purl is ever null). A purl never "
                   "holds a web URL (http/https): URLs are converted to the registry purl or dropped.")
    source_fix = "Let the generator write a plain purl (pkg:type/namespace/name@version) for every component."

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        policy = ctx.profile.canonical
        assert policy is not None
        for i, c in enumerate(_components(doc)):
            old = c.get("purl")
            new, how = canonical_purl(c, policy.keep_purl_qualifiers, policy.purl_fallback)
            path = f"/components/{i}/purl"
            if new is None:
                if old is not None:
                    c.pop("purl", None)
                ctx.log.note(self.id, f"/components/{i}", f"Component '{c.get('name')}' has no name to build a purl from")
                continue
            if new == old:
                continue
            c["purl"] = new
            reason = {
                "normalized": "purl reduced to type/namespace/name@version",
                "from-bom-ref": "purl taken from the bom-ref",
                "built": "purl built from the ecosystem named by the generator",
                "generic": "no ecosystem known; generic purl so the component has one (Checkmarx will not scan it)",
            }.get(how, how)
            ctx.log.add(self.id, path, "replaced" if old is not None else "added", old, new,
                        WARN if how == "generic" else INFO, reason)


def canonical_licenses(value: Any) -> list[dict[str, Any]]:
    """Licenses reduced to {license: {id}} / {license: {name}} entries, or one {expression}."""
    if not isinstance(value, list):
        return []
    licenses: list[dict[str, Any]] = []
    expressions: list[str] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        expr = _str(entry.get("expression"))
        lic = entry.get("license")
        if expr:
            expressions.append(expr)
        elif isinstance(lic, dict):
            if _str(lic.get("id")):
                item = {"license": {"id": _str(lic["id"])}}
            elif _str(lic.get("name")):
                item = {"license": {"name": _str(lic["name"])}}
            else:
                continue
            if item not in licenses:
                licenses.append(item)
    if licenses:
        return licenses
    return [{"expression": expressions[0]}] if expressions else []


@register
class LicensesCanonical(CanonicalRule):
    id = "CXN-030"
    title = "Every component has a licence"
    description = ("Licences were reduced to the SPDX id or name (or one expression); licence text, URLs and other "
                   "details were dropped. A component without a licence got NOASSERTION, because Checkmarx rejects "
                   "empty licence arrays.")

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        policy = ctx.profile.canonical
        assert policy is not None
        if "licenses" not in policy.component_fields:
            return
        # NOASSERTION is not in the SPDX licence id list of the CycloneDX schema, so it goes in "name"
        default = [{"license": {"name": policy.default_license}}]
        for i, c in enumerate(_components(doc)):
            old = c.get("licenses", _MISSING)
            new = canonical_licenses(old)
            if not new:
                new = [dict(x, license=dict(x["license"])) for x in default]
                reason = f"No licence; {policy.default_license} added"
            else:
                reason = "Licences reduced to id / name / expression"
            if old is _MISSING or new != old:
                c["licenses"] = new
                ctx.log.add(self.id, f"/components/{i}/licenses", "added" if old is _MISSING else "replaced",
                            None if old is _MISSING else old, new, INFO, reason)


@register
class ComponentsCanonical(CanonicalRule):
    id = "CXN-040"
    title = "Components reduced to the fields Checkmarx reads"
    description = ("Each component was reduced to bom-ref, type, name, version, purl and licenses (profile key "
                   "canonical.component_fields). Hashes, evidence, properties, externalReferences, descriptions and "
                   "the other fields Checkmarx does not read were dropped; the original SBOM still has them. A missing "
                   "bom-ref (or one holding a web URL, renamed in dependencies too) was set to the purl (or the name), "
                   "a missing type to library.")

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        policy = ctx.profile.canonical
        assert policy is not None
        comps = _components(doc)
        meta = doc.get("metadata")
        root = meta.get("component") if isinstance(meta, dict) else None
        renames: dict[str, str] = {}  # bom-refs that held a web URL -> their replacement
        if isinstance(root, dict):
            self._root_without_urls(root, ctx, renames)
        used: set[str] = {root["bom-ref"]} if isinstance(root, dict) and isinstance(root.get("bom-ref"), str) else set()
        needs_version = not _version_at_least(ctx.version, "1.4")
        out: list[dict[str, Any]] = []
        for i, c in enumerate(comps):
            path = f"/components/{i}"
            purl = c.get("purl") if isinstance(c.get("purl"), str) else None
            p = try_purl(purl) if purl else None
            name = _str(c.get("name")) or (p.name if p else None) or _str(c.get("bom-ref")) or "unknown"
            version = _str(c.get("version")) or (p.version if p else None)
            if version is None and needs_version:
                version = "unknown"  # version is required before CycloneDX 1.4
            ref = _str(c.get("bom-ref"))
            url_ref = ref if ref is not None and has_url(ref) else None
            if url_ref:
                ref = None
            if ref is None or ref in used:
                base = purl or (f"{name}@{version}" if version else name)
                ref, n = base, 1
                while ref in used:
                    n += 1
                    ref = f"{base}#{n}"
                ctx.log.add(self.id, f"{path}/bom-ref", "added" if c.get("bom-ref") is None else "replaced",
                            c.get("bom-ref"), ref, INFO,
                            "bom-ref held a web URL; replaced by the purl" if url_ref else "bom-ref missing or not unique")
            if url_ref:
                renames[url_ref] = ref
            used.add(ref)
            values: dict[str, Any] = {
                "bom-ref": ref,
                "type": _str(c.get("type")) or "library",
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": c.get("licenses"),
            }
            new: dict[str, Any] = {}
            for key in policy.component_fields:
                value = values[key] if key in values else c.get(key)
                if value is not None:
                    new[key] = value
            dropped = sorted(k for k in c if k not in new)
            if dropped:
                ctx.log.add(self.id, path, "removed", {k: c[k] for k in dropped}, None, WARN,
                            f"Fields not read by Checkmarx dropped: {', '.join(dropped)}")
            out.append(new)
        if "components" in doc or out:
            doc["components"] = out
        if renames:
            for d in doc.get("dependencies") or []:
                if not isinstance(d, dict):
                    continue
                if d.get("ref") in renames:
                    d["ref"] = renames[d["ref"]]
                if isinstance(d.get("dependsOn"), list):
                    d["dependsOn"] = [renames.get(t, t) if isinstance(t, str) else t for t in d["dependsOn"]]

    def _root_without_urls(self, root: dict[str, Any], ctx: Ctx, renames: dict[str, str]) -> None:
        """metadata.component is kept as it is, except a purl or bom-ref that holds a web URL."""
        policy = ctx.profile.canonical
        assert policy is not None
        old = root.get("purl")
        if isinstance(old, str) and has_url(old):
            new, _ = canonical_purl(root, policy.keep_purl_qualifiers, policy.purl_fallback)
            if new is None:
                root.pop("purl")
            else:
                root["purl"] = new
            ctx.log.add(self.id, "/metadata/component/purl", "replaced" if new else "removed", old, new, INFO,
                        "purl held a web URL")
        ref = root.get("bom-ref")
        if isinstance(ref, str) and has_url(ref):
            new_ref = root.get("purl") or _dashes(str(root.get("name") or "application"))
            root["bom-ref"] = renames[ref] = new_ref
            ctx.log.add(self.id, "/metadata/component/bom-ref", "replaced", ref, new_ref, INFO,
                        "bom-ref held a web URL; replaced by the purl")


def canonical_tools(doc: dict[str, Any], policy: Any) -> tuple[list[dict[str, str]], str]:
    """(metadata.tools, reason): the profile's tool list, or with tool_per_ecosystem the tool for the ecosystem."""
    tools = [dict(t) for t in policy.tools]
    if not policy.tool_per_ecosystem:
        return tools, "Tools set to the profile's canonical tool list"
    found = detect_ecosystem(doc, force=policy.ecosystem)
    name = policy.ecosystem_tools.get(found.ecosystem or "")
    if name is None:
        return tools, f"{found.describe()}; the profile's default tool ({tools[0].get('name')}) kept"
    base = tools[0]
    entry = {k: base[k] for k in ("vendor",) if base.get(k)} | {"name": name} | {k: base[k] for k in ("version",) if base.get(k)}
    return [entry], f"Tool {name} for the {found.describe()}"


@register
class MetadataCanonical(CanonicalRule):
    id = "CXN-011"
    title = "metadata is timestamp, tools and component"
    description = ("metadata was reduced to timestamp (kept; added when missing), tools (the tool list of the "
                   "profile, by default cyclonedx-dotnet in the 1.4 array form, which Checkmarx reads in every version; "
                   "with tool_per_ecosystem the name follows the detected ecosystem: cyclonedx-java, cyclonedx-node, ...) "
                   "and the root component (kept as it was). Other metadata (authors, lifecycles, properties, ...) "
                   "was dropped.")

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        policy = ctx.profile.canonical
        assert policy is not None
        old = doc.get("metadata")
        old = old if isinstance(old, dict) else {}
        new: dict[str, Any] = {}
        ts = old.get("timestamp")
        if isinstance(ts, str) and ts:
            new["timestamp"] = ts
        else:
            new["timestamp"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            ctx.log.add(self.id, "/metadata/timestamp", "added", None, new["timestamp"], INFO, "No timestamp; set to now")
        tools, why = canonical_tools(doc, policy)
        new["tools"] = tools
        if old.get("tools") != tools:
            ctx.log.add(self.id, "/metadata/tools", "replaced" if "tools" in old else "added", old.get("tools"), tools,
                        INFO, why)
        elif policy.tool_per_ecosystem:
            ctx.log.note(self.id, "/metadata/tools", why, INFO)
        if isinstance(old.get("component"), dict):
            new["component"] = old["component"]
        dropped = sorted(k for k in old if k not in ("timestamp", "tools", "component"))
        if dropped:
            ctx.log.add(self.id, "/metadata", "removed", {k: old[k] for k in dropped}, None, WARN,
                        f"metadata fields not read by Checkmarx dropped: {', '.join(dropped)}")
        doc["metadata"] = new


@register
class DependenciesCanonical(CanonicalRule):
    id = "CXN-050"
    title = "Dependencies point only at existing components"
    description = ("dependencies entries were reduced to ref and dependsOn. An entry whose ref is not a component "
                   "(or the root component) was removed; dependsOn values that are not a component bom-ref, "
                   "self-references and duplicates were removed; entries with the same ref were merged.")

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        deps = doc.get("dependencies")
        if deps is None:
            return
        valid = {c["bom-ref"] for c in _components(doc) if isinstance(c.get("bom-ref"), str)}
        meta = doc.get("metadata")
        root = meta.get("component") if isinstance(meta, dict) else None
        if isinstance(root, dict) and isinstance(root.get("bom-ref"), str):
            valid.add(root["bom-ref"])
        merged: dict[str, list[str]] = {}
        for i, d in enumerate(deps if isinstance(deps, list) else []):
            path = f"/dependencies/{i}"
            ref = d.get("ref") if isinstance(d, dict) else None
            if not isinstance(ref, str) or ref not in valid:
                ctx.log.add(self.id, path, "removed", d, None, WARN, "ref is not a component in this SBOM")
                continue
            targets = merged.setdefault(ref, [])
            for j, t in enumerate(d.get("dependsOn") or []):
                if t == ref:
                    ctx.log.add(self.id, f"{path}/dependsOn/{j}", "removed", t, None, INFO, "self-dependency (cycle)")
                elif not isinstance(t, str) or t not in valid:
                    ctx.log.add(self.id, f"{path}/dependsOn/{j}", "removed", t, None, WARN,
                                "dependsOn points at a component that does not exist")
                elif t not in targets:
                    targets.append(t)
            extra = sorted(k for k in d if k not in ("ref", "dependsOn"))
            if extra:
                ctx.log.add(self.id, path, "removed", {k: d[k] for k in extra}, None, INFO,
                            f"dependency fields not read by Checkmarx dropped: {', '.join(extra)}")
        doc["dependencies"] = [{"ref": r, "dependsOn": t} for r, t in merged.items()]


@register
class TopLevelCanonical(CanonicalRule):
    id = "CXN-010"
    title = "Top level is bomFormat, specVersion, serialNumber, version, metadata, components, dependencies"
    description = ("Top-level sections Checkmarx does not read (services, compositions, vulnerabilities, "
                   "annotations, externalReferences, properties, formulation, declarations, definitions, signature, "
                   "$schema) were dropped. bomFormat and specVersion are kept as they were; serialNumber and version "
                   "were added when missing.")

    def run(self, doc: dict[str, Any], ctx: Ctx) -> None:
        if not (isinstance(doc.get("serialNumber"), str) and doc["serialNumber"]):
            serial = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'sbom-fixer:' + ctx.source_sha256)}"
            doc["serialNumber"] = serial
            ctx.log.add(self.id, "/serialNumber", "added", None, serial, INFO, "No serialNumber; derived from the input hash")
        if not isinstance(doc.get("version"), int) or isinstance(doc.get("version"), bool) or doc["version"] < 1:
            ctx.log.add(self.id, "/version", "replaced" if "version" in doc else "added", doc.get("version"), 1, INFO,
                        "BOM version set to 1")
            doc["version"] = 1
        dropped = [k for k in doc if k not in TOP_LEVEL]
        for k in dropped:
            ctx.log.add(self.id, f"/{k}", "removed", doc[k], None, WARN, "top-level section not read by Checkmarx")
        ordered = {k: doc[k] for k in TOP_LEVEL if k in doc}
        doc.clear()
        doc.update(ordered)
