"""Checkmarx purl rules (CXP-*): keep supported purl types, repair their format, remap unsupported types on evidence.

Active only when the profile has a `purl:` section. Source of the type lists: Checkmarx One "Scanning SBOMs".
Supported purls are never rewritten to another alias (yarn stays yarn); unsupported ones change only on hard evidence
(generator property, bom-ref, or a registry URL qualifier) and the original is kept in sbom-fixer:original-purl.
"""

from __future__ import annotations

import re
from typing import Any

from packageurl import PackageURL

from ..changes import DATA_LOSS, INFO, WARN
from ..jsonutil import iter_components, parse_pointer
from ..purlmap import (
    MAVEN_FAMILY,
    NONSTANDARD_ALIASES,
    Slot,
    is_os_package,
    purl_from_url,
    raw_type,
    slots,
    try_purl,
    unsupported_reason,
)
from .base import SANITIZE, Ctx, Rule, register
from .sanitize import _ECOSYSTEM_HINTS, _HINT_PROPS, _version_at_least

ORIGINAL_PROP = "sbom-fixer:original-purl"
_GO_HINTS = {"go-module", "gomod", "gobinary", "golang"}
_NPM_SCOPE = re.compile(r"^(pkg:(?:npm|yarn|bower)/)@", re.IGNORECASE)


class PurlRule(Rule):
    case, kind, specs = "C", SANITIZE, ("cyclonedx", "spdx")

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if ctx.profile.purl is None:
            return
        for slot in slots(doc, ctx.spec):
            self.check(slot, ctx)

    def check(self, slot: Slot, ctx: Ctx) -> None:
        raise NotImplementedError


def _keep_original(slot: Slot, original: str, ctx: Ctx) -> None:
    """Record the generator's purl once, before the first rewrite."""
    pkg = slot.package
    if slot.spec == "cyclonedx":
        if not _version_at_least(ctx.version, "1.3"):
            return
        props = pkg.setdefault("properties", [])
        if not any(isinstance(p, dict) and p.get("name") == ORIGINAL_PROP for p in props):
            props.append({"name": ORIGINAL_PROP, "value": original})
    else:
        comment = pkg.get("comment") or ""
        if ORIGINAL_PROP not in comment:
            pkg["comment"] = f"{comment}; {ORIGINAL_PROP}={original}" if comment else f"{ORIGINAL_PROP}={original}"


def _rewrite(slot: Slot, new: str, rule_id: str, ctx: Ctx, reason: str, keep_original: bool = False) -> None:
    old = slot.purl
    if old is None or new == old:
        return
    if keep_original:
        _keep_original(slot, old, ctx)
    slot.set_purl(new)
    ctx.log.add(rule_id, slot.purl_path, "replaced", old, new, INFO, reason)


def _supported(ctx: Ctx, purl_type: str) -> bool:
    return ctx.profile.purl is not None and ctx.profile.purl.pm_for(purl_type) is not None


def _hint(slot: Slot) -> str | None:
    value = slot.prop(*_HINT_PROPS)
    return value.lower() if value else None


def _build(eco: str, name: Any, version: str | None, group: str | None) -> PackageURL | None:
    """purl from component fields; None when the ecosystem needs data the component does not have."""
    if not isinstance(name, str) or not name or not version:
        return None
    ns = group
    if eco == "npm" and name.startswith("@") and "/" in name:
        ns, name = name.split("/", 1)
    elif eco == "golang" and "/" in name and not ns:
        ns, name = name.rsplit("/", 1)
    if eco == "maven" and not ns:
        return None
    return PackageURL(type=eco, namespace=ns, name=name, version=version)


@register
class TypeCase(PurlRule):
    id = "CXP-001"
    title = "purl type in lower case"
    description = "The purl type (or the 'pkg:' prefix) was not lower case; it was lower-cased as the purl specification requires."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        purl = slot.purl
        if purl is None or try_purl(purl) is None:
            return
        t = raw_type(purl)
        new = "pkg:" + t.lower() + purl[4 + len(t):]
        _rewrite(slot, new, self.id, ctx, "purl type lower-cased")


@register
class NpmScope(PurlRule):
    id = "CXP-002"
    title = "npm scope percent-encoded"
    description = "An npm scope was written as '@scope'; Checkmarx only matches the encoded form '%40scope', so '@' was percent-encoded."
    source_fix = "Use a generator that writes scoped npm purls as pkg:npm/%40scope/name@version."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        purl = slot.purl
        if purl is not None and _NPM_SCOPE.match(purl):
            _rewrite(slot, _NPM_SCOPE.sub(r"\1%40", purl, count=1), self.id, ctx, "npm scope '@' encoded as %40")


@register
class GithubToGolang(PurlRule):
    id = "CXP-010"
    title = "github purl of a Go module remapped to golang"
    description = ("A Go module was identified as pkg:github (not scanned by Checkmarx); the generator marks it as a Go module, "
                   "so it was rewritten to pkg:golang/github.com/... The original purl is kept in sbom-fixer:original-purl.")
    source_fix = "Configure the generator to write pkg:golang purls for Go modules."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        p = try_purl(slot.purl)
        if p is None or p.type != "github" or not ctx.profile.purl or not ctx.profile.purl.remap:
            return
        ref = slot.bom_ref
        evidence = _hint(slot) in _GO_HINTS or (isinstance(ref, str) and ref.lower().startswith("pkg:golang/"))
        if not evidence or not p.namespace:
            return
        path = ["github.com", p.namespace, p.name] + [s for s in (p.subpath or "").split("/") if s]
        new = PackageURL(type="golang", namespace="/".join(path[:-1]), name=path[-1], version=p.version or slot.version)
        _rewrite(slot, new.to_string(), self.id, ctx, "Go module remapped from github to golang (generator marks it as a Go module)",
                 keep_original=True)


@register
class GenericFromHint(PurlRule):
    id = "CXP-011"
    title = "generic purl remapped from the generator's package type"
    description = ("A pkg:generic purl (not scanned by Checkmarx) belonged to a component whose generator property names the "
                   "ecosystem; it was rebuilt as that ecosystem's purl from the component's name, group and version.")
    source_fix = "Configure the generator to write ecosystem purls instead of pkg:generic."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        p = try_purl(slot.purl)
        if p is None or p.type != "generic" or not ctx.profile.purl or not ctx.profile.purl.remap:
            return
        hint = _hint(slot)
        eco = _ECOSYSTEM_HINTS.get(hint or "")
        if not eco or not _supported(ctx, eco):
            return
        new = _build(eco, slot.name or p.name, slot.version or p.version, slot.group or p.namespace)
        if new is not None:
            _rewrite(slot, new.to_string(), self.id, ctx, f"generic purl rebuilt as {eco} (generator package type '{hint}')",
                     keep_original=True)


@register
class GenericFromUrl(PurlRule):
    id = "CXP-012"
    title = "generic purl remapped from its registry URL"
    description = ("A pkg:generic purl carried a download_url / repository_url / vcs_url on a known package registry "
                   "(Maven Central, npm, PyPI, NuGet, RubyGems, Go proxy, pub.dev); it was rewritten to that registry's purl.")
    source_fix = "Configure the generator to write ecosystem purls instead of pkg:generic."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        p = try_purl(slot.purl)
        if p is None or p.type != "generic" or not ctx.profile.purl or not ctx.profile.purl.remap:
            return
        for key in ("download_url", "repository_url", "vcs_url"):
            url = (p.qualifiers or {}).get(key)
            new = purl_from_url(url, slot.version or p.version, allow_github=False) if isinstance(url, str) else None
            if new is not None and _supported(ctx, new.type):
                _rewrite(slot, new.to_string(), self.id, ctx, f"generic purl rewritten from its {key} ({new.type} registry)",
                         keep_original=True)
                return


@register
class NonstandardType(PurlRule):
    id = "CXP-013"
    title = "Non-standard purl type with one meaning"
    description = ("The purl used a type that is not in the purl specification but has exactly one meaning "
                   "(nodejs/node -> npm, dotnet/nupkg -> nuget, jar -> maven when a groupId is present); the type was replaced.")
    source_fix = "Use the purl specification's type names (npm, nuget, maven)."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        p = try_purl(slot.purl)
        if p is None or not ctx.profile.purl or not ctx.profile.purl.remap or _supported(ctx, p.type):
            return
        target = NONSTANDARD_ALIASES.get(p.type.lower())
        if target is None or not _supported(ctx, target) or (target == "maven" and not p.namespace):
            return
        new = PackageURL(type=target, namespace=p.namespace, name=p.name, version=p.version, qualifiers=p.qualifiers,
                         subpath=p.subpath)
        _rewrite(slot, new.to_string(), self.id, ctx, f"type '{p.type}' replaced by '{target}'", keep_original=True)


@register
class VersionFromComponent(PurlRule):
    id = "CXP-003"
    title = "purl version taken from the component"
    description = ("A supported purl had no version, which makes Checkmarx check the latest version instead; the component's own "
                   "version was added. Without any version the component is reported (results may not match the version in use).")
    source_fix = "Make the generator write the resolved version into every purl."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        p = try_purl(slot.purl)
        if p is None or p.version or not _supported(ctx, p.type):
            return
        if slot.version:
            new = p._replace(version=slot.version).to_string()
            _rewrite(slot, new, self.id, ctx, "purl had no version; component version added")
        else:
            ctx.log.note(self.id, slot.purl_path, f"'{p.name}' has no version; Checkmarx will check it against the latest version")


@register
class MavenNamespace(PurlRule):
    id = "CXP-004"
    title = "Maven purl groupId"
    description = ("A Maven-family purl (maven, gradle, sbt, ivy) had no namespace (groupId), so Checkmarx cannot look it up; "
                   "the component's group was used. Without a group the component is reported.")
    source_fix = "Maven purls need the groupId as namespace: pkg:maven/<groupId>/<artifactId>@<version>."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        p = try_purl(slot.purl)
        if p is None or p.type.lower() not in MAVEN_FAMILY or p.namespace:
            return
        if slot.group:
            _rewrite(slot, p._replace(namespace=slot.group).to_string(), self.id, ctx, "Maven groupId taken from component group")
        else:
            ctx.log.note(self.id, slot.purl_path, f"Maven purl for '{p.name}' has no groupId; Checkmarx will likely not match it")


@register
class UrlQualifiers(PurlRule):
    id = "CXP-005"
    title = "URL qualifiers removed from the purl"
    description = ("A supported purl carried URL-valued qualifiers or subpath (for example repository_url=https://...). Checkmarx documents "
                   "purls as pkg:type/[namespace/]name@version and matches by name and version, so they were removed; "
                   "the original purl is kept in sbom-fixer:original-purl.")

    def check(self, slot: Slot, ctx: Ctx) -> None:
        if not ctx.profile.purl or not ctx.profile.purl.strip_url_qualifiers:
            return
        p = try_purl(slot.purl)
        if p is None or not _supported(ctx, p.type):
            return  # Checkmarx skips unsupported types anyway; keep their qualifiers as written
        quals = dict(p.qualifiers or {})
        url_keys = [k for k, v in quals.items() if isinstance(v, str) and "://" in v]
        raw_subpath = (slot.purl or "").partition("#")[2]
        drop_subpath = "://" in raw_subpath or ":/" in (p.subpath or "")
        if not url_keys and not drop_subpath:
            return
        for k in url_keys:
            quals.pop(k)
        new = PackageURL(type=p.type, namespace=p.namespace, name=p.name, version=p.version, qualifiers=quals or None,
                         subpath=None if drop_subpath else p.subpath)
        what = ", ".join(url_keys + (["subpath"] if drop_subpath else []))
        _rewrite(slot, new.to_string(), self.id, ctx, f"URL-valued purl parts removed: {what}", keep_original=True)


@register
class UnsupportedTypes(PurlRule):
    id = "CXP-020"
    title = "purl types Checkmarx does not scan"
    description = ("The component's purl type is not in the Checkmarx supported list (for example cargo, hex, generic, docker, "
                   "github); Checkmarx skips it silently. It is kept and listed (or removed when unsupported_action: remove).")
    source_fix = "Scan ecosystems Checkmarx does not support (for example Rust crates) with another tool."

    def apply(self, doc: Any, ctx: Ctx) -> None:
        _classify_and_act(doc, ctx, os_packages=False)


@register
class OsPackages(PurlRule):
    id = "CXP-021"
    title = "OS packages"
    description = ("The component is an operating-system package (rpm, apk, alpm, or deb from a Linux distribution). Checkmarx "
                   "does not scan OS packages and reads deb as a C++ (Conan) package, so results for it may be wrong. "
                   "It is kept and listed (or removed when os_package_action: remove).")
    source_fix = "Scan container and OS packages with a container scanner (Checkmarx Container Security)."

    def apply(self, doc: Any, ctx: Ctx) -> None:
        _classify_and_act(doc, ctx, os_packages=True)


def _classify_and_act(doc: Any, ctx: Ctx, os_packages: bool) -> None:
    policy = ctx.profile.purl
    if policy is None:
        return
    rule_id = "CXP-021" if os_packages else "CXP-020"
    action = policy.os_package_action if os_packages else policy.unsupported_action
    doomed: list[Slot] = []
    for slot in slots(doc, ctx.spec):
        p = try_purl(slot.purl)
        if p is None:
            continue
        is_os = is_os_package(p, slot, policy)
        if os_packages != is_os or (not is_os and policy.pm_for(p.type) is not None):
            continue
        label = f"'{slot.name}' ({slot.purl})"
        if action == "remove" and ctx.spec == "cyclonedx":
            doomed.append(slot)
        elif is_os and p.type.lower() == "deb":
            ctx.log.note(rule_id, slot.path, f"{label}: OS package; Checkmarx reads deb as C++ (Conan), results may be wrong", WARN)
        elif is_os:
            ctx.log.note(rule_id, slot.path, f"{label}: OS package; not scanned by Checkmarx", INFO)
        else:
            ctx.log.note(rule_id, slot.path, f"{label}: {unsupported_reason(p.type)}; not scanned by Checkmarx", INFO)
    if doomed:
        _remove_components(doc, doomed, rule_id, ctx)


def _remove_components(doc: dict[str, Any], doomed: list[Slot], rule_id: str, ctx: Ctx) -> None:
    targets = {id(s.package) for s in doomed}
    refs = {s.bom_ref for s in doomed if isinstance(s.bom_ref, str)}
    for path, comp in reversed(list(iter_components(doc))):
        if id(comp) not in targets:
            continue
        parts = parse_pointer(path)
        container: Any = doc
        for part in parts[:-1]:
            container = container[part]
        container.pop(parts[-1])
        ctx.log.add(rule_id, path, "removed", comp, None, DATA_LOSS,
                    f"'{comp.get('name')}' ({comp.get('purl')}) is not scanned by Checkmarx; removed by profile")
    deps = doc.get("dependencies")
    if not refs or not isinstance(deps, list):
        return
    for i in range(len(deps) - 1, -1, -1):
        d = deps[i]
        if not isinstance(d, dict):
            continue
        if d.get("ref") in refs:
            deps.pop(i)
            ctx.log.add(rule_id, f"/dependencies/{i}", "removed", d, None, INFO, "dependency entry of a removed component")
            continue
        on = d.get("dependsOn")
        if isinstance(on, list) and refs.intersection(on):
            for j in range(len(on) - 1, -1, -1):
                if on[j] in refs:
                    ctx.log.add(rule_id, f"/dependencies/{i}/dependsOn/{j}", "removed", on.pop(j), None, INFO,
                                "edge to a removed component")


@register
class OtherIdentityOnly(PurlRule):
    id = "CXP-030"
    title = "Components identified only by CPE or hash"
    description = ("The component has no purl, only a CPE, SWID or hash; Checkmarx skips such components silently. "
                   "A purl is never derived from a CPE, because the mapping is not reliable.")
    source_fix = "Use a generator that writes purls for every package component."

    def check(self, slot: Slot, ctx: Ctx) -> None:
        if slot.purl is None and slot.has_other_identity():
            ctx.log.note(self.id, slot.path, f"'{slot.name}' is identified only by CPE/SWID/hash; Checkmarx will skip it")


@register
class SpdxDirectDependencies(Rule):
    id = "CXP-051"
    title = "SPDX direct dependencies"
    description = ("The SPDX document has no DESCRIBES or DEPENDS_ON relationship; Checkmarx then treats every package as a direct "
                   "dependency. Relationships are never invented.")
    source_fix = "Declare DESCRIBES / DEPENDS_ON from the main package to each direct dependency."
    case, kind, specs = "C", SANITIZE, ("spdx",)

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if ctx.profile.purl is None:
            return
        rels = doc.get("relationships") or []
        if doc.get("documentDescribes") or any(
                isinstance(r, dict) and r.get("relationshipType") in ("DESCRIBES", "DEPENDS_ON") for r in rels):
            return
        ctx.log.note(self.id, "/relationships", "No DESCRIBES or DEPENDS_ON relationship; Checkmarx will show every package as direct")
