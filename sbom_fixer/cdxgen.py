"""Step 1 of `cdxgen-fix`: turn any supported SBOM into CycloneDX JSON in the layout cdxgen writes.

cdxgen (AppThreat / CycloneDX) builds SBOMs from source code; it cannot read an existing SBOM. This module gives an
SBOM from any generator the same shape instead:

- SPDX 2.2 / 2.3 JSON  -> CycloneDX 1.6 (cdxgen's default version): packages become components, the purl from
  externalRefs, licences from licenseConcluded / licenseDeclared, checksums become hashes, DEPENDS_ON and
  *_DEPENDENCY_OF relationships become dependencies, the described package (or the document) becomes the root;
- CycloneDX JSON (any generator, any version) -> kept at its version (CycloneDX 1.8+ goes to 1.7); a bare JSON array
  or an object without bomFormat is read as CycloneDX components (`prepare_input`);
- in both cases: bom-ref = purl when a component has none (as cdxgen does), and every component has a dependencies
  entry (empty dependsOn when nothing is known).

The generator's own tool names are kept, so the ecosystem detection of step 2 can use them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from .complete import prepare_input
from .licenses import canonical_id, looks_like_expression, normalize_expression
from .purlmap import URL_RE, purl_from_url, try_purl
from .schemas import version_key

SPDX_TARGET_VERSION = "1.6"

_PURPOSE_TYPE = {
    "APPLICATION": "application", "FRAMEWORK": "framework", "LIBRARY": "library", "CONTAINER": "container",
    "OPERATING-SYSTEM": "operating-system", "OPERATING_SYSTEM": "operating-system", "DEVICE": "device",
    "FIRMWARE": "firmware", "FILE": "file", "INSTALL": "application", "ARCHIVE": "library", "SOURCE": "library",
    "OTHER": "library",
}
_CHECKSUM_ALG = {
    "MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
    "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
    "BLAKE2B-256": "BLAKE2b-256", "BLAKE2B-384": "BLAKE2b-384", "BLAKE2B-512": "BLAKE2b-512", "BLAKE3": "BLAKE3",
}
_EMPTY = {"", "NOASSERTION", "NONE"}


@dataclass
class Conversion:
    doc: dict[str, Any]
    source_spec: str
    source_version: str
    target_version: str
    notes: list[str] = field(default_factory=list)


def to_cdxgen(raw: bytes, spec_version: str | None = None) -> Conversion:
    """Any supported SBOM (bytes) -> CycloneDX in cdxgen layout. Raises DetectError for unsupported input."""
    data, spec, version, notes = prepare_input(raw)
    if spec == "spdx":
        target = spec_version or SPDX_TARGET_VERSION
        doc = spdx_to_cyclonedx(data, target, notes)
        conv = Conversion(doc, "spdx", version, target, notes)
    else:
        if spec_version and spec_version != version:
            notes.append(f"specVersion {version} relabelled to {spec_version} (--spec-version); the fix step repairs "
                         "fields that do not exist in that version")
            data["specVersion"] = spec_version
        conv = Conversion(data, "cyclonedx", version, spec_version or version, notes)
    _cdxgen_layout(conv.doc, conv.notes)
    return conv


def url_to_purl(value: Any, version: Any = None) -> str | None:
    """A purl as it is, or the purl of a registry / package-page URL; None for anything else (never a URL)."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if URL_RE.match(text):
        found = purl_from_url(text, version if isinstance(version, str) else None, allow_github=False)
        return found.to_string() if found is not None else None
    return text if try_purl(text) is not None else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str | None:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    t = str(value).strip()
    return None if t.upper() in _EMPTY else t


def spdx_licenses(*values: Any) -> list[dict[str, Any]]:
    """The first SPDX licence field that says something, as CycloneDX licences."""
    for value in values:
        text = _text(value)
        if not text:
            continue
        lid = canonical_id(text)
        if lid:
            return [{"license": {"id": lid}}]
        if looks_like_expression(text):
            return [{"expression": normalize_expression(text) or text}]
        return [{"license": {"name": text}}]
    return []


def _party(value: Any) -> dict[str, str] | None:
    """SPDX 'Organization: X (email)' / 'Person: X' -> {"name": X}."""
    text = _text(value)
    if not text:
        return None
    for prefix in ("Organization:", "Person:", "Tool:"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    name = text.split(" (", 1)[0].strip()
    return {"name": name} if name else None


def _spdx_tools(creators: Any) -> list[dict[str, Any]]:
    tools = []
    for c in creators or []:
        if isinstance(c, str) and c.startswith("Tool:"):
            text = c.removeprefix("Tool:").strip()
            name, _, version = text.rpartition("-")
            if not name or not version[:1].isdigit():
                name, version = text, ""
            tools.append({"type": "application", "name": name} | ({"version": version} if version else {}))
    return tools


def spdx_to_cyclonedx(spdx: dict[str, Any], version: str, notes: list[str]) -> dict[str, Any]:
    packages = [p for p in spdx.get("packages") or [] if isinstance(p, dict)]
    rels = [r for r in spdx.get("relationships") or [] if isinstance(r, dict)]
    doc_id = str(spdx.get("SPDXID") or "SPDXRef-DOCUMENT")
    info: dict[str, Any] = _dict(spdx.get("creationInfo"))

    described = [r.get("relatedSpdxElement") for r in rels
                 if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == doc_id]
    described += [d for d in spdx.get("documentDescribes") or [] if d not in described]
    by_id = {p.get("SPDXID"): p for p in packages}
    root_id = described[0] if len(described) == 1 and described[0] in by_id and len(packages) > 1 else None

    refs: dict[str, str] = {}  # SPDXID -> bom-ref
    used: set[str] = set()
    components: list[dict[str, Any]] = []
    root: dict[str, Any] | None = None
    for p in packages:
        sid = str(p.get("SPDXID") or f"SPDXRef-{len(refs)}")
        comp = _spdx_package(p)
        ref = comp.get("purl") if comp.get("purl") not in used else None
        ref = ref or sid
        while ref in used:
            ref = f"{ref}-dup"
        used.add(ref)
        refs[sid] = ref
        comp = {"bom-ref": ref} | comp
        if sid == root_id:
            comp["type"] = "application" if comp.get("type") == "library" else comp["type"]
            root = comp
        else:
            components.append(comp)
    if root is None:
        root = {"bom-ref": doc_id, "type": "application", "name": str(spdx.get("name") or "application")}
        refs[doc_id] = doc_id
    else:
        refs[doc_id] = root["bom-ref"]

    edges: dict[str, list[str]] = {root["bom-ref"]: []}
    edges.update({c["bom-ref"]: [] for c in components})

    def edge(a: Any, b: Any) -> None:
        ra, rb = refs.get(a), refs.get(b)
        if ra and rb and ra != rb and rb not in edges.setdefault(ra, []):
            edges[ra].append(rb)

    for r in rels:
        kind = str(r.get("relationshipType", "")).upper()
        a, b = r.get("spdxElementId"), r.get("relatedSpdxElement")
        if kind == "DEPENDS_ON":
            edge(a, b)
        elif kind.endswith("DEPENDENCY_OF") and kind != "DEPENDENCY_MANIFEST_OF":
            edge(b, a)
        elif kind == "DESCRIBES" and a == doc_id and root_id is None:
            edge(doc_id, b)  # no single described package: the described packages are the direct dependencies
    if root_id is not None and not edges[root["bom-ref"]]:
        edges[root["bom-ref"]] = [c["bom-ref"] for c in components]  # nothing says otherwise: all direct
        notes.append("SPDX has no DEPENDS_ON from the described package; every package taken as a direct dependency")

    namespace = _text(spdx.get("documentNamespace")) or doc_id
    meta: dict[str, Any] = {}
    if _text(info.get("created")):
        meta["timestamp"] = info["created"]
    tools = _spdx_tools(info.get("creators"))
    if tools:
        meta["tools"] = {"components": tools} if (version_key(version) or (0,)) >= (1, 5) else [
            {k: v for k, v in t.items() if k != "type"} for t in tools]
    meta["component"] = root
    skipped = len(spdx.get("files") or []) + len(spdx.get("snippets") or [])
    if skipped:
        notes.append(f"{skipped} SPDX files/snippets not converted (CycloneDX components are packages)")
    notes.append(f"{spdx.get('spdxVersion')} converted to CycloneDX {version}: {len(components)} components, "
                 f"root '{root.get('name')}'")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": version,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, namespace)}",
        "version": 1,
        "metadata": meta,
        "components": components,
        "dependencies": [{"ref": r, "dependsOn": t} for r, t in edges.items()],
    }


def _spdx_package(p: dict[str, Any]) -> dict[str, Any]:
    comp: dict[str, Any] = {"type": _PURPOSE_TYPE.get(str(p.get("primaryPackagePurpose", "")).upper(), "library")}
    supplier = _party(p.get("supplier"))
    if supplier:
        comp["supplier"] = supplier
    comp["name"] = str(p.get("name") or p.get("SPDXID") or "unknown")
    if _text(p.get("versionInfo")):
        comp["version"] = _text(p["versionInfo"])
    if _text(p.get("description")) or _text(p.get("summary")):
        comp["description"] = _text(p.get("description")) or _text(p.get("summary"))
    hashes = []
    for ch in p.get("checksums") or []:
        alg = _CHECKSUM_ALG.get(str((ch or {}).get("algorithm", "")).upper())
        if alg and _text(ch.get("checksumValue")):
            hashes.append({"alg": alg, "content": str(ch["checksumValue"]).lower()})
    if hashes:
        comp["hashes"] = hashes
    licenses = spdx_licenses(p.get("licenseConcluded"), p.get("licenseDeclared"))
    if licenses:
        comp["licenses"] = licenses
    if _text(p.get("copyrightText")):
        comp["copyright"] = _text(p["copyrightText"])
    for ref in p.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        kind = str(ref.get("referenceType", "")).lower()
        loc = ref.get("referenceLocator")
        if kind == "purl" and "purl" not in comp:
            purl = url_to_purl(loc, comp.get("version"))
            if purl:
                comp["purl"] = purl
        elif kind in ("cpe23type", "cpe22type") and "cpe" not in comp and _text(loc):
            comp["cpe"] = loc
    return comp


def _cdxgen_layout(doc: dict[str, Any], notes: list[str]) -> None:
    """bom-ref = purl when missing, and one dependencies entry per component (cdxgen writes both)."""
    comps = [c for c in doc.get("components") or [] if isinstance(c, dict)]
    used = {c["bom-ref"] for c in comps if isinstance(c.get("bom-ref"), str)}
    meta: dict[str, Any] = _dict(doc.get("metadata"))
    root = meta.get("component") if isinstance(meta.get("component"), dict) else None
    if root is not None and isinstance(root.get("bom-ref"), str):
        used.add(root["bom-ref"])
    added = converted = 0
    for c in comps + ([root] if root is not None else []):
        purl = c.get("purl")
        version = c.get("version") if isinstance(c.get("version"), str) else None
        if isinstance(purl, str) and URL_RE.match(purl.strip()):
            new = url_to_purl(purl, version)
            if new:  # registry / package-page URL -> real purl; other URLs are moved out of purl in step 2 (SAN-009)
                c["purl"] = purl = new
                converted += 1
        elif "purl" not in c and isinstance(c.get("bom-ref"), str) and URL_RE.match(c["bom-ref"].strip()):
            new = url_to_purl(c["bom-ref"], version)
            if new:
                c["purl"] = purl = new
                converted += 1
        if not c.get("bom-ref") and isinstance(purl, str) and try_purl(purl) is not None and purl not in used:
            c["bom-ref"] = purl
            used.add(purl)
            added += 1
    if converted:
        notes.append(f"{converted} purl(s) written as a URL converted to the real purl")
    if added:
        notes.append(f"bom-ref set to the purl for {added} component(s)")
    deps = doc.get("dependencies")
    if not isinstance(deps, list):
        deps = []
    listed = {d.get("ref") for d in deps if isinstance(d, dict)}
    missing = [c["bom-ref"] for c in comps if isinstance(c.get("bom-ref"), str) and c["bom-ref"] not in listed]
    if missing:
        doc["dependencies"] = deps + [{"ref": r, "dependsOn": []} for r in missing]
        notes.append(f"{len(missing)} dependencies entr{'y' if len(missing) == 1 else 'ies'} added (dependsOn unknown)")
