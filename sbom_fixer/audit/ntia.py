"""Built-in NTIA minimum elements checker (2021) for CycloneDX and SPDX 2.x."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..jsonutil import iter_components
from ..purlmap import try_purl

COMPONENT_FIELDS = ("Supplier name", "Component name", "Component version", "Unique identifier")
DOC_FIELDS = ("Dependency relationships", "Author of SBOM data", "Timestamp")


@dataclass
class FieldCoverage:
    covered: int
    total: int
    missing_examples: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.covered == self.total

    @property
    def missing(self) -> int:
        return self.total - self.covered


@dataclass
class NtiaReport:
    components: dict[str, FieldCoverage]
    document: dict[str, bool]
    author_from_tools_only: bool
    total_components: int

    @property
    def passed(self) -> bool:
        return all(c.complete for c in self.components.values()) and all(self.document.values())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["passed"] = self.passed
        return d


def _cov(items: list[tuple[str, bool]]) -> FieldCoverage:
    missing = [label for label, ok in items if not ok]
    return FieldCoverage(len(items) - len(missing), len(items), missing[:20])


def _cdx(doc: dict[str, Any]) -> NtiaReport:
    comps = list(iter_components(doc))

    def label(p: str, c: dict[str, Any]) -> str:
        return str(c.get("bom-ref") or c.get("name") or p)

    def supplier(c: dict[str, Any]) -> bool:
        return bool((c.get("supplier") or {}).get("name") or c.get("publisher") or (c.get("manufacturer") or {}).get("name"))

    components = {
        "Supplier name": _cov([(label(p, c), supplier(c)) for p, c in comps]),
        "Component name": _cov([(label(p, c), bool(c.get("name"))) for p, c in comps]),
        "Component version": _cov([(label(p, c), bool(c.get("version")) and c.get("version") != "unknown") for p, c in comps]),
        # a purl only identifies the component when it parses (a URL in the purl field does not)
        "Unique identifier": _cov([(label(p, c), bool(try_purl(c.get("purl")) or c.get("cpe") or c.get("swid"))) for p, c in comps]),
    }
    meta = doc.get("metadata") or {}
    deps = doc.get("dependencies") or []
    has_author = bool(meta.get("authors") or meta.get("manufacture") or meta.get("manufacturer"))
    document = {
        "Dependency relationships": any(isinstance(d, dict) and d.get("ref") for d in deps),
        "Author of SBOM data": has_author,
        "Timestamp": bool(meta.get("timestamp")),
    }
    return NtiaReport(components, document, (not has_author) and bool(meta.get("tools")), len(comps))


def _spdx(doc: dict[str, Any]) -> NtiaReport:
    pkgs = [p for p in doc.get("packages") or [] if isinstance(p, dict)]

    def label(p: dict[str, Any]) -> str:
        return str(p.get("SPDXID") or p.get("name"))

    def known(v: Any) -> bool:
        return bool(v) and v not in ("NOASSERTION", "NONE")

    def ident(p: dict[str, Any]) -> bool:
        return any(isinstance(r, dict) and r.get("referenceType") in ("purl", "cpe23Type", "cpe22Type", "swid")
                   for r in p.get("externalRefs") or [])

    components = {
        "Supplier name": _cov([(label(p), known(p.get("supplier"))) for p in pkgs]),
        "Component name": _cov([(label(p), bool(p.get("name"))) for p in pkgs]),
        "Component version": _cov([(label(p), known(p.get("versionInfo"))) for p in pkgs]),
        "Unique identifier": _cov([(label(p), ident(p)) for p in pkgs]),
    }
    creators = (doc.get("creationInfo") or {}).get("creators") or []
    people = [c for c in creators if isinstance(c, str) and (c.startswith("Person:") or c.startswith("Organization:"))]
    rels = doc.get("relationships") or []
    document = {
        "Dependency relationships": any(isinstance(r, dict) and r.get("relationshipType") in
                                        ("DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS", "CONTAINED_BY") for r in rels),
        "Author of SBOM data": bool(people),
        "Timestamp": bool((doc.get("creationInfo") or {}).get("created")),
    }
    return NtiaReport(components, document, (not people) and bool(creators), len(pkgs))


def ntia_check(doc: dict[str, Any], spec: str) -> NtiaReport:
    return _cdx(doc) if spec == "cyclonedx" else _spdx(doc)
