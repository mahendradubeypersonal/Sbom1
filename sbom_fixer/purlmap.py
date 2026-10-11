"""purl helpers: registry URL -> purl, and the Checkmarx coverage classification of every component."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

from packageurl import PackageURL

from .jsonutil import iter_components

if TYPE_CHECKING:
    from .changes import ChangeLog
    from .profile import PurlPolicy

URL_RE = re.compile(r"^https?://", re.IGNORECASE)
UNENCODED_NPM_SCOPE = re.compile(r"^pkg:[^/]+/@", re.IGNORECASE)
NPM_FAMILY = {"npm", "yarn", "bower"}
MAVEN_FAMILY = {"maven", "gradle", "sbt", "ivy"}
OS_DEB_NAMESPACES = {"debian", "ubuntu"}
# purl types that are not in the purl spec but have exactly one meaning (CXP-013)
NONSTANDARD_ALIASES = {"nodejs": "npm", "node": "npm", "dotnet": "nuget", "nupkg": "nuget", "jar": "maven"}
# rules whose output purl counts as "remapped" (type changed) or "fixed" (same type, format repaired)
REMAP_RULES = {"SAN-009", "CXP-010", "CXP-011", "CXP-012", "CXP-013"}
FIX_RULES = {"CXP-001", "CXP-002", "CXP-003", "CXP-004", "CXP-005"}


def try_purl(text: Any) -> PackageURL | None:
    if not isinstance(text, str):
        return None
    try:
        return PackageURL.from_string(text)
    except ValueError:
        return None


def _segments(path: str) -> list[str]:
    return [unquote(s) for s in path.split("/") if s]


def _maven(segs: list[str]) -> PackageURL | None:
    if "maven2" in segs:
        segs = segs[segs.index("maven2") + 1:]
    if len(segs) < 4:
        return None
    group, artifact, version, filename = segs[:-3], segs[-3], segs[-2], segs[-1]
    if not filename.startswith(f"{artifact}-{version}"):
        return None
    return PackageURL(type="maven", namespace=".".join(group), name=artifact, version=version)


def _npm(segs: list[str]) -> PackageURL | None:
    if "-" not in segs:
        return None
    i = segs.index("-")
    name_parts, rest = segs[:i], segs[i + 1:]
    if not name_parts or len(rest) != 1 or not rest[0].endswith(".tgz"):
        return None
    name = name_parts[-1]
    ns = name_parts[0] if len(name_parts) == 2 and name_parts[0].startswith("@") else None
    stem = rest[0][:-4]
    if not stem.startswith(name + "-"):
        return None
    return PackageURL(type="npm", namespace=ns, name=name, version=stem[len(name) + 1:])


def _pypi(segs: list[str]) -> PackageURL | None:
    if len(segs) >= 3 and segs[0] == "project":
        return PackageURL(type="pypi", name=segs[1].lower(), version=segs[2])
    filename = segs[-1] if segs else ""
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) >= 5:
            return PackageURL(type="pypi", name=parts[0].lower().replace("_", "-"), version=parts[1])
        return None
    for ext in (".tar.gz", ".zip", ".tar.bz2"):
        if filename.endswith(ext):
            m = re.match(r"^(.+)-(\d[^-]*)$", filename[: -len(ext)])
            if m:
                return PackageURL(type="pypi", name=m.group(1).lower().replace("_", "-"), version=m.group(2))
    return None


def _nuget(segs: list[str]) -> PackageURL | None:
    for marker in ("v3-flatcontainer", "packages"):
        if marker in segs:
            rest = segs[segs.index(marker) + 1:]
            if len(rest) >= 2:
                return PackageURL(type="nuget", name=rest[0], version=rest[1])
    return None


def _gem(segs: list[str]) -> PackageURL | None:
    if len(segs) >= 2 and segs[0] == "gems":
        m = re.match(r"^(.+?)-(\d[0-9A-Za-z.]*)(?:-[^.]+)?\.gem$", segs[1])
        if m:
            return PackageURL(type="gem", name=m.group(1), version=m.group(2))
    return None


def _golang(segs: list[str]) -> PackageURL | None:
    if "@v" not in segs:
        return None
    i = segs.index("@v")
    module = [re.sub(r"!([a-z])", lambda m: m.group(1).upper(), s) for s in segs[:i]]
    rest = segs[i + 1:]
    if len(module) < 2 or len(rest) != 1:
        return None
    version = re.sub(r"\.(zip|mod|info)$", "", rest[0])
    return PackageURL(type="golang", namespace="/".join(module[:-1]), name=module[-1], version=version)


def _pub(segs: list[str]) -> PackageURL | None:
    if len(segs) >= 4 and segs[0] == "packages" and segs[2] == "versions":
        return PackageURL(type="pub", name=segs[1], version=segs[3])
    if len(segs) >= 3 and segs[:2] == ["api", "archives"]:
        m = re.match(r"^(.+?)-(\d[^-]*)\.tar\.gz$", segs[2])
        if m:
            return PackageURL(type="pub", name=m.group(1), version=m.group(2))
    return None


def _github(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2:
        return None
    owner, repo = segs[0], re.sub(r"\.git$", "", segs[1])
    tag = None
    if len(segs) >= 5 and segs[2] == "releases" and segs[3] == "tag":
        tag = segs[4]
    elif len(segs) >= 6 and segs[2:5] == ["archive", "refs", "tags"]:
        tag = re.sub(r"\.(tar\.gz|zip)$", "", segs[5])
    return PackageURL(type="github", namespace=owner, name=repo, version=tag or version)


# package pages on registry websites (the version comes from the URL when it has one, else from the component)
def _npm_web(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2 or segs[0] != "package":
        return None
    rest = segs[1:]
    ns = None
    if rest[0].startswith("@") and len(rest) >= 2:
        ns, rest = rest[0], rest[1:]
    name = rest[0]
    if len(rest) >= 3 and rest[1] == "v":
        version = rest[2]
    return PackageURL(type="npm", namespace=ns, name=name, version=version)


def _mvnrepository(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 3 or segs[0] != "artifact":
        return None
    return PackageURL(type="maven", namespace=segs[1], name=segs[2], version=segs[3] if len(segs) > 3 else version)


def _crates(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2 or segs[0] != "crates":
        return None
    return PackageURL(type="cargo", name=segs[1], version=segs[2] if len(segs) > 2 else version)


def _packagist(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 3 or segs[0] != "packages":
        return None
    return PackageURL(type="composer", namespace=segs[1], name=segs[2], version=version)


def _hex(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2 or segs[0] != "packages":
        return None
    return PackageURL(type="hex", name=segs[1], version=segs[2] if len(segs) > 2 else version)


def _gem_web(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2 or segs[0] != "gems":
        return None
    return PackageURL(type="gem", name=segs[1], version=segs[3] if len(segs) > 3 and segs[2] == "versions" else version)


def _pkg_go_dev(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2:
        return None
    path = "/".join(segs)
    if "@" in path:
        path, version = path.rsplit("@", 1)
    module = path.split("/")
    return PackageURL(type="golang", namespace="/".join(module[:-1]), name=module[-1], version=version)


def _nuget_web(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2 or segs[0] != "packages":
        return None
    return PackageURL(type="nuget", name=segs[1], version=segs[2] if len(segs) > 2 else version)


def _pypi_web(segs: list[str], version: str | None) -> PackageURL | None:
    if len(segs) < 2 or segs[0] != "project":
        return None
    return PackageURL(type="pypi", name=segs[1].lower(), version=segs[2] if len(segs) > 2 else version)


_WEB_HOSTS = {
    "www.npmjs.com": _npm_web, "npmjs.com": _npm_web,
    "mvnrepository.com": _mvnrepository,
    "crates.io": _crates,
    "packagist.org": _packagist,
    "hex.pm": _hex,
    "rubygems.org": _gem_web,
    "pkg.go.dev": _pkg_go_dev,
    "www.nuget.org": _nuget_web, "nuget.org": _nuget_web,
    "pypi.org": _pypi_web,
}


_HOSTS = {
    "repo1.maven.org": _maven, "repo.maven.apache.org": _maven, "central.sonatype.com": _maven,
    "registry.npmjs.org": _npm,
    "files.pythonhosted.org": _pypi, "pypi.org": _pypi,
    "api.nuget.org": _nuget, "www.nuget.org": _nuget, "nuget.org": _nuget,
    "rubygems.org": _gem,
    "proxy.golang.org": _golang,
    "pub.dev": _pub, "pub.dartlang.org": _pub,
}


def purl_from_url(url: str, version: str | None = None, *, allow_github: bool = True) -> PackageURL | None:
    """Exact purl for a package registry URL; None when the host or path pattern is not known."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    segs = _segments(parts.path)
    if host == "github.com" and allow_github:
        return _github(segs, version)
    fn = _HOSTS.get(host)
    try:
        found = fn(segs) if fn is not None else None
        if found is None and host in _WEB_HOSTS:
            found = _WEB_HOSTS[host](segs, version)
        return found
    except ValueError:
        return None


def raw_type(purl: str) -> str:
    """The type exactly as written (before the first '/'), without the 'pkg:' prefix."""
    body = purl[4:] if purl[:4].lower() == "pkg:" else purl
    return body.split("/", 1)[0]


# ---------------------------------------------------------------- slots: where a purl lives in each format


@dataclass
class Slot:
    """One package and its purl, independent of the SBOM format."""

    path: str  # pointer of the component / SPDX package
    purl_path: str  # pointer of the purl string itself ("" when there is none)
    holder: dict[str, Any] | None  # dict that holds the purl string
    key: str  # key of the purl string in holder
    package: dict[str, Any]
    spec: str

    @property
    def purl(self) -> str | None:
        v = self.holder.get(self.key) if self.holder is not None else None
        return v if isinstance(v, str) else None

    def set_purl(self, value: str) -> None:
        if self.holder is not None:
            self.holder[self.key] = value

    @property
    def name(self) -> Any:
        return self.package.get("name")

    @property
    def version(self) -> str | None:
        v = self.package.get("version" if self.spec == "cyclonedx" else "versionInfo")
        if v is None:
            return None
        s = str(v).strip()
        return s if s and s.lower() not in ("unknown", "noassertion", "none") else None

    @property
    def group(self) -> str | None:
        g = self.package.get("group") if self.spec == "cyclonedx" else None
        return g if isinstance(g, str) and g else None

    @property
    def bom_ref(self) -> Any:
        return self.package.get("bom-ref") if self.spec == "cyclonedx" else self.package.get("SPDXID")

    def prop(self, *names: str) -> str | None:
        for p in self.package.get("properties") or []:
            if isinstance(p, dict) and p.get("name") in names and p.get("value") is not None:
                return str(p["value"])
        return None

    def has_other_identity(self) -> bool:
        if self.spec == "cyclonedx":
            return bool(self.package.get("cpe") or self.package.get("hashes") or self.package.get("swid"))
        refs = self.package.get("externalRefs") or []
        return bool(self.package.get("checksums")) or any(
            isinstance(r, dict) and str(r.get("referenceType", "")).startswith("cpe") for r in refs)


def _is_purl_ref(ref: Any) -> bool:
    return (isinstance(ref, dict) and str(ref.get("referenceType", "")).lower() == "purl"
            and str(ref.get("referenceCategory", "")).upper().replace("_", "-") == "PACKAGE-MANAGER")


def slots(doc: Any, spec: str) -> list[Slot]:
    out: list[Slot] = []
    if not isinstance(doc, dict):
        return out
    if spec == "cyclonedx":
        for path, c in iter_components(doc):
            has = "purl" in c
            out.append(Slot(path, f"{path}/purl" if has else "", c, "purl", c, spec))
        return out
    for i, p in enumerate(doc.get("packages") or []):
        if not isinstance(p, dict):
            continue
        refs = p.get("externalRefs") or []
        j = next((j for j, r in enumerate(refs) if _is_purl_ref(r)), None)
        if j is None:
            out.append(Slot(f"/packages/{i}", "", None, "referenceLocator", p, spec))
        else:
            out.append(Slot(f"/packages/{i}", f"/packages/{i}/externalRefs/{j}/referenceLocator", refs[j],
                            "referenceLocator", p, spec))
    return out


# ---------------------------------------------------------------- Checkmarx coverage

SCANNED = ("supported", "fixed", "remapped", "versionless")
NOT_SCANNED = ("unsupported", "os-package", "missing", "malformed")


@dataclass
class CoverageRow:
    path: str
    bom_ref: str
    name: str
    version: str
    original_purl: str
    final_purl: str
    purl_type: str
    checkmarx_pm: str
    status: str
    rule_ids: str
    reason: str

    @property
    def scanned(self) -> bool:
        return self.status in SCANNED


@dataclass
class Coverage:
    rows: list[CoverageRow] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.rows)

    @property
    def scanned(self) -> int:
        return sum(1 for r in self.rows if r.scanned)

    def by_status(self) -> dict[str, int]:
        c = Counter(r.status for r in self.rows)
        return {s: c.get(s, 0) for s in SCANNED + NOT_SCANNED}

    def by_type(self) -> list[tuple[str, int, str, str]]:
        """(type, count, Checkmarx package manager, worst status) sorted by count."""
        groups: dict[str, list[CoverageRow]] = {}
        for r in self.rows:
            groups.setdefault(r.purl_type or "(no purl)", []).append(r)
        out = []
        for t, rows in groups.items():
            statuses = Counter(r.status for r in rows)
            out.append((t, len(rows), rows[0].checkmarx_pm or "-", ", ".join(f"{s} {n}" for s, n in statuses.most_common())))
        return sorted(out, key=lambda x: (-x[1], x[0]))

    def summary(self) -> dict[str, Any]:
        return {"total": self.total, "scanned": self.scanned, "by_status": self.by_status(),
                "by_type": {t: n for t, n, _, _ in self.by_type()}}


def is_os_package(p: PackageURL, slot: Slot, policy: PurlPolicy) -> bool:
    t = p.type.lower()
    if t in policy.os_types:
        return True
    if t != "deb":
        return False
    if (p.namespace or "").lower() in OS_DEB_NAMESPACES or "distro" in (p.qualifiers or {}):
        return True
    hint = (slot.prop("syft:package:type", "aquasecurity:trivy:PkgType") or "").lower()
    return hint in ("deb", "debian", "ubuntu")


def _chain(final: str, log: ChangeLog | None) -> tuple[str, list[str]]:
    """Follow purl edits backwards from the final value: (original purl, rule ids oldest first)."""
    if log is None:
        return final, []
    edits: dict[str, tuple[str, str]] = {}
    for c in log.changes:
        if isinstance(c.after, str) and isinstance(c.before, str) and (c.rule_id in REMAP_RULES or c.rule_id in FIX_RULES):
            edits.setdefault(c.after, (c.before, c.rule_id))
    cur, rules, seen = final, [], set()
    while cur in edits and cur not in seen:
        seen.add(cur)
        cur, rid = edits[cur]
        rules.append(rid)
    return cur, list(reversed(rules))


def classify(doc: Any, spec: str, policy: PurlPolicy, log: ChangeLog | None = None) -> Coverage:
    cov = Coverage()
    for s in slots(doc, spec):
        purl = s.purl
        base = dict(path=s.path, bom_ref=str(s.bom_ref or ""), name=str(s.name or ""), version=str(s.version or ""))
        if purl is None:
            reason = "no purl; identified only by CPE/hash" if s.has_other_identity() else "no purl"
            cov.rows.append(CoverageRow(**base, original_purl="", final_purl="", purl_type="", checkmarx_pm="",
                                        status="missing", rule_ids="", reason=reason))
            continue
        p = try_purl(purl)
        original, rules = _chain(purl, log)
        common = dict(base, original_purl=original, final_purl=purl, rule_ids=" ".join(rules))
        if p is None:
            cov.rows.append(CoverageRow(**common, purl_type=raw_type(purl), checkmarx_pm="", status="malformed",
                                        reason="purl does not parse"))
            continue
        pm = policy.pm_for(p.type)
        if pm is not None and is_os_package(p, s, policy):
            cov.rows.append(CoverageRow(**common, purl_type=p.type, checkmarx_pm=pm, status="os-package",
                                        reason="OS package; Checkmarx reads deb as C++ (Conan), results may be wrong"))
            continue
        if pm is None:
            os_pkg = is_os_package(p, s, policy)
            cov.rows.append(CoverageRow(**common, purl_type=p.type, checkmarx_pm="",
                                        status="os-package" if os_pkg else "unsupported",
                                        reason=unsupported_reason(p.type)))
            continue
        if p.type.lower() in NPM_FAMILY and UNENCODED_NPM_SCOPE.match(purl):
            # documented by Checkmarx: scoped packages are only found with '@' encoded as %40 (CXP-002 fixes it)
            cov.rows.append(CoverageRow(**common, purl_type=p.type, checkmarx_pm=pm, status="malformed",
                                        reason="npm scope '@' not encoded as %40; Checkmarx does not match it"))
            continue
        if any(r in REMAP_RULES for r in rules):
            status, reason = "remapped", f"remapped from {raw_type(original) or 'url'}"
        elif rules:
            status, reason = "fixed", "format repaired for Checkmarx"
        else:
            status, reason = "supported", ""
        if not p.version:
            status, reason = "versionless", "no version; Checkmarx checks it against the latest version"
        cov.rows.append(CoverageRow(**common, purl_type=p.type, checkmarx_pm=pm, status=status, reason=reason))
    return cov


_UNSUPPORTED_REASONS = {
    "rpm": "OS package; not in the Checkmarx vulnerability database",
    "apk": "OS package; not in the Checkmarx vulnerability database",
    "alpm": "OS package; not in the Checkmarx vulnerability database",
    "generic": "no package registry; cannot be matched",
    "docker": "container image; use Checkmarx Container Security",
    "oci": "container image; use Checkmarx Container Security",
    "cargo": "Rust crates are not supported by the Checkmarx SBOM scan",
    "hex": "Hex packages are not supported by the Checkmarx SBOM scan",
    "github": "GitHub repository or action, not a registry package",
}


def unsupported_reason(purl_type: str) -> str:
    return _UNSUPPORTED_REASONS.get(purl_type.lower(), f"purl type '{purl_type}' is not recognized by Checkmarx")


def coverage_csv(cov: Coverage) -> str:
    import csv
    import io

    buf = io.StringIO()
    cols = ["path", "bom_ref", "name", "version", "original_purl", "final_purl", "purl_type", "checkmarx_pm",
            "status", "rule_ids", "reason"]
    wr = csv.writer(buf, lineterminator="\n")
    wr.writerow(cols)
    for r in cov.rows:
        wr.writerow([getattr(r, c) for c in cols])
    return buf.getvalue()
