"""Same-version repair rules REP-001..REP-012 (case A). They act on the current level's validation issues."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from packageurl import PackageURL

from ..changes import DATA_LOSS, INFO, WARN
from ..jsonutil import add_property, get_at, pointer
from ..licenses import canonical_id, looks_like_expression, normalize_expression, spdx_ids
from ..schemas import schema_url
from ..validate import FORMAT_CHECKER as _FORMATS
from ..validate import Issue
from .base import REPAIR, Ctx, Rule, register


def _current(doc: Any, issue: Issue) -> tuple[bool, Any]:
    try:
        return True, get_at(doc, issue.parts)
    except (KeyError, IndexError, TypeError):
        return False, None


def _set(doc: Any, parts: tuple[Any, ...], value: Any) -> None:
    get_at(doc, parts[:-1])[parts[-1]] = value


def _norm_token(s: str) -> str:
    return re.sub(r"[-_ .]", "", s.lower())


@register
class SchemaUrlMatchesVersion(Rule):
    id = "REP-001"
    title = "$schema matches specVersion"
    description = "$schema pointed to a different CycloneDX version than specVersion; $schema was corrected."
    source_fix = "Make the generator write a $schema URL that matches specVersion, or omit $schema."
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        if "$schema" not in doc:
            return
        expected = schema_url(ctx.version)
        if doc["$schema"] != expected:
            ctx.log.add(self.id, "/$schema", "replaced", doc["$schema"], expected, WARN,
                        f"$schema must be {expected} for specVersion {ctx.version}")
            doc["$schema"] = expected


@register
class SpecVersionIsString(Rule):
    id = "REP-002"
    title = "specVersion is a string"
    description = "specVersion was written as a number; it must be a string such as \"1.5\"."
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        sv = doc.get("specVersion")
        if not isinstance(sv, str):
            new = ctx.version
            ctx.log.add(self.id, "/specVersion", "replaced", sv, new, INFO, "specVersion must be a string")
            doc["specVersion"] = new


@register
class EnumCase(Rule):
    id = "REP-003"
    title = "Enum values in the exact form the schema expects"
    description = "A value was written in the wrong case or spelling (for example 'Library' or 'sha256'); it was mapped to the one allowed value it matches."
    specs = ("cyclonedx", "spdx")
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            if issue.keyword != "enum" or not isinstance(issue.instance, str) or not issue.parts:
                continue
            ok, cur = _current(doc, issue)
            if not ok or cur != issue.instance:
                continue
            allowed = [a for a in issue.expected if isinstance(a, str)]
            matches = [a for a in allowed if _norm_token(a) == _norm_token(cur)]
            if len(matches) == 1:
                _set(doc, issue.parts, matches[0])
                ctx.log.add(self.id, issue.path, "replaced", cur, matches[0], INFO,
                            f"'{cur}' is not an allowed value; the schema expects '{matches[0]}'")
            else:
                ctx.log.note(self.id, issue.path, f"'{cur}' is not an allowed value and no single allowed value matches it; left unchanged")


@register
class ScalarTypes(Rule):
    id = "REP-004"
    title = "Scalars have the type the schema expects"
    description = "A number or boolean was written where the schema expects a string (or the reverse); it was converted without changing its meaning."
    specs = ("cyclonedx", "spdx")
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            if issue.keyword != "type" or not issue.parts:
                continue
            ok, cur = _current(doc, issue)
            if not ok or cur is None or cur != issue.instance:
                continue
            exp = issue.expected if isinstance(issue.expected, list) else [issue.expected]
            new: Any = _SENTINEL
            if "string" in exp and isinstance(cur, bool):
                new = "true" if cur else "false"
            elif "string" in exp and isinstance(cur, (int, float)):
                new = str(cur)
            elif "integer" in exp and isinstance(cur, str) and cur.strip().isdigit():
                new = int(cur.strip())
            elif "number" in exp and isinstance(cur, str) and re.fullmatch(r"-?\d+(\.\d+)?", cur.strip()):
                new = float(cur) if "." in cur else int(cur)
            elif "boolean" in exp and isinstance(cur, str) and cur.strip().lower() in ("true", "false"):
                new = cur.strip().lower() == "true"
            if new is not _SENTINEL:
                _set(doc, issue.parts, new)
                ctx.log.add(self.id, issue.path, "converted", cur, new, INFO,
                            f"Schema expects {'/'.join(map(str, exp))}")


_SENTINEL = object()


@register
class NullsAndEmpties(Rule):
    id = "REP-005"
    title = "Remove null and empty values the schema rejects"
    description = "A field was null or empty where the schema requires content; the field was removed."
    specs = ("cyclonedx", "spdx")
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            if not issue.parts:
                continue
            ok, cur = _current(doc, issue)
            if not ok:
                continue
            if (issue.keyword == "type" and cur is None) or (issue.keyword == "minLength" and cur == "") or (
                issue.keyword == "minItems" and cur == [] and not isinstance(issue.parts[-1], int)
            ):
                if issue.parts[-1] == "version" and len(issue.parts) >= 2:
                    owner = get_at(doc, issue.parts[:-1])
                    purl = _purl(owner) if isinstance(owner, dict) else None
                    if purl is not None and purl.version:
                        owner["version"] = purl.version
                        ctx.log.add(self.id, issue.path, "replaced", cur, purl.version, INFO, "Empty version taken from the purl")
                        continue
                ctx.schedule_removal(issue.parts, self.id, INFO, "Value was null or empty")


_REQ = re.compile(r"'([^']+)' is a required property")
_DROP_INCOMPLETE = {"dependencies", "hashes", "externalReferences", "properties", "references", "advisories"}


def _purl(component: dict[str, Any]) -> PackageURL | None:
    p = component.get("purl")
    if not isinstance(p, str):
        return None
    try:
        return PackageURL.from_string(p)
    except ValueError:
        return None


@register
class RequiredFields(Rule):
    id = "REP-006"
    title = "Fill or remove entries that miss required fields"
    description = "An entry missed a required field. It was filled only when the value is unambiguous (for example a name taken from the purl); otherwise the entry was removed or reported."
    source_fix = "Check why the generator writes components without name or type."
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            if issue.keyword != "required":
                continue
            m = _REQ.search(issue.message)
            if not m:
                continue
            missing = m.group(1)
            ok, obj = _current(doc, issue)
            if not ok or not isinstance(obj, dict) or missing in obj:
                continue
            parts = issue.parts
            if not parts:  # document root
                if missing == "version":
                    obj["version"] = 1
                    ctx.log.add(self.id, "/version", "added", None, 1, INFO, "BOM version is required at this spec version")
                continue
            is_component = len(parts) >= 2 and parts[-2] == "components" or parts[-1:] == ("component",)
            if is_component:
                self._component(doc, ctx, issue, obj, missing)
                continue
            container_key = parts[-2] if len(parts) >= 2 and isinstance(parts[-1], int) else None
            if container_key in _DROP_INCOMPLETE:
                ctx.schedule_removal(parts, self.id, WARN, f"Entry has no '{missing}' and cannot be used")
            else:
                ctx.log.note(self.id, issue.path, f"Required field '{missing}' is missing and cannot be derived")

    def _component(self, doc: Any, ctx: Ctx, issue: Issue, comp: dict[str, Any], missing: str) -> None:
        purl = _purl(comp)
        path = issue.path
        if missing == "type":
            if purl is not None:
                comp["type"] = "library"
                ctx.log.add(self.id, f"{path}/type", "added", None, "library", WARN,
                            "Component has a package purl, so its type is 'library'")
            else:
                ctx.log.note(self.id, path, "Component has no type and no purl; type cannot be derived")
        elif missing == "name":
            if purl is not None and purl.name:
                comp["name"] = purl.name
                ctx.log.add(self.id, f"{path}/name", "added", None, purl.name, INFO, "Name taken from the purl")
            else:
                ctx.schedule_removal(issue.parts, self.id, DATA_LOSS, "Component has no name and no purl")
        elif missing == "version":
            ver = purl.version if purl is not None and purl.version else None
            comp["version"] = ver or "unknown"
            ctx.log.add(self.id, f"{path}/version", "added", None, comp["version"], INFO if ver else WARN,
                        "Version taken from the purl" if ver else "Version is required at this spec version and is unknown")
        else:
            ctx.log.note(self.id, path, f"Component misses required field '{missing}'")


@register
class SerialNumber(Rule):
    id = "REP-007"
    title = "serialNumber is a urn:uuid"
    description = "serialNumber was not in urn:uuid form; a deterministic UUID was written and the old value kept in metadata.properties."
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            if issue.parts == ("serialNumber",) and issue.keyword in ("pattern", "format", "type"):
                old = doc.get("serialNumber")
                new = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "sbom-fixer:" + ctx.source_sha256))
                doc["serialNumber"] = new
                if old not in (None, ""):
                    add_property(doc.setdefault("metadata", {}), "sbom-fixer:originalSerialNumber", str(old))
                ctx.log.add(self.id, "/serialNumber", "replaced", old, new, INFO, "serialNumber must match urn:uuid:<uuid>")
                return


_DT_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S", "%Y%m%dT%H%M%SZ")


def parse_datetime(text: str) -> tuple[datetime | None, bool]:
    """Return (aware datetime, assumed_utc)."""
    s = text.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for fmt in _DT_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None, False
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC), True
    return dt, False


def format_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@register
class DateTimes(Rule):
    id = "REP-008"
    title = "Timestamps are ISO 8601 date-times"
    description = "A timestamp was not a valid ISO 8601 date-time; it was rewritten in UTC (a missing timezone is assumed to be UTC and reported)."
    specs = ("cyclonedx", "spdx")
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            fmt_issue = issue.keyword == "format" and issue.expected == "date-time"
            pattern_issue = issue.keyword == "pattern" and issue.parts and str(issue.parts[-1]) in ("created", "timestamp")
            if not (fmt_issue or pattern_issue) or not isinstance(issue.instance, str):
                continue
            ok, cur = _current(doc, issue)
            if not ok or cur != issue.instance:
                continue
            dt, assumed = parse_datetime(cur)
            if dt is None:
                ctx.log.note(self.id, issue.path, f"'{cur}' is not a recognisable date-time; left unchanged")
                continue
            new = format_utc(dt)
            _set(doc, issue.parts, new)
            ctx.log.add(self.id, issue.path, "replaced", cur, new, WARN if assumed else INFO,
                        "No timezone given; UTC assumed" if assumed else "Rewritten as ISO 8601 UTC")


_URI_FORMATS = ("iri-reference", "uri-reference", "iri", "uri")


@register
class Uris(Rule):
    id = "REP-009"
    title = "URLs are valid IRI references"
    description = "A URL contained characters that are not allowed (for example spaces); they were percent-encoded. External references whose URL could not be repaired were removed."
    specs = ("cyclonedx", "spdx")
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            if not issue.parts:
                continue
            if issue.keyword == "format" and issue.expected == "idn-email":
                ctx.schedule_removal(issue.parts, self.id, WARN, "Not a valid e-mail address")
                continue
            if issue.keyword != "format" or issue.expected not in _URI_FORMATS or not isinstance(issue.instance, str):
                continue
            ok, cur = _current(doc, issue)
            if not ok or cur != issue.instance:
                continue
            new = quote(cur.strip(), safe=":/?#[]@!$&'()*+,;=%~")
            if new != cur and _FORMATS.conforms(new, issue.expected):
                _set(doc, issue.parts, new)
                ctx.log.add(self.id, issue.path, "replaced", cur, new, INFO, "Characters not allowed in a URL were percent-encoded")
            elif len(issue.parts) >= 3 and issue.parts[-1] == "url" and issue.parts[-3] == "externalReferences":
                ctx.schedule_removal(issue.parts[:-1], self.id, DATA_LOSS, "External reference URL cannot be repaired")
            else:
                ctx.log.note(self.id, issue.path, f"'{cur}' is not a valid {issue.expected}; left unchanged")


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def fix_license_array(arr: list[Any], path: str, ctx: Ctx, rule_id: str) -> list[Any]:
    """Normalize a CycloneDX licenses array for the current version. Returns the new array."""
    out: list[Any] = []
    for i, entry in enumerate(arr):
        p = f"{path}/{i}"
        if isinstance(entry, str):
            entry = _wrap_string(entry, p, ctx, rule_id)
        elif isinstance(entry, dict) and "license" not in entry and "expression" not in entry and (
            {"id", "name", "url", "text"} & set(entry)
        ):
            ctx.log.add(rule_id, p, "converted", dict(entry), {"license": entry}, INFO, "License entry must be wrapped in {\"license\": ...}")
            entry = {"license": entry}
        if isinstance(entry, dict) and isinstance(entry.get("license"), dict):
            _fix_license_object(entry["license"], f"{p}/license", ctx, rule_id)
        out.append(entry)
    if _version_tuple(ctx.version) >= (1, 5):
        has_expr = any(isinstance(e, dict) and "expression" in e for e in out)
        if has_expr and (len(out) > 1):
            new_out = []
            for i, e in enumerate(out):
                if isinstance(e, dict) and "expression" in e:
                    conv = {"license": {"name": str(e["expression"])}}
                    ctx.log.add(rule_id, f"{path}/{i}", "converted", e, conv, INFO,
                                "From CycloneDX 1.5 a licenses array holds either license objects or one expression; the expression text was kept as a license name")
                    new_out.append(conv)
                else:
                    new_out.append(e)
            out = new_out
    return out


def _wrap_string(s: str, p: str, ctx: Ctx, rule_id: str) -> dict[str, Any]:
    cid = canonical_id(s)
    if cid:
        new: dict[str, Any] = {"license": {"id": cid}}
    elif looks_like_expression(s) and normalize_expression(s):
        new = {"expression": normalize_expression(s)}
    else:
        new = {"license": {"name": s}}
    ctx.log.add(rule_id, p, "converted", s, new, INFO, "A license was written as a plain string")
    return new


def _fix_license_object(lic: dict[str, Any], p: str, ctx: Ctx, rule_id: str) -> None:
    lid = lic.get("id")
    if lid is not None and lid not in spdx_ids():
        cid = canonical_id(str(lid))
        if cid:
            lic["id"] = cid
            ctx.log.add(rule_id, f"{p}/id", "replaced", lid, cid, INFO, f"'{lid}' is not an SPDX license ID; it matches '{cid}'")
        else:
            del lic["id"]
            if not lic.get("name"):
                lic["name"] = str(lid)
            ctx.log.add(rule_id, f"{p}/id", "moved", lid, f"name={lic['name']}", INFO,
                        f"'{lid}' is not an SPDX license ID; kept as license name")
    if "id" in lic and "name" in lic:
        name = lic.pop("name")
        ctx.log.add(rule_id, f"{p}/name", "removed", name, None, INFO, "A license may have id or name, not both; the SPDX id was kept")


@register
class LicenseStructure(Rule):
    id = "REP-010"
    title = "License entries have a valid structure"
    description = "A licenses array was malformed (plain strings, unwrapped objects, id and name together, non-SPDX IDs, or expressions mixed with license objects); it was restructured without dropping license text."
    source_fix = "Use SPDX license IDs (https://spdx.org/licenses/) in the build metadata."
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        arrays: dict[tuple[Any, ...], None] = {}
        for issue in ctx.issues:
            parts = issue.parts
            if "licenses" not in parts:
                continue
            idx = max(i for i, p in enumerate(parts) if p == "licenses")
            arrays[tuple(parts[: idx + 1])] = None
        for parts in arrays:
            try:
                arr = get_at(doc, parts)
            except (KeyError, IndexError, TypeError):
                continue
            if isinstance(arr, dict):
                arr = [arr]
            if not isinstance(arr, list):
                continue
            new = fix_license_array(arr, pointer(parts), ctx, self.id)
            get_at(doc, parts[:-1])[parts[-1]] = new


@register
class Hashes(Rule):
    id = "REP-011"
    title = "Hash values match their algorithm"
    description = "A hash value did not match its algorithm (wrong length or characters) or used an unknown algorithm; that hash was removed."
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            parts = issue.parts
            if len(parts) >= 3 and parts[-3] == "hashes" and parts[-1] in ("content", "alg") and issue.keyword in ("pattern", "enum"):
                ok, cur = _current(doc, issue)
                if not ok or cur != issue.instance:
                    continue
                if issue.keyword == "enum":
                    allowed = [a for a in issue.expected if isinstance(a, str)]
                    if len([a for a in allowed if _norm_token(a) == _norm_token(str(cur))]) == 1:
                        continue  # REP-003 fixes the case
                ctx.schedule_removal(parts[:-1], self.id, INFO, "Hash content does not match its algorithm")


@register
class ContainerTypes(Rule):
    id = "REP-012"
    title = "Arrays where the schema expects arrays"
    description = "A single value was written where the schema expects an array; it was wrapped in an array."
    specs = ("cyclonedx", "spdx")
    kind = REPAIR

    def apply(self, doc: Any, ctx: Ctx) -> None:
        for issue in ctx.issues:
            if issue.keyword != "type" or not issue.parts:
                continue
            exp = issue.expected if isinstance(issue.expected, list) else [issue.expected]
            if "array" not in exp:
                continue
            ok, cur = _current(doc, issue)
            if not ok or cur is None or isinstance(cur, list) or cur != issue.instance:
                continue
            _set(doc, issue.parts, [cur])
            ctx.log.add(self.id, issue.path, "converted", cur, [cur], INFO, "Schema expects an array")
