"""fill-required / fill-all: add the fields the schema defines, derived from the SBOM where a rule allows it,
otherwise a placeholder value that is valid for the schema and clearly marked as such.

Order of preference for every missing field:
  1. derived  - from data already in the SBOM (purl, bom-ref, publisher, evidence, file name, ...), same rules as `fix`
  2. standard - the value the spec defines for "unknown" (SPDX NOASSERTION, CycloneDX version 1, ...)
  3. default  - the schema's own default
  4. example  - the schema's first example, when it fits the schema
  5. enum     - an allowed value ("unknown"/"other" first)
  6. dummy    - PLACEHOLDER text, https://placeholder.invalid/, placeholder@example.invalid, 0, false

Never invented, only derived (a dummy would be read as a real fact by scanners):
  identity fields (purl, cpe, swid, omniborId, swhid, SPDX externalRefs) and references to other elements (refType ...).
Skipped unless --include-sensitive: hashes, signatures, vulnerabilities, attestations, crypto, SPDX checksums/files.
Every addition that would make the document schema-invalid is rolled back and reported.
"""

from __future__ import annotations

import copy
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from packageurl import PackageURL

from . import __version__
from .jsonutil import pointer
from .prune import _branch_for
from .rules.sanitize import _ecosystem
from .schemas import load_schema, resolve_local, schema_url
from .validate import FORMAT_CHECKER, validate

NONE: Any = object()  # "no value could be produced"
MODES = ("required", "all")
MAX_NEW_DEPTH = 4  # in mode "all", objects created deeper than this only get their required fields

REF_DEFINITIONS = {"refType", "refLinkType", "bomLinkDocumentType", "bomLinkElementType", "bomLink"}
REF_KEYS = {"ref", "dependsOn", "provides", "assemblies", "dependencies", "services", "hasFiles", "spdxElementId",
            "relatedSpdxElement", "documentDescribes", "relationships", "subjects"}
IDENTITY_KEYS = {"cyclonedx": {"purl", "cpe", "swid", "omniborId", "swhid"},
                 "spdx": {"externalRefs", "externalDocumentRefs"}}
SENSITIVE_KEYS = {"cyclonedx": {"hashes", "signature", "vulnerabilities", "declarations", "definitions", "cryptoProperties",
                                "formulation"},
                  "spdx": {"checksums", "packageVerificationCode", "files", "snippets", "annotations"}}
ENUM_PREFERENCE = ("unknown", "other", "library", "NOASSERTION")
PLACEHOLDER = "PLACEHOLDER"
PLACEHOLDER_URL = "https://placeholder.invalid/"
PLACEHOLDER_EMAIL = "placeholder@example.invalid"
# Only lengths with a single common algorithm (128 hex could also be BLAKE2b-512 / SHA3-512, so it is not derived)
HASH_ALG_BY_HEX_LENGTH = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 96: "SHA-384"}
# tried in order when "PLACEHOLDER-<field>" does not match a field's pattern (mime types, versions, ids ...)
PATTERN_FRIENDLY_PLACEHOLDERS = ("PLACEHOLDER", "placeholder", "application/x-placeholder", "x-placeholder", "0.0.0", "0")
NOASSERTION_FIELDS = {"downloadLocation", "licenseConcluded", "licenseDeclared", "copyrightText", "supplier", "originator"}


@dataclass
class Fill:
    path: str
    value: Any
    source: str  # derived:<how> | standard | default | example | enum | dummy | container

    def to_dict(self) -> dict[str, Any]:
        if self.source == "container":  # its fields are listed as their own entries
            shown: Any = f"[{len(self.value)} item(s)]" if isinstance(self.value, list) else "{object}"
            return {"path": self.path, "source": self.source, "value": shown}
        text = json.dumps(self.value, ensure_ascii=False, default=str)
        return {"path": self.path, "source": self.source, "value": self.value if len(text) <= 200 else text[:200] + "..."}


@dataclass
class Skip:
    path: str
    reason: str


@dataclass
class FillResult:
    doc: Any
    spec: str
    version: str
    mode: str
    fills: list[Fill] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    unresolved: list[Skip] = field(default_factory=list)  # required fields that could not be filled
    removed: list[Fill] = field(default_factory=list)  # existing values the schema rejects, removed (and refilled)
    prepared: list[str] = field(default_factory=list)  # how the input was turned into an SBOM (markers, version)
    repairs: list[dict[str, Any]] = field(default_factory=list)  # same-version repair rules applied first (REP/SAN)
    errors_before: int = 0
    errors_after: int = 0

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.fills:
            key = f.source.split(":")[0]
            out[key] = out.get(key, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"spec": self.spec, "version": self.version, "mode": self.mode, "counts": self.counts(),
                "schema_errors_before": self.errors_before, "schema_errors_after": self.errors_after,
                "prepared": self.prepared, "repairs": self.repairs,
                "removed_invalid": [f.to_dict() for f in self.removed],
                "fills": [f.to_dict() for f in self.fills], "skipped": [s.__dict__ for s in self.skipped],
                "unresolved_required": [s.__dict__ for s in self.unresolved]}


def _def_name(schema: Any) -> str | None:
    ref = schema.get("$ref") if isinstance(schema, dict) else None
    if isinstance(ref, str) and ref.startswith("#/definitions/"):
        return ref.rsplit("/", 1)[1]
    if isinstance(schema, dict) and schema.get("type") == "array":
        return _def_name(schema.get("items"))
    return None


def _deprecated(schema: dict[str, Any]) -> bool:
    if schema.get("deprecated") is True:
        return True
    text = f"{schema.get('title', '')} {schema.get('description', '')}".strip().lower()
    return text.startswith("deprecated") or text.startswith("[deprecated")


def _try_purl(text: Any) -> PackageURL | None:
    if not isinstance(text, str):
        return None
    try:
        return PackageURL.from_string(text)
    except ValueError:
        return None


class Filler:
    def __init__(self, doc: dict[str, Any], spec: str, version: str, mode: str, *, file_stem: str, now: datetime,
                 source_sha256: str, include_sensitive: bool = False) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.doc, self.spec, self.version, self.mode = doc, spec, version, mode
        self.root = load_schema(spec, version)
        self.file_stem = file_stem
        self.now = now.astimezone(UTC).replace(microsecond=0)
        self.sha = source_sha256
        self.include_sensitive = include_sensitive
        self.result = FillResult(doc, spec, version, mode)
        self.added: list[tuple[Any, ...]] = []
        self.refs = self._existing_refs()
        self.counter = 0

    # ------------------------------------------------------------------ entry

    def run(self, errors_before: int | None = None) -> FillResult:
        self.result.errors_before = (len(validate(self.doc, self.spec, self.version)) if errors_before is None
                                     else errors_before)
        self.visit(self.doc, self.root, (), (), 0, is_new=False)
        self._rollback_invalid()
        for _ in range(6):  # existing values the schema rejects: remove them, then fill the gap again
            if not self._coerce_existing():
                break
            self.visit(self.doc, self.root, (), (), 0, is_new=False)
            self._rollback_invalid()
        self.result.errors_after = len(validate(self.doc, self.spec, self.version))
        return self.result

    def _coerce_existing(self) -> bool:
        """Remove each existing value a schema error points at (for a required field that could not be filled:
        the object that misses it). Returns True when something was removed, so the gaps get filled again."""
        issues = validate(self.doc, self.spec, self.version)
        targets: dict[tuple[Any, ...], Any] = {}
        for issue in issues:
            parts = tuple(issue.parts)
            if parts:
                targets.setdefault(parts, issue)
        removed = False
        for parts in sorted(targets, key=lambda t: (len(t), [str(x) for x in t]), reverse=True):
            if not self._exists(parts):
                continue
            container = self._get(parts[:-1])
            if not isinstance(container, (dict, list)):
                continue
            issue = targets[parts]
            old = container[parts[-1]]
            converted = _convert(old, issue.expected) if issue.keyword == "type" else NONE
            if converted is not NONE:
                container[parts[-1]] = converted
                self.result.removed.append(Fill(pointer(parts), {"before": old, "after": copy.deepcopy(converted)},
                                                f"converted: {issue.message[:120]}"))
            else:
                container.pop(parts[-1])
                self.result.removed.append(Fill(pointer(parts), old, f"removed: {issue.keyword}: {issue.message[:120]}"))
            removed = True
        if removed:
            self.refs = self._existing_refs()
        return removed

    # ------------------------------------------------------------------ helpers

    def _existing_refs(self) -> set[str]:
        out: set[str] = set()

        def rec(node: Any) -> None:
            if isinstance(node, dict):
                for k in ("bom-ref", "SPDXID"):
                    if isinstance(node.get(k), str):
                        out.add(node[k])
                for v in node.values():
                    rec(v)
            elif isinstance(node, list):
                for v in node:
                    rec(v)

        rec(self.doc)
        return out

    def _unique_ref(self, wanted: str | None, prefix: str) -> str:
        if wanted and wanted not in self.refs:
            self.refs.add(wanted)
            return wanted
        while True:
            self.counter += 1
            cand = f"{prefix}{self.counter}"
            if cand not in self.refs:
                self.refs.add(cand)
                return cand

    def _resolve(self, schema: Any) -> dict[str, Any] | None:
        return resolve_local(schema, self.root) if isinstance(schema, dict) else None

    def _record(self, parts: tuple[Any, ...], value: Any, source: str) -> None:
        self.added.append(parts)
        self.result.fills.append(Fill(pointer(parts), value, source))

    def _skip(self, parts: tuple[Any, ...], reason: str, required: bool, is_new: bool = False) -> None:
        """A required field of an EXISTING object that stays missing is unresolved; inside a new object it only
        means the new object is dropped again, which is a plain skip."""
        target = self.result.unresolved if (required and not is_new) else self.result.skipped
        target.append(Skip(pointer(parts), reason + (" (so the new object was not added)" if required and is_new else "")))

    def _blocked(self, key: str, prop: dict[str, Any]) -> str | None:
        if key in IDENTITY_KEYS[self.spec]:
            return "identity field: only derived, never a placeholder"
        if key in REF_KEYS or _def_name(prop) in REF_DEFINITIONS:
            return "reference to another element: only derived, never a placeholder"
        if not self.include_sensitive and key in SENSITIVE_KEYS[self.spec]:
            return "sensitive field (use --include-sensitive to add placeholders)"
        return None

    # ------------------------------------------------------------------ walker

    def visit(self, node: Any, schema: Any, parts: tuple[Any, ...], stack: tuple[str, ...], new_level: int,
              is_new: bool) -> bool:
        """Fill node in place. Returns False when a required field of a NEW node could not be produced."""
        name = _def_name(schema)
        schema = self._resolve(schema)
        if schema is None:
            return True
        if name:
            stack = (*stack, name)
        ok = True
        for sub in schema.get("allOf", []):
            ok = self.visit(node, sub, parts, stack, new_level, is_new) and ok
        if isinstance(node, dict):
            branch = self._object_branch(node, schema)
            if branch is not None:
                ok = self._fill_object(node, schema, branch, parts, stack, new_level, is_new) and ok
        elif isinstance(node, list):
            if "items" not in schema and (schema.get("oneOf") or schema.get("anyOf")):
                branches = schema.get("oneOf") or schema.get("anyOf")
                picked = _branch_for(node, branches, self.root) if node and not is_new else None
                if picked is None:  # new list, or ambiguous: the first array branch (e.g. "list of licenses")
                    picked = next((b for b in (self._resolve(x) for x in branches)
                                   if b is not None and b.get("type") == "array" and "items" in b), None)
                return ok if picked is None else self.visit(node, picked, parts, stack, new_level, is_new) and ok
            items = self._resolve(schema.get("items"))
            if items is not None:
                item_name = _def_name(schema.get("items"))
                for i, item in enumerate(node):
                    ok = self.visit(item, schema["items"] if item_name else items, (*parts, i), stack, new_level,
                                    is_new) and ok
        return ok

    def _object_branch(self, node: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any] | None:
        """Merge a oneOf/anyOf branch into the object schema (e.g. license: id XOR name)."""
        branches = schema.get("oneOf") or schema.get("anyOf")
        if not branches:
            return schema if ("properties" in schema or "required" in schema) else None
        resolved = [b for b in (self._resolve(x) for x in branches) if b is not None]
        req_only = all(set(b) <= {"required", "title", "description"} for b in resolved)
        if req_only and "properties" in schema:
            chosen = next((b for b in resolved if all(k in node for k in b.get("required", []))), None)
            if chosen is None:
                chosen = next((b for b in resolved if all(self._can_make(schema["properties"].get(k)) for k in
                                                           b.get("required", []))), resolved[0] if resolved else {})
            others = set().union(*(set(b.get("required", [])) for b in resolved if b is not chosen)) - set(
                chosen.get("required", []))
            merged = dict(schema)
            merged["required"] = list(dict.fromkeys([*schema.get("required", []), *chosen.get("required", [])]))
            merged["properties"] = {k: v for k, v in schema["properties"].items() if k not in others}
            return merged
        picked = _branch_for(node, branches, self.root) if node else None
        if picked is None and not node:
            picked = next((b for b in resolved if b.get("type") == "object" or "properties" in b), None)
        if picked is None:
            return schema if "properties" in schema else None
        merged = dict(picked)
        if "properties" in schema:
            merged["properties"] = {**schema["properties"], **picked.get("properties", {})}
            merged["required"] = list(dict.fromkeys([*schema.get("required", []), *picked.get("required", [])]))
        return merged

    def _can_make(self, prop: Any) -> bool:
        return prop is not None and self._make(prop, ("?",), "?", 0) is not NONE

    def _targets(self, schema: dict[str, Any], new_level: int) -> list[str]:
        props = schema.get("properties") or {}
        required = [k for k in schema.get("required", []) if k in props]
        if self.mode == "required" or new_level > MAX_NEW_DEPTH:
            return required
        rest = [k for k, v in props.items() if k not in required and not _deprecated(self._resolve(v) or {})]
        deferred = [k for k in rest if k in ("dependencies", "compositions")]
        return required + [k for k in rest if k not in deferred] + deferred

    def _fill_object(self, node: dict[str, Any], whole: dict[str, Any], schema: dict[str, Any], parts: tuple[Any, ...],
                     stack: tuple[str, ...], new_level: int, is_new: bool) -> bool:
        props = schema.get("properties") or {}
        required = set(schema.get("required", []))
        complete = True
        # existing children first: derivations on this level can depend on them (dependencies need component bom-refs)
        for key in [k for k in node if k in props]:
            self.visit(node[key], props[key], (*parts, key), stack, new_level, is_new=False)
        for key in self._targets(schema, new_level):
            if key in node:
                continue
            prop = props[key]
            kparts = (*parts, key)
            is_req = key in required
            derived = self.derive(node, key, parts)
            if derived is not NONE:
                value, how = derived
                node[key] = value
                self._record(kparts, value, how if how.startswith("standard") else f"derived:{how}")
                if isinstance(value, (dict, list)):
                    self.visit(value, prop, kparts, stack, new_level + 1, is_new=True)
                continue
            blocked = self._blocked(key, prop)
            if blocked:
                self._skip(kparts, blocked, is_req, is_new)
                complete = complete and not (is_req and is_new)
                continue
            if _def_name(prop) in stack:
                self._skip(kparts, "recursive structure (not expanded)", is_req, is_new)
                complete = complete and not (is_req and is_new)
                continue
            value = self._make(prop, kparts, key, new_level + 1)
            if value is NONE:
                self._skip(kparts, "no value fits the schema (pattern/format/external definition)", is_req, is_new)
                complete = complete and not (is_req and is_new)
                continue
            value, source = value
            node[key] = value
            if isinstance(value, (dict, list)):
                built = self.visit(value, prop, kparts, stack, new_level + 1, is_new=True)
                if not built or (isinstance(value, list) and not value and self._min_items(prop) > 0):
                    del node[key]
                    self._skip(kparts, "a required part of it could not be produced", is_req, is_new)
                    complete = complete and not (is_req and is_new)
                    continue
                if isinstance(value, list) and not value and self.mode == "all":
                    del node[key]  # an empty optional array adds nothing
                    continue
            self._record(kparts, value, source)
        return complete

    def _min_items(self, prop: Any) -> int:
        r = self._resolve(prop) or {}
        return int(r.get("minItems", 0))

    # ------------------------------------------------------------------ value factory

    def _make(self, prop: Any, parts: tuple[Any, ...], key: str, depth: int) -> Any:
        """(value, source) for a missing field, containers empty (the walker fills them), or NONE."""
        schema = self._resolve(prop)
        if schema is None:
            return NONE
        if "const" in schema:
            return schema["const"], "standard"
        if "default" in schema and schema["default"] is not None and self._fits(schema["default"], schema):
            return copy.deepcopy(schema["default"]), "default"
        if "enum" in schema:
            values = schema["enum"]
            pick = next((v for v in ENUM_PREFERENCE if v in values), values[0] if values else NONE)
            return (pick, "enum") if pick is not NONE else NONE
        for alt in ("oneOf", "anyOf"):
            if alt in schema and "type" not in schema and "properties" not in schema:
                for branch in schema[alt]:
                    option = self._make(branch, parts, key, depth)
                    if option is not NONE:
                        return option
                return NONE
        types = schema.get("type")
        typ = next((t for t in types if t != "null"), None) if isinstance(types, list) else types
        if typ is None and "properties" in schema:
            typ = "object"
        if typ == "object":
            return {}, "container"
        if typ == "array":
            if self.mode == "required" and self._min_items(prop) == 0:
                return [], "container"
            items_schema = schema.get("items")
            if items_schema is None:  # items inside a oneOf branch (CycloneDX 1.5+ licenseChoice)
                branch = next((b for b in (self._resolve(x) for x in schema.get("oneOf", []) + schema.get("anyOf", []))
                               if b is not None and "items" in b), None)
                items_schema = branch.get("items") if branch else {}
            item = self._make(items_schema, (*parts, 0), key, depth + 1)
            if item is NONE:
                return ([], "container") if self._min_items(prop) == 0 else NONE
            return [item[0]], "container"
        made: Any = NONE
        if typ == "string":
            fmt = schema.get("format")
            if fmt == "date-time":
                cands = [self.now.strftime("%Y-%m-%dT%H:%M:%SZ")]
            elif fmt in ("iri-reference", "uri-reference", "iri", "uri"):
                cands = [PLACEHOLDER_URL]
            elif fmt in ("idn-email", "email"):
                cands = [PLACEHOLDER_EMAIL]
            else:
                cands = [f"{PLACEHOLDER}-{key}" if key != "?" else PLACEHOLDER, *PATTERN_FRIENDLY_PLACEHOLDERS]
            made = next((c for c in cands if self._fits(c, schema)), NONE)
        elif typ in ("integer", "number"):
            low = schema.get("minimum", schema.get("exclusiveMinimum", -1) + 1 if "exclusiveMinimum" in schema else 0)
            made = low if self._fits(low, schema) else NONE
        elif typ == "boolean":
            made = False
        if made is not NONE:
            return made, "dummy"
        # last resort: a schema example (looks like real data, so it is reported separately as "example")
        for ex in schema.get("examples", []) or []:
            if self._fits(ex, schema):
                return copy.deepcopy(ex), "example"
        return NONE

    def _fits(self, value: Any, schema: dict[str, Any]) -> bool:
        if "enum" in schema and value not in schema["enum"]:
            return False
        if isinstance(value, str):
            if schema.get("type") not in (None, "string") and "string" not in (schema.get("type") or []):
                return False
            if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 10**9):
                return False
            if "pattern" in schema and not re.search(schema["pattern"], value):
                return False
            fmt = schema.get("format")
            return not fmt or fmt not in FORMAT_CHECKER.checkers or FORMAT_CHECKER.conforms(value, fmt)
        if isinstance(value, bool):
            return schema.get("type") in (None, "boolean")
        if isinstance(value, (int, float)):
            if schema.get("type") not in (None, "integer", "number"):
                return False
            return schema.get("minimum", value) <= value <= schema.get("maximum", value)
        return True

    # ------------------------------------------------------------------ derivation rules

    def derive(self, node: dict[str, Any], key: str, parts: tuple[Any, ...]) -> Any:
        return self._derive_cdx(node, key, parts) if self.spec == "cyclonedx" else self._derive_spdx(node, key, parts)

    def _uuid(self) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, "sbom-fixer:" + self.sha))

    def _derive_cdx(self, node: dict[str, Any], key: str, parts: tuple[Any, ...]) -> Any:
        if parts == ():
            fixed = {"bomFormat": ("CycloneDX", "format"), "specVersion": (self.version, "detected version"),
                     "serialNumber": (f"urn:uuid:{self._uuid()}", "deterministic uuid from the input hash (SAN-003)"),
                     "version": (1, "first revision of this BOM (CDX15-010)"),
                     "$schema": (schema_url(self.version), "schema of the declared version")}
            if key in fixed:
                return fixed[key]
            if key == "dependencies" and self.mode == "all":
                refs = [c["bom-ref"] for c in self._components() if isinstance(c.get("bom-ref"), str)]
                if refs:
                    return [{"ref": r} for r in refs], "one entry per component (no dependsOn: dependencies unknown)"
            return NONE
        if parts == ("metadata",):
            if key == "timestamp":
                return self.now.strftime("%Y-%m-%dT%H:%M:%SZ"), "time of this run (UTC)"
            if key == "tools":
                tool = {"type": "application", "name": "sbom-fixer", "version": __version__}
                if self.version in ("1.2", "1.3", "1.4"):
                    return [{"vendor": "sbom-fixer", "name": "sbom-fixer", "version": __version__}], "this tool (SAN-013)"
                return {"components": [tool]}, "this tool (SAN-013)"
            if key == "component":
                return {}, "root component built from the file name"
            return NONE
        if parts == ("metadata", "component"):
            if key == "name":
                return self.file_stem, "file name"
            if key == "type":
                return "application", "root component of an SBOM"
            if key == "bom-ref":
                return self._unique_ref(f"root-{self.file_stem}", "sbom-fixer-ref-"), "unique reference"
        if self._is_component(parts):
            return self._derive_component(node, key)
        if key == "alg" and len(parts) >= 2 and parts[-2] == "hashes" and isinstance(node.get("content"), str):
            alg = HASH_ALG_BY_HEX_LENGTH.get(len(node["content"])) if re.fullmatch(r"[0-9a-fA-F]+", node["content"]) else None
            if alg:
                return alg, f"content length {len(node['content'])} hex characters"
        if key == "bom-ref":
            return self._unique_ref(None, "sbom-fixer-ref-"), "unique reference"
        return NONE

    def _is_component(self, parts: tuple[Any, ...]) -> bool:
        return (len(parts) >= 2 and isinstance(parts[-1], int) and parts[-2] == "components") or parts == (
            "metadata", "component")

    def _components(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []

        def rec(comps: Any) -> None:
            for c in comps or []:
                if isinstance(c, dict):
                    out.append(c)
                    rec(c.get("components"))

        rec(self.doc.get("components"))
        return out

    def _derive_component(self, c: dict[str, Any], key: str) -> Any:
        p = _try_purl(c.get("purl")) or (_try_purl(c.get("bom-ref")) if isinstance(c.get("bom-ref"), str) else None)
        if key == "name" and p is not None:
            return p.name, "purl name (REP-006)"
        if key == "version" and p is not None and p.version:
            return p.version, "purl version (CDX14-001)"
        if key == "group" and p is not None and p.namespace and p.type in ("maven", "gradle", "npm", "composer"):
            return p.namespace, "purl namespace"
        if key == "type":
            return "library", "package component"
        if key == "purl":
            if c.get("purl") is None and isinstance(c.get("bom-ref"), str) and _try_purl(c["bom-ref"]):
                return c["bom-ref"], "bom-ref is a purl (SAN-011)"
            eco = _ecosystem(c)
            if eco and eco != "from-bom-ref" and c.get("name") and c.get("version"):
                ns = c.get("group") or None
                if eco != "maven" or ns:
                    return PackageURL(type=eco, namespace=ns, name=c["name"], version=str(c["version"])).to_string(), \
                        f"generator package type '{eco}' (SAN-011)"
            return NONE
        if key == "bom-ref":
            wanted = c.get("purl") if isinstance(c.get("purl"), str) else None
            if wanted is None and c.get("name"):
                wanted = f"{c['name']}@{c['version']}" if c.get("version") else str(c["name"])
            return self._unique_ref(wanted, "sbom-fixer-ref-"), "purl or name@version, unique"
        if key == "supplier" and isinstance(c.get("publisher"), str) and c["publisher"]:
            return {"name": c["publisher"]}, "publisher"
        if key == "publisher" and isinstance((c.get("supplier") or {}).get("name"), str):
            return c["supplier"]["name"], "supplier name"
        evidence = c.get("evidence") or {}
        if key == "licenses" and evidence.get("licenses"):
            return copy.deepcopy(evidence["licenses"]), "evidence.licenses"
        if key == "copyright" and evidence.get("copyright"):
            first = evidence["copyright"][0]
            if isinstance(first, dict) and first.get("text"):
                return first["text"], "evidence.copyright"
        if key == "externalReferences" and p is not None:
            refs = [{"type": t, "url": p.qualifiers[q]} for q, t in
                    (("download_url", "distribution"), ("vcs_url", "vcs"), ("repository_url", "distribution"))
                    if (p.qualifiers or {}).get(q)]
            if refs:
                return refs, "purl qualifiers"
        return NONE

    def _derive_spdx(self, node: dict[str, Any], key: str, parts: tuple[Any, ...]) -> Any:
        if parts == ():
            fixed = {"spdxVersion": (f"SPDX-{self.version}", "detected version"),
                     "dataLicense": ("CC0-1.0", "the only value SPDX allows"),
                     "SPDXID": ("SPDXRef-DOCUMENT", "SPDX document id"),
                     "name": (self.file_stem, "file name"),
                     "documentNamespace": (f"https://spdx.org/spdxdocs/{self.file_stem}-{self._uuid()}",
                                           "deterministic namespace from file name and input hash"),
                     "creationInfo": ({}, "creation info")}
            return fixed.get(key, NONE)
        if parts == ("creationInfo",):
            if key == "created":
                return self.now.strftime("%Y-%m-%dT%H:%M:%SZ"), "time of this run (UTC)"
            if key == "creators":
                return [f"Tool: sbom-fixer-{__version__}"], "this tool (SAN-013)"
            return NONE
        if len(parts) == 2 and parts[0] == "packages":
            p = None
            for ref in node.get("externalRefs") or []:
                if isinstance(ref, dict) and str(ref.get("referenceType", "")).lower() == "purl":
                    p = _try_purl(ref.get("referenceLocator"))
            if key == "SPDXID":
                return self._unique_ref(None, "SPDXRef-Package-sbom-fixer-"), "unique SPDX id"
            if key == "name" and p is not None:
                return p.name, "purl name"
            if key == "versionInfo" and p is not None and p.version:
                return p.version, "purl version"
            if key == "downloadLocation" and p is not None and (p.qualifiers or {}).get("download_url"):
                return p.qualifiers["download_url"], "purl download_url"
            if key in NOASSERTION_FIELDS:
                return "NOASSERTION", "standard:SPDX NOASSERTION (value for unknown)"
            if key == "filesAnalyzed":
                return False, "no files listed"
        return NONE

    # ------------------------------------------------------------------ rollback

    def _rollback_invalid(self) -> None:
        """Remove every addition that a schema error points into (or that sits under an object now in error)."""
        for _ in range(10):
            issues = validate(self.doc, self.spec, self.version)
            if not issues:
                return
            doomed: set[tuple[Any, ...]] = set()
            live = [a for a in self.added if self._exists(a)]
            for issue in issues:
                ip = tuple(issue.parts)
                inside = [a for a in live if ip[:len(a)] == a]
                if inside:
                    doomed.add(min(inside, key=len))
                    continue
                under = [a for a in live if a[:len(ip)] == ip]
                doomed.update(under)
            if not doomed:
                return
            for a in sorted(doomed, key=len, reverse=True):
                if not self._exists(a):
                    continue
                container = self._get(a[:-1])
                if isinstance(container, dict):
                    container.pop(a[-1], None)
                    self.result.skipped.append(Skip(pointer(a), "removed again: made the document schema-invalid"))
            gone = {pointer(a) for a in doomed}
            self.result.fills = [f for f in self.result.fills
                                 if not any(f.path == g or f.path.startswith(g + "/") for g in gone)]
            self.added = [a for a in self.added if self._exists(a)]

    def _get(self, parts: tuple[Any, ...]) -> Any:
        node: Any = self.doc
        for p in parts:
            node = node[p]
        return node

    def _exists(self, parts: tuple[Any, ...]) -> bool:
        try:
            self._get(parts)
            return True
        except (KeyError, IndexError, TypeError):
            return False


_TRUE, _FALSE = {"true", "yes", "y", "1"}, {"false", "no", "n", "0"}


def _convert(value: Any, expected: Any) -> Any:
    """Keep the meaning when the schema wants another JSON type; NONE when there is no unambiguous conversion."""
    wanted = expected if isinstance(expected, list) else [expected]
    if "boolean" in wanted and isinstance(value, str) and value.strip().lower() in _TRUE | _FALSE:
        return value.strip().lower() in _TRUE
    if "integer" in wanted and isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    if "number" in wanted and isinstance(value, str) and re.fullmatch(r"-?\d+(\.\d+)?", value.strip()):
        return float(value.strip())
    if "object" in wanted and isinstance(value, str) and value.strip():
        return {"name": value.strip()}  # a bare name where an entity/component object is expected
    if "array" in wanted and not isinstance(value, list):
        return [value]
    return NONE


def fill(doc: dict[str, Any], spec: str, version: str, mode: str, *, file_stem: str, source_sha256: str,
         now: datetime | None = None, include_sensitive: bool = False, repair: bool = True,
         prepared: list[str] | None = None) -> FillResult:
    """Repair at the version (same rules as `fix`, never a downgrade), then fill and coerce to the schema."""
    work = copy.deepcopy(doc)
    errors_before = len(validate(work, spec, version))
    repairs: list[dict[str, Any]] = []
    early: list[Fill] = []
    when = now or datetime.now(UTC)
    if repair and errors_before:
        # derive the required fields first, so a repair rule does not drop an entry the SBOM can still complete
        # (REP-006 removes a component without a name, although its purl / bom-ref names it)
        pre = Filler(work, spec, version, "required", file_stem=file_stem, now=when, source_sha256=source_sha256)
        pre.visit(work, pre.root, (), (), 0, is_new=False)
        early = pre.result.fills
        repairs = repair_same_version(work, spec, version, source_sha256)
    filler = Filler(work, spec, version, mode, file_stem=file_stem, now=when,
                    source_sha256=source_sha256, include_sensitive=include_sensitive)
    result = filler.run(errors_before)
    result.fills = early + result.fills
    result.repairs = repairs
    result.prepared = list(prepared or [])
    return result


def repair_same_version(doc: dict[str, Any], spec: str, version: str, source_sha256: str) -> list[dict[str, Any]]:
    """The `fix` repair and sanitize rules at this version only (no descent, no consumer-specific purl rules)."""
    from .changes import ChangeLog
    from .descent import process_level
    from .profile import parse_profile
    from .rules import Ctx

    profile = parse_profile({"name": "fill", "cyclonedx": {"floor": "declared", "accepted_versions": []},
                             "spdx": {"floor": "declared", "accepted_versions": []},
                             "acceptance": "schema-only", "provenance": False})
    log = ChangeLog(level=version)
    ctx = Ctx(log=log, spec=spec, version=version, declared=version, profile=profile, source_sha256=source_sha256)
    ctx._doc = doc
    process_level(doc, ctx)
    return [c.to_dict() for c in log.changes]


DEFAULT_VERSION = {"cyclonedx": "1.6", "spdx": "2.3"}


def prepare_input(raw: bytes, spec: str | None = None,
                  version: str | None = None) -> tuple[dict[str, Any], str, str, list[str]]:
    """Turn any JSON into an SBOM document of a vendored version: (doc, spec, version, notes).

    - a JSON array becomes the components (CycloneDX) / packages (SPDX) of a new document
    - an object without bomFormat/spdxVersion is treated as CycloneDX (or --spec) and gets the markers
    - a CycloneDX version newer than the vendored ones goes through the generic future hop (1.8+ -> 1.7)
    - an unknown or missing version, or --version, is relabelled to that / the default version
    """
    from .changes import ChangeLog
    from .detect import decode
    from .errors import DetectError
    from .schemas import VERSION_ORDER, is_future

    notes: list[str] = []
    text, _encoding, issues = decode(raw)
    notes += [i.message for i in issues]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DetectError(f"The file is not valid JSON: {exc}") from exc
    if isinstance(data, dict) and ("@context" in data or "@graph" in data):
        raise DetectError("SPDX 3.0 JSON-LD is not supported. Regenerate the SBOM as CycloneDX or SPDX 2.3.")
    if isinstance(data, list):
        target = spec or "cyclonedx"
        key = "components" if target == "cyclonedx" else "packages"
        data = {key: data}
        notes.append(f"JSON array taken as the {key} of a new {target} document")
    if not isinstance(data, dict):
        raise DetectError("The JSON root is neither an object nor an array.")
    if str(data.get("bomFormat", "")).lower() == "cyclonedx" or "specVersion" in data:
        found: str | None = "cyclonedx"
    elif "spdxVersion" in data or "SPDXID" in data:
        found = "spdx"
    else:
        found = None
    use = spec or found or "cyclonedx"
    if found is None:
        notes.append(f"no bomFormat/spdxVersion: treated as {use}")
    if use == "cyclonedx":
        if data.get("bomFormat") != "CycloneDX":
            notes.append(f"bomFormat set to CycloneDX (was {data.get('bomFormat')!r})")
            data["bomFormat"] = "CycloneDX"
        declared = str(data.get("specVersion", "")).strip()
    else:
        declared = str(data.get("spdxVersion", "")).strip().removeprefix("SPDX-")
    m = re.match(r"^(\d+)\.(\d+)", declared)
    declared = f"{m.group(1)}.{m.group(2)}" if m else declared
    order = VERSION_ORDER[use]
    if version is None and use == "cyclonedx" and is_future(use, declared):
        from .descent import descend
        from .oracle import SchemaOnlyOracle
        from .profile import parse_profile

        prof = parse_profile({"name": "fill", "cyclonedx": {"floor": "declared", "accepted_versions": [order[-1]],
                                                            "max_version": order[-1], "future_versions": "downgrade"},
                              "acceptance": "schema-only", "provenance": False})
        descend(data, use, declared, prof, SchemaOnlyOracle(), ChangeLog(), "0" * 64)
        data["specVersion"] = order[-1]
        notes.append(f"CycloneDX {declared} is newer than the vendored schemas; brought down to {order[-1]} (future hop)")
        return data, use, order[-1], notes
    target_version = version or declared
    if target_version not in order:
        target_version = version or DEFAULT_VERSION[use]
        if target_version not in order:
            raise DetectError(f"{use} version {target_version} has no vendored schema ({', '.join(order)})")
        notes.append(f"version {declared or 'missing'} relabelled to {target_version}")
    elif version is not None and version != declared:
        notes.append(f"version {declared or 'missing'} relabelled to {version} (--version)")
    if use == "cyclonedx":
        data["specVersion"] = target_version
    else:
        data["spdxVersion"] = f"SPDX-{target_version}"
    return data, use, target_version, notes


def render_summary(input_name: str, result: FillResult, outputs: dict[str, str]) -> str:
    lines = [f"{input_name}: {result.spec} {result.version}, mode={result.mode}"]
    for note in result.prepared:
        lines.append(f"  input         : {note}")
    if result.repairs:
        lines.append(f"  repaired      : {len(result.repairs)} value(s) with the fix rules (same version, see report)")
    if result.removed:
        lines.append(f"  replaced      : {len(result.removed)} value(s) the schema rejects were converted, or removed and filled again")
    counts = result.counts()
    lines.append(f"  fields added  : {len(result.fills)} ("
                 + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ")")
    lines.append(f"  skipped       : {len(result.skipped)} (identity/reference/sensitive/recursive or no fitting value)")
    if result.unresolved:
        lines.append(f"  NOT filled (required): {len(result.unresolved)}, e.g. "
                     + "; ".join(f"{u.path} ({u.reason})" for u in result.unresolved[:3]))
    lines.append(f"  schema errors : {result.errors_before} before, {result.errors_after} after")
    if result.errors_after:
        lines.append("  Some errors could not be resolved automatically; see unresolved_required in the report.")
    for k, v in outputs.items():
        lines.append(f"  {k:13} : {v}")
    return "\n".join(lines)
