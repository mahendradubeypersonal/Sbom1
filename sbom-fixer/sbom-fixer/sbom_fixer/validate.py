"""Schema validation with JSON Pointer paths and grouped causes (Guide Step 08)."""

from __future__ import annotations

import copy
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from jsonschema import FormatChecker
from jsonschema.exceptions import ValidationError, best_match
from jsonschema.validators import extend, validator_for
from rfc3986_validator import validate_rfc3986

from .jsonutil import pointer
from .schemas import load_schema, registry_for


def _ascii(s: str) -> str:
    return "".join(c if ord(c) < 128 else quote(c) for c in s)


def _make_format_checker() -> FormatChecker:
    """Default checker, but IRI formats use a fast RFC 3986 regex (the default IRI parser costs ~80 ms per URL)."""
    fc = FormatChecker()

    def iri_reference(value: object) -> bool:
        return not isinstance(value, str) or bool(validate_rfc3986(_ascii(value), rule="URI_reference"))

    def iri(value: object) -> bool:
        return not isinstance(value, str) or bool(validate_rfc3986(_ascii(value), rule="URI"))

    for name, fn in (("iri-reference", iri_reference), ("uri-reference", iri_reference), ("iri", iri), ("uri", iri)):
        fc.checkers[name] = (fn, ())
    return fc


FORMAT_CHECKER = _make_format_checker()


def _fast_unique_items(validator: Any, unique: Any, instance: Any, schema: Any) -> Any:
    """O(n) uniqueItems; the built-in check compares every pair (O(n^2)) and takes minutes on large BOMs."""
    if not unique or not validator.is_type(instance, "array"):
        return
    seen: set[str] = set()
    for item in instance:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        if key in seen:
            yield ValidationError(f"array has non-unique elements (first duplicate: {key[:120]})")
            return
        seen.add(key)


@dataclass(frozen=True)
class Issue:
    path: str  # JSON Pointer, e.g. /components/12/type
    parts: tuple[Any, ...]
    keyword: str  # enum, type, required, additionalProperties, format, pattern ...
    message: str
    expected: Any  # validator_value, e.g. the enum list or the expected type
    instance: Any

    @property
    def group_path(self) -> str:
        return re.sub(r"/\d+(?=/|$)", "/*", self.path) or "/"


_validators: dict[tuple[str, str], Any] = {}


def _validator(spec: str, version: str) -> Any:
    key = (spec, version)
    if key not in _validators:
        schema = load_schema(spec, version)
        cls = extend(validator_for(schema), {"uniqueItems": _fast_unique_items})
        _validators[key] = cls(schema, registry=registry_for(spec), format_checker=FORMAT_CHECKER)
    return _validators[key]


def _leaf(err: ValidationError) -> ValidationError:
    """For oneOf/anyOf failures, descend into the most relevant branch error."""
    while err.validator in ("oneOf", "anyOf") and err.context:
        inner = best_match(err.context)
        if inner is None or inner is err:
            break
        err = inner
    return err


_fast: dict[tuple[str, str, str], Any] = {}


def _fast_fn(spec: str, version: str, part: str = "root") -> Any:
    """Compiled fastjsonschema validator, or None when disabled or the schema does not compile."""
    if os.environ.get("SBOM_FIXER_FAST_VALIDATION", "1") == "0":
        return None
    key = (spec, version, part)
    if key not in _fast:
        try:
            import fastjsonschema

            # fastjsonschema rewrites the schema it is given; never hand it the cached dicts the pruner reads
            root = copy.deepcopy(load_schema(spec, version))
            schema = root if part == "root" else {"$id": root.get("$id", ""), "definitions": root.get("definitions", {}),
                                                  "$ref": f"#/definitions/{part}"}
            store = _schema_store(spec)
            formats = {name: (lambda fn: (lambda v: fn(v)))(FORMAT_CHECKER.checkers[name][0])
                       for name in ("iri-reference", "uri-reference", "iri", "uri", "idn-email") if name in FORMAT_CHECKER.checkers}
            _fast[key] = fastjsonschema.compile(schema, handlers={"http": lambda uri: store[uri.split("#")[0]],
                                                                  "https": lambda uri: store[uri.split("#")[0]]},
                                                formats=formats, use_default=False)
        except Exception:  # any compile problem falls back to jsonschema
            _fast[key] = None
    return _fast[key]


def _schema_store(spec: str) -> dict[str, Any]:
    from .schemas import SCHEMA_ROOT

    store: dict[str, Any] = {}
    for f in (SCHEMA_ROOT / spec).glob("*.json"):
        s = json.loads(f.read_text(encoding="utf-8"))
        store[s.get("$id", f.name)] = s
    return store


def _fast_ok(fn: Any, data: Any) -> bool:
    import fastjsonschema

    try:
        fn(data)
        return True
    except fastjsonschema.JsonSchemaException:
        return False


def validate(doc: Any, spec: str, version: str, limit: int | None = None) -> list[Issue]:
    fn = _fast_fn(spec, version)
    if fn is not None:
        try:
            if _fast_ok(fn, doc):
                return []
        except RecursionError:
            fn = None
    comps = doc.get("components") if isinstance(doc, dict) else None
    if fn is not None and spec == "cyclonedx" and isinstance(comps, list) and len(comps) > 50:
        cfn = _fast_fn(spec, version, "component")
        if cfn is not None:
            bad = [i for i, c in enumerate(comps) if not _fast_ok(cfn, c)]
            reduced = dict(doc)
            reduced["components"] = [comps[i] for i in bad]
            issues = [_remap(i, bad) for i in _full(reduced, spec, version, limit) if i.keyword != "uniqueItems" or i.parts != ("components",)]
            unique = list(_fast_unique_items(_validator(spec, version), True, comps, {}))
            if unique:
                issues.append(Issue("/components", ("components",), "uniqueItems", unique[0].message, True, None))
            issues.sort(key=lambda i: (i.path, i.keyword))
            return issues[:limit] if limit else issues
    return _full(doc, spec, version, limit)


def _remap(issue: Issue, bad: list[int]) -> Issue:
    p = issue.parts
    if len(p) >= 2 and p[0] == "components" and isinstance(p[1], int) and p[1] < len(bad):
        parts = ("components", bad[p[1]], *p[2:])
        return Issue(pointer(parts), parts, issue.keyword, issue.message, issue.expected, issue.instance)
    return issue


def _full(doc: Any, spec: str, version: str, limit: int | None = None) -> list[Issue]:
    v = _validator(spec, version)
    out: list[Issue] = []
    for e in v.iter_errors(doc):
        leaf = _leaf(e)
        parts = tuple(leaf.absolute_path)
        out.append(
            Issue(
                path=pointer(parts),
                parts=parts,
                keyword=str(leaf.validator),
                message=leaf.message[:400],
                expected=leaf.validator_value,
                instance=leaf.instance,
            )
        )
        if limit and len(out) >= limit:
            break
    out.sort(key=lambda i: (i.path, i.keyword))
    return out


def is_valid(doc: Any, spec: str, version: str) -> bool:
    return not validate(doc, spec, version, limit=1)


def group(issues: list[Issue]) -> list[tuple[str, str, int, str]]:
    """Return (keyword, normalized path, count, example message) sorted by count desc."""
    counts: Counter[tuple[str, str]] = Counter()
    example: dict[tuple[str, str], str] = {}
    for i in issues:
        k = (i.keyword, i.group_path)
        counts[k] += 1
        example.setdefault(k, i.message)
    return [(kw, p, n, example[(kw, p)]) for (kw, p), n in counts.most_common()]
