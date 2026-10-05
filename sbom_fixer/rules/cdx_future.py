"""Generic future hop: a CycloneDX version newer than every vendored schema (1.8+) down to the profile's max_version.

There is no schema for the declared version, so the target schema decides: CycloneDX objects use
additionalProperties: false, which makes every field the target does not know show up as a prune candidate.
When a schema for the new version is vendored, write a proper cdx_NN_to_MM.py hop and this stays for newer ones.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from ..changes import DATA_LOSS, INFO, WARN, ChangeLog
from ..jsonutil import add_property, get_at, parse_pointer, pointer
from ..prune import prune_to
from ..schemas import schema_url
from ..validate import validate
from .base import HOP, Ctx, Rule, register

# Objects that carry a properties array in CycloneDX 1.5+ (target of the future hop is always 1.5 or newer)
_HAS_PROPERTIES = re.compile(
    r"^(?:|/metadata|/metadata/component(?:/components/\d+)*|/components/\d+(?:/components/\d+)*"
    r"|/services/\d+(?:/services/\d+)*|/metadata/tools/(?:components|services)/\d+|/vulnerabilities/\d+)$"
)
MAX_PROPERTY_BYTES = 4096


def _tag(version: str) -> str:
    return "cdx" + version.replace(".", "")


@register
class FutureVersion(Rule):
    id = "CDX-FWD-001"
    title = "Newer CycloneDX version brought down to max_version"
    description = ("The SBOM declared a CycloneDX version newer than this tool knows (for example 1.8); specVersion was set to "
                   "the profile's max_version and the document was checked against that schema (generic future hop).")
    source_fix = "If the generator has a spec-version option, set it to a version Checkmarx accepts (1.6 or 1.7)."
    case, kind = "B", HOP

    def apply(self, doc: Any, ctx: Ctx) -> None:
        old = doc.get("specVersion")
        doc["specVersion"] = ctx.version
        if "$schema" in doc:
            doc["$schema"] = schema_url(ctx.version)
        ctx.log.add(self.id, "/specVersion", "replaced", old, ctx.version, INFO,
                    f"CycloneDX {ctx.declared} is unknown to this tool; generic downgrade to {ctx.version}")


@register
class FutureFields(Rule):
    id = "CDX-FWD-002"
    title = "Fields unknown to the target version kept as properties"
    description = ("A field that the target CycloneDX version does not define was moved into a property "
                   "sbom-fixer:cdxNN:<field> where the object allows properties; otherwise it was removed (DATA_LOSS).")
    case, kind = "B", HOP

    def apply(self, doc: Any, ctx: Ctx) -> None:
        probe, probe_log = copy.deepcopy(doc), ChangeLog()
        prune_to(probe, "cyclonedx", ctx.version, probe_log)
        tag = _tag(ctx.declared)
        for change in probe_log.changes:
            parts = parse_pointer(change.path)
            parent_parts, key = parts[:-1], parts[-1]
            try:
                parent = get_at(doc, parent_parts)
            except (KeyError, IndexError, TypeError):
                continue
            if not isinstance(parent, dict) or key not in parent:
                continue
            value = parent[key]
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
            parent_path = pointer(parent_parts)
            if _HAS_PROPERTIES.match(parent_path) and len(text.encode("utf-8")) <= MAX_PROPERTY_BYTES:
                parent.pop(key)
                name = f"sbom-fixer:{tag}:{key}"
                add_property(parent, name, text)
                ctx.log.add(self.id, change.path, "moved", value, name, INFO,
                            f"'{key}' is not defined in CycloneDX {ctx.version}; kept as property {name}")
            else:
                parent.pop(key)
                ctx.log.add(self.id, change.path, "removed", value, None, DATA_LOSS,
                            f"'{key}' is not defined in CycloneDX {ctx.version} and cannot be kept as a property here")


@register
class FutureEnums(Rule):
    id = "CDX-FWD-003"
    title = "Enum values unknown to the target version"
    description = ("A value that the target CycloneDX version does not allow (a new enum value) became 'other' where the schema "
                   "allows it, with the original value kept; otherwise the value was removed (DATA_LOSS).")
    case, kind = "B", HOP

    def apply(self, doc: Any, ctx: Ctx) -> None:
        issues = [i for i in validate(doc, "cyclonedx", ctx.version) if i.keyword == "enum"]
        tag = _tag(ctx.declared)
        for issue in sorted(issues, key=lambda i: tuple((1, p) if isinstance(p, int) else (0, str(p)) for p in i.parts),
                            reverse=True):
            parts = list(issue.parts)
            try:
                container = get_at(doc, parts[:-1])
                old = container[parts[-1]]
            except (KeyError, IndexError, TypeError):
                continue
            allowed = issue.expected if isinstance(issue.expected, list) else []
            if "other" in allowed:
                container[parts[-1]] = "other"
                kept = ""
                if isinstance(container, dict):
                    if _HAS_PROPERTIES.match(pointer(parts[:-1])):
                        add_property(container, f"sbom-fixer:{tag}:original-{parts[-1]}", str(old))
                        kept = "; original kept as a property"
                    elif "url" in container and "comment" not in container:
                        container["comment"] = f"original {parts[-1]}: {old}"
                        kept = "; original kept in comment"
                ctx.log.add(self.id, issue.path, "replaced", old, "other", WARN,
                            f"'{old}' is not allowed in CycloneDX {ctx.version}{kept}")
            else:
                if isinstance(container, list):
                    container.pop(parts[-1])
                else:
                    del container[parts[-1]]
                ctx.log.add(self.id, issue.path, "removed", old, None, DATA_LOSS,
                            f"'{old}' is not allowed in CycloneDX {ctx.version} and has no 'other' equivalent")


FUTURE_RULES = ("CDX-FWD-001", "CDX-FWD-002", "CDX-FWD-003")
