"""Offline registry of the vendored CycloneDX and SPDX JSON schemas."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from .errors import SchemaNotFoundError

SCHEMA_ROOT = Path(__file__).parent / "data" / "schemas"

CDX_VERSIONS = ["1.2", "1.3", "1.4", "1.5", "1.6", "1.7"]
SPDX_VERSIONS = ["2.2", "2.3"]
VERSION_ORDER = {"cyclonedx": CDX_VERSIONS, "spdx": SPDX_VERSIONS}

_MAIN_FILE = {
    "cyclonedx": "bom-{v}.schema.json",
    "spdx": "spdx-{v}.schema.json",
}


def available_versions(spec: str) -> list[str]:
    return list(VERSION_ORDER.get(spec, []))


def version_key(version: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(x) for x in version.split("."))
    except ValueError:
        return None


def is_future(spec: str, version: str) -> bool:
    """True for a version newer than every vendored one with the same major number (CycloneDX 1.8 today)."""
    known = VERSION_ORDER.get(spec, [])
    key, newest = version_key(version), version_key(known[-1]) if known else None
    return key is not None and newest is not None and key[0] == newest[0] and key > newest


def schema_url(version: str) -> str:
    return f"http://cyclonedx.org/schema/bom-{version}.schema.json"


@cache
def _registry(spec: str) -> Registry:
    registry: Registry = Registry()
    folder = SCHEMA_ROOT / spec
    for f in sorted(folder.glob("*.json")):
        contents = json.loads(f.read_text(encoding="utf-8"))
        res = Resource.from_contents(contents, default_specification=DRAFT7)
        if "$id" in contents:
            registry = registry.with_resource(contents["$id"], res)
        registry = registry.with_resource(f.name, res)
    return registry.crawl()


@cache
def load_schema(spec: str, version: str) -> dict[str, Any]:
    versions = VERSION_ORDER.get(spec)
    if versions is None or version not in versions:
        avail = ", ".join(versions or [])
        raise SchemaNotFoundError(f"No vendored schema for {spec} {version}. Available: {avail}")
    path = SCHEMA_ROOT / spec / _MAIN_FILE[spec].format(v=version)
    return json.loads(path.read_text(encoding="utf-8"))


def registry_for(spec: str) -> Registry:
    return _registry(spec)


def resolve_local(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any] | None:
    """Follow local '#/...' refs. Returns None for external refs (spdx, jsf, crypto defs)."""
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return None
        node: Any = root
        for part in ref[2:].split("/"):
            node = node[part.replace("~1", "/").replace("~0", "~")]
        schema = node
        seen += 1
        if seen > 50:
            return None
    return schema


def definition(spec: str, version: str, name: str) -> dict[str, Any]:
    root = load_schema(spec, version)
    defs = root.get("definitions") or root.get("$defs") or {}
    return defs.get(name, {})


def enum_of(spec: str, version: str, definition_name: str, prop: str) -> list[str]:
    """Enum values of definitions.<definition_name>.properties.<prop>, following local refs."""
    root = load_schema(spec, version)
    d = definition(spec, version, definition_name)
    p = resolve_local((d.get("properties") or {}).get(prop, {}), root) or {}
    if "enum" in p:
        return list(p["enum"])
    for key in ("oneOf", "anyOf"):
        for branch in p.get(key, []):
            b = resolve_local(branch, root) or {}
            if "enum" in b:
                return list(b["enum"])
            if "const" in b:
                return [b["const"] for b in (resolve_local(x, root) or {} for x in p[key]) if "const" in b]
    return []
