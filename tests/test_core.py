"""Schemas, detection, validation, profile, change log, serializer (Phase 1)."""

from __future__ import annotations

import codecs
import json

import pytest

from sbom_fixer.changes import ChangeLog
from sbom_fixer.detect import detect
from sbom_fixer.errors import DetectError, ProfileError, SchemaNotFoundError
from sbom_fixer.profile import load_profile, parse_profile
from sbom_fixer.schemas import CDX_VERSIONS, SPDX_VERSIONS, enum_of, load_schema
from sbom_fixer.serialize import dumps, write_json
from sbom_fixer.validate import group, is_valid, validate

from .conftest import bom


@pytest.mark.parametrize("v", CDX_VERSIONS)
def test_every_cyclonedx_schema_loads_and_resolves_refs_offline(v: str) -> None:
    load_schema("cyclonedx", v)
    doc = bom("1.5" if v >= "1.5" else v)
    doc["specVersion"] = v
    doc["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]  # forces the spdx.schema.json $ref
    assert validate(doc, "cyclonedx", v) == [] or v == "1.2"


@pytest.mark.parametrize("v", SPDX_VERSIONS)
def test_spdx_schemas_load(v: str) -> None:
    assert "properties" in load_schema("spdx", v)


def test_unknown_version_raises() -> None:
    with pytest.raises(SchemaNotFoundError, match="Available"):
        load_schema("cyclonedx", "1.8")


def test_enum_lookup() -> None:
    assert "cryptographic-asset" in enum_of("cyclonedx", "1.6", "component", "type")
    assert "cryptographic-asset" not in enum_of("cyclonedx", "1.5", "component", "type")


def _raw(doc: object) -> bytes:
    return json.dumps(doc).encode("utf-8")


def test_detect_cyclonedx_and_generator() -> None:
    doc = bom("1.5")
    doc["metadata"]["tools"] = {"components": [{"type": "application", "name": "trivy", "version": "0.56.2"}]}
    det, parsed = detect(_raw(doc))
    assert (det.spec, det.version, det.generator, det.encoding) == ("cyclonedx", "1.5", "trivy 0.56.2", "utf-8")
    assert parsed["bomFormat"] == "CycloneDX"


def test_detect_encodings() -> None:
    text = json.dumps(bom())
    det, _ = detect(codecs.BOM_UTF8 + text.encode())
    assert det.encoding_issues[0].rule_id == "ENC-001"
    det, _ = detect(codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
    assert det.encoding_issues[0].rule_id == "ENC-002"
    det, _ = detect(text.replace("lodash", "lodésh").encode("cp1252"))
    assert det.encoding_issues[0].rule_id == "ENC-003"


def test_detect_numeric_spec_version_and_spdx() -> None:
    doc = bom()
    doc["specVersion"] = 1.5
    assert detect(_raw(doc))[0].version == "1.5"
    assert detect(_raw({"spdxVersion": "SPDX-2.3"}))[0].spec == "spdx"


@pytest.mark.parametrize("raw,msg", [
    (b"", "empty"), (b"{not json", "not valid JSON"), (b"[1]", "not an object"),
    (json.dumps({"@context": "x", "@graph": []}).encode(), "SPDX 3.0"),
    (b'<bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>', "XML 1.5"),
    (b"SPDXVersion: SPDX-2.3\n", "tag-value"), (b'{"a": 1}', "neither"),
])
def test_detect_rejects(raw: bytes, msg: str) -> None:
    with pytest.raises(DetectError, match=msg):
        detect(raw)


def test_validation_paths_and_grouping() -> None:
    doc = bom()
    doc["components"] = [dict(doc["components"][0], type="Library"),
                         dict(doc["components"][0], type="Library", **{"bom-ref": "second"})]
    issues = validate(doc, "cyclonedx", "1.5")
    assert {i.path for i in issues} == {"/components/0/type", "/components/1/type"}
    grouped = group(issues)
    assert grouped[0][:3] == ("enum", "/components/*/type", 2)
    assert is_valid(bom(), "cyclonedx", "1.5")


def test_fast_and_full_validation_agree_on_corpus(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from sbom_fixer import validate as vmod

    from .conftest import CORPUS

    checked = 0
    for f in sorted(CORPUS.rglob("*.json")):
        try:
            det, doc = detect(f.read_bytes())
        except DetectError:
            continue
        for v in (vmod.load_schema.__wrapped__ and [det.version]):
            if det.spec == "cyclonedx" and v not in CDX_VERSIONS:
                continue
            fast = vmod.validate(doc, det.spec, v)
            full = vmod._full(doc, det.spec, v)
            assert (fast == []) == (full == []), f"{f.name} {v}: fast={len(fast)} full={len(full)}"
            checked += 1
    big = bom()
    big["components"] = [dict(big["components"][0], **{"bom-ref": f"r{i}", "type": "Library" if i in (3, 77) else "library"})
                         for i in range(120)]
    issues = vmod.validate(big, "cyclonedx", "1.5")
    assert {i.path for i in issues} == {"/components/3/type", "/components/77/type"}
    monkeypatch.setenv("SBOM_FIXER_FAST_VALIDATION", "0")
    vmod._fast.clear()
    assert {i.path for i in vmod.validate(big, "cyclonedx", "1.5")} == {"/components/3/type", "/components/77/type"}
    vmod._fast.clear()
    assert checked > 10


def test_builtin_profiles_load() -> None:
    cx = load_profile("checkmarx")
    assert cx.rules_for("cyclonedx").accepted_versions == ["1.3", "1.4", "1.5"]
    comp = load_profile("compliance")
    assert comp.rules_for("cyclonedx").floor_for("1.6") == "1.6"


@pytest.mark.parametrize("data,msg", [
    ({"name": "x", "target": {}}, "was removed"),
    ({"name": "x", "supported": []}, "was removed"),
    ({"name": "x", "bogus": 1}, "Unknown key"),
    ({"name": "x", "cyclonedx": {"floor": "0.9"}}, "not one of"),
    ({"name": "x", "acceptance": "maybe"}, "acceptance"),
    ({"cyclonedx": {}}, "no 'name'"),
])
def test_profile_validation(data: dict, msg: str) -> None:
    with pytest.raises(ProfileError, match=msg):
        parse_profile(data)


def test_missing_profile() -> None:
    with pytest.raises(ProfileError, match="Built-in profiles"):
        load_profile("nope")


def test_changelog() -> None:
    log = ChangeLog()
    log.add("REP-003", "/a", "replaced", 1, 2, "INFO", "r")
    log.note("SAN-011", "/b", "m")
    log.note("SAN-011", "/b", "m")
    assert len(log) == 1 and len(log.findings) == 1 and log.count("INFO") == 1
    with pytest.raises(ValueError):
        log.add("X", "/", "a", 0, 0, "BAD", "r")


def test_serializer_writes_utf8_without_bom(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "o.json"
    write_json({"name": "café"}, p)
    data = p.read_bytes()
    assert not data.startswith(codecs.BOM_UTF8) and b"\r\n" not in data and "café".encode() in data
    assert dumps({"a": 1}).endswith("\n")
