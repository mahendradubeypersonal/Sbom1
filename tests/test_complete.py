"""fill-required / fill-all: derive first, placeholders second, never invent identities or references."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sbom_fixer.cli import app
from sbom_fixer.complete import IDENTITY_KEYS, PLACEHOLDER, fill
from sbom_fixer.validate import validate

from .conftest import CORPUS

NOW = datetime(2026, 10, 6, 10, 0, 0, tzinfo=UTC)
SHA = "0" * 64


def run_fill(doc: dict[str, Any], mode: str, spec: str = "cyclonedx", version: str = "1.6", **kw: Any):  # type: ignore[no-untyped-def]
    return fill(doc, spec, version, mode, file_stem="app", source_sha256=SHA, now=NOW, **kw)


def subset(small: Any, big: Any) -> bool:
    """Every value of the original is still in the output, unchanged."""
    if isinstance(small, dict):
        return isinstance(big, dict) and all(k in big and subset(v, big[k]) for k, v in small.items())
    if isinstance(small, list):
        return isinstance(big, list) and len(small) <= len(big) and all(subset(a, b) for a, b in zip(small, big, strict=False))
    return small == big


def broken_cdx() -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [
        {"purl": "pkg:maven/org.slf4j/slf4j-api@2.0.9", "bom-ref": "a"},
        {"type": "library", "name": "x", "externalReferences": [{"url": "https://example.org/x"}],
         "hashes": [{"content": "d919d904486c037f8d193412da0c92e22a9fa24230b9d67a57855c5c31c5e94e"}]},
        {"bom-ref": "pkg:npm/left-pad@1.3.0"}]}


def broken_spdx() -> dict[str, Any]:
    return {"spdxVersion": "SPDX-2.3", "name": "svc", "creationInfo": {"creators": ["Tool: gen"]},
            "packages": [{"name": "lodash", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                                              "referenceType": "purl",
                                                              "referenceLocator": "pkg:npm/lodash@4.17.21"}]}]}


def fills_by_path(res: Any) -> dict[str, Any]:
    return {f.path: f for f in res.fills}


# ------------------------------------------------------------------ fill-required


def test_required_derives_missing_mandatory_fields() -> None:
    res = run_fill(broken_cdx(), "required")
    f = fills_by_path(res)
    assert res.errors_before > 0 and res.errors_after == 0
    assert f["/components/0/name"].value == "slf4j-api" and f["/components/0/name"].source.startswith("derived")
    assert f["/components/0/type"].value == "library"
    assert f["/components/2/name"].value == "left-pad"  # from bom-ref, which is a purl
    assert f["/components/1/hashes/0/alg"].value == "SHA-256"  # 64 hex characters
    assert f["/components/1/externalReferences/0/type"].value == "other"
    assert subset(broken_cdx(), res.doc)


def test_required_adds_only_required_fields() -> None:
    res = run_fill(broken_cdx(), "required")
    assert "metadata" not in res.doc  # optional: never added in required mode
    assert not any(f.source == "dummy" for f in res.fills)
    # the fix repair rules still run first; their changes are listed separately (SAN-011 purl from a purl bom-ref)
    assert res.doc["components"][2]["purl"] == "pkg:npm/left-pad@1.3.0"
    assert any(r["rule_id"] == "SAN-011" for r in res.repairs)


def test_required_spdx() -> None:
    res = run_fill(broken_spdx(), "required", spec="spdx", version="2.3")
    f = fills_by_path(res)
    assert res.errors_after == 0
    assert f["/dataLicense"].value == "CC0-1.0" and f["/SPDXID"].value == "SPDXRef-DOCUMENT"
    assert f["/packages/0/downloadLocation"].value == "NOASSERTION" and f["/packages/0/downloadLocation"].source.startswith("standard")
    assert f["/creationInfo/created"].value == "2026-10-06T10:00:00Z"


@pytest.mark.parametrize("rel", ["minimal/min-cdx-1.3.json", "minimal/min-cdx-1.4.json", "minimal/min-cdx-1.5.json",
                                 "minimal/min-cdx-1.6.json", "minimal/min-cdx-1.7.json", "minimal/min-spdx-2.2.json",
                                 "minimal/min-spdx-2.3.json"])
def test_required_on_complete_file_changes_nothing(rel: str) -> None:
    doc = json.loads((CORPUS / rel).read_text(encoding="utf-8"))
    spec = "spdx" if "spdxVersion" in doc else "cyclonedx"
    version = doc["spdxVersion"].removeprefix("SPDX-") if spec == "spdx" else doc["specVersion"]
    res = run_fill(doc, "required", spec=spec, version=version)
    assert res.fills == [] and res.doc == doc


def test_required_repairs_and_coerces_invalid_values() -> None:
    doc = broken_cdx()
    doc["components"][1]["hashes"] = [{"content": "not-hex"}]  # unusable hash: removed by REP-011
    doc["components"].append("just-a-string")  # a bare name where a component object is expected
    doc["version"] = "1"
    res = run_fill(doc, "required")
    assert res.errors_after == 0
    assert any(r["rule_id"] == "REP-011" for r in res.repairs) and any(r["rule_id"] == "REP-004" for r in res.repairs)
    conv = next(f for f in res.removed if f.path == "/components/3")
    assert conv.source.startswith("converted") and conv.value == {"before": "just-a-string", "after": {"name": "just-a-string"}}
    assert res.doc["components"][3] == {"name": "just-a-string", "type": "library"}


@pytest.mark.parametrize("value,expected,out", [("no", "boolean", False), ("Yes", "boolean", True), ("42", "integer", 42),
                                                ("1.5", "number", 1.5), ("acme", "object", {"name": "acme"}),
                                                ("x", "array", ["x"]), ("maybe", "boolean", None)])
def test_convert(value: Any, expected: str, out: Any) -> None:
    from sbom_fixer.complete import NONE, _convert

    got = _convert(value, expected)
    assert (None if got is NONE else got) == out


# ------------------------------------------------------------------ fill-all


@pytest.mark.parametrize("rel", ["minimal/min-cdx-1.3.json", "minimal/min-cdx-1.4.json", "minimal/min-cdx-1.5.json",
                                 "minimal/min-cdx-1.6.json", "minimal/min-cdx-1.7.json", "minimal/min-spdx-2.2.json",
                                 "minimal/min-spdx-2.3.json", "purl/format-fixes.cdx.json"])
def test_all_is_schema_valid_and_keeps_the_original(rel: str) -> None:
    doc = json.loads((CORPUS / rel).read_text(encoding="utf-8"))
    spec = "spdx" if "spdxVersion" in doc else "cyclonedx"
    version = doc["spdxVersion"].removeprefix("SPDX-") if spec == "spdx" else doc["specVersion"]
    res = run_fill(doc, "all", spec=spec, version=version)
    assert validate(res.doc, spec, version) == []
    assert subset(doc, res.doc)
    assert len(res.fills) > 10


def test_all_never_invents_identities_or_uses_example_data() -> None:
    res = run_fill(copy.deepcopy(broken_cdx()), "all")
    for f in res.fills:
        last = f.path.rsplit("/", 1)[1]
        if last in IDENTITY_KEYS["cyclonedx"]:
            assert f.source.startswith("derived"), f
        assert f.source != "example", f
    comps = res.doc["components"]
    assert comps[2]["purl"] == "pkg:npm/left-pad@1.3.0"  # derived from bom-ref
    assert "cpe" not in comps[0] and "swid" not in comps[0]


def test_all_placeholders_are_recognisable() -> None:
    res = run_fill(broken_cdx(), "all")
    dummies = [f for f in res.fills if f.source == "dummy" and isinstance(f.value, str)]
    assert dummies
    for f in dummies:
        assert ("PLACEHOLDER" in f.value or "placeholder" in f.value or f.value.endswith("Z")), f


def test_all_derives_root_metadata_and_dependencies() -> None:
    res = run_fill(broken_cdx(), "all")
    d = res.doc
    assert d["metadata"]["timestamp"] == "2026-10-06T10:00:00Z"
    assert d["metadata"]["tools"]["components"][0]["name"] == "sbom-fixer"
    assert d["metadata"]["component"]["name"] == "app" and d["metadata"]["component"]["type"] == "application"
    assert d["serialNumber"].startswith("urn:uuid:")
    assert [x["ref"] for x in d["dependencies"]] == [c["bom-ref"] for c in d["components"]]
    assert all("dependsOn" not in x for x in d["dependencies"])  # unknown, not "no dependencies"


def test_all_supplier_from_publisher_and_group_from_maven_purl() -> None:
    doc = broken_cdx()
    doc["components"][0]["publisher"] = "QOS.ch"
    res = run_fill(doc, "all")
    c = res.doc["components"][0]
    assert c["supplier"]["name"] == "QOS.ch" and c["group"] == "org.slf4j" and c["version"] == "2.0.9"


def test_all_skips_sensitive_unless_asked() -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "components": [{"type": "library", "name": "x", "version": "1"}]}
    plain = run_fill(copy.deepcopy(doc), "all")
    assert "hashes" not in plain.doc["components"][0] and "vulnerabilities" not in plain.doc
    assert any(s.reason.startswith("sensitive") for s in plain.skipped)
    wide = run_fill(copy.deepcopy(doc), "all", include_sensitive=True)
    assert validate(wide.doc, "cyclonedx", "1.6") == []
    assert len(wide.fills) > len(plain.fills)


def test_all_does_not_expand_recursive_structures() -> None:
    res = run_fill(broken_cdx(), "all")
    assert "components" not in res.doc["components"][0]
    assert any("recursive" in s.reason for s in res.skipped)


def test_all_is_deterministic() -> None:
    a = run_fill(broken_cdx(), "all")
    b = run_fill(broken_cdx(), "all")
    assert a.doc == b.doc


def test_existing_license_choice_is_respected() -> None:
    doc = broken_cdx()
    doc["components"][1]["licenses"] = [{"license": {"id": "MIT"}}]
    res = run_fill(doc, "all")
    lic = res.doc["components"][1]["licenses"][0]["license"]
    assert lic["id"] == "MIT" and "name" not in lic  # id XOR name
    assert validate(res.doc, "cyclonedx", "1.6") == []


# ------------------------------------------------------------------ CLI


def test_cli_fill_required_and_all(tmp_path: Path) -> None:
    src = tmp_path / "svc.cdx.json"
    src.write_text(json.dumps(broken_cdx()), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(app, ["fill-required", str(src), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    out = json.loads((tmp_path / "o" / "svc.fill-required.cdx.json").read_text(encoding="utf-8"))
    report = json.loads((tmp_path / "o" / "svc.fill-required.cdx.report.json").read_text(encoding="utf-8"))
    assert out["components"][0]["name"] == "slf4j-api" and report["schema_errors_after"] == 0
    res = runner.invoke(app, ["fill-all", str(src), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    out = json.loads((tmp_path / "o" / "svc.fill-all.cdx.json").read_text(encoding="utf-8"))
    assert PLACEHOLDER in json.dumps(out) and "metadata" in out


def test_cli_fill_brings_18_down_to_17(tmp_path: Path) -> None:
    res = CliRunner().invoke(app, ["fill-required", str(CORPUS / "future" / "min-cdx-1.8.json"), "--out", str(tmp_path)])
    assert res.exit_code == 0 and "brought down to 1.7" in res.output
    out = json.loads((tmp_path / "min-cdx-1.8.fill-required.cdx.json").read_text(encoding="utf-8"))
    assert out["specVersion"] == "1.7" and validate(out, "cyclonedx", "1.7") == []


@pytest.mark.parametrize("payload,args,spec,version,note", [
    ({"components": [{"name": "requests", "purl": "pkg:pypi/requests@2.31.0"}]}, [], "cyclonedx", "1.6", "treated as cyclonedx"),
    ([{"name": "express", "purl": "pkg:npm/express@4.18.2"}], [], "cyclonedx", "1.6", "JSON array taken as the components"),
    ({"bomFormat": "CycloneDX", "specVersion": "1.1", "components": []}, [], "cyclonedx", "1.6", "version 1.1 relabelled to 1.6"),
    ({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, ["--version", "1.7"], "cyclonedx", "1.7", "--version"),
    ([{"name": "lodash"}], ["--spec", "spdx"], "spdx", "2.3", "packages of a new spdx document"),
    ({"spdxVersion": "SPDX-2.3", "packages": [{"name": "x", "filesAnalyzed": "no", "downloadLocation": 5}]}, [], "spdx", "2.3", ""),
])
def test_cli_fill_accepts_any_json(payload: Any, args: list[str], spec: str, version: str, note: str, tmp_path: Path) -> None:
    src = tmp_path / "in.json"
    src.write_text(json.dumps(payload), encoding="utf-8")
    for command in ("fill-required", "fill-all"):
        res = CliRunner().invoke(app, [command, str(src), "--out", str(tmp_path / "o"), *args])
        assert res.exit_code == 0, res.output
        assert note in res.output
        ext = "cdx" if spec == "cyclonedx" else "spdx"
        mode = command.removeprefix("fill-")
        out = json.loads((tmp_path / "o" / f"in.fill-{mode}.{ext}.json").read_text(encoding="utf-8"))
        assert validate(out, spec, version) == []


def test_cli_fill_rejects_non_json(tmp_path: Path) -> None:
    src = tmp_path / "x.json"
    src.write_text("{not json", encoding="utf-8")
    res = CliRunner().invoke(app, ["fill-required", str(src), "--out", str(tmp_path)])
    assert res.exit_code == 2 and "not valid JSON" in res.output
