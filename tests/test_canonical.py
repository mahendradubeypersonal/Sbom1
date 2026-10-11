"""Checkmarx canonical form (CXN-*): the minimal cyclonedx-dotnet layout Checkmarx One SCA ingests reliably."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from sbom_fixer.cli import app
from sbom_fixer.diff import apply_patch
from sbom_fixer.errors import ProfileError
from sbom_fixer.pipeline import run_fix
from sbom_fixer.profile import DEFAULT_CANONICAL_TOOLS, load_profile, parse_profile
from sbom_fixer.purlmap import try_purl
from sbom_fixer.rules.canonical import TOP_LEVEL
from sbom_fixer.validate import validate

from .conftest import CORPUS, LODASH, ROOT, bom, ids, run

EXPECTED = yaml.safe_load((CORPUS / "expected.yaml").read_text(encoding="utf-8"))
CDX_FILES = sorted(rel for rel, exp in EXPECTED.items() if exp["exit_code"] != 2 and "spdx" not in rel)
FIELDS = {"bom-ref", "type", "name", "version", "purl", "licenses"}


def assert_canonical(doc: dict[str, Any], version: str) -> None:
    assert validate(doc, "cyclonedx", version) == []
    assert list(doc) == [k for k in TOP_LEVEL if k in doc]
    assert set(doc["metadata"]) <= {"timestamp", "tools", "component"} and doc["metadata"]["timestamp"]
    assert doc["metadata"]["tools"] == DEFAULT_CANONICAL_TOOLS
    refs = set()
    for c in doc.get("components", []):
        assert set(c) <= FIELDS and {"bom-ref", "type", "name", "purl", "licenses"} <= set(c), c
        assert try_purl(c["purl"]) is not None and "?" not in c["purl"], c["purl"]
        assert c["licenses"], c
        assert "components" not in c
        assert c["bom-ref"] not in refs
        refs.add(c["bom-ref"])
    root = doc["metadata"].get("component") or {}
    if root.get("bom-ref"):
        refs.add(root["bom-ref"])
    for d in doc.get("dependencies", []):
        assert set(d) == {"ref", "dependsOn"} and d["ref"] in refs
        assert d["ref"] not in d["dependsOn"] and set(d["dependsOn"]) <= refs
        assert len(d["dependsOn"]) == len(set(d["dependsOn"]))


def checkmarx_doc(doc: dict[str, Any], version: str | None = None) -> tuple[dict[str, Any], Any, Any]:
    return run(doc, load_profile("checkmarx"), version)


# ---------------------------------------------------------------- whole corpus


@pytest.mark.parametrize("rel", CDX_FILES)
def test_corpus_canonical(rel: str, tmp_path: Path) -> None:
    prof = load_profile("checkmarx")
    r = run_fix(CORPUS / rel, prof, tmp_path, audit=False)
    assert r.ok, (r.error, [a.reason for a in r.descent.attempts] if r.descent else None)
    assert r.final_version == EXPECTED[rel]["final_version"]  # canonical never changes the version
    out = Path(r.outputs["sbom"])
    fixed = json.loads(out.read_text(encoding="utf-8"))
    assert fixed["specVersion"] == r.final_version
    assert_canonical(fixed, r.final_version)
    patch = json.loads(Path(r.outputs["patch"]).read_text(encoding="utf-8"))
    assert apply_patch(r.original_doc, patch) == fixed
    again = run_fix(out, prof, tmp_path / "again", audit=False)
    assert len(again.log) == 0, [(c.rule_id, c.path) for c in again.log.changes]
    assert again.exit_code in (0, 7)


def test_ratecard_gradle_sbom_matches_prompt_layout(tmp_path: Path) -> None:
    """The gradle SBOM was schema-valid (fix said 'unchanged') but Checkmarx did not ingest it."""
    r = run_fix(ROOT / "ratecard-sbom.json", load_profile("checkmarx"), tmp_path, audit=False)
    assert r.exit_code == 1
    out = json.loads(Path(r.outputs["sbom"]).read_text(encoding="utf-8"))
    assert_canonical(out, "1.5")
    assert out["serialNumber"] == r.original_doc["serialNumber"]
    assert out["metadata"]["timestamp"] == r.original_doc["metadata"]["timestamp"]
    assert out["metadata"]["component"] == r.original_doc["metadata"]["component"]
    first = out["components"][0]
    assert first == {"bom-ref": "pkg:maven/com.fasterxml/classmate@1.7.3?type=jar", "type": "library",
                     "name": "classmate", "version": "1.7.3", "purl": "pkg:maven/com.fasterxml/classmate@1.7.3",
                     "licenses": [{"license": {"id": "Apache-2.0"}}]}
    assert len(out["components"]) == len(r.original_doc["components"])


# ---------------------------------------------------------------- rules


def test_component_reduced_and_unknown_fields_dropped() -> None:
    c = dict(LODASH, description="x", hashes=[{"alg": "SHA-256", "content": "a" * 64}],
             externalReferences=[{"type": "website", "url": "https://lodash.com"}],
             properties=[{"name": "p", "value": "v"}], licenses=[{"license": {"id": "MIT", "url": "https://x.org"}}])
    out, res, log = checkmarx_doc(bom("1.5", components=[c]))
    assert res.ok
    assert out["components"][0] == {"bom-ref": "pkg:npm/lodash@4.17.20", "type": "library", "name": "lodash",
                                     "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
                                     "licenses": [{"license": {"id": "MIT"}}]}
    assert {"CXN-040", "CXN-030", "CXN-011"} <= ids(log)


def test_missing_license_gets_noassertion() -> None:
    out, _, _ = checkmarx_doc(bom("1.6"))
    assert out["components"][0]["licenses"] == [{"license": {"name": "NOASSERTION"}}]


def test_purl_qualifiers_stripped_and_version_filled() -> None:
    c = {"bom-ref": "a", "type": "library", "name": "b", "version": "1.0", "purl": "pkg:Maven/org.a/b?type=jar#sub"}
    out, _, log = checkmarx_doc(bom("1.5", components=[c]))
    assert out["components"][0]["purl"] == "pkg:maven/org.a/b@1.0"


@pytest.mark.parametrize(("component", "expected"), [
    ({"name": "@angular/core", "version": "15.0.0"}, "pkg:npm/%40angular/core@15.0.0"),
    ({"name": "Django_Rest", "version": "3.0", "properties": [{"name": "syft:package:type", "value": "python"}]},
     "pkg:pypi/django-rest@3.0"),
    ({"name": "libssl tools", "version": "3.0.2"}, "pkg:generic/libssl-tools@3.0.2"),
    ({"bom-ref": "pkg:nuget/Newtonsoft.Json@13.0.1", "name": "Newtonsoft.Json", "version": "13.0.1"},
     "pkg:nuget/Newtonsoft.Json@13.0.1"),
])
def test_missing_purl_is_generated(component: dict[str, Any], expected: str) -> None:
    out, res, _ = checkmarx_doc(bom("1.5", components=[dict(component, type="library")]))
    assert res.ok
    assert out["components"][0]["purl"] == expected


def test_no_generic_fallback_when_switched_off() -> None:
    prof = load_profile("checkmarx")
    assert prof.canonical is not None
    prof.canonical.purl_fallback = "none"
    out, res, _ = run(bom("1.5", components=[{"type": "library", "name": "thing", "version": "1"}]), prof)
    assert res.ok and "purl" not in out["components"][0]


def test_bom_ref_missing_or_duplicate() -> None:
    a = {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"}
    b = {"type": "library", "name": "b", "version": "1"}
    out, res, _ = checkmarx_doc(bom("1.5", components=[a, b]))
    assert res.ok
    assert [c["bom-ref"] for c in out["components"]] == ["pkg:npm/a@1", "pkg:generic/b@1"]


def test_dependencies_dangling_self_duplicate_and_merge() -> None:
    a = dict(LODASH)
    b = {"bom-ref": "b", "type": "library", "name": "b", "version": "1", "purl": "pkg:npm/b@1"}
    deps = [{"ref": a["bom-ref"], "dependsOn": ["b", "ghost", a["bom-ref"]]},
            {"ref": "ghost", "dependsOn": ["b"]},
            {"ref": "b"}]
    d = bom("1.5", components=[a, b], dependencies=deps)
    out, res, log = checkmarx_doc(d)
    assert res.ok
    assert out["dependencies"] == [{"ref": a["bom-ref"], "dependsOn": ["b"]}, {"ref": "b", "dependsOn": []}]
    assert "CXN-050" in ids(log) or "SAN-021" in ids(log)


def test_root_component_counts_as_dependency_target() -> None:
    root = {"type": "application", "bom-ref": "app", "name": "app", "version": "1"}
    d = bom("1.5", dependencies=[{"ref": "app", "dependsOn": [LODASH["bom-ref"]]}])
    d["metadata"]["component"] = root
    out, res, _ = checkmarx_doc(d)
    assert res.ok and out["metadata"]["component"] == root
    assert {"ref": "app", "dependsOn": [LODASH["bom-ref"]]} in out["dependencies"]


def test_nested_components_flattened_including_metadata_component() -> None:
    child = {"bom-ref": "c", "type": "library", "name": "c", "version": "1", "purl": "pkg:npm/c@1"}
    inner = {"bom-ref": "i", "type": "library", "name": "i", "version": "1", "purl": "pkg:npm/i@1"}
    parent = dict(LODASH, components=[child])
    d = bom("1.5", components=[parent])
    d["metadata"]["component"] = {"type": "application", "bom-ref": "app", "name": "app", "components": [inner]}
    out, res, _ = checkmarx_doc(d)
    assert res.ok
    assert sorted(c["bom-ref"] for c in out["components"]) == sorted([LODASH["bom-ref"], "c", "i"])
    assert "components" not in out["metadata"]["component"]


def test_top_level_sections_dropped_and_version_kept() -> None:
    d = bom("1.6", services=[{"bom-ref": "s", "name": "svc"}], externalReferences=[{"type": "website", "url": "https://x.org"}],
            compositions=[{"aggregate": "complete"}], vulnerabilities=[{"id": "CVE-2020-1"}])
    d["$schema"] = "http://cyclonedx.org/schema/bom-1.6.schema.json"
    out, res, _ = checkmarx_doc(d)
    assert res.ok and res.final_version == "1.6"
    assert list(out) == ["bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"]


def test_cdx13_component_without_version_gets_one() -> None:
    d = bom("1.3", components=[{"type": "library", "name": "x", "purl": "pkg:npm/x"}])
    out, res, _ = checkmarx_doc(d)
    assert res.ok and res.final_version == "1.3"
    assert out["components"][0]["version"] == "unknown"
    assert_canonical(out, "1.3")


def test_mixed_license_and_expression_keeps_licenses() -> None:
    c = dict(LODASH, licenses=[{"license": {"id": "MIT"}}, {"expression": "Apache-2.0 OR MIT"}])
    out, res, _ = checkmarx_doc(bom("1.4", components=[c]))
    assert res.ok and out["components"][0]["licenses"] == [{"license": {"id": "MIT"}}]


def test_compliance_profile_is_not_canonical() -> None:
    d = bom("1.5")
    d["components"][0]["description"] = "kept"
    out, _, log = run(d, load_profile("compliance"))
    assert out["components"][0]["description"] == "kept" and not any(r.startswith("CXN") for r in ids(log))


def test_spdx_is_untouched_by_canonical() -> None:
    src = CORPUS / "minimal" / "min-spdx-2.3.json"
    doc = json.loads(src.read_text(encoding="utf-8"))
    _, res, log = run(copy.deepcopy(doc), load_profile("checkmarx"))
    assert res.ok and not any(r.startswith("CXN") for r in ids(log))


# ---------------------------------------------------------------- profile and CLI


def test_profile_canonical_parsing() -> None:
    base = {"name": "x", "cyclonedx": {"accepted_versions": ["1.5"]}}
    assert parse_profile(base).canonical is None
    assert parse_profile(dict(base, canonical=True)).canonical is not None
    assert parse_profile(dict(base, canonical={"enabled": False})).canonical is None
    custom = parse_profile(dict(base, canonical={"tools": [{"vendor": "V", "name": "n", "version": "1"}],
                                                 "component_fields": ["bom-ref", "name", "version", "group", "purl"]}))
    assert custom.canonical is not None and custom.canonical.tools == [{"vendor": "V", "name": "n", "version": "1"}]
    for bad in ({"nope": 1}, {"component_fields": ["name"]}, {"component_fields": ["name", "purl", "x"]},
                {"tools": []}, {"purl_fallback": "maybe"}):
        with pytest.raises(ProfileError):
            parse_profile(dict(base, canonical=bad))


def test_both_checkmarx_profiles_are_canonical() -> None:
    for name in ("checkmarx", "checkmarx-cli"):
        assert load_profile(name).canonical is not None
    assert load_profile("compliance").canonical is None


def test_cli_no_canonical_keeps_fields(tmp_path: Path) -> None:
    src = ROOT / "ratecard-sbom.json"
    res = CliRunner().invoke(app, ["fix", str(src), "--out", str(tmp_path / "a"), "--no-audit", "--no-canonical"])
    assert res.exit_code == 0, res.output
    out = json.loads((tmp_path / "a" / "ratecard-sbom.checkmarx.cdx.json").read_text(encoding="utf-8"))
    assert "hashes" in out["components"][0]
    res = CliRunner().invoke(app, ["fix", str(src), "--out", str(tmp_path / "b"), "--no-audit"])
    assert res.exit_code == 1, res.output
    out = json.loads((tmp_path / "b" / "ratecard-sbom.checkmarx.cdx.json").read_text(encoding="utf-8"))
    assert set(out["components"][0]) == FIELDS
