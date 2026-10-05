"""Sanitizers SAN-*, pruner and final rules (Phase 4)."""

from __future__ import annotations

import copy

from sbom_fixer.changes import ChangeLog
from sbom_fixer.prune import prune_to

from .conftest import LODASH, bom, ids, profile_with, run


def test_san002_removes_empty_but_keeps_depends_on() -> None:
    doc = bom(dependencies=[{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": []}])
    doc["components"][0]["properties"] = []
    d, res, log = run(doc)
    assert "properties" not in d["components"][0] and d["dependencies"][0]["dependsOn"] == []


def test_san003_adds_deterministic_serial() -> None:
    doc = bom()
    doc.pop("serialNumber")
    d1, _, _ = run(doc)
    d2, _, _ = run(doc)
    assert d1["serialNumber"] == d2["serialNumber"] and d1["serialNumber"].startswith("urn:uuid:")


def test_san004_timestamp_offset_normalized_and_missing_reported() -> None:
    doc = bom()
    doc["metadata"]["timestamp"] = "2026-10-02T15:30:00+05:30"
    d, _, log = run(doc)
    assert d["metadata"]["timestamp"] == "2026-10-02T10:00:00Z"
    doc2 = bom()
    doc2["metadata"].pop("timestamp")
    _, _, log2 = run(doc2)
    assert any(f.rule_id == "SAN-004" for f in log2.findings)


def test_san010_and_011_purls() -> None:
    doc = bom()
    doc["components"] = [
        {"type": "library", "name": "x", "version": "1", "purl": "not a purl"},
        {"type": "library", "bom-ref": "pkg:pypi/requests@2.31.0", "name": "requests", "version": "2.31.0"},
        {"type": "library", "name": "commons-io", "group": "commons-io", "version": "2.11.0",
         "properties": [{"name": "syft:package:type", "value": "java-archive"}]},
        {"type": "library", "name": "mystery", "version": "1"},
    ]
    d, _, log = run(doc)
    c = d["components"]
    assert "purl" not in c[0] and c[1]["purl"] == "pkg:pypi/requests@2.31.0"
    assert c[2]["purl"] == "pkg:maven/commons-io/commons-io@2.11.0"
    assert any(f.rule_id == "SAN-011" and "mystery" in f.message for f in log.findings)
    assert {"SAN-010", "SAN-011"} <= ids(log)


def test_san012_reports_unscanned_purl_types() -> None:
    doc = bom()
    doc["components"][0]["purl"] = "pkg:generic/foo@1"
    _, _, log = run(doc)
    assert any(f.rule_id == "SAN-012" for f in log.findings)


def test_san020_021_022_refs_and_duplicates() -> None:
    a = copy.deepcopy(LODASH)
    b = dict(copy.deepcopy(LODASH), name="other", purl="pkg:npm/other@1")
    dup = dict(copy.deepcopy(LODASH), **{"bom-ref": "lodash-copy"})
    doc = bom(components=[a, b, dup],
              dependencies=[{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": ["ghost"]}, {"ref": "lodash-copy", "dependsOn": []},
                            {"ref": "nobody"}])
    d, _, log = run(doc)
    refs = [c["bom-ref"] for c in d["components"]]
    assert refs == ["pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.20#2"]
    assert all(dep["ref"] in refs for dep in d["dependencies"])
    assert {"SAN-020", "SAN-021", "SAN-022"} <= ids(log)


def test_san030_031_licenses() -> None:
    doc = bom()
    doc["components"][0]["licenses"] = [{"license": {"name": "The Apache Software License, Version 2.0"}}]
    other = dict(copy.deepcopy(LODASH), **{"bom-ref": "x", "purl": "pkg:npm/x@1", "licenses": [{"expression": "mit or apache-2.0"}]})
    bad = dict(copy.deepcopy(LODASH), **{"bom-ref": "y", "purl": "pkg:npm/y@1", "licenses": [{"expression": "Company License"}]})
    bsd = dict(copy.deepcopy(LODASH), **{"bom-ref": "z", "purl": "pkg:npm/z@1", "licenses": [{"license": {"name": "BSD"}}]})
    doc["components"] += [other, bad, bsd]
    d, _, log = run(doc)
    c = d["components"]
    assert c[0]["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    assert c[1]["licenses"][0]["expression"] == "MIT OR Apache-2.0"
    assert c[2]["licenses"] == [{"license": {"name": "Company License"}}]
    assert c[3]["licenses"] == [{"license": {"name": "BSD"}}], "ambiguous alias must never be guessed"


def test_san050_flatten_only_when_profile_says_so() -> None:
    child = dict(copy.deepcopy(LODASH), **{"bom-ref": "child", "purl": "pkg:npm/child@1", "name": "child"})
    parent = dict(copy.deepcopy(LODASH), components=[child])
    d, _, _ = run(bom(components=[parent]), profile_with(["1.5"], flatten_nested_components=True))
    assert [c["bom-ref"] for c in d["components"]] == ["pkg:npm/lodash@4.17.20", "child"]
    d2, _, _ = run(bom(components=[copy.deepcopy(parent)]), profile_with(["1.5"]))
    assert len(d2["components"]) == 1


def test_final_rules_signature_and_provenance_only_when_changed() -> None:
    doc = bom("1.6", signature={"algorithm": "ES256", "value": "abc"})
    d, _, log = run(doc, profile_with(["1.5"], provenance=True))
    assert "signature" not in d and "SAN-060" in ids(log) and "SAN-090" in ids(log)
    assert d["metadata"]["tools"]["components"][-1]["name"] == "sbom-fixer"
    clean, _, log2 = run(bom("1.5"), profile_with(["1.5"], provenance=True))
    assert len(log2) == 0 and "tools" not in clean["metadata"]


def test_provenance_uses_array_tools_at_14() -> None:
    d, _, _ = run(bom("1.5", serialNumber="bad"), profile_with(["1.4"], provenance=True))
    assert d["specVersion"] == "1.4" and d["metadata"]["tools"] == [{"name": "sbom-fixer", "version": "1.0.0"}]


def test_pruner_follows_type_matched_branch_and_skips_ambiguous() -> None:
    doc = bom("1.5")
    doc["metadata"]["tools"] = {"components": [], "junk": 1}
    doc["components"][0]["licenses"] = [{"license": {"id": "MIT", "x": 1}}]
    log = ChangeLog()
    prune_to(doc, "cyclonedx", "1.5", log)
    paths = {c.path for c in log.changes}
    assert "/metadata/tools/junk" in paths and "/components/0/licenses/0/license/x" in paths
    assert all(c.severity == "DATA_LOSS" for c in log.changes)


def test_pruner_does_nothing_on_valid_document() -> None:
    log = ChangeLog()
    prune_to(bom(), "cyclonedx", "1.5", log)
    assert len(log) == 0
