"""Same-version repair rules REP-001..REP-012 (Phase 2). Every case stays at its declared version."""

from __future__ import annotations

import copy

from sbom_fixer.validate import validate

from .conftest import LODASH, bom, ids, run


def fixed(doc: dict, version: str = "1.5") -> tuple[dict, set[str], object]:
    d, res, log = run(doc)
    assert res.final_version == version, [a.reason for a in res.attempts]
    assert res.path == [version], "repair-only cases must not hop"
    assert validate(d, "cyclonedx", version) == []
    return d, ids(log), log


def test_rep001_schema_url_matches_spec_version() -> None:
    d, r, _ = fixed(bom(**{"$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json"}))
    assert d["$schema"].endswith("bom-1.5.schema.json") and "REP-001" in r


def test_rep003_enum_case_and_hash_alg() -> None:
    doc = bom()
    doc["components"][0]["type"] = "Library"
    doc["components"][0]["hashes"] = [{"alg": "sha256", "content": "a" * 64}]
    d, r, _ = fixed(doc)
    assert d["components"][0]["type"] == "library" and d["components"][0]["hashes"][0]["alg"] == "SHA-256"
    assert "REP-003" in r


def test_rep003_ambiguous_value_is_reported_not_guessed() -> None:
    doc = bom()
    doc["components"][0]["scope"] = "maybe"
    d, res, log = run(doc)
    assert any(f.rule_id == "REP-003" for f in log.findings)
    assert res.final_version is None or "scope" not in d["components"][0] or d["components"][0]["scope"] == "maybe"


def test_rep004_scalar_types() -> None:
    doc = bom()
    doc["components"][0]["version"] = 4.17
    d, r, _ = fixed(doc)
    assert d["components"][0]["version"] == "4.17" and "REP-004" in r


def test_rep005_null_and_empty_version_from_purl() -> None:
    doc = bom()
    doc["components"][0]["version"] = None
    doc["components"][0]["description"] = None
    d, r, _ = fixed(doc)
    assert d["components"][0]["version"] == "4.17.20" and "description" not in d["components"][0]
    assert "REP-005" in r


def test_rep006_name_from_purl_and_type_for_package() -> None:
    doc = bom()
    doc["components"] = [{"purl": "pkg:npm/left-pad@1.3.0", "version": "1.3.0"}]
    d, r, log = fixed(doc)
    assert d["components"][0]["name"] == "left-pad" and d["components"][0]["type"] == "library"
    assert any(c.rule_id == "REP-006" and c.severity == "WARN" for c in log.changes)


def test_rep006_component_without_name_or_purl_is_removed_as_data_loss() -> None:
    doc = bom()
    doc["components"].append({"type": "library", "version": "1"})
    d, r, log = fixed(doc)
    assert len(d["components"]) == 1
    assert any(c.rule_id == "REP-006" and c.severity == "DATA_LOSS" for c in log.changes)


def test_rep007_serial_number_and_original_kept() -> None:
    d, r, _ = fixed(bom(serialNumber="ACME-1"))
    assert d["serialNumber"].startswith("urn:uuid:")
    assert {"name": "sbom-fixer:originalSerialNumber", "value": "ACME-1"} in d["metadata"]["properties"]


def test_rep008_timestamp_without_timezone_is_utc_and_warned() -> None:
    doc = bom()
    doc["metadata"]["timestamp"] = "2026-10-02 10:00"
    d, r, log = fixed(doc)
    assert d["metadata"]["timestamp"] == "2026-10-02T10:00:00Z"
    assert any(c.rule_id == "REP-008" and c.severity == "WARN" for c in log.changes)


def test_rep009_url_with_spaces_is_encoded() -> None:
    doc = bom()
    doc["components"][0]["externalReferences"] = [{"type": "website", "url": "https://example.com/a b"}]
    d, r, _ = fixed(doc)
    assert d["components"][0]["externalReferences"][0]["url"] == "https://example.com/a%20b"


def test_rep010_license_structures() -> None:
    doc = bom()
    doc["components"][0]["licenses"] = ["MIT"]
    doc["components"].append(dict(copy.deepcopy(LODASH), **{"bom-ref": "b", "purl": "pkg:npm/b@1",
                                                             "licenses": [{"license": {"id": "Apache 2.0", "name": "Apache"}}]}))
    doc["components"].append(dict(copy.deepcopy(LODASH), **{"bom-ref": "c", "purl": "pkg:npm/c@1",
                                                             "licenses": [{"license": {"id": "Proprietary-Thing"}}]}))
    doc["components"].append(dict(copy.deepcopy(LODASH), **{"bom-ref": "d", "purl": "pkg:npm/d@1",
                                                             "licenses": [{"expression": "MIT OR Apache-2.0"}, {"license": {"id": "MIT"}}]}))
    d, r, _ = fixed(doc)
    c = d["components"]
    assert c[0]["licenses"] == [{"license": {"id": "MIT"}}]
    assert c[1]["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    assert c[2]["licenses"] == [{"license": {"name": "Proprietary-Thing"}}]
    assert c[3]["licenses"][0] == {"license": {"name": "MIT OR Apache-2.0"}}
    assert "REP-010" in r


def test_rep011_bad_hash_removed() -> None:
    doc = bom()
    doc["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "xyz"}, {"alg": "SHA-1", "content": "a" * 40}]
    d, r, _ = fixed(doc)
    assert d["components"][0]["hashes"] == [{"alg": "SHA-1", "content": "a" * 40}] and "REP-011" in r


def test_rep012_single_value_wrapped_in_array() -> None:
    doc = bom(dependencies=[{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": "pkg:npm/lodash@4.17.20"}])
    d, r, _ = fixed(doc)
    assert d["dependencies"][0]["dependsOn"] == ["pkg:npm/lodash@4.17.20"] and "REP-012" in r


def test_unknown_key_is_pruned_at_the_same_level_not_by_downgrading() -> None:
    doc = bom()
    doc["components"][0]["x-scanner"] = {"id": 1}
    d, r, log = fixed(doc)
    assert "x-scanner" not in d["components"][0]
    assert any(c.rule_id == "PRUNE-001" and c.severity == "DATA_LOSS" for c in log.changes)


def test_already_valid_file_has_no_changes() -> None:
    d, res, log = run(bom())
    assert res.path == ["1.5"] and len(log) == 0 and d == bom()
