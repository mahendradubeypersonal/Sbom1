"""Version descent and hop rules (Phase 3)."""

from __future__ import annotations

import copy

from sbom_fixer.oracle import CheckmarxOracle
from sbom_fixer.validate import validate

from .conftest import LODASH, bom, ids, profile_with, run


def test_ok_at_declared_version_means_zero_hops() -> None:
    d, res, log = run(bom("1.4"))
    assert res.path == ["1.4"] and res.final_version == "1.4" and "CDX-VER" not in ids(log)


def test_one_hop_when_declared_version_not_accepted() -> None:
    d, res, log = run(bom("1.6"))
    assert res.path == ["1.6", "1.5"] and d["specVersion"] == "1.5"
    assert res.attempts[0].reason.startswith("schema-valid, but 1.6 is not in accepted_versions")


def test_two_hops_and_stops_at_first_ok_level() -> None:
    d, res, _ = run(bom("1.6"), profile_with(["1.3", "1.4"]))
    assert res.path == ["1.6", "1.5", "1.4"] and res.final_version == "1.4"
    assert validate(d, "cyclonedx", "1.4") == []


def test_floor_failure_reports_every_attempt() -> None:
    d, res, _ = run(bom("1.6"), profile_with([], floor="1.5"))
    assert not res.ok and res.path == ["1.6", "1.5"] and all(not a.accepted for a in res.attempts)


def test_below_floor_needs_upgrade() -> None:
    d, res, _ = run(bom("1.3"), profile_with(["1.4"], floor="1.4"))
    assert not res.ok and "upgrade hop" in res.attempts[0].reason


def test_repairs_are_carried_down() -> None:
    doc = bom("1.6")
    doc["components"][0]["type"] = "Library"
    d, res, log = run(doc)
    rep = [c for c in log.changes if c.rule_id == "REP-003"]
    assert rep and rep[0].level == "1.6" and d["components"][0]["type"] == "library" and res.final_version == "1.5"


def test_floor_declared_never_downgrades() -> None:
    d, res, _ = run(bom("1.6"), profile_with(["1.5"], floor="declared"))
    assert res.path == ["1.6"] and not res.ok


def test_hop_16_to_15_rules() -> None:
    c = dict(copy.deepcopy(LODASH), manufacturer={"name": "M"}, authors=[{"name": "A"}, {"name": "B"}],
             omniborId=["gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64"], swhid=["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"],
             tags=["x"], evidence={"identity": [{"field": "purl", "confidence": 0.2}, {"field": "name", "confidence": 0.9}]},
             licenses=[{"license": {"id": "MIT", "acknowledgement": "declared"}}],
             externalReferences=[{"type": "rfc-9116", "url": "https://example.com/security.txt"}])
    crypto = {"bom-ref": "k", "type": "cryptographic-asset", "name": "AES", "cryptoProperties": {"assetType": "algorithm"}}
    doc = bom("1.6", components=[c, crypto], declarations={"assessors": [{"bom-ref": "a1", "thirdParty": True}]},
              dependencies=[{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": ["k"], "provides": ["k"]}, {"ref": "k"}])
    doc["metadata"]["manufacturer"] = {"name": "ACME"}
    d, res, log = run(doc)
    got = ids(log)
    assert {f"CDX16-{n:03d}" for n in range(1, 12)} <= got
    comp = d["components"][0]
    assert d["metadata"]["manufacture"] == {"name": "ACME"} and comp["supplier"] == {"name": "M"} and comp["author"] == "A, B"
    assert comp["evidence"]["identity"]["field"] == "name"
    assert comp["externalReferences"][0] == {"type": "other", "url": "https://example.com/security.txt", "comment": "original type: rfc-9116"}
    assert len(d["components"]) == 1 and "declarations" not in d
    assert d["dependencies"][0]["dependsOn"] == [] and len(d["dependencies"]) == 1
    names = {p["name"] for p in comp["properties"]}
    assert {"sbom-fixer:omniborId", "sbom-fixer:swhid", "sbom-fixer:tags"} <= names
    assert validate(d, "cyclonedx", "1.5") == []


def test_cdx16_004_leaves_single_object_alone() -> None:
    doc = bom("1.6")
    doc["components"][0]["evidence"] = {"identity": {"field": "purl", "confidence": 1}}
    d, res, log = run(doc)
    assert "CDX16-004" not in ids(log) and d["components"][0]["evidence"]["identity"]["field"] == "purl"


def test_hop_15_to_14_rules() -> None:
    doc = bom("1.5", formulation=[{"bom-ref": "f"}], properties=[{"name": "p", "value": "v"}])
    doc.pop("version")
    doc["metadata"]["tools"] = {"components": [{"type": "application", "name": "syft", "version": "1.0", "supplier": {"name": "Anchore"}}],
                                "services": [{"name": "scanner-svc"}]}
    doc["metadata"]["lifecycles"] = [{"phase": "build"}]
    doc["components"][0]["type"] = "device-driver"
    doc["components"][0]["evidence"] = {"identity": {"field": "purl", "confidence": 1}, "occurrences": [{"location": "/x"}]}
    doc["compositions"] = [{"aggregate": "incomplete_first_party_only" if False else "incomplete_first_party_opensource_only"}]
    d, res, log = run(doc, profile_with(["1.4"]))
    assert res.path == ["1.5", "1.4"]
    assert d["metadata"]["tools"][0] == {"vendor": "Anchore", "name": "syft", "version": "1.0"}
    assert d["components"][0]["type"] == "device" and "evidence" not in d["components"][0]
    assert d["version"] == 1 and "properties" not in d and {"name": "p", "value": "v"} in d["metadata"]["properties"]
    assert d["compositions"][0]["aggregate"] == "incomplete"
    assert {"CDX15-001", "CDX15-002", "CDX15-003", "CDX15-004", "CDX15-006", "CDX15-009", "CDX15-010", "CDX15-011"} <= ids(log)
    assert validate(d, "cyclonedx", "1.4") == []


def test_cdx15_001p_legacy_tools_at_15_when_profile_says_so() -> None:
    doc = bom("1.5")
    doc["metadata"]["tools"] = {"components": [{"type": "application", "name": "trivy", "version": "1"}]}
    d, res, log = run(doc, profile_with(["1.5"], tools_form="legacy-array"))
    assert res.path == ["1.5"] and isinstance(d["metadata"]["tools"], list) and "CDX15-001P" in ids(log)


def test_hop_14_to_13() -> None:
    c = dict(copy.deepcopy(LODASH))
    c.pop("version")
    doc = bom("1.4", components=[c], vulnerabilities=[{"id": "CVE-1"}])
    d, res, log = run(doc, profile_with(["1.3"]))
    assert res.path == ["1.4", "1.3"] and d["components"][0]["version"] == "4.17.20" and "vulnerabilities" not in d
    assert validate(d, "cyclonedx", "1.3") == []


def test_hop_17_to_16() -> None:
    c = dict(copy.deepcopy(LODASH), versionRange="vers:npm/>=4", isExternal=True,
             hashes=[{"alg": "Streebog-256", "content": "a" * 64}])
    c.pop("version")
    doc = bom("1.7", components=[c], citations=[{"bom-ref": "c1", "pointers": ["/components/0"], "timestamp": "2026-10-02T10:00:00Z",
                                                 "attributedTo": "x"}])
    d, res, log = run(doc, profile_with(["1.6"]))
    assert res.path == ["1.7", "1.6"] and "citations" not in d
    assert {"CDX17-001", "CDX17-002", "CDX17-ENUM"} <= ids(log)
    assert validate(d, "cyclonedx", "1.6") == []


def test_spdx_23_to_22_only_when_23_not_accepted() -> None:
    import json

    from .conftest import CORPUS

    doc = json.loads((CORPUS / "sbom-tool" / "service.spdx.json").read_text(encoding="utf-8"))
    prof = profile_with(["1.5"])
    prof.specs["spdx"].accepted_versions = ["2.2"]
    d, res, log = run(doc, prof)
    assert res.path == ["2.3", "2.2"] and d["spdxVersion"] == "SPDX-2.2"
    assert "primaryPackagePurpose" not in d["packages"][0] and "primaryPackagePurpose: LIBRARY" in d["packages"][0]["comment"]
    assert validate(d, "spdx", "2.2") == []


class FakeClient:
    def __init__(self, accept: set[str]) -> None:
        self.accept, self.calls = accept, 0

    def check(self, doc, spec, version):  # type: ignore[no-untyped-def]
        self.calls += 1
        return (version in self.accept, f"fake {'accepted' if version in self.accept else 'rejected'} {version}")


def test_checkmarx_oracle_descends_until_real_import_works_and_caches() -> None:
    from sbom_fixer.changes import ChangeLog
    from sbom_fixer.descent import descend

    client = FakeClient({"1.4"})
    oracle = CheckmarxOracle(client, max_uploads=6)
    prof = profile_with(["1.3", "1.4", "1.5", "1.6"])
    doc = bom("1.6")
    res = descend(doc, "cyclonedx", "1.6", prof, oracle, ChangeLog(), "0" * 64)
    assert res.path == ["1.6", "1.5", "1.4"] and client.calls == 3
    assert oracle.accepts(doc, "cyclonedx", "1.4")[1].endswith("(cached)") and client.calls == 3


def test_checkmarx_oracle_budget() -> None:
    oracle = CheckmarxOracle(FakeClient(set()), max_uploads=1)
    assert oracle.accepts(bom(), "cyclonedx", "1.5")[0] is False
    ok, reason = oracle.accepts(bom("1.4"), "cyclonedx", "1.4")
    assert not ok and "budget" in reason
