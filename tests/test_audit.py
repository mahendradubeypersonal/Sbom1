"""NTIA checker, sbomqs wrapper and quality gate (Phase 5)."""

from __future__ import annotations

import json

import pytest

from sbom_fixer.audit import sbomqs as sbomqs_mod
from sbom_fixer.audit.gate import evaluate
from sbom_fixer.audit.ntia import ntia_check
from sbom_fixer.profile import parse_profile

from .conftest import CORPUS, LODASH, bom


def full() -> dict:
    doc = bom(dependencies=[{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": ["pkg:npm/lodash@4.17.20"]}])
    doc["components"][0]["supplier"] = {"name": "OpenJS"}
    doc["metadata"]["authors"] = [{"name": "Platform Team"}]
    return doc


def test_ntia_pass() -> None:
    assert ntia_check(full(), "cyclonedx").passed


@pytest.mark.parametrize("breaker,field", [
    (lambda d: d["components"][0].pop("supplier"), "Supplier name"),
    (lambda d: d["components"][0].pop("version"), "Component version"),
    (lambda d: d["components"][0].pop("purl"), "Unique identifier"),
])
def test_ntia_component_fields(breaker, field) -> None:  # type: ignore[no-untyped-def]
    d = full()
    breaker(d)
    rep = ntia_check(d, "cyclonedx")
    assert not rep.passed and rep.components[field].covered == 0


@pytest.mark.parametrize("breaker,field", [
    (lambda d: d.pop("dependencies"), "Dependency relationships"),
    (lambda d: d["metadata"].pop("authors"), "Author of SBOM data"),
    (lambda d: d["metadata"].pop("timestamp"), "Timestamp"),
])
def test_ntia_document_fields(breaker, field) -> None:  # type: ignore[no-untyped-def]
    d = full()
    breaker(d)
    assert ntia_check(d, "cyclonedx").document[field] is False


def test_author_from_tools_only_is_flagged() -> None:
    d = full()
    d["metadata"].pop("authors")
    d["metadata"]["tools"] = [{"name": "syft"}]
    rep = ntia_check(d, "cyclonedx")
    assert rep.author_from_tools_only and not rep.passed


def test_ntia_spdx() -> None:
    doc = json.loads((CORPUS / "minimal" / "min-spdx-2.3.json").read_text(encoding="utf-8"))
    assert ntia_check(doc, "spdx").passed
    doc["packages"][0]["supplier"] = "NOASSERTION"
    assert not ntia_check(doc, "spdx").passed


def test_gate_detects_regression_and_required_framework() -> None:
    prof = parse_profile({"name": "g", "cyclonedx": {"accepted_versions": ["1.5"]},
                          "quality": {"audit": "gate", "min_score": 5},
                          "frameworks": [{"id": "ntia-2021", "gate": "required"}, {"id": "bsi-tr-03183-2-v2"}]})
    before = ntia_check(full(), "cyclonedx")
    worse = full()
    worse["components"][0].pop("supplier")
    after = ntia_check(worse, "cyclonedx")
    rep = evaluate(before, after, 7.0, 4.0, prof, "cyclonedx", "1.4", worse, None)
    assert rep.gate_failed
    assert any("'Supplier name' missing on more" in r for r in rep.regressions) and any("sbomqs score dropped" in r for r in rep.regressions)
    bsi = next(f for f in rep.framework_results if f["id"] == "bsi-tr-03183-2-v2")
    assert bsi["passed"] is False and "1.5+" in bsi["detail"]


def test_report_only_never_fails_gate() -> None:
    prof = parse_profile({"name": "r", "cyclonedx": {"accepted_versions": ["1.5"]}, "quality": {"audit": "report"}})
    a = ntia_check(full(), "cyclonedx")
    worse = full()
    worse["components"][0].pop("supplier")
    assert not evaluate(a, ntia_check(worse, "cyclonedx"), None, None, prof, "cyclonedx", "1.5", worse, None).gate_failed


def test_sbomqs_missing_and_parsing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("SBOMQS_BIN", raising=False)
    monkeypatch.setattr(sbomqs_mod.shutil, "which", lambda _: None)
    monkeypatch.setattr(sbomqs_mod, "vendored_binary", lambda: None)
    assert sbomqs_mod.sbomqs_score("x.json").available is False
    assert sbomqs_mod._find_score({"files": [{"avg_score": 7.25}]}) == 7.25
    assert sbomqs_mod._find_score({"score": 3}) == 3.0
    assert sbomqs_mod._find_score({"nothing": 1}) is None


_ = LODASH
