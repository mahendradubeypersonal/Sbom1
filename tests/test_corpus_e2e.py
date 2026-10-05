"""Whole corpus end to end, with the invariants from the Guide (Steps 20-22)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from sbom_fixer.audit.ntia import ntia_check
from sbom_fixer.diff import apply_patch
from sbom_fixer.pipeline import run_fix
from sbom_fixer.profile import Profile, load_profile
from sbom_fixer.validate import validate

from .conftest import CORPUS

EXPECTED = yaml.safe_load((CORPUS / "expected.yaml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("rel", sorted(EXPECTED))
def test_corpus_file(rel: str, tmp_path: Path) -> None:
    exp = EXPECTED[rel]
    prof = load_profile("checkmarx")
    r = run_fix(CORPUS / rel, prof, tmp_path)
    assert r.exit_code == exp["exit_code"], (r.error, [a.reason for a in (r.descent.attempts if r.descent else [])])
    assert Path(r.outputs["notes"]).exists()
    if exp["exit_code"] == 2:
        assert "sbom" not in r.outputs
        return
    assert r.final_version == exp["final_version"]
    if "version_path" in exp:
        assert r.descent is not None and r.descent.path == exp["version_path"]
    got = {c.rule_id for c in r.log.changes}
    assert set(exp.get("rules", [])) <= got

    out = Path(r.outputs["sbom"])
    raw = out.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf") and b"\r\n" not in raw
    fixed = json.loads(raw.decode("utf-8"))
    assert validate(fixed, r.spec, r.final_version) == []

    patch = json.loads(Path(r.outputs["patch"]).read_text(encoding="utf-8"))
    assert apply_patch(r.original_doc, patch) == fixed

    before, after = ntia_check(r.original_doc, r.spec), ntia_check(fixed, r.spec)
    for name, cov in before.components.items():
        assert after.components[name].missing <= cov.missing, f"NTIA regression in {name}"

    again = run_fix(out, prof, tmp_path / "again")
    expected_again = 7 if exp["exit_code"] == 7 else 0  # exit 7 is about the content, not about a fix
    assert again.exit_code == expected_again and len(again.log) == 0, [c.rule_id for c in again.log.changes]

    if exp["exit_code"] == 0:
        assert fixed == r.original_doc


def capped(profile: Profile, top: str) -> Profile:
    """The profile with CycloneDX accepted only up to `top` (the pre-1.6 Checkmarx behaviour)."""
    rules = profile.rules_for("cyclonedx")
    accepted = [v for v in rules.accepted_versions if tuple(map(int, v.split("."))) <= tuple(map(int, top.split(".")))]
    return replace(profile, specs=dict(profile.specs, cyclonedx=replace(rules, accepted_versions=accepted)))


def test_dual_output_compliance_copy_is_never_downgraded(tmp_path: Path) -> None:
    src = CORPUS / "cdxgen" / "analytics.cdxgen.json"
    cx = run_fix(src, load_profile("checkmarx-cli"), tmp_path)
    comp = run_fix(src, load_profile("compliance"), tmp_path)
    assert cx.final_version == "1.6" and comp.final_version == "1.7" and comp.descent is not None and comp.descent.path == ["1.7"]
    assert Path(cx.outputs["sbom"]).name == "analytics.cdxgen.checkmarx-cli.cdx.json"
    assert Path(comp.outputs["sbom"]).name == "analytics.cdxgen.compliance.cdx.json"


def test_data_loss_forbidden_gives_exit_3(tmp_path: Path) -> None:
    prof = replace(capped(load_profile("checkmarx"), "1.5"), allow_data_loss=False)
    assert run_fix(CORPUS / "cdxgen" / "crypto.cdx.json", prof, tmp_path).exit_code == 3


def test_require_purl_fail_gives_exit_2(tmp_path: Path) -> None:
    prof = replace(load_profile("checkmarx"), require_purl="fail")
    r = run_fix(CORPUS / "trivy" / "payments-api.trivy.json", prof, tmp_path)
    assert r.exit_code == 2 and "require_purl" in (r.error or "")


def test_notes_sections(tmp_path: Path) -> None:
    r = run_fix(CORPUS / "trivy" / "payments-api.trivy.json", capped(load_profile("checkmarx"), "1.5"), tmp_path)
    text = Path(r.outputs["notes"]).read_text(encoding="utf-8")
    for heading in ("Version path    : 1.6", "1. WHY THE ORIGINAL FAILED", "2. CHANGES MADE", "3. DATA LOSS",
                    "4. SCAN COVERAGE (Checkmarx)", "5. RECOMMENDED SOURCE FIX", "6. COMPONENTS CHECKMARX WILL SKIP",
                    "7. QUALITY AND COMPLIANCE"):
        assert heading in text
    assert "Trivy writes CycloneDX 1.6" in text and "libssl3" in text
    comp = run_fix(CORPUS / "trivy" / "payments-api.trivy.json", load_profile("compliance"), tmp_path)
    assert "6. COMPONENTS WITHOUT PURL" in Path(comp.outputs["notes"]).read_text(encoding="utf-8")


def test_large_document_performance(tmp_path: Path) -> None:
    import time

    doc = json.loads((CORPUS / "trivy" / "payments-api.trivy.json").read_text(encoding="utf-8"))
    base = doc["components"][0]
    doc["components"] = [dict(base, **{"bom-ref": f"pkg:npm/p{i}@1.0.{i}", "name": f"p{i}", "version": f"1.0.{i}",
                                       "purl": f"pkg:npm/p{i}@1.0.{i}"}) for i in range(5000)]
    doc["dependencies"] = []
    src = tmp_path / "big.cdx.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    t = time.perf_counter()
    r = run_fix(src, load_profile("checkmarx"), tmp_path, audit=False)
    elapsed = time.perf_counter() - t
    assert r.exit_code in (0, 1) and r.final_version == "1.6" and r.coverage is not None and r.coverage.scanned == 5000
    assert elapsed < 30, f"5,000 components took {elapsed:.1f}s"
