"""fix repairs on the file's own schema version; stepping down is opt-in (--allow-downgrade / allow_downgrade)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sbom_fixer.cli import app
from sbom_fixer.pipeline import run_fix
from sbom_fixer.profile import load_profile
from sbom_fixer.validate import validate

from .conftest import CORPUS, bom, ids, run


def doc16(**component_extra: Any) -> dict[str, Any]:
    d = bom("1.6")
    d["metadata"]["tools"] = {"components": [{"type": "application", "name": "gen", "version": "1"}]}
    d["components"][0].update(component_extra)
    return d


@pytest.mark.parametrize("profile_name", ["checkmarx", "checkmarx-cli", "compliance"])
def test_unrepairable_error_is_fixed_on_the_same_version(profile_name: str) -> None:
    d = doc16(modified="no", externalReferences=[{"type": "not-a-real-type", "url": "https://example.org"}])
    out, res, log = run(d, load_profile(profile_name))
    assert res.ok and res.path == ["1.6"] and res.final_version == "1.6"
    assert validate(out, "cyclonedx", "1.6") == []
    assert out["components"][0]["modified"] is False  # converted, not dropped
    assert {"COERCE-001"} <= ids(log)
    assert not any(c.rule_id.startswith("CDX16-") for c in log.changes)  # no 1.6 -> 1.5 hop rules


def test_value_without_a_conversion_is_removed_and_reported() -> None:
    d = doc16(scope="sometimes")  # not an enum value, no case variant to map to
    out, res, log = run(d, load_profile("checkmarx"))
    assert res.final_version == "1.6" and "scope" not in out["components"][0]
    removed = [c for c in log.changes if c.rule_id in ("COERCE-002", "REP-003", "PRUNE-001", "REP-005")]
    assert removed and all(c.path.startswith("/components/0/scope") for c in removed)


def test_not_accepted_version_is_kept_with_a_warning() -> None:
    prof = replace(load_profile("checkmarx"), specs={**load_profile("checkmarx").specs,
                                                    "cyclonedx": replace(load_profile("checkmarx").rules_for("cyclonedx"),
                                                                         accepted_versions=["1.5"])})
    out, res, log = run(doc16(), prof)
    assert res.ok and res.final_version == "1.6" and out["specVersion"] == "1.6"
    assert any(f.rule_id == "VER-KEEP" for f in log.findings)


def test_allow_downgrade_restores_the_descent() -> None:
    prof = load_profile("checkmarx")
    prof = replace(prof, allow_downgrade=True,
                   specs={**prof.specs, "cyclonedx": replace(prof.rules_for("cyclonedx"), accepted_versions=["1.5"])})
    out, res, _ = run(doc16(), prof)
    assert res.path == ["1.6", "1.5"] and out["specVersion"] == "1.5"


def test_cli_fix_never_downgrades_and_flag_opts_in(tmp_path: Path) -> None:
    src = tmp_path / "x.cdx.json"
    src.write_text(json.dumps(doc16(modified="no")), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "a"), "--accepted", "1.5", "--no-audit"])
    assert res.exit_code == 1, res.output
    assert json.loads((tmp_path / "a" / "x.checkmarx.cdx.json").read_text(encoding="utf-8"))["specVersion"] == "1.6"
    res = runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "b"), "--accepted", "1.5", "--allow-downgrade", "--no-audit"])
    assert res.exit_code == 1, res.output
    assert json.loads((tmp_path / "b" / "x.checkmarx.cdx.json").read_text(encoding="utf-8"))["specVersion"] == "1.5"


@pytest.mark.parametrize("rel", ["cdxgen/crypto.cdx.json", "cdxgen/analytics.cdxgen.json", "minimal/min-cdx-1.7.json",
                                 "unsupported/legacy-1.2.cdx.json", "minimal/min-spdx-2.2.json"])
def test_every_profile_keeps_the_declared_version(rel: str, tmp_path: Path) -> None:
    for name in ("checkmarx", "checkmarx-cli", "compliance"):
        r = run_fix(CORPUS / rel, load_profile(name), tmp_path / name, audit=False)
        assert r.final_version == r.declared and r.descent is not None and r.descent.path == [r.declared], (name, r.descent)


def test_future_version_still_maps_to_17(tmp_path: Path) -> None:
    r = run_fix(CORPUS / "future" / "min-cdx-1.8.json", load_profile("checkmarx"), tmp_path, audit=False)
    assert r.final_version == "1.7" and r.descent is not None and r.descent.path == ["1.8", "1.7"]
