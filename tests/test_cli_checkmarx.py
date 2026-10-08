"""CLI commands, Checkmarx client parsing, verification and bisect (Phases 4, 6, 7)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sbom_fixer.bisect import bisect
from sbom_fixer.checkmarx import CheckmarxAcceptanceClient, CxConfig, UploadResult, count_packages, verify
from sbom_fixer.cli import app

from .conftest import CORPUS, LODASH, bom

runner = CliRunner()


def test_cli_version_and_rules() -> None:
    assert "sbom-fixer 1.0.0" in runner.invoke(app, ["--version"]).output
    out = runner.invoke(app, ["rules", "--markdown"]).output
    assert "| REP-003 |" in out and "| CDX16-004 |" in out and "| SAN-090 |" in out


def test_cli_check_is_read_only(tmp_path: Path) -> None:
    src = tmp_path / "m.json"
    src.write_bytes((CORPUS / "maven" / "orders-service.bom.json").read_bytes())
    res = runner.invoke(app, ["check", str(src)])
    assert res.exit_code == 1 and "own-version schema errors" in res.output
    assert sorted(p.name for p in tmp_path.iterdir()) == ["m.json"]


def test_cli_check_accepted_override() -> None:
    res = runner.invoke(app, ["check", str(CORPUS / "minimal" / "min-cdx-1.5.json"), "--accepted", "1.4", "--allow-downgrade"])
    assert res.exit_code == 1 and "level 1.4  : ACCEPTED" in res.output


def test_cli_fix_two_profiles(tmp_path: Path) -> None:
    res = runner.invoke(app, ["fix", str(CORPUS / "trivy" / "payments-api.trivy.json"), "-p", "checkmarx", "-p", "compliance",
                              "--out", str(tmp_path)])
    assert res.exit_code == 0, res.output  # valid 1.6 is kept by both profiles
    names = {p.name for p in tmp_path.iterdir()}
    assert {"payments-api.trivy.checkmarx.cdx.json", "payments-api.trivy.compliance.cdx.json",
            "payments-api.trivy.checkmarx.notes.txt", "payments-api.trivy.checkmarx.diff.patch.json",
            "payments-api.trivy.checkmarx.purl-coverage.csv"} <= names
    assert "payments-api.trivy.compliance.purl-coverage.csv" not in names


def test_cli_fix_unsupported_exit_2(tmp_path: Path) -> None:
    res = runner.invoke(app, ["fix", str(CORPUS / "unsupported" / "bom.xml"), "--out", str(tmp_path)])
    assert res.exit_code == 2 and "XML" in res.output


def test_cli_audit_and_schema_diff() -> None:
    res = runner.invoke(app, ["audit", str(CORPUS / "minimal" / "min-cdx-1.5.json"), "--json"])
    assert res.exit_code == 0 and json.loads(res.output)["ntia"]["passed"] is True
    res = runner.invoke(app, ["schema-diff", "1.5", "1.6"])
    assert res.exit_code == 0 and "omniborId" in res.output


class FakeCx:
    def __init__(self, state: str = "completed", packages: int | None = 10) -> None:
        self.state, self.packages, self.paths = state, packages, []

    def upload(self, path: Path) -> UploadResult:
        self.paths.append(path)
        return UploadResult(self.state, scan_id="s1", package_count=self.packages, detail="fake")


def test_verify_tolerance() -> None:
    assert verify(FakeCx(packages=10), Path("x"), 10)[0]
    assert verify(FakeCx(packages=10), Path("x"), 10.4 and 10)[0]
    ok, res = verify(FakeCx(packages=8), Path("x"), 10)
    assert not ok and "differs" in res.detail
    assert not verify(FakeCx(state="failed"), Path("x"))[0]


def test_acceptance_adapter_writes_temp_file() -> None:
    cx = FakeCx()
    ok, reason = CheckmarxAcceptanceClient(cx).check(bom(), "cyclonedx", "1.5")
    assert ok and "scan s1" in reason and cx.paths[0].name == "probe-cyclonedx-1.5.json"


def test_cx_config_reports_missing_credentials(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for k in ("CX_BASE_URI", "CX_APIKEY", "CX_CLIENT_ID", "CX_CLIENT_SECRET", "CX_BIN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    missing = CxConfig.from_env().missing()
    assert any("cx CLI" in m for m in missing) and "CX_BASE_URI" in missing


def test_count_packages_variants() -> None:
    assert count_packages({"scaPackages": [1, 2, 3]}) == 3
    assert count_packages({"summary": {"totalPackages": 7}}) == 7
    assert count_packages({"x": 1}) is None


def test_bisect_finds_version_and_field() -> None:
    doc = bom("1.6")
    doc["components"].append(dict(LODASH, **{"bom-ref": "bad", "purl": "pkg:npm/bad@1", "omniborId": ["gitoid:x"]}))

    def checkmarx_like(d: dict) -> bool:
        if d.get("specVersion") not in ("1.4", "1.5"):
            return False
        return not any("omniborId" in c for c in d.get("components", []))

    rep = bisect(doc, checkmarx_like, max_uploads=40, base_version="1.5")
    text = " ".join(rep.conclusions)
    assert "Field 'omniborId'" in text and not rep.inconclusive


def test_bisect_original_accepted_and_budget() -> None:
    assert "nothing to bisect" in bisect(bom(), lambda d: True).conclusions[0]
    two = bom("1.6")
    two["components"].append(dict(LODASH, **{"bom-ref": "b", "purl": "pkg:npm/b@1", "name": "b"}))
    rep = bisect(two, lambda d: False, max_uploads=2)
    assert rep.inconclusive and rep.uploads == 2
