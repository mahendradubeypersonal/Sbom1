"""The sbomqs copy vendored in tools/sbomqs: integrity, discovery order, offline scoring."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from sbom_fixer.audit import sbomqs as sbomqs_mod
from sbom_fixer.pipeline import run_fix
from sbom_fixer.profile import load_profile

from .conftest import CORPUS, ROOT

VENDORED = ROOT / "tools" / "sbomqs"
needs_binary = pytest.mark.skipif(sbomqs_mod.vendored_binary() is None,
                                  reason="no vendored sbomqs for this platform (Windows x64 runs it as is)")


def test_vendored_files_match_sha256sums() -> None:
    lines = (VENDORED / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert lines, "SHA256SUMS is empty"
    for line in lines:
        digest, rel = line.split(maxsplit=1)
        assert hashlib.sha256((VENDORED / rel).read_bytes()).hexdigest() == digest, f"{rel} changed since vendoring"


def test_vendored_archives_match_upstream_checksums() -> None:
    upstream = dict(reversed(line.split()) for line in (VENDORED / "checksums.txt").read_text(encoding="utf-8").splitlines())
    for archive in (VENDORED / "linux-amd64").glob("*.tar.gz"):
        assert upstream[archive.name] == hashlib.sha256(archive.read_bytes()).hexdigest()


def test_dockerfile_pins_the_vendored_version() -> None:
    version = (VENDORED / "VERSION").read_text(encoding="utf-8").strip()
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(rf"^ARG SBOMQS_VERSION={re.escape(version)}$", dockerfile, re.MULTILINE)
    assert (VENDORED / "linux-amd64" / f"sbomqs_{version}_Linux_x86_64.tar.gz").is_file()
    assert (VENDORED / "LICENSE").is_file()


def test_discovery_order(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = tmp_path / "vendored.exe"
    fake.write_text("x")
    monkeypatch.setattr(sbomqs_mod.shutil, "which", lambda _: "/usr/bin/sbomqs")
    monkeypatch.setattr(sbomqs_mod, "vendored_binary", lambda: fake)
    monkeypatch.setenv("SBOMQS_BIN", "C:/custom/sbomqs.exe")
    assert sbomqs_mod.find_sbomqs() == "C:/custom/sbomqs.exe"
    monkeypatch.delenv("SBOMQS_BIN")
    assert sbomqs_mod.find_sbomqs() == str(fake)
    monkeypatch.setattr(sbomqs_mod, "vendored_binary", lambda: None)
    assert sbomqs_mod.find_sbomqs() == "/usr/bin/sbomqs"


def test_vendored_binary_per_platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "windows-amd64").mkdir()
    (tmp_path / "windows-amd64" / "sbomqs.exe").write_text("x")
    (tmp_path / "linux-amd64").mkdir()
    monkeypatch.setattr(sbomqs_mod.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(sbomqs_mod.sys, "platform", "win32")
    assert sbomqs_mod.vendored_binary(tmp_path) == tmp_path / "windows-amd64" / "sbomqs.exe"
    monkeypatch.setattr(sbomqs_mod.sys, "platform", "linux")
    assert sbomqs_mod.vendored_binary(tmp_path) is None  # archive not extracted yet
    (tmp_path / "linux-amd64" / "sbomqs").write_text("x")
    assert sbomqs_mod.vendored_binary(tmp_path) == tmp_path / "linux-amd64" / "sbomqs"
    monkeypatch.setattr(sbomqs_mod.platform, "machine", lambda: "arm64")
    assert sbomqs_mod.vendored_binary(tmp_path) is None


def test_clean_error_strips_colours_and_timestamps() -> None:
    raw = ("2026-10-05T15:28:59.915+0530\t\x1b[31mERROR\x1b[0m\tsbom/sbom.go:299\tFailed to parse SBOM document\t"
           '{"version": "1.8", "error": "invalid specification version"}\n')
    out = sbomqs_mod.clean_error(raw)
    assert "\x1b" not in out and not out.startswith("2026")
    assert out.startswith("Failed to parse SBOM document") and "invalid specification version" in out


def test_grade_parsing() -> None:
    assert sbomqs_mod._find_grade({"files": [{"grade": "C", "sbom_quality_score": 7.0}]}) == "C"
    assert sbomqs_mod._find_grade({"files": []}) is None


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any network attempt goes to a closed port, so a passing test proves sbomqs works offline."""
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("SBOMQS_BIN", raising=False)


@needs_binary
@pytest.mark.usefixtures("offline")
@pytest.mark.parametrize("rel", ["minimal/min-cdx-1.6.json", "minimal/min-cdx-1.4.json", "minimal/min-spdx-2.3.json"])
def test_vendored_sbomqs_scores_offline(rel: str) -> None:
    res = sbomqs_mod.sbomqs_score(str(CORPUS / rel))
    assert res.available and res.error is None, res.error
    assert res.score is not None and 0 <= res.score <= 10 and res.grade in ("A", "B", "C", "D", "F")
    assert res.exe is not None and Path(res.exe).resolve() == sbomqs_mod.vendored_binary().resolve()  # type: ignore[union-attr]


@needs_binary
@pytest.mark.usefixtures("offline")
def test_vendored_sbomqs_unreadable_input_gives_clean_error() -> None:
    res = sbomqs_mod.sbomqs_score(str(CORPUS / "future" / "min-cdx-1.8.json"))
    assert res.available and res.score is None and res.error and "\x1b" not in res.error


@needs_binary
@pytest.mark.usefixtures("offline")
def test_fix_reports_sbomqs_before_and_after(tmp_path: Path) -> None:
    r = run_fix(CORPUS / "purl" / "format-fixes.cdx.json", load_profile("checkmarx"), tmp_path)
    assert r.quality is not None and r.quality.before_score is not None and r.quality.after_score is not None
    notes = Path(r.outputs["notes"]).read_text(encoding="utf-8")
    assert "sbomqs score (0-10)" in notes and "n/a" not in notes.split("sbomqs score (0-10)")[1].splitlines()[0]


@needs_binary
@pytest.mark.usefixtures("offline")
def test_audit_command_shows_grade_and_binary() -> None:
    from typer.testing import CliRunner

    from sbom_fixer.cli import app

    res = CliRunner().invoke(app, ["audit", str(CORPUS / "minimal" / "min-cdx-1.6.json")])
    assert res.exit_code == 0 and "(grade " in res.output and "sbomqs binary:" in res.output
