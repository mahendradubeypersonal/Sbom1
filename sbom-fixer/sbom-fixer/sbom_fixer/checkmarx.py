"""Checkmarx One upload and verification through the `cx` CLI (SBOMFIX-701).

The exact cx flags differ between CLI releases. Confirm them with `cx scan create --help` and
`cx results show --help` and override the templates with SBOM_FIXER_CX_SCAN_ARGS /
SBOM_FIXER_CX_RESULTS_ARGS if needed. Credentials are read by the cx CLI itself from
CX_BASE_URI, CX_TENANT, CX_CLIENT_ID and CX_CLIENT_SECRET (or CX_APIKEY); this module never
puts them on a command line and never logs them.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .serialize import write_json

DEFAULT_SCAN_ARGS = (
    "scan create --project-name {project} --branch {branch} -s {file} --scan-types sca "
    "--sbom-only --scan-info-format json"
)
DEFAULT_RESULTS_ARGS = "results show --scan-id {scan_id} --report-format json --output-path {outdir} --output-name cx_result"
_SECRET_ENV = ("CX_CLIENT_SECRET", "CX_APIKEY")


@dataclass
class UploadResult:
    state: str  # completed | failed | timeout | error
    scan_id: str | None = None
    package_count: int | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state, "scan_id": self.scan_id, "package_count": self.package_count, "detail": self.detail}


class CheckmarxClient(Protocol):
    def upload(self, path: Path) -> UploadResult: ...


@dataclass
class CxConfig:
    cx_bin: str
    project: str
    branch: str
    timeout_s: int
    scan_args: str
    results_args: str

    @classmethod
    def from_env(cls) -> CxConfig:
        exe = os.environ.get("CX_BIN") or shutil.which("cx") or ""
        return cls(
            cx_bin=exe,
            project=os.environ.get("SBOM_FIXER_CX_PROJECT", "sbom-fixer-verification"),
            branch=os.environ.get("SBOM_FIXER_CX_BRANCH", "sbom-fixer"),
            timeout_s=int(os.environ.get("SBOM_FIXER_CX_TIMEOUT_S", "900")),
            scan_args=os.environ.get("SBOM_FIXER_CX_SCAN_ARGS", DEFAULT_SCAN_ARGS),
            results_args=os.environ.get("SBOM_FIXER_CX_RESULTS_ARGS", DEFAULT_RESULTS_ARGS),
        )

    def missing(self) -> list[str]:
        out = []
        if not self.cx_bin:
            out.append("cx CLI not found (install it or set CX_BIN)")
        if not os.environ.get("CX_BASE_URI"):
            out.append("CX_BASE_URI")
        if not (os.environ.get("CX_APIKEY") or (os.environ.get("CX_CLIENT_ID") and os.environ.get("CX_CLIENT_SECRET"))):
            out.append("CX_APIKEY or CX_CLIENT_ID + CX_CLIENT_SECRET")
        return out


def _redact(text: str) -> str:
    for name in _SECRET_ENV:
        val = os.environ.get(name)
        if val:
            text = text.replace(val, "***")
    return text


def _find(data: Any, keys: tuple[str, ...]) -> Any:
    if isinstance(data, dict):
        for k, v in data.items():
            if k in keys:
                return v
        for v in data.values():
            found = _find(v, keys)
            if found is not None:
                return found
    elif isinstance(data, list):
        for v in data:
            found = _find(v, keys)
            if found is not None:
                return found
    return None


def count_packages(results: Any) -> int | None:
    """Count SCA packages in a cx results JSON. Field names vary; returns None when not found."""
    for key in ("scaPackages", "packages", "Packages"):
        v = _find(results, (key,))
        if isinstance(v, list):
            return len(v)
    total = _find(results, ("totalPackages", "TotalPackages"))
    return int(total) if isinstance(total, (int, float)) else None


class CxCliClient:
    def __init__(self, config: CxConfig | None = None) -> None:
        self.config = config or CxConfig.from_env()

    def _run(self, args: str, **fmt: str) -> subprocess.CompletedProcess[str]:
        argv = [self.config.cx_bin] + [a.format(**fmt) for a in shlex.split(args)]
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              timeout=self.config.timeout_s, check=False)

    def upload(self, path: Path) -> UploadResult:
        missing = self.config.missing()
        if missing:
            return UploadResult("error", detail="Checkmarx not configured: " + ", ".join(missing))
        try:
            proc = self._run(self.config.scan_args, project=self.config.project, branch=self.config.branch, file=str(path))
        except subprocess.TimeoutExpired:
            return UploadResult("timeout", detail=f"scan did not finish within {self.config.timeout_s}s")
        except OSError as exc:
            return UploadResult("error", detail=_redact(str(exc)))
        out = _redact(proc.stdout + "\n" + proc.stderr)
        scan: Any = None
        for chunk in (proc.stdout, proc.stdout[proc.stdout.find("{"):] if "{" in proc.stdout else ""):
            try:
                scan = json.loads(chunk)
                break
            except (json.JSONDecodeError, TypeError):
                continue
        scan_id = _find(scan, ("ID", "Id", "id", "scanId")) if scan is not None else None
        status = str(_find(scan, ("Status", "status")) or "").lower() if scan is not None else ""
        if proc.returncode != 0 or status in ("failed", "canceled", "partial"):
            return UploadResult("failed", scan_id=str(scan_id) if scan_id else None, detail=out.strip()[-800:])
        pkgs = None
        if scan_id:
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    self._run(self.config.results_args, scan_id=str(scan_id), outdir=tmp)
                    res_file = next(Path(tmp).glob("cx_result*.json"), None)
                    if res_file is not None:
                        pkgs = count_packages(json.loads(res_file.read_text(encoding="utf-8")))
                except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
                    pkgs = None
        return UploadResult("completed", scan_id=str(scan_id) if scan_id else None, package_count=pkgs,
                            detail=f"status={status or 'unknown'}")


class CheckmarxAcceptanceClient:
    """Adapter so the descent oracle can try a document against Checkmarx (acceptance: checkmarx)."""

    def __init__(self, client: CheckmarxClient) -> None:
        self.client = client

    def check(self, doc: Any, spec: str, version: str) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / f"probe-{spec}-{version}.json"
            write_json(doc, path)
            res = self.client.upload(path)
        if res.state == "completed":
            return True, f"Checkmarx import completed (scan {res.scan_id})"
        return False, f"Checkmarx import {res.state}: {res.detail[:200]}"


def verify(client: CheckmarxClient, path: Path, expected_packages: int | None = None, tolerance: float = 0.05) -> tuple[bool, UploadResult]:
    res = client.upload(path)
    if res.state != "completed":
        return False, res
    if expected_packages is not None and res.package_count is not None and expected_packages > 0:
        gap = abs(res.package_count - expected_packages) / expected_packages
        if gap > tolerance:
            res.detail += f"; package count {res.package_count} differs from expected {expected_packages} by {gap:.0%}"
            return False, res
    return True, res
