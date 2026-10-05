"""Wrapper around the sbomqs CLI (Interlynk). Optional: the audit still runs without it.

Where the binary comes from, in this order:
  1. SBOMQS_BIN (full path to a sbomqs executable)
  2. the copy vendored in this repository (tools/sbomqs, pinned by tools/vendor_sbomqs.py), so a checkout scores
     SBOMs offline without installing anything; on Linux the archive there must be extracted first (see its README)
  3. sbomqs on PATH (the Docker image installs the same pinned version in /usr/local/bin)

JSON field names differ between sbomqs releases (2.x: files[0].sbom_quality_score, 1.x: avg_score); keep the
parsing below defensive.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VENDORED = Path(__file__).resolve().parents[2] / "tools" / "sbomqs"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_LOG_PREFIX = re.compile(r"^\S+T\S+\s+(ERROR|WARN|INFO)\s+\S+\s+", re.MULTILINE)


@dataclass
class SbomqsResult:
    available: bool
    score: float | None = None
    error: str | None = None
    raw: Any = None
    grade: str | None = None
    exe: str | None = None


def _find_score(data: Any) -> float | None:
    if isinstance(data, dict):
        files = data.get("files")
        if isinstance(files, list) and files and isinstance(files[0], dict):
            for key in ("avg_score", "sbom_quality_score", "score"):
                if isinstance(files[0].get(key), (int, float)):
                    return float(files[0][key])
        for key in ("avg_score", "sbom_quality_score", "score"):
            if isinstance(data.get(key), (int, float)):
                return float(data[key])
    return None


def _find_grade(data: Any) -> str | None:
    files = data.get("files") if isinstance(data, dict) else None
    if isinstance(files, list) and files and isinstance(files[0], dict) and isinstance(files[0].get("grade"), str):
        return str(files[0]["grade"])
    return None


def vendored_binary(root: Path = VENDORED) -> Path | None:
    """The repository copy for this platform, or None (other OS/CPU, or not extracted yet on Linux)."""
    machine = platform.machine().lower()
    if machine not in ("amd64", "x86_64"):
        return None
    candidate = root / "windows-amd64" / "sbomqs.exe" if sys.platform == "win32" else root / "linux-amd64" / "sbomqs"
    return candidate if candidate.is_file() else None


def find_sbomqs() -> str | None:
    if os.environ.get("SBOMQS_BIN"):
        return os.environ["SBOMQS_BIN"]
    vendored = vendored_binary()
    return str(vendored) if vendored else shutil.which("sbomqs")


def clean_error(text: str) -> str:
    """sbomqs logs with colours and timestamps; keep only the messages."""
    text = _LOG_PREFIX.sub("", _ANSI.sub("", text))
    return " | ".join(line.strip() for line in text.splitlines() if line.strip())[:500]


def sbomqs_score(path: str, timeout: int = 300) -> SbomqsResult:
    exe = find_sbomqs()
    if not exe:
        return SbomqsResult(available=False, error="sbomqs not found (set SBOMQS_BIN, put it on PATH, or keep tools/sbomqs)")
    try:
        proc = subprocess.run([exe, "score", path, "--json"], capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return SbomqsResult(available=True, error=str(exc)[:300], exe=exe)
    if proc.returncode != 0:
        return SbomqsResult(available=True, error=clean_error(proc.stderr or proc.stdout), exe=exe)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return SbomqsResult(available=True, error=clean_error(proc.stderr or proc.stdout) or "sbomqs output is not JSON", exe=exe)
    return SbomqsResult(available=True, score=_find_score(data), raw=data, grade=_find_grade(data), exe=exe)
