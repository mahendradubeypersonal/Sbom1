"""Wrapper around the sbomqs CLI (Interlynk). Optional: the audit still runs without it.

JSON field names differ between sbomqs releases; confirm with `sbomqs score --help` for the pinned
version (Docker image pins it) and keep the parsing below defensive.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class SbomqsResult:
    available: bool
    score: float | None = None
    error: str | None = None
    raw: Any = None


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


def sbomqs_score(path: str, timeout: int = 300) -> SbomqsResult:
    exe = os.environ.get("SBOMQS_BIN") or shutil.which("sbomqs")
    if not exe:
        return SbomqsResult(available=False, error="sbomqs not found on PATH (set SBOMQS_BIN to use it)")
    try:
        proc = subprocess.run([exe, "score", path, "--json"], capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return SbomqsResult(available=True, error=str(exc)[:300])
    if proc.returncode != 0:
        return SbomqsResult(available=True, error=(proc.stderr or proc.stdout).strip()[:500])
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return SbomqsResult(available=True, error="sbomqs output is not JSON")
    return SbomqsResult(available=True, score=_find_score(data), raw=data)
