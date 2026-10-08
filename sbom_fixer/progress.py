"""Progress lines on stderr for long runs, so a big SBOM never looks hung.

On by default for inputs of 1 MB or more; SBOM_FIXER_PROGRESS=1 forces it on, SBOM_FIXER_PROGRESS=0 off.
"""

from __future__ import annotations

import os
import sys
import time

AUTO_BYTES = 1_000_000


class Progress:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.start = time.perf_counter()

    def __call__(self, message: str) -> None:
        if self.enabled:
            sys.stderr.write(f"[{time.perf_counter() - self.start:7.1f}s] {message}\n")
            sys.stderr.flush()


def for_input(size_bytes: int) -> Progress:
    forced = os.environ.get("SBOM_FIXER_PROGRESS")
    if forced in ("0", "1"):
        return Progress(forced == "1")
    return Progress(size_bytes >= AUTO_BYTES)


def size_text(size_bytes: int) -> str:
    return f"{size_bytes / 1_000_000:.1f} MB" if size_bytes >= 100_000 else f"{size_bytes / 1000:.0f} KB"


SILENT = Progress(False)
