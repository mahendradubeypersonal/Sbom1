"""Write JSON as UTF-8 without BOM and with LF line endings (Guide Step 14)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def dumps(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def write_json(doc: Any, path: Path) -> int:
    data = dumps(doc).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return len(data)


def write_text(text: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))
