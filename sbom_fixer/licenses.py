"""SPDX license helpers shared by REP-010, SAN-030 and SAN-031."""

from __future__ import annotations

import json
import re
from functools import cache
from typing import Any

from .schemas import SCHEMA_ROOT

ALIASES = {
    "apache 2.0": "Apache-2.0", "apache2": "Apache-2.0", "apache-2": "Apache-2.0", "apache 2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0", "asl 2.0": "Apache-2.0",
    "the apache software license, version 2.0": "Apache-2.0", "the apache license, version 2.0": "Apache-2.0",
    "mit license": "MIT", "the mit license": "MIT", "mit/x11": "MIT",
    "bsd": None, "bsd license": None,  # ambiguous: 2-clause or 3-clause; never guessed
    "bsd 2-clause": "BSD-2-Clause", "bsd-2": "BSD-2-Clause", "simplified bsd": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause", "bsd-3": "BSD-3-Clause", "new bsd license": "BSD-3-Clause",
    "revised bsd": "BSD-3-Clause",
    "gpl-2.0+": "GPL-2.0-or-later", "gpl-3.0+": "GPL-3.0-or-later", "lgpl-2.1+": "LGPL-2.1-or-later",
    "gplv2": "GPL-2.0-only", "gplv3": "GPL-3.0-only", "lgplv3": "LGPL-3.0-only",
    "eclipse public license 1.0": "EPL-1.0", "eclipse public license - v 1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0", "eclipse public license - v 2.0": "EPL-2.0",
    "mozilla public license 2.0": "MPL-2.0", "mpl 2.0": "MPL-2.0",
    "isc license": "ISC", "unlicense": "Unlicense", "the unlicense": "Unlicense",
    "cddl 1.0": "CDDL-1.0", "cddl 1.1": "CDDL-1.1", "public domain": None,
}


@cache
def spdx_ids() -> frozenset[str]:
    data = json.loads((SCHEMA_ROOT / "cyclonedx" / "spdx.schema.json").read_text(encoding="utf-8"))
    return frozenset(data.get("enum", []))


@cache
def _ids_lower() -> dict[str, str]:
    return {i.lower(): i for i in spdx_ids()}


def canonical_id(text: str) -> str | None:
    """Exact SPDX ID (case-insensitive) or a known unambiguous alias; None when unknown or ambiguous."""
    t = text.strip()
    if t in spdx_ids():
        return t
    low = t.lower()
    if low in _ids_lower():
        return _ids_lower()[low]
    if low in ALIASES:
        return ALIASES[low]
    return None


@cache
def _licensing() -> Any:
    from license_expression import get_spdx_licensing

    return get_spdx_licensing()


_EXPR_HINT = re.compile(r"\b(AND|OR|WITH)\b|[()]")


def looks_like_expression(text: str) -> bool:
    return bool(_EXPR_HINT.search(text))


def normalize_expression(text: str) -> str | None:
    """Return a normalized SPDX expression when every symbol is known, else None."""
    try:
        lic = _licensing()
        parsed = lic.parse(text, validate=True, strict=True)
        if parsed is None:
            return None
        if lic.unknown_license_keys(parsed):
            return None
        return str(parsed)
    except Exception:  # license-expression raises several exception types for bad input
        return None
