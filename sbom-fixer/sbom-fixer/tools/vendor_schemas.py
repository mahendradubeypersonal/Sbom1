"""Download the official CycloneDX and SPDX schemas into sbom_fixer/data/schemas (SBOMFIX-202).

Run only when upgrading schemas; the tool itself never touches the network. Commit the result
together with the updated schemas/SOURCES.md.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

DEST = Path(__file__).resolve().parent.parent / "sbom_fixer" / "data" / "schemas"
CDX_REPO, CDX_REF = "CycloneDX/specification", "master"
CDX_FILES = ["bom-1.2.schema.json", "bom-1.3.schema.json", "bom-1.4.schema.json", "bom-1.5.schema.json",
             "bom-1.6.schema.json", "bom-1.7.schema.json", "spdx.schema.json", "jsf-0.82.schema.json",
             "cryptography-defs.schema.json"]
# SPDX 2.2: the original v2.2 schema nests everything under "Document"; the 2.2.2 patch schema fixes that.
SPDX = {"2.2": "development/v2.2.2", "2.3": "v2.3"}


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - fixed https URLs
        return r.read()


def _sha(repo: str, ref: str) -> str:
    return json.loads(_get(f"https://api.github.com/repos/{repo}/commits/{ref}"))["sha"]


def main() -> int:
    cdx_sha = _sha(CDX_REPO, CDX_REF)
    (DEST / "cyclonedx").mkdir(parents=True, exist_ok=True)
    for f in CDX_FILES:
        (DEST / "cyclonedx" / f).write_bytes(_get(f"https://raw.githubusercontent.com/{CDX_REPO}/{cdx_sha}/schema/{f}"))
    lines = ["# Schema sources", "", f"Downloaded {datetime.now(UTC):%Y-%m-%d} by tools/vendor_schemas.py.", "",
             "| File | Source | Commit |", "|---|---|---|"]
    lines += [f"| cyclonedx/{f} | github.com/{CDX_REPO} schema/{f} | `{cdx_sha}` |" for f in CDX_FILES]
    (DEST / "spdx").mkdir(parents=True, exist_ok=True)
    for ver, ref in SPDX.items():
        sha = _sha("spdx/spdx-spec", ref)
        (DEST / "spdx" / f"spdx-{ver}.schema.json").write_bytes(
            _get(f"https://raw.githubusercontent.com/spdx/spdx-spec/{sha}/schemas/spdx-schema.json"))
        lines.append(f"| spdx/spdx-{ver}.schema.json | github.com/spdx/spdx-spec ({ref}) schemas/spdx-schema.json | `{sha}` |")
    (DEST / "SOURCES.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Schemas written to {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
