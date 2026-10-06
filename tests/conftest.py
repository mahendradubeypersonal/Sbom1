from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from sbom_fixer.changes import ChangeLog
from sbom_fixer.descent import DescentResult, descend
from sbom_fixer.oracle import ProfileOracle, SchemaOnlyOracle
from sbom_fixer.profile import Profile, load_profile, parse_profile

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"

LODASH = {"bom-ref": "pkg:npm/lodash@4.17.20", "type": "library", "name": "lodash", "version": "4.17.20",
          "purl": "pkg:npm/lodash@4.17.20"}


def bom(version: str = "1.5", **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX", "specVersion": version,
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "version": 1,
        "metadata": {"timestamp": "2026-10-02T10:00:00Z"},
        "components": [copy.deepcopy(LODASH)],
    }
    doc.update(extra)
    return doc


def profile_with(accepted: list[str], floor: str = "1.3", **kw: Any) -> Profile:
    """Test profile for the descent (hop) machinery, which is opt-in: allow_downgrade defaults to True here."""
    data = {"name": "test", "cyclonedx": {"floor": floor, "accepted_versions": accepted},
            "spdx": {"floor": "2.2", "accepted_versions": ["2.2", "2.3"]}, "provenance": False, "allow_downgrade": True}
    data.update(kw)
    return parse_profile(data)


def run(doc: dict[str, Any], profile: Profile | None = None, version: str | None = None,
        schema_only: bool = False) -> tuple[dict[str, Any], DescentResult, ChangeLog]:
    profile = profile or profile_with(["1.3", "1.4", "1.5"])
    log = ChangeLog()
    d = copy.deepcopy(doc)
    spec = "spdx" if "spdxVersion" in d else "cyclonedx"
    ver = version or (d["spdxVersion"].removeprefix("SPDX-") if spec == "spdx" else str(d["specVersion"]))
    oracle = SchemaOnlyOracle() if schema_only else ProfileOracle(profile)
    res = descend(d, spec, ver, profile, oracle, log, "0" * 64)
    return d, res, log


def ids(log: ChangeLog) -> set[str]:
    return {c.rule_id for c in log.changes}


@pytest.fixture
def checkmarx() -> Profile:
    return load_profile("checkmarx")
