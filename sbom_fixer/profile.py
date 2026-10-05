"""Profiles describe what a consumer accepts. Loaded from YAML with strict key checking."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import ProfileError
from .schemas import VERSION_ORDER

BUILTIN_DIR = Path(__file__).parent / "data" / "profiles"

_REMOVED_KEYS = {
    "target": "use per-spec 'floor' and 'accepted_versions' instead",
    "supported": "use 'accepted_versions'",
    "convert": "the version is now chosen by descent from the declared version",
}
_TOP_KEYS = {
    "name", "description", "cyclonedx", "spdx", "acceptance", "tools_form", "flatten_nested_components",
    "require_purl", "allow_data_loss", "max_size_mb", "quality", "frameworks", "provenance",
}
_SPEC_KEYS = {"floor", "accepted_versions"}
_QUALITY_KEYS = {"audit", "fail_on_regression", "min_score", "score_tolerance"}
_FRAMEWORK_KEYS = {"id", "gate", "min_spec_version", "version_note"}
ACCEPTANCE_MODES = ("profile", "checkmarx", "schema-only")


@dataclass
class SpecRules:
    floor: str  # a version, or "declared"
    accepted_versions: list[str]

    def floor_for(self, declared: str) -> str:
        return declared if self.floor == "declared" else self.floor


@dataclass
class Framework:
    id: str
    gate: str = "advisory"  # required | advisory
    min_spec_version: str | None = None
    version_note: str | None = None


@dataclass
class Quality:
    audit: str = "report"  # report | gate | off
    fail_on_regression: bool = True
    min_score: float = 0.0
    score_tolerance: float = 0.2


@dataclass
class Profile:
    name: str
    description: str = ""
    specs: dict[str, SpecRules] = field(default_factory=dict)
    acceptance: str = "profile"
    tools_form: str = "as-is"  # as-is | legacy-array
    flatten_nested_components: bool = False
    require_purl: str = "warn"  # warn | fail
    allow_data_loss: bool = True
    max_size_mb: float = 50.0
    quality: Quality = field(default_factory=Quality)
    frameworks: list[Framework] = field(default_factory=list)
    provenance: bool = True

    def rules_for(self, spec: str) -> SpecRules:
        if spec not in self.specs:
            raise ProfileError(f"Profile '{self.name}' has no section for {spec}.")
        return self.specs[spec]


def _check_keys(section: str, data: dict[str, Any], allowed: set[str]) -> None:
    for k in data:
        if k in _REMOVED_KEYS and section == "profile":
            raise ProfileError(f"Profile key '{k}' was removed: {_REMOVED_KEYS[k]}.")
        if k not in allowed:
            raise ProfileError(f"Unknown key '{k}' in {section}. Allowed: {', '.join(sorted(allowed))}.")


def parse_profile(data: dict[str, Any], source: str = "<dict>") -> Profile:
    if not isinstance(data, dict):
        raise ProfileError(f"Profile {source} must be a mapping.")
    _check_keys("profile", data, _TOP_KEYS)
    if "name" not in data:
        raise ProfileError(f"Profile {source} has no 'name'.")
    specs: dict[str, SpecRules] = {}
    for spec in ("cyclonedx", "spdx"):
        if spec not in data:
            continue
        sec = data[spec] or {}
        _check_keys(spec, sec, _SPEC_KEYS)
        order = VERSION_ORDER[spec]
        floor = str(sec.get("floor", order[0]))
        accepted = [str(v) for v in sec.get("accepted_versions", [])]
        for v in accepted + ([] if floor == "declared" else [floor]):
            if v not in order:
                raise ProfileError(f"{spec}: version '{v}' is not one of {', '.join(order)}.")
        specs[spec] = SpecRules(floor=floor, accepted_versions=accepted)
    acceptance = data.get("acceptance", "profile")
    if acceptance not in ACCEPTANCE_MODES:
        raise ProfileError(f"acceptance must be one of {', '.join(ACCEPTANCE_MODES)}, got '{acceptance}'.")
    tools_form = data.get("tools_form", "as-is")
    if tools_form not in ("as-is", "legacy-array"):
        raise ProfileError("tools_form must be 'as-is' or 'legacy-array'.")
    q = data.get("quality") or {}
    _check_keys("quality", q, _QUALITY_KEYS)
    quality = Quality(
        audit=str(q.get("audit", "report")),
        fail_on_regression=bool(q.get("fail_on_regression", True)),
        min_score=float(q.get("min_score", 0.0)),
        score_tolerance=float(q.get("score_tolerance", 0.2)),
    )
    if quality.audit not in ("report", "gate", "off"):
        raise ProfileError("quality.audit must be report, gate or off.")
    frameworks = []
    for f in data.get("frameworks") or []:
        _check_keys("frameworks[]", f, _FRAMEWORK_KEYS)
        if f.get("gate", "advisory") not in ("required", "advisory"):
            raise ProfileError("frameworks[].gate must be required or advisory.")
        frameworks.append(Framework(id=f["id"], gate=f.get("gate", "advisory"),
                                    min_spec_version=f.get("min_spec_version"), version_note=f.get("version_note")))
    return Profile(
        name=str(data["name"]),
        description=str(data.get("description", "")),
        specs=specs,
        acceptance=acceptance,
        tools_form=tools_form,
        flatten_nested_components=bool(data.get("flatten_nested_components", False)),
        require_purl=str(data.get("require_purl", "warn")),
        allow_data_loss=bool(data.get("allow_data_loss", True)),
        max_size_mb=float(data.get("max_size_mb", 50)),
        quality=quality,
        frameworks=frameworks,
        provenance=bool(data.get("provenance", True)),
    )


def load_profile(name_or_path: str) -> Profile:
    p = Path(name_or_path)
    if not p.suffix:
        p = BUILTIN_DIR / f"{name_or_path}.yaml"
    if not p.exists():
        builtins = ", ".join(sorted(x.stem for x in BUILTIN_DIR.glob("*.yaml")))
        raise ProfileError(f"Profile '{name_or_path}' not found. Built-in profiles: {builtins}.")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProfileError(f"Profile {p} is not valid YAML: {exc}") from exc
    return parse_profile(data, str(p))
