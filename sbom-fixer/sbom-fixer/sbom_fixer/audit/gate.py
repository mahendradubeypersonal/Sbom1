"""Compare quality before and after the fix (Guide Step 17.4) and evaluate framework gates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..profile import Profile
from .ntia import NtiaReport

_BSI_MIN = (1, 5)


@dataclass
class QualityReport:
    before_ntia: NtiaReport
    after_ntia: NtiaReport
    before_score: float | None
    after_score: float | None
    sbomqs_note: str | None
    regressions: list[str] = field(default_factory=list)
    framework_results: list[dict[str, Any]] = field(default_factory=list)
    gate_failed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": {"ntia": self.before_ntia.to_dict(), "sbomqs_score": self.before_score},
            "after": {"ntia": self.after_ntia.to_dict(), "sbomqs_score": self.after_score},
            "sbomqs_note": self.sbomqs_note,
            "regressions": self.regressions,
            "frameworks": self.framework_results,
            "gate_failed": self.gate_failed,
        }


def _framework(fid: str, spec: str, version: str, ntia: NtiaReport, doc: dict[str, Any]) -> tuple[bool | None, str]:
    if fid == "ntia-2021":
        return ntia.passed, "all NTIA minimum elements present" if ntia.passed else "NTIA minimum elements missing (see table)"
    if fid == "bsi-tr-03183-2-v2":
        if spec == "cyclonedx" and tuple(map(int, version.split("."))) < _BSI_MIN:
            return False, f"BSI TR-03183-2 v2 needs CycloneDX 1.5+, file is {version}"
        if spec == "cyclonedx":
            comps = doc.get("components") or []
            no512 = sum(1 for c in comps if isinstance(c, dict) and not any(
                isinstance(h, dict) and h.get("alg") == "SHA-512" for h in c.get("hashes") or []))
            if no512:
                return False, f"no SHA-512 hash on {no512} of {len(comps)} components"
        return True, "spec version and SHA-512 hashes present (other BSI fields not checked by the built-in audit)"
    if fid == "cisa-fsct-2024":
        if spec != "cyclonedx":
            return None, "not evaluated for SPDX by the built-in audit"
        comps = doc.get("components") or []
        nohash = sum(1 for c in comps if isinstance(c, dict) and not c.get("hashes"))
        nolic = sum(1 for c in comps if isinstance(c, dict) and not c.get("licenses"))
        ok = ntia.passed and nohash == 0 and nolic == 0
        return ok, f"minimum level: NTIA {'ok' if ntia.passed else 'missing'}, {nohash} components without hash, {nolic} without license"
    return None, "framework not evaluated by the built-in audit; use sbomqs compliance"


def evaluate(before: NtiaReport, after: NtiaReport, before_score: float | None, after_score: float | None,
             profile: Profile, spec: str, final_version: str, doc_after: dict[str, Any], sbomqs_note: str | None) -> QualityReport:
    rep = QualityReport(before, after, before_score, after_score, sbomqs_note)
    if profile.quality.fail_on_regression:
        for name, b in before.components.items():
            a = after.components[name]
            if a.missing > b.missing:
                rep.regressions.append(f"NTIA '{name}' missing on more components: {b.missing} -> {a.missing}")
        for name, bv in before.document.items():
            if bv and not after.document[name]:
                rep.regressions.append(f"NTIA '{name}' was present and is now missing")
    if before_score is not None and after_score is not None and after_score < before_score - profile.quality.score_tolerance:
        rep.regressions.append(f"sbomqs score dropped {before_score} -> {after_score}")
    if after_score is not None and after_score < profile.quality.min_score:
        rep.regressions.append(f"sbomqs score {after_score} is below the minimum {profile.quality.min_score}")
    required_failed = False
    for fw in profile.frameworks:
        ok, detail = _framework(fw.id, spec, final_version, after, doc_after)
        rep.framework_results.append({"id": fw.id, "gate": fw.gate, "passed": ok, "detail": detail, "version_note": fw.version_note})
        if fw.gate == "required" and ok is False:
            required_failed = True
    rep.gate_failed = profile.quality.audit == "gate" and (bool(rep.regressions) or required_failed)
    return rep
