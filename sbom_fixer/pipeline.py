"""End-to-end run: detect, audit, descend, write outputs, compute the exit code."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit.gate import QualityReport, evaluate
from .audit.ntia import ntia_check
from .audit.sbomqs import sbomqs_score
from .changes import DATA_LOSS, INFO, ChangeLog
from .descent import DescentResult, descend
from .detect import Detected, detect
from .diff import human_diff, machine_diff
from .errors import DetectError, SbomFixerError
from .oracle import AcceptanceClient, oracle_for
from .profile import Profile
from .progress import for_input, size_text
from .purlmap import Coverage, classify, coverage_csv
from .schemas import VERSION_ORDER
from .serialize import dumps, write_json, write_text
from .validate import Issue, validate

EXIT_OK, EXIT_FIXED, EXIT_CANNOT_FIX, EXIT_DATA_LOSS, EXIT_QUALITY, EXIT_VERIFY, EXIT_BISECT = 0, 1, 2, 3, 4, 5, 6
EXIT_NO_SCANNABLE = 7  # CXP-040: the consumer would reject the file, no component has a supported purl


@dataclass
class RunResult:
    input_name: str
    profile: Profile
    acceptance: str
    source_sha256: str
    detected: Detected | None = None
    original_doc: Any = None
    fixed_doc: Any = None
    log: ChangeLog = field(default_factory=ChangeLog)
    descent: DescentResult | None = None
    original_issues: list[Issue] = field(default_factory=list)
    quality: QualityReport | None = None
    exit_code: int = EXIT_CANNOT_FIX
    error: str | None = None
    outputs: dict[str, str] = field(default_factory=dict)
    verification: dict[str, Any] | None = None
    coverage_before: Coverage | None = None
    coverage: Coverage | None = None

    @property
    def spec(self) -> str:
        return self.detected.spec if self.detected else "cyclonedx"

    @property
    def declared(self) -> str:
        return self.detected.version if self.detected else ""

    @property
    def final_version(self) -> str | None:
        return self.descent.final_version if self.descent else None

    @property
    def ok(self) -> bool:
        return self.error is None and self.descent is not None and self.descent.ok


def output_stem(input_path: Path) -> str:
    name = input_path.name
    for suffix in (".json",):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    for suffix in (".cdx", ".bom", ".spdx", ".sbom"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    return name


def run_fix(input_path: Path, profile: Profile, out_dir: Path | None = None, *, acceptance: str | None = None,
            client: AcceptanceClient | None = None, max_uploads: int = 6, audit: bool = True, write: bool = True,
            dry_run: bool = False, progress: Any = None, sbom_name: str | None = None) -> RunResult:
    raw = input_path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    mode = acceptance or profile.acceptance
    result = RunResult(input_name=input_path.name, profile=profile, acceptance=mode, source_sha256=sha)
    stem = output_stem(input_path)
    out_dir = out_dir or input_path.parent

    try:
        progress = progress or for_input(len(raw))
        progress(f"{input_path.name}: reading ({size_text(len(raw))}), profile {profile.name}")
        detected, doc = detect(raw)
    except DetectError as exc:
        result.error = str(exc)
        result.exit_code = EXIT_CANNOT_FIX
        if write:
            _write_failure(result, out_dir, stem)
        return result
    result.detected = detected
    result.original_doc = copy.deepcopy(doc)
    log = result.log
    for issue in detected.encoding_issues:
        log.level = detected.version
        log.add(issue.rule_id, "", "converted", detected.encoding, "utf-8 (no BOM)", INFO, issue.message)

    if detected.version in VERSION_ORDER[detected.spec]:
        progress(f"validating against {detected.spec} {detected.version}")
        result.original_issues = validate(result.original_doc, detected.spec, detected.version)

    try:
        oracle = oracle_for(profile, mode, client, max_uploads)
        profile.rules_for(detected.spec)
    except (ValueError, SbomFixerError) as exc:
        result.error = str(exc)
        if write:
            _write_failure(result, out_dir, stem)
        return result

    before_ntia = ntia_check(result.original_doc, detected.spec) if audit and profile.quality.audit != "off" else None
    before_score = sbomqs_score(str(input_path)) if before_ntia is not None else None

    initial = result.original_issues if detected.version in VERSION_ORDER[detected.spec] else None
    progress("repairing (and stepping down a version only if needed)")
    result.descent = descend(doc, detected.spec, detected.version, profile, oracle, log, sha, initial)
    progress(f"version path {' -> '.join(result.descent.path)}: "
             f"{'accepted ' + str(result.descent.final_version) if result.descent.ok else 'no level accepted'}, "
             f"{len(log.changes):,} change(s)")
    if result.descent.ok:
        result.fixed_doc = doc
    ext = "cdx" if detected.spec == "cyclonedx" else "spdx"
    sbom_path = out_dir / (sbom_name or f"{stem}.{profile.name}.{ext}.json")

    if result.ok:
        size_mb = len(dumps(doc).encode("utf-8")) / 1_000_000
        if size_mb > profile.max_size_mb:
            log.note("SIZE", "", f"Output is {size_mb:.1f} MB, above the profile limit of {profile.max_size_mb} MB", "WARN")
        if write and not dry_run:
            write_json(doc, sbom_path)
            result.outputs["sbom"] = str(sbom_path)
        if before_ntia is not None:
            progress("quality audit (NTIA, sbomqs)")
            after_ntia = ntia_check(doc, detected.spec)
            after_score = sbomqs_score(str(sbom_path)) if (write and not dry_run) else None
            note = None
            if before_score is not None and not before_score.available:
                note = before_score.error
            elif before_score is not None and before_score.error:
                note = f"sbomqs error: {before_score.error}"
            result.quality = evaluate(before_ntia, after_ntia, before_score.score if before_score else None,
                                      after_score.score if after_score else None, profile, detected.spec,
                                      result.final_version or detected.version, doc, note)

    if profile.purl is not None:
        result.coverage_before = classify(result.original_doc, detected.spec, profile.purl)
        if result.ok:
            result.coverage = classify(doc, detected.spec, profile.purl, log)
    result.exit_code = _exit_code(result)
    if write:
        progress("writing reports (diff, change log, notes)")
        _write_reports(result, out_dir, stem, dry_run)
    progress(f"done, exit code {result.exit_code}")
    return result


def _exit_code(result: RunResult) -> int:
    if not result.ok:
        return EXIT_CANNOT_FIX
    policy = result.profile.purl
    if policy is not None and result.coverage is not None and result.coverage.scanned < policy.min_supported:
        return EXIT_NO_SCANNABLE
    if result.profile.require_purl == "fail":
        from .notes import scan_coverage

        total, ok, _ = scan_coverage(result.fixed_doc, result.spec)
        if ok < total:
            result.error = f"require_purl: fail and {total - ok} components have no valid purl"
            return EXIT_CANNOT_FIX
    if not result.log.changes:
        return EXIT_OK
    if not result.profile.allow_data_loss and result.log.count(DATA_LOSS):
        return EXIT_DATA_LOSS
    if result.quality and result.quality.gate_failed:
        return EXIT_QUALITY
    return EXIT_FIXED


def _write_reports(result: RunResult, out_dir: Path, stem: str, dry_run: bool) -> None:
    from .notes import render

    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"{stem}.{result.profile.name}"
    changes: dict[str, Any] = {
        "input": result.input_name,
        "source_sha256": result.source_sha256,
        "spec": result.spec,
        "declared_version": result.declared,
        "final_version": result.final_version,
        "version_path": result.descent.path if result.descent else [],
        "attempts": [{"version": a.version, "schema_errors": a.schema_errors, "accepted": a.accepted, "reason": a.reason}
                     for a in (result.descent.attempts if result.descent else [])],
        "exit_code": result.exit_code,
        "changes": [c.to_dict() for c in result.log.changes],
        "findings": [f.__dict__ for f in result.log.findings],
    }
    if result.coverage_before is not None:
        changes["checkmarx_coverage"] = {"before": result.coverage_before.summary(),
                                         "after": result.coverage.summary() if result.coverage else None}
    write_text(json.dumps(changes, indent=2, ensure_ascii=False, default=str) + "\n", out_dir / f"{base}.changes.json")
    result.outputs["changes"] = str(out_dir / f"{base}.changes.json")
    if result.ok and result.fixed_doc is not None:
        patch = machine_diff(result.original_doc, result.fixed_doc)
        write_text(json.dumps(patch, indent=2, ensure_ascii=False) + "\n", out_dir / f"{base}.diff.patch.json")
        write_text(human_diff(result.original_doc, result.fixed_doc, result.input_name, result.log, patch), out_dir / f"{base}.diff.txt")
        result.outputs["patch"] = str(out_dir / f"{base}.diff.patch.json")
        result.outputs["diff"] = str(out_dir / f"{base}.diff.txt")
    if result.coverage is not None:
        write_text(coverage_csv(result.coverage), out_dir / f"{base}.purl-coverage.csv")
        result.outputs["coverage"] = str(out_dir / f"{base}.purl-coverage.csv")
    if result.quality:
        write_text(json.dumps(result.quality.to_dict(), indent=2, ensure_ascii=False, default=str) + "\n",
                   out_dir / f"{base}.quality.json")
        result.outputs["quality"] = str(out_dir / f"{base}.quality.json")
    write_text(render(result), out_dir / f"{base}.notes.txt")
    result.outputs["notes"] = str(out_dir / f"{base}.notes.txt")


def _write_failure(result: RunResult, out_dir: Path, stem: str) -> None:
    from .notes import render

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{stem}.{result.profile.name}.notes.txt"
    write_text(render(result), path)
    result.outputs["notes"] = str(path)
