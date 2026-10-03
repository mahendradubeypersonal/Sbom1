"""notes.txt: why the original failed, what changed, what was lost, coverage, source fixes, quality."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from packageurl import PackageURL

from .changes import DATA_LOSS, WARN
from .jsonutil import iter_components
from .rules import describe, rule_by_id
from .validate import group

if TYPE_CHECKING:
    from .pipeline import RunResult


def _fix_types(result: RunResult) -> str:
    cases = []
    ids = {c.rule_id for c in result.log.changes}
    if any(i.startswith("REP-") for i in ids) or result.original_issues:
        n = len(result.original_issues)
        cases.append(f"A (same-version repair, {n} errors in own {result.declared} schema)")
    elif any(i.startswith("ENC-") for i in ids):
        cases.append("A (encoding only)")
    path = result.descent.path if result.descent else []
    if len(path) > 1:
        cases.append(f"B (downgrade {path[0]} -> {path[-1]})")
    if any(i.startswith("SAN-") and i != "SAN-090" for i in ids):
        cases.append("C (importer-specific fixes)")
    return " + ".join(cases) if cases else "none (already compatible)"


def scan_coverage(doc: dict[str, Any], spec: str) -> tuple[int, int, list[str]]:
    if spec != "cyclonedx":
        pkgs = [p for p in doc.get("packages") or [] if isinstance(p, dict)]
        with_purl = [p for p in pkgs if any(isinstance(r, dict) and r.get("referenceType") == "purl" for r in p.get("externalRefs") or [])]
        missing = [f"{p.get('SPDXID')} name=\"{p.get('name')}\" version=\"{p.get('versionInfo', '')}\"" for p in pkgs if p not in with_purl]
        return len(pkgs), len(with_purl), missing
    total, ok, missing = 0, 0, []
    for path, c in iter_components(doc):
        total += 1
        p = c.get("purl")
        valid = False
        if isinstance(p, str):
            try:
                PackageURL.from_string(p)
                valid = True
            except ValueError:
                valid = False
        if valid:
            ok += 1
        else:
            missing.append(f"{path}   name=\"{c.get('name')}\"  version=\"{c.get('version', '')}\"")
    return total, ok, missing


_GENERATOR_HINTS = [
    ("trivy", "Trivy writes CycloneDX 1.6 by default and has no version flag in many releases; keep sbom-fixer in the pipeline."),
    ("syft", "Syft can write an older version directly: -o cyclonedx-json@1.5 (check your Syft version)."),
    ("cdxgen", "cdxgen can write an older version directly: --spec-version 1.5."),
    ("cyclonedx-maven", "CycloneDX Maven plugin: set -DschemaVersion=1.5 (or <schemaVersion> in the POM)."),
    ("cyclonedx-npm", "CycloneDX npm: use --spec-version 1.5."),
    ("cyclonedx-gradle", "CycloneDX Gradle plugin: set schemaVersion = \"1.5\"."),
]


def source_fixes(result: RunResult) -> list[str]:
    out: list[str] = []
    gen = (result.detected.generator or "").lower() if result.detected else ""
    path = result.descent.path if result.descent else []
    if len(path) > 1:
        for key, hint in _GENERATOR_HINTS:
            if key in gen:
                out.append(hint)
                break
        else:
            out.append(f"The generator wrote {path[0]}; if it has a spec-version option, set it to {path[-1]}.")
    if any(c.rule_id.startswith("ENC-") for c in result.log.changes):
        out.append("Write the SBOM with the tool's own --output option, not with shell redirection (PowerShell 5.1 '>' writes UTF-16).")
    seen: set[str] = set()
    for c in result.log.changes:
        r = rule_by_id(c.rule_id)
        if r is not None and r.source_fix and r.id not in seen:
            seen.add(r.id)
            out.append(f"[{r.id}] {r.source_fix}")
    for f in result.log.findings:
        r = rule_by_id(f.rule_id)
        if r is not None and r.source_fix and r.id not in seen:
            seen.add(r.id)
            out.append(f"[{r.id}] {r.source_fix}")
    if result.quality and not result.quality.after_ntia.document.get("Author of SBOM data"):
        out.append("Set metadata.authors (the team or organisation that produced the SBOM) in the pipeline; NTIA requires an author.")
    return out


def render(result: RunResult) -> str:
    L: list[str] = []
    w = L.append
    w("SBOM FIXER NOTES")
    w("================")
    w(f"Input file      : {result.input_name}")
    w(f"SHA-256         : {result.source_sha256}")
    if result.detected:
        d = result.detected
        enc = {"utf-8": "UTF-8", "utf-8-sig": "UTF-8 with BOM", "utf-16": "UTF-16", "cp1252": "Windows-1252"}.get(d.encoding, d.encoding)
        w(f"Detected        : {'CycloneDX' if d.spec == 'cyclonedx' else 'SPDX'} {d.version} JSON, {enc}")
        w(f"Generator       : {d.generator or 'unknown'}")
    w(f"Profile         : {result.profile.name}  (acceptance: {result.acceptance})")
    if result.error:
        w("Result          : CANNOT FIX")
        w(f"Reason          : {result.error}")
        return "\n".join(L) + "\n"
    w(f"Fix type        : {_fix_types(result)}")
    if result.descent:
        first = True
        for a in result.descent.attempts:
            label = "Version path    : " if first else "                  "
            status = "ACCEPTED" if a.accepted else "NOT accepted"
            errs = f"{a.schema_errors} schema errors" if a.schema_errors >= 0 else "not tried"
            w(f"{label}{a.version:4} {errs}, {status} ({a.reason})")
            first = False
    if result.ok:
        w(f"Result          : {'UNCHANGED - already compatible' if result.exit_code == 0 else 'FIXED'} - output validates against "
          f"{'CycloneDX' if result.spec == 'cyclonedx' else 'SPDX'} {result.final_version}")
        if result.outputs.get("sbom"):
            w(f"Output          : {result.outputs['sbom']}")
    else:
        w("Result          : CANNOT FIX - no version down to the floor was OK")
    w(f"Exit code       : {result.exit_code}")
    w("")

    w("1. WHY THE ORIGINAL FAILED")
    if not result.original_issues and not any(c.rule_id.startswith("ENC-") for c in result.log.changes) and len(result.descent.path if result.descent else []) <= 1:
        w("   The original was valid against its declared version and accepted.")
    for c in result.log.changes:
        if c.rule_id.startswith("ENC-"):
            w(f"   [{c.rule_id}]   {c.reason}")
    if result.descent and len(result.descent.path) > 1:
        w(f"   [version]   {result.descent.attempts[0].reason}")
    if result.original_issues:
        grouped = group(result.original_issues)
        w(f"   [schema]    Original has {len(result.original_issues)} errors against its own {result.declared} schema, from {len(grouped)} causes:")
        for kw, p, n, msg in grouped[:15]:
            w(f"               - {kw:20} {p:45} {n:>6}   e.g. {msg[:70]}")
    w("")

    w("2. CHANGES MADE (by rule)")
    for rule_id, changes in result.log.by_rule().items():
        sev = max((c.severity for c in changes), key=lambda s: {"INFO": 0, "WARN": 1, "DATA_LOSS": 2}[s])
        w(f"   {rule_id:11} {sev:9} {len(changes):>5}  {describe(rule_id)}")
        for c in changes[:3]:
            w(f"   {'':27}e.g. {c.path or '(whole file)'}  ({c.level})")
    if not result.log.changes:
        w("   No changes.")
    w("")

    w("3. DATA LOSS")
    lost = [c for c in result.log.changes if c.severity == DATA_LOSS]
    if lost:
        for rule_id in dict.fromkeys(c.rule_id for c in lost):
            items = [c for c in lost if c.rule_id == rule_id]
            w(f"   {rule_id}: {len(items)} item(s) removed, e.g. {', '.join(c.path for c in items[:3])}")
    else:
        w("   None. No fields with information were removed.")
    warns = [c for c in result.log.changes if c.severity == WARN]
    if warns:
        w(f"   {len(warns)} change(s) need review (WARN), see section 2.")
    w("")

    doc = result.fixed_doc if result.fixed_doc is not None else result.original_doc
    total, ok, missing = scan_coverage(doc or {}, result.spec)
    w("4. SCAN COVERAGE")
    w(f"   Components in output        : {total:,}")
    w(f"   With valid purl (scannable) : {ok:,}")
    w(f"   Without purl (not scanned)  : {len(missing):,}" + ("  -> see section 6" if missing else ""))
    unscanned = [f for f in result.log.findings if f.rule_id == "SAN-012"]
    if unscanned:
        w(f"   purl types scanners usually ignore: {len(unscanned)}")
    w("")

    w("5. RECOMMENDED SOURCE FIX")
    fixes = source_fixes(result)
    for f in fixes or ["None needed."]:
        w(f"   - {f}")
    w("")

    w("6. COMPONENTS WITHOUT PURL")
    for m in missing[:200] or ["None."]:
        w(f"   {m}")
    if len(missing) > 200:
        w(f"   ... {len(missing) - 200} more")
    w("")

    if result.quality:
        q = result.quality
        w("7. QUALITY AND COMPLIANCE")
        w(f"   {'':32}{'original':>12}{'fixed':>12}")
        bs = f"{q.before_score:.1f}" if q.before_score is not None else "n/a"
        as_ = f"{q.after_score:.1f}" if q.after_score is not None else "n/a"
        w(f"   {'sbomqs score (0-10)':32}{bs:>12}{as_:>12}")
        if q.sbomqs_note:
            w(f"   ({q.sbomqs_note})")
        w(f"   {'NTIA minimum elements':32}{'PASS' if q.before_ntia.passed else 'FAIL':>12}{'PASS' if q.after_ntia.passed else 'FAIL':>12}")
        for name, cov_b in q.before_ntia.components.items():
            cov_a = q.after_ntia.components[name]
            delta = "same" if cov_a.covered == cov_b.covered else f"{cov_a.covered - cov_b.covered:+d}"
            w(f"     {name:30}{f'{cov_b.covered}/{cov_b.total}':>12}{f'{cov_a.covered}/{cov_a.total}':>12}   {delta}")
        for name, bv in q.before_ntia.document.items():
            av = q.after_ntia.document[name]
            w(f"     {name:30}{'yes' if bv else 'no':>12}{'yes' if av else 'no':>12}")
        if q.after_ntia.author_from_tools_only:
            w("     (only a tool is recorded as author; NTIA expects the person or organisation)")
        w(f"   Quality regression: {'; '.join(q.regressions) if q.regressions else 'none'}")
        for fr in q.framework_results:
            status = {True: "PASS", False: "FAIL", None: "n/a"}[fr["passed"]]
            w(f"   {fr['id']} ({fr['gate']}): {status} - {fr['detail']}")
        w("")

    if result.log.findings:
        w("8. FINDINGS NOT CHANGED (review)")
        for finding in result.log.findings[:100]:
            w(f"   [{finding.rule_id}] {finding.path or '/'}: {finding.message}")
        if len(result.log.findings) > 100:
            w(f"   ... {len(result.log.findings) - 100} more")
        w("")

    if result.verification:
        v = result.verification
        w("9. CHECKMARX VERIFICATION")
        for k in ("state", "scan_id", "package_count", "expected_packages", "detail"):
            if v.get(k) is not None:
                w(f"   {k:18}: {v[k]}")
        w("")
    return "\n".join(L) + "\n"
