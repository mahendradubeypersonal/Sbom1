"""Command line interface: check | fix | audit | schema-diff | verify | bisect | rules."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .audit.ntia import ntia_check
from .audit.sbomqs import sbomqs_score
from .errors import SbomFixerError
from .pipeline import (
    EXIT_BISECT,
    EXIT_CANNOT_FIX,
    EXIT_NO_SCANNABLE,
    EXIT_OK,
    EXIT_VERIFY,
    RunResult,
    run_fix,
)
from .profile import Profile, load_profile, parse_profile
from .validate import group

ALLOW_DOWNGRADE_HELP = ("Allow stepping down one version at a time (e.g. 1.7 -> 1.6) when the file is not valid or not "
                        "accepted at its own version. Off by default: fix repairs on the file's own schema.")

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Repair SBOMs on their own schema version (never a downgrade unless asked) and explain every change.")


def _profile(name: str, accepted: str | None = None, floor: str | None = None,
             allow_downgrade: bool = False) -> Profile:
    prof = load_profile(name)
    if allow_downgrade:
        import dataclasses

        prof = dataclasses.replace(prof, allow_downgrade=True)
    if accepted or floor:
        import dataclasses

        specs = dict(prof.specs)
        for spec, rules in specs.items():
            new_acc = [v.strip() for v in accepted.split(",")] if accepted and spec == "cyclonedx" else rules.accepted_versions
            specs[spec] = dataclasses.replace(rules, accepted_versions=new_acc,
                                              floor=floor if floor and spec == "cyclonedx" else rules.floor)
        prof = dataclasses.replace(prof, specs=specs)
        parse_profile({"name": prof.name, "cyclonedx": {"floor": specs["cyclonedx"].floor,
                                                        "accepted_versions": specs["cyclonedx"].accepted_versions}})
    return prof


def _echo_summary(r: RunResult) -> None:
    det = r.detected
    typer.echo(f"{r.input_name}: profile={r.profile.name}")
    if det:
        typer.echo(f"  detected   : {det.spec} {det.version} ({det.encoding}), generator: {det.generator or 'unknown'}")
    if r.error:
        typer.echo(f"  result     : CANNOT FIX - {r.error}")
    if r.descent:
        for a in r.descent.attempts:
            typer.echo(f"  level {a.version:4} : {'ACCEPTED' if a.accepted else 'not accepted'} - {a.reason}")
    typer.echo(f"  changes    : {len(r.log.changes)} ({r.log.count('WARN')} WARN, {r.log.count('DATA_LOSS')} DATA_LOSS), findings: {len(r.log.findings)}")
    for k, v in r.outputs.items():
        typer.echo(f"  {k:10} : {v}")
    typer.echo(f"  exit code  : {r.exit_code}")


@app.command()
def check(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="SBOM file")],
    profile: Annotated[str, typer.Option("--profile", "-p", help="Profile name or YAML path")] = "checkmarx",
    accepted: Annotated[str | None, typer.Option(help="Override cyclonedx accepted_versions, e.g. 1.3,1.4,1.5,1.6,1.7")] = None,
    allow_downgrade: Annotated[bool, typer.Option("--allow-downgrade", help=ALLOW_DOWNGRADE_HELP)] = False,
) -> None:
    """Read-only diagnosis: own-version errors grouped by cause and what a fix would do."""
    try:
        prof = _profile(profile, accepted, allow_downgrade=allow_downgrade)
        r = run_fix(file, prof, write=False, audit=False)
    except SbomFixerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX) from None
    _echo_summary(r)
    if r.original_issues:
        typer.echo(f"  own-version schema errors ({len(r.original_issues)}), grouped:")
        for kw, p, n, msg in group(r.original_issues)[:20]:
            typer.echo(f"    {n:>6}  {kw:20} {p}  e.g. {msg[:80]}")
    raise typer.Exit(r.exit_code)


@app.command()
def fix(
    files: Annotated[list[Path], typer.Argument(exists=True, dir_okay=False, help="One or more SBOM files")],
    profile: Annotated[list[str], typer.Option("--profile", "-p", help="Profile name or path; repeat for several outputs")] = ["checkmarx"],  # noqa: B006
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output folder (default: next to the input)")] = None,
    acceptance: Annotated[str | None, typer.Option(help="Override acceptance: profile | checkmarx | schema-only")] = None,
    verify_each_step: Annotated[bool, typer.Option("--verify-each-step", help="Same as --acceptance checkmarx")] = False,
    verify_output: Annotated[bool, typer.Option("--verify", help="Upload the fixed file to the Checkmarx verification project")] = False,
    expected_packages: Annotated[int | None, typer.Option(help="Expected Checkmarx package count for --verify (5% tolerance; default: components with a supported purl)")] = None,
    max_uploads: Annotated[int, typer.Option(help="Upload budget for --verify-each-step")] = 6,
    no_audit: Annotated[bool, typer.Option("--no-audit", help="Skip the NTIA / sbomqs quality audit")] = False,
    accepted: Annotated[str | None, typer.Option(help="Override cyclonedx accepted_versions, e.g. 1.3,1.4,1.5,1.6,1.7")] = None,
    allow_downgrade: Annotated[bool, typer.Option("--allow-downgrade", help=ALLOW_DOWNGRADE_HELP)] = False,
) -> None:
    """Fix SBOMs on their own schema version (never a downgrade unless --allow-downgrade); write SBOM, diff, notes, quality."""
    worst = EXIT_OK
    client = None
    if verify_each_step or acceptance == "checkmarx" or verify_output:
        from .checkmarx import CheckmarxAcceptanceClient, CxCliClient

        cx = CxCliClient()
        client = CheckmarxAcceptanceClient(cx)
    mode = "checkmarx" if verify_each_step else acceptance
    for f in files:
        for pname in profile:
            try:
                prof = _profile(pname, accepted, allow_downgrade=allow_downgrade)
                r = run_fix(f, prof, out, acceptance=mode, client=client, max_uploads=max_uploads, audit=not no_audit)
            except SbomFixerError as exc:
                typer.echo(f"error: {exc}", err=True)
                worst = max(worst, EXIT_CANNOT_FIX)
                continue
            if verify_output and r.ok and r.outputs.get("sbom") and r.exit_code != EXIT_NO_SCANNABLE:
                from .checkmarx import verify as cx_verify
                from .notes import render
                from .serialize import write_text

                # default: the number of components Checkmarx is expected to scan (notes section 4)
                expected = expected_packages if expected_packages is not None else (r.coverage.scanned if r.coverage else None)
                ok, res = cx_verify(cx, Path(r.outputs["sbom"]), expected)
                r.verification = dict(res.to_dict(), expected_packages=expected)
                write_text(render(r), Path(r.outputs["notes"]))
                if not ok:
                    r.exit_code = EXIT_VERIFY
            _echo_summary(r)
            worst = max(worst, r.exit_code)
    raise typer.Exit(worst)


@app.command()
def audit(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON")] = False,
) -> None:
    """Quality and compliance report only (built-in NTIA check + sbomqs). Never writes an SBOM."""
    from .detect import detect

    try:
        det, doc = detect(file.read_bytes())
    except SbomFixerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX) from None
    rep = ntia_check(doc, det.spec)
    qs = sbomqs_score(str(file))
    if as_json:
        typer.echo(json.dumps({"ntia": rep.to_dict(), "sbomqs": {"available": qs.available, "score": qs.score, "grade": qs.grade,
                                                                 "error": qs.error, "exe": qs.exe}}, indent=2))
        raise typer.Exit(EXIT_OK)
    typer.echo(f"{file.name}: {det.spec} {det.version}")
    typer.echo(f"  NTIA minimum elements: {'PASS' if rep.passed else 'FAIL'}")
    for name, cov in rep.components.items():
        typer.echo(f"    {name:28} {cov.covered}/{cov.total}" + (f"   missing e.g. {', '.join(cov.missing_examples[:3])}" if cov.missing_examples else ""))
    for name, ok in rep.document.items():
        typer.echo(f"    {name:28} {'yes' if ok else 'no'}")
    score = f"{qs.score:.2f}" + (f" (grade {qs.grade})" if qs.grade else "") if qs.score is not None else "n/a"
    typer.echo(f"  sbomqs score: {score}" + (f" ({qs.error})" if qs.error else ""))
    if qs.exe:
        typer.echo(f"  sbomqs binary: {qs.exe}")
    raise typer.Exit(EXIT_OK)


def _fill(file: Path, out: Path | None, mode: str, include_sensitive: bool, spec: str | None,
          version: str | None) -> None:
    import hashlib

    from .complete import fill, prepare_input, render_summary
    from .pipeline import output_stem
    from .progress import for_input, size_text
    from .serialize import write_json, write_text

    if spec is not None and spec not in ("cyclonedx", "spdx"):
        typer.echo("error: --spec must be cyclonedx or spdx", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX)
    raw = file.read_bytes()
    progress = for_input(len(raw))
    progress(f"{file.name}: reading ({size_text(len(raw))})")
    try:
        doc, use_spec, use_version, notes = prepare_input(raw, spec, version)
    except SbomFixerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX) from None
    stem = output_stem(file)
    res = fill(doc, use_spec, use_version, mode, file_stem=stem, source_sha256=hashlib.sha256(raw).hexdigest(),
               include_sensitive=include_sensitive, prepared=notes, progress=progress)
    out_dir = out or file.parent
    ext = "cdx" if use_spec == "cyclonedx" else "spdx"
    sbom_path = out_dir / f"{stem}.fill-{mode}.{ext}.json"
    report_path = out_dir / f"{stem}.fill-{mode}.{ext}.report.json"
    progress(f"writing {sbom_path.name}")
    write_json(res.doc, sbom_path)
    progress(f"writing {report_path.name}")
    report = {"input": file.name, **res.to_dict()}
    write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n", report_path)
    progress("done")
    typer.echo(render_summary(file.name, res, {"sbom": str(sbom_path), "report": str(report_path)}))
    out_size = sbom_path.stat().st_size
    if mode == "all" and out_size > 10 * len(raw):
        typer.echo(f"  note          : output is {out_size / max(len(raw), 1):.0f}x the input ({size_text(out_size)}). "
                   "fill-all shows every schema field; for a Checkmarx upload use fill-required (+ fix).")
    raise typer.Exit(EXIT_OK if res.errors_after == 0 else 1)


_SPEC_HELP = "Treat the input as cyclonedx or spdx (default: detected; plain JSON without markers is cyclonedx)"
_VERSION_HELP = ("Write this schema version, e.g. 1.6 or 2.3 (default: the declared one; missing/unknown -> 1.6 / 2.3, "
                 "CycloneDX 1.8+ -> 1.7)")


@app.command("fill-required")
def fill_required(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="SBOM or any JSON file")],
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output folder (default: next to the input)")] = None,
    spec: Annotated[str | None, typer.Option("--spec", help=_SPEC_HELP)] = None,
    version: Annotated[str | None, typer.Option("--version", help=_VERSION_HELP)] = None,
) -> None:
    """Make any JSON schema-valid with every MANDATORY field: repair, derive, else placeholder.

    Steps: read any JSON (adds bomFormat/specVersion if missing), apply the fix repair rules at that version (never
    a downgrade), add each missing required field (derived from the SBOM where possible, else a placeholder), and
    replace values the schema rejects. Writes <name>.fill-required.<cdx|spdx>.json and
    <name>.fill-required.<cdx|spdx>.report.json (every change with its source). Identity fields (purl, cpe, ...)
    and references are only derived, never invented. Exit 0 = schema-valid output.
    """
    _fill(file, out, "required", False, spec, version)


@app.command("fill-all")
def fill_all(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="SBOM or any JSON file")],
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output folder (default: next to the input)")] = None,
    spec: Annotated[str | None, typer.Option("--spec", help=_SPEC_HELP)] = None,
    version: Annotated[str | None, typer.Option("--version", help=_VERSION_HELP)] = None,
    include_sensitive: Annotated[bool, typer.Option("--include-sensitive",
                                                    help="Also add placeholders for hashes, signatures, vulnerabilities, "
                                                         "attestations and crypto (off by default)")] = False,
) -> None:
    """Make any JSON schema-valid with EVERY field the schema defines: repair, derive, else placeholder.

    Same steps as fill-required, but for required and optional fields. Writes <name>.fill-all.<cdx|spdx>.json and
    <name>.fill-all.<cdx|spdx>.report.json. Deprecated fields and recursive structures (components inside new
    components) are not expanded. Exit 0 = schema-valid output.
    """
    _fill(file, out, "all", include_sensitive, spec, version)


@app.command("schema-diff")
def schema_diff_cmd(
    old: Annotated[str, typer.Argument(help="Older version, e.g. 1.5")],
    new: Annotated[str, typer.Argument(help="Newer version, e.g. 1.6")],
    spec: Annotated[str, typer.Option(help="cyclonedx | spdx")] = "cyclonedx",
) -> None:
    """Added / removed properties and enum values between two vendored schema versions."""
    from .schemadiff import format_diff

    try:
        typer.echo(format_diff(spec, old, new))
    except SbomFixerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX) from None


@app.command()
def verify(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    expected_packages: Annotated[int | None, typer.Option(help="Expected package count (5% tolerance)")] = None,
) -> None:
    """Upload a file to the Checkmarx verification project and check the import (exit 5 on failure)."""
    from .checkmarx import CxCliClient
    from .checkmarx import verify as cx_verify

    ok, res = cx_verify(CxCliClient(), file, expected_packages)
    typer.echo(json.dumps(res.to_dict(), indent=2))
    raise typer.Exit(EXIT_OK if ok else EXIT_VERIFY)


@app.command("bisect")
def bisect_cmd(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    max_uploads: Annotated[int, typer.Option(help="Upload budget")] = 30,
    profile: Annotated[str, typer.Option("--profile", "-p", help="Profile whose highest accepted version labels the content stages")] = "checkmarx",
) -> None:
    """Shrink a failing SBOM against the Checkmarx verification project to find the breaking field (exit 6 if inconclusive)."""
    from .bisect import bisect
    from .checkmarx import CheckmarxAcceptanceClient, CxCliClient
    from .detect import detect

    det, doc = detect(file.read_bytes())
    if det.spec != "cyclonedx":
        typer.echo("error: bisect supports CycloneDX JSON only", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX)
    accepted = load_profile(profile).rules_for("cyclonedx").accepted_versions
    base = max(accepted, key=lambda v: tuple(map(int, v.split(".")))) if accepted else None
    client = CheckmarxAcceptanceClient(CxCliClient())
    rep = bisect(doc, lambda d: client.check(d, det.spec, str(d.get("specVersion", det.version)))[0], max_uploads, base)
    for s in rep.steps:
        status = {True: "accepted", False: "rejected", None: "not tried (budget)"}[s.accepted]
        typer.echo(f"  [{s.stage:15}] {s.description:55} {status}")
    typer.echo("Conclusions:")
    for c in rep.conclusions or ["none"]:
        typer.echo(f"  - {c}")
    typer.echo(f"Uploads used: {rep.uploads}")
    raise typer.Exit(EXIT_BISECT if rep.inconclusive else EXIT_OK)


@app.command()
def rules(markdown: Annotated[bool, typer.Option("--markdown", help="Print the rule catalog as Markdown")] = False) -> None:
    """List every rule with its case, kind and description."""
    from .rules import RULES

    if markdown:
        typer.echo("| Rule | Case | Kind | Hop | Description |\n|---|---|---|---|---|")
        for r in RULES:
            hop = f"{r.hop[0]} -> {r.hop[1]}" if r.hop else ""
            typer.echo(f"| {r.id} | {r.case} | {r.kind} | {hop} | {r.description} |")
        return
    for r in RULES:
        typer.echo(f"{r.id:11} {r.case} {r.kind:9} {r.title}")


@app.callback(invoke_without_command=True)
def main(version: Annotated[bool, typer.Option("--version", help="Show the version")] = False) -> None:
    if version:
        typer.echo(f"sbom-fixer {__version__}")
        raise typer.Exit(0)


if __name__ == "__main__":
    sys.exit(app())
