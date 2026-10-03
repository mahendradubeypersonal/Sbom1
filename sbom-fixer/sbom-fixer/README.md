# sbom-fixer

Makes SBOMs from any generator import into Checkmarx, and explains every change it makes.

For each SBOM the tool:

1. Checks the file against the schema of the version it **declares**, and repairs what can be repaired without guessing.
2. If the corrected file is OK (schema-valid **and** accepted by the consumer), it stops. The version does not change.
3. If not, it steps down **one version** (for example 1.6 to 1.5), applies that hop's rules, and checks again.
4. It repeats until a level is OK or the floor is reached (exit code 2, with every attempt reported).

Every edit is recorded with a rule ID, so the diff, the notes file and the change log always match what happened.

Background: `SBOM_Fixer_Guide.md`, `SBOM_Fixer_Implementation_Plan.md` and `SBOM_Fixer_Jira_Stories/` (decisions ADR-01 to ADR-19).

## Install

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"     # Windows (Git Bash); on Linux use .venv/bin/pip
```

or use the image:

```bash
docker build -t sbom-fixer:1.0.0 .
docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 fix build/sbom.json --out build/sbom-fixed
```

Python 3.11 or newer. The tool never uses the network except for the optional Checkmarx commands.

## Use

```bash
sbom-fixer check sbom.json                          # read-only: errors grouped by cause + version path a fix would take
sbom-fixer fix sbom.json --out out/                 # write the fixed SBOM and reports (profile: checkmarx)
sbom-fixer fix sbom.json -p checkmarx -p compliance # Checkmarx copy + compliance copy in one run
sbom-fixer audit sbom.json                          # NTIA minimum elements + sbomqs score only
sbom-fixer schema-diff 1.5 1.6                      # what changed between two schema versions
sbom-fixer rules                                    # every rule with its case and kind
sbom-fixer verify out/sbom.checkmarx.cdx.json       # upload to the Checkmarx verification project
sbom-fixer bisect failing.json                      # find the field that makes Checkmarx reject a file
```

Useful options for `fix`:

| Option | Effect |
|---|---|
| `--accepted 1.4,1.5` | Override the profile's accepted CycloneDX versions for this run |
| `--verify-each-step` | Ask Checkmarx (real upload) at each level instead of the profile list; `--max-uploads` sets the budget |
| `--verify --expected-packages N` | Upload the final file and check the package count (5% tolerance) |
| `--no-audit` | Skip the NTIA / sbomqs audit |

On Windows PowerShell 5.1, never write SBOMs with `>`; it produces UTF-16. The tool always writes its files itself.

## Outputs

For `out/<name>.<profile>.*`:

| File | Content |
|---|---|
| `<name>.checkmarx.cdx.json` | The fixed SBOM (UTF-8 without BOM, LF) |
| `<name>.checkmarx.diff.patch.json` | RFC 6902 JSON Patch from original to fixed |
| `<name>.checkmarx.diff.txt` | Human diff (unified diff for small files, one line per patch operation for large ones) |
| `<name>.checkmarx.changes.json` | Change log: every change with rule ID, path, before, after, severity, level |
| `<name>.checkmarx.notes.txt` | Why the original failed, version path, changes by rule, data loss, scan coverage, source fixes, quality |
| `<name>.checkmarx.quality.json` | NTIA coverage and sbomqs score before and after, framework results |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Already compatible; output identical to input |
| 1 | Fixed |
| 2 | Cannot fix: unsupported format, below the floor, or no level down to the floor was OK |
| 3 | DATA_LOSS changes happened and the profile sets `allow_data_loss: false` |
| 4 | Quality gate failed (profile `quality.audit: gate`) |
| 5 | Checkmarx verification failed |
| 6 | Bisect inconclusive |

## Profiles

Built in: `checkmarx` and `compliance` (`sbom_fixer/data/profiles/`). Pass a YAML path to use your own.

```yaml
name: checkmarx
cyclonedx:
  floor: "1.3"                              # lowest version the descent may reach ("declared" = never downgrade)
  accepted_versions: ["1.3", "1.4", "1.5"]  # PROVISIONAL until docs/checkmarx-matrix.md is filled in
spdx:
  floor: "2.2"
  accepted_versions: ["2.2", "2.3"]
acceptance: profile        # profile | checkmarx | schema-only
tools_form: as-is          # legacy-array if Checkmarx only reads the 1.4 tools array
flatten_nested_components: true
require_purl: warn         # fail -> exit 2 when a component has no valid purl
allow_data_loss: true
quality: {audit: report, fail_on_regression: true, min_score: 0, score_tolerance: 0.2}
```

The old keys `target`, `supported` and `convert` are rejected with a message.

## Checkmarx configuration

Only needed for `verify`, `bisect`, `--verify` and `--verify-each-step`. The `cx` CLI reads its own credentials from the environment; the tool never puts them on a command line or in a log.

| Variable | Purpose |
|---|---|
| `CX_BASE_URI`, `CX_TENANT` | Checkmarx One tenant |
| `CX_CLIENT_ID` + `CX_CLIENT_SECRET`, or `CX_APIKEY` | Service account (Jenkins credentials) |
| `CX_BIN` | Path to `cx` if not on PATH |
| `SBOM_FIXER_CX_PROJECT` | Verification project (default `sbom-fixer-verification`) |
| `SBOM_FIXER_CX_SCAN_ARGS`, `SBOM_FIXER_CX_RESULTS_ARGS` | Override the `cx` argument templates if your CLI version uses other flags (check `cx scan create --help`) |
| `SBOM_FIXER_CX_TIMEOUT_S` | Scan timeout (default 900) |
| `SBOMQS_BIN` | Path to `sbomqs` if not on PATH |
| `SBOM_FIXER_FAST_VALIDATION=0` | Disable the fastjsonschema pre-check (use only for debugging) |

## Development

```bash
python tools/make_corpus.py          # regenerate corpus/ and corpus/expected.yaml
.venv/Scripts/pytest                 # 124 tests, about 10 seconds
.venv/Scripts/ruff check sbom_fixer tests tools
.venv/Scripts/mypy sbom_fixer
python tools/vendor_schemas.py       # only when upgrading schemas; commit with schemas/SOURCES.md
```

Adding a rule follows the seven-step recipe in the Implementation Plan (evidence, classify, fixture, implement, describe, run everything, catalog). `docs/rule-catalog.md` is generated with `sbom-fixer rules --markdown`.

## How the stories map to the code

| Phase | Stories | Where |
|---|---|---|
| 0 Discovery | SBOMFIX-101 to 106 | `corpus/minimal/`, `docs/checkmarx-matrix.md`, `tools/make_corpus.py` |
| 1 Core | SBOMFIX-201 to 207 | `schemas.py`, `detect.py`, `validate.py`, `changes.py`, `rules/base.py`, `cli.py check` |
| 2 Same-version repair | SBOMFIX-301 to 307 | `rules/repair.py`, `descent.process_level`, `serialize.py` |
| 3 Version conversion | SBOMFIX-401 to 407 | `schemadiff.py`, `descent.py`, `oracle.py`, `rules/cdx_*`, `prune.py` |
| 4 Sanitizers, reporting | SBOMFIX-501 to 510 | `rules/sanitize.py`, `diff.py`, `notes.py`, `profile.py`, `pipeline.py`, `Dockerfile` |
| 5 Quality | SBOMFIX-601 to 606 | `audit/ntia.py`, `audit/sbomqs.py`, `audit/gate.py`, `profiles/compliance.yaml` |
| 6 Checkmarx | SBOMFIX-701 to 704 | `checkmarx.py`, `bisect.py`, `tools/run_corpus_checkmarx.py`, `jenkins/nightly-corpus.groovy` |
| 7 SPDX, rollout | SBOMFIX-801 to 806 | `rules/spdx_23_to_22.py`, `audit/ntia.py` (SPDX), `jenkins/sbom-fix-stage.groovy`, `docs/rollout.md` |

## Known limitations

- Performance: a 25 MB SBOM with 50,000 components, every one needing two changes, takes about 38 seconds end to end including audit and reports (measured on a developer laptop). ADR-18 targets 30 seconds; files that need fewer changes are faster.
- Checkmarx `accepted_versions` are provisional (ADR-01) until the upload matrix is run in your tenant.
- The `cx` flags and results JSON fields used by `checkmarx.py` are defaults; confirm them for your CLI version. They have not been run against a real tenant.
- The `corpus/` files are synthetic, modelled on typical generator output. Add real SBOMs from your pipelines (SBOMFIX-103).
- Not supported yet: CycloneDX XML, SPDX tag-value / RDF / 3.0, upgrade hops below the floor, REP-013 and REP-014.
