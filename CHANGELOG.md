# Changelog

Rule changes change outputs, so every new or changed rule is at least a minor version bump (ADR-09).

## Unreleased (next minor version)

Checkmarx version policy and purl handling. Design and sources: `docs/checkmarx-version-purl-fix.md`.

- **Versions:** profile `checkmarx` accepts CycloneDX 1.3-1.7 and repairs 1.6 and 1.7 at their own version (1.7 provisional: the Checkmarx "Scanning SBOMs" page lists 1.0-1.6). New profile `checkmarx-cli` caps at 1.6 for the `cx` CLI; the Jenkins stage uses it.
- **Future versions:** new spec keys `max_version` and `future_versions` (`reject` default, `downgrade`). CycloneDX 1.8+ is brought down to `max_version` by a generic future hop; CycloneDX 2.x is refused (VER-002 in the reason).
- **Rules added:**
  - Future hop: CDX-FWD-001, CDX-FWD-002, CDX-FWD-003.
  - Sanitizers: SAN-009 (purl written as a URL), SAN-013 (default tool when none is named, profile key `ensure_tools`).
  - Checkmarx purl (profile section `purl:`): CXP-001, CXP-002, CXP-003, CXP-004, CXP-005, CXP-010, CXP-011, CXP-012, CXP-013, CXP-020, CXP-021, CXP-030, CXP-051.
- **Changed:** SAN-012 runs only for profiles without a `purl:` section. SAN-090 no longer adds sbom-fixer to metadata.tools twice. The NTIA "Unique identifier" check counts a purl only when it parses.
- **Outputs:** `<name>.<profile>.purl-coverage.csv`; `checkmarx_coverage` (before/after) in changes.json; notes sections 4 and 6 show Checkmarx coverage, coverage by purl type and the expected package count.
- **Exit code 7:** no component has a purl type the profile supports (Checkmarx would fail the scan). `fix --verify` skips the upload then, and uses the supported-component count as the default `--expected-packages`.
- **Corpus:** `corpus/future/` and `corpus/purl/` (9 new files); `expected.yaml` updated for the 1.6/1.7 policy.
- **sbomqs offline:** sbomqs 2.1.2 vendored in `tools/sbomqs` (Windows x64 binary, Linux x64 archive, upstream `checksums.txt`, `SHA256SUMS`, Apache-2.0 `LICENSE`) by the new `tools/vendor_sbomqs.py`, which verifies the release checksums. Lookup order: `SBOMQS_BIN`, `tools/sbomqs`, `PATH`. The Dockerfile no longer downloads sbomqs (was 1.0.0 from GitHub); it extracts the vendored 2.1.2 archive after a sha256 check. `audit` prints the grade and the binary; sbomqs errors are shown without colour codes and timestamps. `.gitattributes` keeps `tools/sbomqs` byte-for-byte. New tests: `tests/test_sbomqs_vendored.py`.
- **Docs:** `SBOM_Fixer_Rule_Book_And_Installation_guide.docx` (and `docs/SBOM_Fixer_Rule_Book.docx` / `.md`) updated: Step 13.1-13.6 on the bundled sbomqs, 17.5 upgrading sbomqs, and the 1.6/1.7 policy, `checkmarx-cli`, exit 7, purl coverage and the regenerated rule list.

## 1.0.0 - 2026-10-02

First release. All eight phases of the implementation plan.

- **Core:** offline schema registry (CycloneDX 1.2-1.7, SPDX 2.2.2 and 2.3), encoding/format/version/generator detection, validation with JSON Pointer paths and grouped causes, hybrid fast validation (fastjsonschema pre-check, jsonschema for exact errors) with O(n) `uniqueItems` and a fast IRI checker.
- **Version descent (ADR-02):** start at the declared version, repair, accept or step down one version, down to the floor. Oracles: `profile`, `checkmarx` (real upload per level, cached, budgeted), `schema-only`.
- **Rules added:**
  - Same-version repair: REP-001, REP-002, REP-003, REP-004, REP-005, REP-006, REP-007, REP-008, REP-009, REP-010, REP-011, REP-012.
  - CycloneDX 1.7 -> 1.6: CDX17-001, CDX17-002, CDX17-ENUM.
  - CycloneDX 1.6 -> 1.5: CDX16-001 to CDX16-011.
  - CycloneDX 1.5 -> 1.4: CDX15-001 to CDX15-011, plus CDX15-001P (importer-specific tools form).
  - CycloneDX 1.4 -> 1.3: CDX14-001 to CDX14-004.
  - SPDX 2.3 -> 2.2: SPDX23-001, SPDX23-002.
  - Sanitizers: SAN-001, SAN-002, SAN-003, SAN-004, SAN-010, SAN-011, SAN-012, SAN-020, SAN-021, SAN-022, SAN-030, SAN-031, SAN-050, SAN-060, SAN-090.
  - Pipeline IDs: ENC-001, ENC-002, ENC-003, CDX-VER, SPDX-VER, PRUNE-001.
- **Outputs:** fixed SBOM (UTF-8, no BOM), JSON Patch, human diff, change log JSON, notes.txt, quality JSON.
- **Audit:** built-in NTIA 2021 checker (CycloneDX and SPDX), sbomqs wrapper, quality gate (exit 4), framework checks for NTIA, CISA FSCT minimum level and BSI TR-03183-2 v2 basics.
- **Profiles:** `checkmarx` (provisional accepted versions, ADR-01) and `compliance` (`floor: declared`, never downgraded).
- **CLI:** `check`, `fix` (several profiles, `--verify`, `--verify-each-step`), `audit`, `schema-diff`, `verify`, `bisect`, `rules`.
- **Checkmarx:** `cx` CLI client behind an interface; credentials only from environment variables; nightly corpus job.
- **Distribution:** Dockerfile with pinned sbomqs, Jenkins stage, nightly job, repository CI.

Known limitations: CycloneDX XML input, SPDX tag-value/RDF/3.0, upgrade hops (1.2 -> 1.3), REP-013 and REP-014 are not implemented. Checkmarx accepted versions are provisional until `docs/checkmarx-matrix.md` is filled in.
