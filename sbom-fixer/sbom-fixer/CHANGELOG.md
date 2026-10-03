# Changelog

Rule changes change outputs, so every new or changed rule is at least a minor version bump (ADR-09).

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
