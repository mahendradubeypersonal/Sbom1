# Checkmarx import matrix (SBOMFIX-102)

Fill this in by uploading every file in `corpus/minimal/` to the Checkmarx project `sbom-fixer-verification`, once through the portal and once through the `cx` CLI (`cx scan create --help` for the SBOM import flag of your CLI version). Then copy the result into `sbom_fixer/data/profiles/checkmarx.yaml`.

Tenant: ____________  Checkmarx release: ____________  cx CLI version: ____________  Date: ____________  Tested by: ____________

| File | What it proves | Portal | CLI | Findings for lodash shown | Scan ID | Notes |
|---|---|---|---|---|---|---|
| min-cdx-1.3.json | 1.3 accepted? | | | | | |
| min-cdx-1.4.json | 1.4 accepted? | | | | | |
| min-cdx-1.5.json | 1.5 accepted with `metadata.tools` object | | | | | |
| min-cdx-1.5-tools-array.json | 1.5 accepted with legacy tools array | | | | | |
| min-cdx-1.6.json | 1.6 accepted? | | | | | |
| min-cdx-1.7.json | 1.7 accepted? | | | | | |
| min-cdx-1.5-utf8bom.json | UTF-8 BOM rejected? (H4) | | | | | |
| min-cdx-1.5-utf16.json | UTF-16 rejected? (H4) | | | | | |
| min-spdx-2.2.json | SPDX 2.2 accepted? | | | | | |
| min-spdx-2.3.json | SPDX 2.3 accepted? | | | | | |

## Decisions taken from this matrix

| Profile key | Rule | Value |
|---|---|---|
| `cyclonedx.accepted_versions` | every CycloneDX version whose file imported and showed findings | |
| `cyclonedx.floor` | lowest accepted version (normally 1.3) | |
| `tools_form` | `legacy-array` only if the tools-array file passed and the object file failed | |
| `spdx.accepted_versions` | SPDX versions that imported (empty list = SPDX not accepted) | |

Until this table is filled in, the shipped profile uses the provisional values from ADR-01: CycloneDX 1.3, 1.4, 1.5; SPDX 2.2, 2.3; `tools_form: as-is`.

To check a single level against the real importer instead of the profile list, run:

```bash
sbom-fixer fix file.json --verify-each-step --max-uploads 6
```

## PURL checks (docs/checkmarx-version-purl-fix.md, section 8.3)

Upload each file as it is, then the `sbom-fixer fix` output of it, and compare the package count Checkmarx shows with the "Expected package count" line in the notes.

| File | What it proves | Packages, original | Packages, fixed | Expected (notes) | Scan ID | Notes |
|---|---|---|---|---|---|---|
| corpus/purl/mixed-types.cdx.json | Checkmarx type table: 14 supported aliases scanned, rpm/apk/deb(OS)/cargo/hex/docker/conda skipped | | (unchanged) | 14 | | |
| corpus/purl/format-fixes.cdx.json | `@scope` unencoded (CXP-002) and `repository_url=https://` (CXP-005) are not matched before the fix, matched after | | | 6 | | |
| corpus/purl/url-purls.cdx.json | purl written as https URL is skipped; SAN-009 output is matched | | | 2 (github and the unknown URL are skipped) | | |
| corpus/purl/none-supported.cdx.json | Checkmarx fails with "no valid PURLs" (tool exit 7) | | – | 0 | | |
| a real SBOM with `pkg:deb/debian/...` | What Checkmarx shows for OS deb packages (decides `os_package_action`) | | | | | |
