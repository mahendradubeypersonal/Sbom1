# Rolling out sbom-fixer to a service (SBOMFIX-805)

## 1. Add the stage

Copy `jenkins/sbom-fix-stage.groovy` into the service Jenkinsfile, directly after the step that writes the SBOM. Change `build/sbom.json` to your SBOM path. The stage:

- writes `build/sbom-fixed/<name>.checkmarx.cdx.json` for the Checkmarx stage and `<name>.compliance.cdx.json` for customers and auditors;
- fails the build only for exit codes 2 and above;
- archives the original, both outputs, the diffs and the notes.

## 2. Read the notes file

Open `build/sbom-fixed/<name>.checkmarx.notes.txt` from the build artifacts.

| Section | What to do with it |
|---|---|
| Header: Version path | Shows each version tried. If the file stepped down (for example 1.6 to 1.5), consider fixing the generator setting (section 5). |
| 1. Why the original failed | The real causes, grouped. Nothing to do unless they repeat on every build. |
| 2. Changes made | Every rule that changed something. WARN rows deserve a quick look. |
| 3. Data loss | Fields that could not be kept at the accepted version. Check none of them matter to Checkmarx results. |
| 4 and 6. Scan coverage / components without purl | Components without a purl are not scanned. Fix them at the source if they matter. |
| 5. Recommended source fix | The cheapest permanent fixes, usually one generator flag. |
| 7. Quality and compliance | NTIA coverage and sbomqs score before and after. "Quality regression: none" is expected. |

## 3. Exit codes

| Code | Meaning | Build |
|---|---|---|
| 0 | Already compatible, output identical to input | passes |
| 1 | Fixed | passes |
| 2 | Cannot fix (unsupported format, no level down to the floor was OK) | fails |
| 3 | Data loss happened and the profile forbids it | fails |
| 4 | Quality gate failed (only when the profile gates) | fails |
| 5 | Checkmarx verification failed (`--verify`) | fails |
| 6 | Bisect inconclusive (`sbom-fixer bisect`) | n/a |

## 4. When something fails

1. Read the notes file; the header says which levels were tried and why each was not OK.
2. Run `sbom-fixer check <file>` locally to see the grouped schema errors.
3. If Checkmarx rejects a file that the tool says is OK, run `sbom-fixer bisect <file>` against the verification project and add the result as a corpus file and a rule (rule recipe in the Implementation Plan, section 4).
4. Contact the platform team with the notes file and the original SBOM.

## 5. Generator settings that avoid conversion

| Generator | Setting |
|---|---|
| Syft | `-o cyclonedx-json@1.5` (check your Syft version) |
| cdxgen | `--spec-version 1.5` |
| CycloneDX Maven plugin | `-DschemaVersion=1.5` |
| CycloneDX npm | `--spec-version 1.5` |
| CycloneDX Gradle plugin | `schemaVersion = "1.5"` |
| Trivy | no version option in many releases; keep sbom-fixer |

Write the SBOM with the generator's own output option. Shell redirection in Windows PowerShell 5.1 (`>`) writes UTF-16.
