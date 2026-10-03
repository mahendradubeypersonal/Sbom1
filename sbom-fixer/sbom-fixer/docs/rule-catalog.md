# Rule catalog

Generated with `sbom-fixer rules --markdown`. Case A = same-version repair, B = version hop, C = importer-specific. Kind: repair and sanitize run at every level; hop runs once per version step; final runs once at the accepted level.

| Rule | Case | Kind | Hop | Description |
|---|---|---|---|---|
| CDX14-001 | B | hop | 1.4 -> 1.3 | CycloneDX 1.3 requires a component version; it was taken from the purl, or set to 'unknown' and reported. |
| CDX14-002 | B | hop | 1.4 -> 1.3 | CycloneDX 1.3 has no vulnerabilities section; it was removed (the scanner computes its own findings). |
| CDX14-003 | B | hop | 1.4 -> 1.3 | signature and releaseNotes (1.4) do not exist in 1.3 and were removed. |
| CDX14-004 | B | hop | 1.4 -> 1.3 | Values added in 1.4 were mapped: the external reference type release-notes became other; tool externalReferences were removed. |
| CDX15-001 | B | hop | 1.5 -> 1.4 | metadata.tools (and vulnerabilities[].tools) in the 1.5 object form {components, services} were converted to the 1.4 array of {vendor, name, version}. |
| CDX15-001P | C | sanitize |  | The profile sets tools_form: legacy-array, so metadata.tools was written in the legacy array form even though this version also accepts the object form. |
| CDX15-002 | B | hop | 1.5 -> 1.4 | metadata.lifecycles (1.5) was kept as the property sbom-fixer:lifecycles. |
| CDX15-003 | B | hop | 1.5 -> 1.4 | Top-level formulation and annotations (1.5) have no 1.4 equivalent and were removed. |
| CDX15-004 | B | hop | 1.5 -> 1.4 | Component types added in 1.5 were mapped to their nearest 1.4 type (device-driver to device, data to file, platform and machine-learning-model to application); the original type is kept in a property. |
| CDX15-005 | B | hop | 1.5 -> 1.4 | component.modelCard and component.data (1.5) were removed. |
| CDX15-006 | B | hop | 1.5 -> 1.4 | evidence.identity, occurrences and callstack (1.5) were removed; evidence.licenses and copyright were kept. |
| CDX15-007 | B | hop | 1.5 -> 1.4 | Vulnerability fields rejected, proofOfConcept and workaround (1.5) were removed. |
| CDX15-008 | B | hop | 1.5 -> 1.4 | External reference types added in 1.5 became 'other'; the original type is kept in comment. |
| CDX15-009 | B | hop | 1.5 -> 1.4 | CycloneDX 1.4 has no root-level properties; they were moved to metadata.properties. |
| CDX15-010 | B | hop | 1.5 -> 1.4 | CycloneDX 1.4 and older require the root field version (the BOM revision); it was set to 1. |
| CDX15-011 | B | hop | 1.5 -> 1.4 | Enum values added in 1.5 were mapped: composition aggregate incomplete_* became incomplete, rating methods CVSSv4 and SSVC became other. |
| CDX16-001 | B | hop | 1.6 -> 1.5 | metadata.manufacturer (1.6) was renamed to metadata.manufacture, its 1.5 equivalent. |
| CDX16-002 | B | hop | 1.6 -> 1.5 | component.manufacturer (1.6) was moved to supplier when supplier was empty, otherwise dropped. |
| CDX16-003 | B | hop | 1.6 -> 1.5 | component.authors (1.6, a list of contacts) was joined into the 1.5 string field author. |
| CDX16-004 | B | hop | 1.6 -> 1.5 | evidence.identity was an array (1.6 form); the entry with the highest confidence was kept as the single 1.5 object. |
| CDX16-005 | B | hop | 1.6 -> 1.5 | license acknowledgement (declared/concluded, 1.6) does not exist in 1.5 and was removed. |
| CDX16-006 | B | hop | 1.6 -> 1.5 | component.omniborId and swhid (1.6) were kept as properties sbom-fixer:omniborId / sbom-fixer:swhid. |
| CDX16-007 | B | hop | 1.6 -> 1.5 | tags (1.6) on components and services were kept as one property sbom-fixer:tags. |
| CDX16-008 | B | hop | 1.6 -> 1.5 | Top-level declarations and definitions (1.6 attestations and standards) have no 1.5 equivalent and were removed. |
| CDX16-009 | B | hop | 1.6 -> 1.5 | dependencies[].provides (1.6) does not exist in 1.5 and was removed. |
| CDX16-010 | B | hop | 1.6 -> 1.5 | Components of type cryptographic-asset (1.6) are not packages a scanner can match and were removed with their dependency edges. |
| CDX16-011 | B | hop | 1.6 -> 1.5 | External reference types added in 1.6 (source-distribution, digital-signature, electronic-signature, rfc-9116) became 'other'; the original type is kept in comment. |
| CDX17-001 | B | hop | 1.7 -> 1.6 | CycloneDX 1.7 component fields versionRange and isExternal do not exist in 1.6; they were kept as properties. |
| CDX17-002 | B | hop | 1.7 -> 1.6 | CycloneDX 1.7 patent assertions, citations and metadata.distributionConstraints have no 1.6 equivalent and were removed. |
| CDX17-ENUM | B | hop | 1.7 -> 1.6 | Enum values that exist only in CycloneDX 1.7 were mapped: new external reference types became 'other' (original kept in comment); Streebog hashes were removed. |
| REP-001 | A | repair |  | $schema pointed to a different CycloneDX version than specVersion; $schema was corrected. |
| REP-002 | A | repair |  | specVersion was written as a number; it must be a string such as "1.5". |
| REP-003 | A | repair |  | A value was written in the wrong case or spelling (for example 'Library' or 'sha256'); it was mapped to the one allowed value it matches. |
| REP-004 | A | repair |  | A number or boolean was written where the schema expects a string (or the reverse); it was converted without changing its meaning. |
| REP-005 | A | repair |  | A field was null or empty where the schema requires content; the field was removed. |
| REP-006 | A | repair |  | An entry missed a required field. It was filled only when the value is unambiguous (for example a name taken from the purl); otherwise the entry was removed or reported. |
| REP-007 | A | repair |  | serialNumber was not in urn:uuid form; a deterministic UUID was written and the old value kept in metadata.properties. |
| REP-008 | A | repair |  | A timestamp was not a valid ISO 8601 date-time; it was rewritten in UTC (a missing timezone is assumed to be UTC and reported). |
| REP-009 | A | repair |  | A URL contained characters that are not allowed (for example spaces); they were percent-encoded. External references whose URL could not be repaired were removed. |
| REP-010 | A | repair |  | A licenses array was malformed (plain strings, unwrapped objects, id and name together, non-SPDX IDs, or expressions mixed with license objects); it was restructured without dropping license text. |
| REP-011 | A | repair |  | A hash value did not match its algorithm (wrong length or characters) or used an unknown algorithm; that hash was removed. |
| REP-012 | A | repair |  | A single value was written where the schema expects an array; it was wrapped in an array. |
| SAN-001 | C | sanitize |  | null values are invalid in every SBOM schema; they were removed. |
| SAN-002 | C | sanitize |  | Empty arrays and objects in optional fields were removed (dependsOn is kept, because an empty dependsOn means 'no dependencies'). |
| SAN-003 | C | sanitize |  | The BOM had no serialNumber; a deterministic urn:uuid derived from the input was added. |
| SAN-004 | C | sanitize |  | metadata.timestamp had a timezone offset; it was normalized to UTC 'Z' form. A missing timestamp is reported, never invented. |
| SAN-010 | C | sanitize |  | A purl did not parse; characters were percent-encoded where that made it valid, otherwise the purl was removed and the component reported as not scannable. |
| SAN-011 | C | sanitize |  | A component had no purl. One was built when the ecosystem was certain (bom-ref is a purl, or a generator property names the package type); otherwise the component is reported as not scannable. |
| SAN-012 | C | sanitize |  | Components with purl types such as generic or github are kept but counted separately, because SCA scanners usually do not match them. |
| SAN-020 | C | sanitize |  | Several components shared one bom-ref; duplicates were renamed with a #2, #3 suffix (dependencies keep pointing to the first). |
| SAN-021 | C | sanitize |  | Dependency entries referred to bom-refs that do not exist in the document; those edges were removed. |
| SAN-022 | C | sanitize |  | Top-level components with an identical purl were merged into the first one; dependency references were rewritten to it. |
| SAN-030 | C | sanitize |  | A license name was an SPDX ID or an unambiguous alias of one (for example 'Apache 2.0'); it was written as the SPDX id. |
| SAN-031 | C | sanitize |  | A license expression did not parse as SPDX; it was normalized when every license in it is known, otherwise kept as a license name. |
| SAN-050 | C | sanitize |  | Nested components were moved to the top-level components list, which the profile requires. |
| SAN-060 | C | final |  | The document carried a signature; any change invalidates it, so it was removed. Re-sign the output if signatures are required. |
| SAN-090 | C | final |  | sbom-fixer was added to metadata.tools and metadata.properties record the source version and hash, so the output can be traced to its original. |
| SPDX23-001 | B | hop | 2.3 -> 2.2 | Package fields added in SPDX 2.3 (primaryPackagePurpose, releaseDate, builtDate, validUntilDate) were moved into the package comment. |
| SPDX23-002 | B | hop | 2.3 -> 2.2 | Relationship types added in SPDX 2.3 (REQUIREMENT_DESCRIPTION_FOR, SPECIFICATION_FOR) became OTHER with the original type in the comment. |

Additional IDs written by the pipeline: ENC-001/002/003 (encoding), CDX-VER / SPDX-VER (version change), PRUNE-001 (field not allowed by the current schema, always DATA_LOSS).
