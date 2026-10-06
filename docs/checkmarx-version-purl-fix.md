# Checkmarx fix: CycloneDX 1.6/1.7 support, 1.8+ downgrade, PURL types, https purls, default tool

> Status: **Implemented** (tests: `tests/test_purl_checkmarx.py`, `tests/test_future.py`, `corpus/future/`, `corpus/purl/`)
> Date: 2026-10-05
> Owner: sbom-fixer
> Related: `docs/checkmarx-sbom-upload-failures.md`, `docs/checkmarx-matrix.md`, `docs/rule-catalog.md`, `sbom_fixer/data/profiles/checkmarx.yaml`, `checkmarx-cli.yaml`
> Primary source: [Checkmarx One – Scanning SBOMs](https://docs.checkmarx.com/en/34965-728599-scanning-sboms.html) (2026-10-05 ko padha gaya)

---

## 0. Summary

| # | Kya | Kaise | Rule IDs |
|---|---|---|---|
| 1 | **CycloneDX 1.6 aur 1.7 as-is** | Jo version declare hai (1.3–1.7) usi par repair hota hai, version nahi badalta. `checkmarx-cli` profile bhi 1.6 aur 1.7 dono rakhta hai (update 2026-10-06; pehle wo 1.7 ko 1.6 par laata tha). Ek run ke liye cap: `--accepted 1.3,1.4,1.5,1.6`. Pehle likha tha: `cx` CLI 1.6 tak padhta hai. | existing REP-*, SAN-* |
| 2 | **1.8+ → 1.7** | Generic "future hop": specVersion 1.7, naye fields property mein, naye enum values `other` mein. CycloneDX 2.x refuse hota hai. | CDX-FWD-001/002/003 |
| 3 | **Checkmarx PURL types** | Supported types jaise hain waise rakhe jaate hain. Format ki dikkatein theek hoti hain. Unsupported types sirf pakke evidence par remap hote hain. Baaki sab report hota hai. | CXP-001..005, 010..013, 020, 021, 030, 051 |
| 4 | **purl mein `https://` URL** | Registry URL ho to exact purl banta hai. Doosra URL ho to externalReferences mein jaata hai. Supported purl ke URL wale qualifiers hatte hain. | SAN-009, CXP-005 |
| 5 | **Tool missing** | `metadata.tools` (SPDX: `Tool:` creator) na ho to sbom-fixer default tool ke roop mein add hota hai | SAN-013 |
| 6 | **Coverage report** | notes.txt mein Checkmarx coverage, `purl-coverage.csv`, changes.json mein `checkmarx_coverage` | – |
| 7 | **Exit 7** | Ek bhi supported purl nahi bacha → Checkmarx scan fail karega, isliye upload mat karo | pipeline gate |

**Checkmarx docs aapas mein match nahi karte.** "Scanning SBOMs" page par CycloneDX **1.0–1.6** likha hai, jabki SBOM Reports page ke hisaab se portal **1.7** aur CLI 1.6 support karta hai. Isliye 1.7 `checkmarx` profile mein **provisional** hai, aur Jenkins `checkmarx-cli` use karta hai (section 3.4).

---

## 1. Background: Checkmarx kya maangta hai

Neeche ka saara content [Scanning SBOMs](https://docs.checkmarx.com/en/34965-728599-scanning-sboms.html) page se hai.

### 1.1 Formats

| Format | Supported versions | File types |
|---|---|---|
| CycloneDX | 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6 | JSON, XML |
| SPDX | 2.2, 2.3 | **JSON only** |

### 1.2 PURL requirement

- Sirf **valid PURL** wale components analyze hote hain.
- Bina PURL wale (sirf CPE ya file hash) **chupchaap skip** hote hain: koi error nahi, scan chalta rehta hai.
- **Ek bhi** valid, supported PURL na ho to scan **error** deta hai ("no valid PURLs").
- PURL type matching **case-insensitive** hai.
- Bina version wali PURL ko package ke **latest version** ke against check kiya jaata hai.
- Results mein **skip hue components ka count nahi dikhta**. Coverage ke liye input ke components ko result ke package count se milana padta hai.

### 1.3 Supported PURL types (official table)

| Checkmarx package manager | Accepted PURL type values |
|---|---|
| NPM | `npm`, `yarn`, `bower` |
| Python (Pip) | `pip`, `python`, `pypi`, `poetry` |
| NuGet | `nuget` |
| Maven | `maven`, `sbt`, `ivy`, `gradle` |
| PHP (Composer) | `php`, `composer` |
| Swift / iOS | `ios`, `swift`, `swiftpm`, `carthage`, `cocoapods` |
| Go | `go`, `golang`, `gomodules` |
| C++ (Conan) | `conan`, `cpp`, `deb` |
| Ruby (RubyGems) | `gem`, `ruby`, `rubygems` |
| Unity | `unity` |
| Perl (CPAN) | `perl`, `cpan` |
| Dart (Pub) | `dart`, `pub` |

`deb` yahan **C++ library packages** ke liye hai (jaise `libcurl4-openssl-dev`), OS-level Debian packages ke liye nahi.

### 1.4 Unsupported PURL types (official table)

| PURL type | Skip kyun hota hai |
|---|---|
| `rpm`, `apk` | OS-level packages; Checkmarx vulnerability database mein nahi |
| `generic` | Kisi registry se juda nahi |
| `docker` | Is scan mode mein container images analyze nahi hote |
| `cargo`, `hex` | Abhi supported nahi |
| Baaki saare | Pehchane nahi jaate, bina error ke skip (jaise `github`, `oci`, `conda`, `alpm`, `swid`, `hackage`) |

### 1.5 Troubleshooting points jo is fix mein aate hain

- npm scope: `pkg:npm/%40angular/core@14.2.0`, na ki `pkg:npm/@angular/core@14.2.0`.
- Gradle/SBT/Ivy ka namespace Maven convention follow kare (`groupId/artifactId`).
- SPDX mein `DESCRIBES` / `DEPENDS_ON` relationship nahi hai → saare packages "direct" maane jaate hain.
- PURL ka format: `pkg:type/[namespace/]name@version`.

---

## 2. Pehle aur ab

| Area | Pehle | Ab |
|---|---|---|
| Accepted CycloneDX (`checkmarx`) | 1.3, 1.4, 1.5; isliye 1.6/1.7 hamesha 1.5 par downgrade | 1.3–1.7; version nahi badalta |
| CLI ke liye | Koi alag profile nahi | `checkmarx-cli`: 1.3–1.7 (2026-10-06 se; pehle 1.3–1.6) |
| 1.8+ | exit 2 ("no vendored schema") | Future hop → 1.7 (cli mein → 1.6) |
| Unsupported purl types | SAN-012: chhoti generic list, sirf INFO note | Checkmarx ki exact list (CXP-020/021); remap on evidence (CXP-010..013) |
| npm `@` scope | Encode nahi hota tha (purl parse ho jaata hai) | CXP-002 |
| Versionless purl | Koi check nahi | CXP-003: component version se bharta hai, nahi to WARN |
| purl = `https://...` | SAN-010 purl ko hata deta tha; component scan se bahar | SAN-009: registry URL → purl; baaki URL externalReferences mein |
| URL qualifiers (`repository_url=https://...`) | Jaise the | CXP-005: supported purls se hatte hain, original property mein |
| Tool missing | Kuch nahi | SAN-013 default tool |
| Coverage | "with valid purl" count | Checkmarx status per component, type breakdown, CSV, expected package count |
| Zero scannable | Upload hota, Checkmarx fail karta | Exit 7 |

---

## 3. Version policy

### 3.1 Decision table

| Declared version | `checkmarx` (portal) | `checkmarx-cli` | Rule IDs |
|---|---|---|---|
| CycloneDX 1.3 – 1.5 | Same version repair | Same | REP-*, SAN-*, CXP-* |
| **CycloneDX 1.6** | **1.6** (repair only) | **1.6** | same |
| **CycloneDX 1.7** | **1.7** (repair only) | **1.7** (repair only); sirf `--accepted ...,1.6` dene par 1.6 | CDX17-* sirf cap ke saath |
| **CycloneDX 1.8, 1.9, 1.10 …** | Future hop → **1.7** | Future hop → **1.7** | CDX-FWD-001/002/003 |
| CycloneDX 2.x | Refuse, exit 2 (reason mein VER-002) | same | – |
| CycloneDX 1.2 | Floor 1.3 se neeche: exit 2 (pehle jaisa; upgrade hop nahi hai) | same | – |
| CycloneDX XML, SPDX tag-value, SPDX 3.0 | exit 2 (tool sirf JSON padhta hai) | same | – |
| SPDX 2.2 / 2.3 | Same version | same | REP-*, SAN-001, SAN-009, SAN-013, CXP-* |

"Same version" ka matlab: declared version par REPAIR → PRUNE → SANITIZE. Agar file schema-valid aur accepted hai, to wahi final. Version tabhi neeche jaata hai jab us version par unrepairable schema errors bachein, ya `--verify-each-step` mein Checkmarx reject kare (purana descent fallback).

### 3.2 Future hop (`sbom_fixer/rules/cdx_future.py`, `descent.py`)

CycloneDX schemas zyada tar objects par `additionalProperties: false` rakhte hain. Isliye 1.8 file ko 1.7 schema ke against chalane par **har naya field prune candidate ke roop mein dikh jaata hai**, aur 1.8 ka schema hona zaroori nahi.

```
1. Gate (descent.py)
   - version vendored list mein nahi, aur major alag (2.x)      -> exit 2, reason "VER-002 ..."
   - profile future_versions: reject (default)                -> exit 2
   - spec SPDX                                                -> exit 2 (future hop sirf CycloneDX ke liye)
   - warna attempt "1.8 is newer than this tool knows; generic future hop to 1.7"

2. CDX-FWD-001   specVersion 1.8 -> 1.7, $schema -> 1.7 URL         INFO, level "1.8->1.7"
3. CDX-FWD-002   pruner ko copy par chala kar unknown fields nikalo:
                 - parent properties le sakta hai (root, metadata, component, service, tool, vulnerability)
                   aur value <= 4 KB  -> property "sbom-fixer:cdx18:<field>"   INFO (moved)
                 - warna hatao                                                  DATA_LOSS
4. CDX-FWD-003   1.7 enum errors:
                 - allowed list mein "other" -> "other"; original property ya
                   (externalReference ho to) comment mein                     WARN
                 - "other" nahi -> value hatao                                  DATA_LOSS
5. 1.7 par normal process_level (REPAIR/PRUNE/SANITIZE/CXP); bacha hua PRUNE-001 hata deta hai
6. Oracle: checkmarx aur checkmarx-cli dono -> 1.7 accept (`--accepted` se cap ho to CDX17 hops se 1.6)
```

- `sbom-fixer:sourceSpecVersion = 1.8` SAN-090 (provenance) likhta hai.
- Notes mein: `Fix type: B (downgrade 1.8 -> 1.7)` aur version path ki pehli line `1.8 not tried (... generic future hop to 1.7)`.
- Jab CycloneDX 1.8 release ho aur `tools/vendor_schemas.py` se uska schema aa jaaye, tab `rules/cdx_18_to_17.py` mein specific mappings likhni hongi. Tab future hop sirf 1.9+ ke liye bachega.

### 3.3 Profile keys

```yaml
cyclonedx:
  floor: "1.3"
  accepted_versions: ["1.3", "1.4", "1.5", "1.6", "1.7"]   # checkmarx-cli: same
  max_version: "1.7"            # NEW: newer declared versions are brought down to this one
  future_versions: downgrade    # NEW: downgrade | reject (default reject, e.g. compliance profile)
```

Validation (`profile.py`): `max_version` vendored list mein hona chahiye; `future_versions: downgrade` ke liye `max_version` zaroori hai.

### 3.4 1.7 ka risk

| Scenario | Kya karein |
|---|---|
| Portal 1.7 accept karta hai (SBOM Reports page) | `checkmarx` profile jaisa hai |
| Portal 1.7 reject karta hai (Scanning SBOMs page: 1.0–1.6) | `--accepted 1.3,1.4,1.5,1.6` (ek run), ya profile se 1.7 hatao |
| `cx` CLI / Jenkins / GitHub Action | `checkmarx-cli` (1.7 bhi rakhta hai). CLI 1.7 reject kare to Jenkins fix command mein `--accepted 1.3,1.4,1.5,1.6` jodo |

Matrix (`docs/checkmarx-matrix.md`) mein `min-cdx-1.7.json` ki row bharne ke baad hi 1.7 ko pakka maano.

---

## 4. PURL handling

### 4.1 Har component ka status (`purlmap.classify`)

| Status | Matlab | Checkmarx scan karega? |
|---|---|---|
| `supported` | Valid purl, supported type, kuch nahi badla | Haan |
| `fixed` | Supported type; format theek kiya (CXP-001..005) | Haan |
| `remapped` | Unsupported type; evidence se supported type (SAN-009 / CXP-010..013) | Haan |
| `versionless` | Supported type, par version kahin nahi | Haan, **latest** ke against |
| `unsupported` | Type Checkmarx list mein nahi | Nahi |
| `os-package` | `rpm`/`apk`/`alpm`, ya OS `deb` (namespace `debian`/`ubuntu`, qualifier `distro=`, ya generator property `deb`/`debian`/`ubuntu`) | Nahi (OS deb ko Checkmarx C++ maanta hai) |
| `missing` | Purl nahi (CPE/hash only bhi) | Nahi |
| `malformed` | Purl parse nahi hota, ya npm scope `@` encode nahi (Checkmarx docs ke hisaab se match nahi hota) | Nahi |

`fixed` / `remapped` status changes ki chain se nikalta hai: final purl se peeche chalte hain (`after` → `before`). Isliye CSV mein **asli original purl** aur saare rule IDs order mein aate hain, jaise `CXP-001 CXP-013 CXP-005`.

### 4.2 Principles

1. **Supported purl ko chhedo mat.** `yarn`, `gradle`, `poetry` jaise aliases normalize nahi hote.
2. **Remap sirf evidence par.** Evidence ka matlab: generator property (`syft:package:type`, `aquasecurity:trivy:PkgType`, ...), `bom-ref` jo khud purl hai, ya registry URL qualifier. Sirf naam dekh kar guess kabhi nahi.
3. **Unsupported default mein rakhe jaate hain** (`unsupported_action: keep`), kyunki Checkmarx unhe waise bhi skip karta hai aur hatane se dependency graph toot-ta hai.
4. Har remap/strip par original purl `sbom-fixer:original-purl` property mein bachta hai (SPDX: package `comment` mein). CycloneDX 1.2 mein properties nahi hoti, wahan sirf changes.json mein.
5. CXP rules sirf un profiles mein chalte hain jinme `purl:` section ho (`checkmarx`, `checkmarx-cli`). `compliance` copy mein purl nahi badalte, sirf SAN-009 chalta hai.

### 4.3 Rules (`sbom_fixer/rules/sanitize_purl.py`, execution order)

| Rule | Trigger | Action | Severity |
|---|---|---|---|
| **CXP-001** | Type ya `pkg:` uppercase (`pkg:NPM/...`) | Lowercase (purl spec) | INFO |
| **CXP-002** | npm/yarn/bower namespace `@scope` | `%40scope` | INFO |
| **CXP-010** | `pkg:github/...` + Go evidence (property `go-module`/`gomod`/`gobinary`, ya bom-ref `pkg:golang/...`) | `pkg:golang/github.com/<owner>/<repo>@<v>` | INFO |
| **CXP-011** | `pkg:generic/...` + ecosystem hint property; target supported ho; Maven ke liye group zaroori | Ecosystem purl (name/group/version component se) | INFO |
| **CXP-012** | `pkg:generic/...` jiska `download_url`/`repository_url`/`vcs_url` known registry par ho (4.4) | Registry purl | INFO |
| **CXP-013** | Non-standard type: `nodejs`/`node` → npm, `dotnet`/`nupkg` → nuget, `jar` → maven (namespace ho to) | Type badlo | INFO |
| **CXP-003** | Supported purl bina version; component version hai (`unknown`/`NOASSERTION` nahi) | `@version` jodo. Version kahin nahi → finding: "checked against the latest version" | INFO / finding WARN |
| **CXP-004** | Maven-family purl bina namespace; component `group` hai | Namespace = group. Group nahi → finding | INFO / finding WARN |
| **CXP-005** | **Supported** purl mein URL-valued qualifier (`://`) ya subpath | Wo parts hatao, baaki qualifiers (jaise `type=jar`) rakho | INFO |
| **CXP-020** | Unsupported type (OS nahi) | keep: finding INFO; remove: component + dependency edges hatao | INFO / DATA_LOSS |
| **CXP-021** | OS package | keep: finding (deb → WARN "Checkmarx reads deb as C++"); remove: hatao | INFO/WARN / DATA_LOSS |
| **CXP-030** | Purl nahi, par CPE/SWID/hash hai | Finding. CPE se purl **nahi** banaya jaata (bharosemand nahi) | finding WARN |
| **CXP-051** | SPDX: koi `DESCRIBES`/`DEPENDS_ON`/`documentDescribes` nahi | Finding. Relationship invent **nahi** hoti | finding WARN |

SPDX ke liye wahi rules `packages[].externalRefs[referenceType=purl, referenceCategory=PACKAGE-MANAGER/PACKAGE_MANAGER].referenceLocator` par chalte hain. SPDX mein `remove` action support nahi hai; wahan unsupported components hamesha rakhe jaate hain.

`SAN-012` (purane generic "scanners usually ignore" notes) ab sirf bina `purl:` section wale profiles mein chalta hai.

### 4.4 Registry URL → purl (`purlmap.purl_from_url`, SAN-009 aur CXP-012 dono use karte hain)

| Host | Ecosystem | Example → result |
|---|---|---|
| `repo1.maven.org`, `repo.maven.apache.org`, `central.sonatype.com` | maven | `.../maven2/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar` → `pkg:maven/org.yaml/snakeyaml@2.2` |
| `registry.npmjs.org` | npm | `/@types/node/-/node-20.10.0.tgz` → `pkg:npm/%40types/node@20.10.0` |
| `files.pythonhosted.org`, `pypi.org` | pypi | `typing_extensions-4.9.0-py3-none-any.whl` → `pkg:pypi/typing-extensions@4.9.0`; `/project/Django/4.2.7/` → `pkg:pypi/django@4.2.7` |
| `api.nuget.org`, `www.nuget.org`, `nuget.org` | nuget | `/v3-flatcontainer/<id>/<ver>/...`, `/packages/<id>/<ver>` |
| `rubygems.org` | gem | `/gems/nokogiri-1.15.5-x86_64-linux.gem` → `pkg:gem/nokogiri@1.15.5` |
| `proxy.golang.org` | golang | `/github.com/!burnt!sushi/toml/@v/v1.3.2.zip` → `pkg:golang/github.com/BurntSushi/toml@v1.3.2` |
| `pub.dev`, `pub.dartlang.org` | pub | `/packages/http/versions/1.1.0` → `pkg:pub/http@1.1.0` |
| `github.com` (sirf SAN-009) | github | `/acme/widget` + component version → `pkg:github/acme/widget@2.0.0` (valid purl hai, par Checkmarx skip karta hai, CXP-020) |

Path pattern match na ho, ya version na mile, to **koi purl nahi banta**.

### 4.5 Jo fix nahi ho sakte

| Type | Notes / CSV mein reason | Recommendation (notes section 5) |
|---|---|---|
| `cargo`, `hex` | "not supported by the Checkmarx SBOM scan" | Doosre tool se scan karo (jaise cargo-audit) |
| `docker`, `oci` | "container image; use Checkmarx Container Security" | Container Security |
| `rpm`, `apk`, `alpm`, OS `deb` | "OS package ..." | Container/OS scanner |
| `generic` bina evidence, `github` (Actions/repos) | "no package registry" / "GitHub repository or action" | Generator se ecosystem purl likhwao |
| `conda`, `cran`, `hackage`, ... | "purl type 'X' is not recognized by Checkmarx" | – |

`conda` → `pypi` remap jaan-boojh kar nahi kiya: dono ke naam aur versions alag hote hain (`pytorch` vs `torch`).

### 4.6 Profile (`purl:` section)

```yaml
purl:
  supported_types:            # Checkmarx table 1.3, keys = Checkmarx package manager names
    NPM: [npm, yarn, bower]
    Python (Pip): [pip, python, pypi, poetry]
    # ... (full list in sbom_fixer/data/profiles/checkmarx.yaml)
  os_types: [rpm, apk, alpm]
  remap: true                 # CXP-010..013
  unsupported_action: keep    # keep | remove
  os_package_action: keep     # keep | remove
  strip_url_qualifiers: true  # CXP-005
  min_supported: 1            # fewer supported components -> exit 7 (0 = gate off)
```

---

## 5. PURL aur `https` — verification

User ka sawal tha ki shayad `https` wala purl kaam nahi karta. Ye teen alag cases hain, aur teeno packageurl-python 0.17.6 (tool ki library) aur purl spec par verify kiye gaye (`tests/test_purl_checkmarx.py`):

| Case | Example | Library kya karti hai | Checkmarx par asar | Fix |
|---|---|---|---|---|
| **A. purl field mein seedha URL** | `"purl": "https://registry.npmjs.org/axios/-/axios-1.6.2.tgz"` | **Parse fail**: `purl is missing the required "pkg" scheme component` | Checkmarx ise invalid purl maan kar component skip karta hai. Saare purls aise hon to scan error | **SAN-009**: registry URL → `pkg:npm/axios@1.6.2`. Doosra URL → `externalReferences` (`distribution`, ya GitHub/GitLab/Bitbucket ke liye `vcs`), aur purl hata diya jaata hai (WARN) |
| **B. Qualifier mein URL** | `pkg:maven/org.slf4j/slf4j-api@2.0.9?repository_url=https://repo.example.com/maven2` | Parse **OK**. `to_string()` value ko **bina encode** kiye `https://...` likhta hai | Checkmarx docs ka format `pkg:type/[namespace/]name@version` hai aur matching name+version se hoti hai, isliye qualifier ki zaroorat nahi. Unencoded `://` kisi strict parser ko tod sakta hai | **CXP-005** (sirf supported types): URL wale qualifiers hatao, baaki rakho; original property mein |
| **C. Subpath mein URL** | `pkg:npm/lodash@4.17.21#https://x` | Parse OK, par subpath bigad kar `https:/x` ban jaata hai | Bekaar data | **CXP-005**: subpath hatao |

Pehle (is fix se pehle) case A mein SAN-010 percent-encoding try karta tha, fail hone par **purl hata deta tha**. Component chupchaap scan se bahar ho jaata tha aur URL ka data bhi chala jaata tha. Ab SAN-009, SAN-010 se pehle chalta hai.

NTIA check (`audit/ntia.py`) ab purl ko "Unique identifier" tabhi ginta hai jab wo parse ho. URL ko identifier ginna galat tha.

**Kya verify nahi hua:** asli Checkmarx tenant par upload, kyunki is environment se tenant access nahi hai. Matrix mein `corpus/purl/format-fixes.cdx.json` ka original (CXP-005 se pehle wala) aur fixed, dono upload karke package count milao (section 8.3).

---

## 6. Default tool (SAN-013)

- Trigger: profile mein `ensure_tools: true` (`checkmarx`, `checkmarx-cli`), aur
  - CycloneDX: `metadata.tools` nahi hai, ya khaali hai (`[]`, `{}`, `{"components": []}`)
  - SPDX: `creationInfo.creators` mein koi `Tool:` entry nahi
- Kya add hota hai (version ke hisaab se sahi form):
  - CycloneDX 1.5+: `{"components": [{"type": "application", "name": "sbom-fixer", "version": "<ver>"}]}`
  - CycloneDX 1.3/1.4, ya `tools_form: legacy-array`: `[{"vendor": "sbom-fixer", "name": "sbom-fixer", "version": "<ver>"}]`
  - SPDX: `"Tool: sbom-fixer-<ver>"` creators mein append
- Default tool **sbom-fixer** hi kyun: asli generator ka naam file mein nahi hai, aur koi aur naam likhna fabrication hoga. sbom-fixer ne file badli hai, isliye wahi sahi "tool" hai.
- SAN-090 (provenance) ab sbom-fixer ko dobara add nahi karta, agar SAN-013 pehle add kar chuka ho.
- Note: CycloneDX mein `metadata.tools` optional hai, aur Checkmarx docs ise mandatory nahi kehte. Ye ek defensive fix hai jo `ensure_tools: false` se band ho sakta hai.

---

## 7. Reporting

### 7.1 changes.json

Har edit ek entry hai (rule_id, path, action, before, after, severity, reason, level). Naya top-level key:

```json
"checkmarx_coverage": {
  "before": {"total": 6, "scanned": 0, "by_status": {...}, "by_type": {"github": 2, "generic": 3, "nodejs": 1}},
  "after":  {"total": 6, "scanned": 4, "by_status": {"remapped": 4, "unsupported": 2, ...}, "by_type": {...}}
}
```

Findings (jahan file nahi badli: CXP-020/021 keep, CXP-003/004 without data, CXP-030, CXP-051) `findings` mein jaate hain.

### 7.2 notes.txt (real output, `corpus/purl/remap.cdx.json`)

```
Fix type        : C (importer-specific fixes)
1. WHY THE ORIGINAL FAILED
   The original was valid against its declared version, but:
   [purl]      Checkmarx would scan 0 of 6 components of the original (after the fix: 4 of 6).
   [CXP-010]    1 x github purl of a Go module remapped to golang
   [CXP-011]    1 x generic purl remapped from the generator's package type
   [CXP-012]    1 x generic purl remapped from its registry URL
   [CXP-013]    1 x Non-standard purl type with one meaning

4. SCAN COVERAGE (Checkmarx)
   Components in output                : 6
   Scanned by Checkmarx                : 4   (66.7%)
     ...
   By purl type:
     type            count  Checkmarx package manager   status
     ...
   Expected package count in Checkmarx results: about 4

6. COMPONENTS CHECKMARX WILL SKIP
   /components/1      checkout v4     pkg:github/actions/checkout@v4     GitHub repository or action, not a registry package
   /components/4      internal-lib    pkg:generic/internal-lib@1.0.0     no package registry; cannot be matched
```

Exit 7 par header mein: `WARNING : no component has a purl type Checkmarx supports; Checkmarx would fail the scan ('no valid PURLs'). Do not upload`.

### 7.3 `<name>.<profile>.purl-coverage.csv`

Columns: `path, bom_ref, name, version, original_purl, final_purl, purl_type, checkmarx_pm, status, rule_ids, reason`. Har component ki ek row.

### 7.4 Verify

`fix --verify` mein `--expected-packages` na diya ho to default = "Scanned by Checkmarx" count. Exit 7 par upload skip hota hai.

---

## 8. Tests

### 8.1 Corpus (`tools/make_corpus.py` generate karta hai, `corpus/expected.yaml`)

| File | Expected (profile `checkmarx`) |
|---|---|
| `minimal/min-cdx-1.6.json`, `min-cdx-1.7.json` | exit 0, version same |
| `cdxgen/analytics.cdxgen.json` (1.7), `cdxgen/crypto.cdx.json`, `trivy/payments-api.trivy.json` (1.6) | exit 0, version same |
| `future/min-cdx-1.8.json` | exit 1, 1.8 → 1.7, CDX-FWD-001/002/003 |
| `future/min-cdx-2.0.json` | exit 2 |
| `purl/mixed-types.cdx.json` | Saare 12 package managers ke aliases + rpm/apk/deb/cargo/hex/docker/conda: exit 0, 14 of 21 scanned |
| `purl/format-fixes.cdx.json` | CXP-001..005 |
| `purl/remap.cdx.json` | CXP-010..013; GitHub Action aur generic bina evidence wale rakhe jaate hain |
| `purl/url-purls.cdx.json` | SAN-009 (npm, maven, github URL → purl; unknown URL → externalReferences) |
| `purl/none-supported.cdx.json` | exit 7 |
| `purl/no-tools.cdx.json` | SAN-013 |
| `purl/spdx-issues.spdx.json` | CXP-001, SAN-013, finding CXP-051 |

Har corpus file par invariants check hote hain: output schema-valid, JSON Patch original ko output mein badalta hai, NTIA mein regression nahi, aur output par dobara chalane se koi change nahi (exit 7 file dobara bhi 7 deti hai).

### 8.2 Unit tests

- `tests/test_purl_checkmarx.py` (83 cases): har supported alias unchanged; har CXP rule ka positive aur negative case (bina evidence remap nahi, maven bina group nahi, `unknown` version use nahi, unsupported purl ke qualifiers nahi chhede jaate); remove actions aur dependency edges; SAN-009 ke 17 URL patterns; SAN-013 1.4/1.6/SPDX forms aur duplicate-free provenance; coverage chain; CSV; exit 7; CLI; profile validation.
- `tests/test_future.py` (19 cases): 1.6/1.7 keep in every profile and command, `--accepted` cap 1.7 → 1.6, future hop (scalar/object property, no-properties parent, 4 KB limit, enum → other, enum without other), 1.8 → 1.7 → 1.6 in cli, reject profile, 2.0 refused, end-to-end notes, read-only `check`, profile validation.
- Poora suite: **235 passed**, `ruff` clean, `mypy` clean.

### 8.3 Checkmarx tenant par abhi baaki

1. `docs/checkmarx-matrix.md`: `min-cdx-1.7.json` portal aur CLI par. Portal reject kare to `checkmarx.yaml` se 1.7 hatao.
2. `corpus/purl/mixed-types.cdx.json` upload karo. Checkmarx ka package count notes ke "Expected package count" (14) se milna chahiye. Isse docs ki type table tenant par confirm hogi.
3. `corpus/purl/format-fixes.cdx.json` ka original aur `sbom-fixer fix` wala output, dono upload karo. Original mein `@angular` scope wala package aur `repository_url=https://` wala package result mein na aayein, aur fixed mein aayein, to CXP-002/CXP-005 Checkmarx par bhi sahi saabit honge.
4. Ek `pkg:deb/debian/...` wala SBOM upload karke dekho. Iske result se `os_package_action` ka default decide hoga.

---

## 9. Exit codes

| Code | Meaning |
|---|---|
| 0 | Already compatible; output identical to input |
| 1 | Fixed |
| 2 | Cannot fix (ab isme CycloneDX 2.x aur `future_versions: reject` bhi aate hain) |
| 3 | DATA_LOSS with `allow_data_loss: false` |
| 4 | Quality gate failed |
| 5 | Checkmarx verification failed |
| 6 | Bisect inconclusive |
| **7** | **Fixed, but no component has a purl type the profile supports; Checkmarx would fail the scan. Do not upload.** |

---

## 10. Files

| File | Change |
|---|---|
| `sbom_fixer/data/profiles/checkmarx.yaml` | 1.3–1.7, `max_version`, `future_versions`, `ensure_tools`, `purl:` |
| `sbom_fixer/data/profiles/checkmarx-cli.yaml` | NEW: cx CLI / Jenkins profile, 1.3–1.7 (pehle 1.6 cap) |
| `sbom_fixer/profile.py` | `PurlPolicy`, `max_version`, `future_versions`, `ensure_tools`, validation |
| `sbom_fixer/schemas.py` | `version_key`, `is_future` |
| `sbom_fixer/descent.py` | Future hop branch |
| `sbom_fixer/rules/cdx_future.py` | NEW: CDX-FWD-001/002/003 |
| `sbom_fixer/purlmap.py` | NEW: registry URL → purl, slots (CycloneDX + SPDX), coverage classification, CSV |
| `sbom_fixer/rules/sanitize_purl.py` | NEW: CXP-* |
| `sbom_fixer/rules/sanitize.py` | SAN-009, SAN-013, SAN-012 gate, SAN-090 dedupe |
| `sbom_fixer/audit/ntia.py` | Identifier = parseable purl |
| `sbom_fixer/notes.py` | Checkmarx sections 1/4/6, exit 7 warning, fix type |
| `sbom_fixer/pipeline.py` | Coverage, CSV, `checkmarx_coverage`, exit 7 |
| `sbom_fixer/cli.py` | Verify skip on 7, default expected packages |
| `jenkins/sbom-fix-stage.groovy` | `checkmarx-cli` profile aur file name |
| `tools/make_corpus.py`, `corpus/` | New cases, updated expectations |
| `tests/test_purl_checkmarx.py`, `tests/test_future.py` | NEW |
| `README.md`, `CHANGELOG.md`, `docs/rule-catalog.md` | Updated |

---

## 11. Open questions

| # | Question | Default jab tak decide na ho |
|---|---|---|
| Q1 | Portal 1.7 accept karta hai? | `checkmarx` = 1.7, CI = `checkmarx-cli` |
| Q2 | OS `deb` packages rakhein ya hataayein? | keep + WARN |
| Q3 | Unsupported components hataane hain? | keep |
| Q4 | Cargo/hex ke liye alag scanner? | Notes mein recommendation |
| Q5 | Package version bump (CHANGELOG "Unreleased", ADR-09 ke hisaab se minor) | Release ke waqt `__version__`, Dockerfile tag aur wheelhouse saath mein |

---

## Sources

- [Checkmarx One – Scanning SBOMs](https://docs.checkmarx.com/en/34965-728599-scanning-sboms.html): formats, PURL requirements, supported/unsupported PURL types, SPDX relationships, troubleshooting
- [SCA Scanner – Supported Languages and Package Managers](https://docs.checkmarx.com/en/34965-322679-sca-scanner---supported-languages-and-package-managers.html)
- [Checkmarx One SBOM Reports](https://docs.checkmarx.com/en/34965-388392-checkmarx-one-sbom-reports.html): portal 1.7 / CLI 1.6
- [Checkmarx One CLI – scan](https://docs.checkmarx.com/en/34965-68643-scan.html)
- [package-url specification](https://github.com/package-url/purl-spec): types, npm scope encoding, qualifiers
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
