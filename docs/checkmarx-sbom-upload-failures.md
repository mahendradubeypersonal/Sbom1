# Checkmarx One par SBOM upload kyun fail hota hai — detailed analysis

> Date: 2026-10-05
> Scope: Checkmarx One portal (UI), `cx` CLI aur REST API se SBOM scan
> Sources: Checkmarx official docs + release notes (links neeche "Sources" mein). Jo baatein docs mein seedhi likhi hain unhe **[Docs]** se mark kiya hai; jo SBOM spec / parser behaviour / field experience se nikali hain unhe **[Inferred]** se mark kiya hai, taaki pata rahe ki kis par kitna bharosa karna hai.

---

## 1. Short answer

"Correct SBOM" ka matlab do alag cheezein hain:

1. **Spec-valid** — CycloneDX/SPDX schema ke against valid hai (jaise `cyclonedx validate` pass ho jaata hai).
2. **Checkmarx-acceptable** — Checkmarx ka importer use padh sake, uske packages pehchaan sake, aur SCA scanner un par result de sake.

Ye dono ek cheez nahi hain. Ek SBOM jo pehli condition pass karta hai, wo dusri mein fail ho sakta hai. Teen bade reason hain:

- Checkmarx ki **apni extra requirements** hain jo spec mein mandatory nahi hain (har package par `purl`, sirf "manual" project, kuch hi versions).
- **Portal, CLI aur API ke supported versions alag-alag hain**, aur Checkmarx releases ke saath badle hain.
- Bahut si failures **file ke content ki wajah se nahi**, balki file ki **encoding, project type, scanner selection, ya platform bug** ki wajah se hoti hain.

---

## 2. Checkmarx ki official requirements [Docs]

Ye sab Checkmarx One docs ("Scanning SBOMs" / "Scanning Projects" / CLI `scan` page) mein likha hai:

| # | Requirement | Docs mein kya likha hai |
|---|---|---|
| R1 | **Format** | "Scanning SBOMs" page (2026-10-05): CycloneDX 1.0–1.6 (JSON, XML), SPDX 2.2/2.3 (**sirf JSON**). Purane search results mein "1.0–1.7 / SPDX 2.3" dikhta tha |
| R2 | **purl mandatory** | Sirf valid PURL wale components analyze hote hain; bina PURL wale chupchaap skip. Ek bhi valid PURL nahi → scan error. Supported/unsupported types ki list `docs/checkmarx-version-purl-fix.md` section 1.3/1.4 mein hai |
| R3 | **Sirf SCA scanner** | "Only the SCA scanner can run on an SBOM" |
| R4 | **Sirf manual project** | SBOM scan sirf "manual" project par chalega, code-repository integration (GitHub/GitLab/Bitbucket se juda project) par nahi |
| R5 | **SPDX direct deps** | SPDX mein main component ke SPDXID par `DESCRIBES` ya `DEPENDS_ON` relationship deni chahiye; nahi di to saare packages "direct" dikhenge |
| R6 | **Portal mein source type** | "Source to Scan" mein **SBOM** select karna padta hai, phir file drag ya "Select File" |
| R7 | **CLI/portal version gap** | Release notes ke hisaab se CLI CycloneDX **v1.6** aur SPDX v2.3 support karta hai, jabki web portal CycloneDX **v1.7** aur SPDX v2.3 |
| R8 | **SPDX 2.2** | Version 3.45 (14 Sep 2025) mein SPDX 2.3 add hua; SBOM submit karte waqt ab 2.2 aur 2.3 dono chalte hain |
| R9 | **Platform bug fix** | Version 3.48 (16 Nov 2025) mein "SBOM-only scans failed to execute" wala issue fix hua |

Docs mein hi ek conflict dikhta hai: ek jagah sirf "SPDX v2.3" likha hai aur release notes mein "2.2 aur 2.3". Isi tarah CycloneDX ke liye "1.0–1.7" likha hai, par CLI ke liye 1.6 bataya gaya hai. **Matlab aapke tenant / CLI version par jo behaviour hai wahi asli sach hai.** Isliye repo mein `docs/checkmarx-matrix.md` ka matrix bharna zaroori hai.

---

## 3. Failure cases — ek-ek karke

Har case mein: **kya hota hai**, **SBOM mein kya issue hota hai**, **kaise pakdein**, **kaise theek karein**.

### Category A — Upload / project level (SBOM ka content theek ho tab bhi fail)

#### A1. Project "manual" nahi hai [Docs]
- **Kya hota hai:** Jo project GitHub/GitLab/Bitbucket/Azure repo integration se bana hai, usme SBOM option nahi aata, ya scan fail ho jaata hai.
- **SBOM mein issue:** Koi nahi. Masla project type ka hai.
- **Fix:** Ek alag **manual project** banao (jaise `myapp-sbom`) aur SBOM wahin upload karo.

#### A2. Galat source type ya galat scanner select hua [Docs]
- **Kya hota hai:** File ko "Upload File / Zip" ki tarah upload kiya, ya SAST/KICS/API Security bhi enable rakha. SAST ko JSON file mein source code nahi milta, to scan "Failed" ya "Partial" ho jaata hai.
- **Fix:** Portal mein **Source to Scan = SBOM** chuno aur sirf **SCA** scanner rakho. CLI mein `--scan-types sca`.

#### A3. CLI aur portal ka version gap [Docs]
- **Kya hota hai:** CycloneDX **1.7** file portal par chal jaati hai par `cx` CLI (ya CLI pe chalne wale Jenkins/GitHub Action) se fail hoti hai, kyunki CLI 1.6 tak hi support karta hai.
- **SBOM mein issue:** `"specVersion": "1.7"`.
- **Fix:** CLI ke liye 1.6 (ya 1.5) par downgrade karo. Repo ka tool yahi karta hai: `sbom-fixer fix sbom.json --accepted 1.5,1.6`.

#### A4. Purana CLI / purana tenant release [Docs + Inferred]
- **Kya hota hai:** 3.45 se pehle SPDX 2.3 nahi chalta tha; 3.48 se pehle SBOM-only scan platform bug ki wajah se fail ho sakta tha.
- **Fix:** `cx version` check karo aur latest CLI use karo. Tenant release purana ho to Checkmarx support / admin se poochho.

#### A5. Network / timeout / bade file [Docs + Inferred]
- **Kya hota hai:** Upload beech mein toot jaata hai, ya scan "queued" mein atak kar timeout ho jaata hai.
- **SBOM mein issue:** File bahut badi hai (lakhon components, embedded license text, base64 hashes, `vulnerabilities` section).
- **Fix:** CLI mein client timeout badhao; SBOM se `vulnerabilities`, license `text`, `signature` jaise bhaari fields hatao (SCA apne findings khud nikalta hai).

#### A6. Permissions [Inferred]
- **Kya hota hai:** User ke paas project par scan create karne ka role nahi, ya API key ka scope chhota hai → upload ke waqt 401/403.
- **Fix:** IAM mein role check karo (scan create + project access).

---

### Category B — File / encoding level (dekhne mein JSON theek, par parser ke liye nahi)

#### B1. UTF-8 BOM ya UTF-16 encoding [Inferred — bahut common]
- **Kya hota hai:** File editor mein bilkul theek dikhti hai, `cyclonedx validate` bhi kabhi-kabhi pass kar deta hai, par Checkmarx parse nahi kar paata.
- **SBOM mein issue:** File ki shuruaat mein invisible bytes `EF BB BF` (UTF-8 BOM) ya `FF FE` (UTF-16). **Windows PowerShell 5.1 mein `>` ya `Out-File` se SBOM likhne par UTF-16 file banti hai.**
- **Kaise pakdein:** `head -c 4 sbom.json | xxd`
- **Fix:** UTF-8 **without BOM** mein save karo. `> sbom.json` mat use karo; generator ka `-o` / `--output-file` flag use karo.

#### B2. Galat extension ya galat content-type [Inferred]
- **Kya hota hai:** `.txt`, `.bom`, `.cdx` jaisa extension, ya JSON ko `.xml` naam se upload kiya. Importer format detect nahi kar paata.
- **Fix:** `.json` (CycloneDX/SPDX JSON) ya `.xml` (CycloneDX XML) use karo, aur extension content se match hona chahiye. `bom.cdx.json` / `sbom.spdx.json` jaisa naam safe hai.

#### B3. Ek file mein ek se zyada SBOM / JSON Lines / wrapper object [Inferred]
- **Kya hota hai:** Kuch tools (Trivy ke kuch modes, custom scripts) SBOM ko `{"Results": ...}` ya `{"sbom": {...}}` ke andar lapet dete hain, ya ek file mein kai JSON objects daal dete hain.
- **SBOM mein issue:** Root par `bomFormat` / `spdxVersion` hi nahi hai.
- **Fix:** Root object khud SBOM hona chahiye. Kai SBOMs ko `cyclonedx merge` se ek karo.

#### B4. SPDX tag-value, SPDX 3.0 (JSON-LD), CycloneDX protobuf [Docs + Inferred]
- **Kya hota hai:** Ye formats supported list mein nahi hain, to reject ho jaate hain.
- **Fix:** SPDX 2.3 JSON ya CycloneDX JSON/XML mein convert karo (repo mein `corpus/unsupported/spdx3.jsonld` isi case ka example hai).

---

### Category C — Version / schema level

#### C1. specVersion jo tenant support nahi karta [Docs]
- CLI par 1.7 (A3 dekho). CycloneDX 1.2 ya usse purani files bhi problem kar sakti hain, kyunki unme purl ka support kamzor tha.
- **Fix:** 1.5 sabse safe target hai — har jagah chalta hai aur fields bhi kaafi hain.

#### C2. `$schema` aur `specVersion` mismatch [Inferred]
- `"$schema": ".../bom-1.6.schema.json"` par `"specVersion": "1.5"`. Strict parser reject kar deta hai.
- **Fix:** Dono ek hi version ke hone chahiye (sbom-fixer rule `REP-001`).

#### C3. `specVersion` string ki jagah number [Inferred]
- `"specVersion": 1.5` (number) — schema ke hisaab se invalid hai, ise string hona chahiye.
- **Fix:** `"specVersion": "1.5"` (`REP-002`).

#### C4. Version-specific fields galat version mein [Inferred]
Ye sabse confusing case hai: file "correct" lagti hai par jo version declare kiya hai uske schema mein woh field hai hi nahi.

| Field | Kis version mein aaya | Agar purane version mein likha |
|---|---|---|
| `metadata.tools` object form `{components, services}` | 1.5 | 1.4 ya usse purane mein invalid |
| `metadata.lifecycles`, `formulation`, `annotations` | 1.5 | 1.4 mein invalid |
| `component.authors[]`, `component.manufacturer`, `metadata.manufacturer` | 1.6 | 1.5 mein invalid |
| `declarations`, `definitions`, `cryptographic-asset` type | 1.6 | 1.5 mein invalid |
| `evidence.identity` as array | 1.6 | 1.5 mein object hona chahiye |
| `versionRange`, `isExternal`, patent assertions | 1.7 | 1.6 (CLI) mein invalid |
| `primaryPackagePurpose`, `releaseDate`, `builtDate` | SPDX 2.3 | SPDX 2.2 mein invalid |

- **Fix:** `sbom-fixer check sbom.json` batata hai kaunsa field kis version ka hai; `sbom-fixer fix` safe downgrade karta hai.

#### C5. Basic schema errors [Inferred]
Generators (especially custom scripts aur vendor tools) aksar ye galtiyaan karte hain:
- `null` values (`"version": null`) — kisi bhi SBOM schema mein valid nahi.
- Galat enum casing: `"type": "Library"` (sahi: `"library"`), hash alg `"sha256"` (sahi: `"SHA-256"`).
- `serialNumber` `urn:uuid:` format mein nahi.
- `timestamp` ISO-8601 nahi (`"2025-01-01 10:00"`).
- License mein `id` aur `name` dono saath, ya non-SPDX `id` (`"id": "Apache 2.0"`).
- Hash ki length algorithm se match nahi karti.
- URL mein space ya illegal characters.
- Array ki jagah single value.

---

### Category D — Content level (upload ho jaata hai, par result 0 ya galat)

Ye category sabse zyada dhokha deti hai: **portal "Completed" dikhata hai, par packages 0 ya bahut kam hote hain, ya koi vulnerability nahi dikhti.** Log ise "upload fail" hi samajhte hain.

#### D1. purl missing [Docs — sabse important]
- Checkmarx ke liye har package par purl **mandatory** hai. Jin components mein `purl` nahi hai, unhe SCA match nahi kar paata, to woh results mein nahi aate. Agar saare components bina purl ke hain to scan fail hota hai ya 0 packages aate hain.
- **Typical source:** Vendor SBOMs, OS-level SBOMs, `sbom-tool` (Microsoft) ke kuch outputs, hand-written SBOMs, SPDX jisme `externalRefs` mein `PACKAGE-MANAGER`/`purl` nahi hai.
- **SPDX mein purl kahan hona chahiye:**
  ```json
  "externalRefs": [{
    "referenceCategory": "PACKAGE-MANAGER",
    "referenceType": "purl",
    "referenceLocator": "pkg:npm/lodash@4.17.21"
  }]
  ```
- **Kaise pakdein:** `jq '[.components[] | select(.purl == null)] | length' sbom.json`
- **Fix:** Generator mein purl enable karo; nahi to sbom-fixer `SAN-011` jahan ecosystem pakka ho wahan purl banata hai, baaki ko "not scannable" report karta hai.

#### D2. purl invalid / parse nahi hota [Inferred]
- Examples: `pkg:npm/@angular/core@15.0.0` (scope ka `@` encode nahi hua: sahi hai `pkg:npm/%40angular/core@15.0.0`), purl mein space, version missing (`pkg:maven/org.foo/bar`), galat type (`pkg:java/...`, `pkg:nodejs/...`).
- **Fix:** purl spec ke hisaab se percent-encode karo (`SAN-010`).

#### D3. purl type jise Checkmarx support nahi karta [Docs]
- Docs mein list hai. Supported: npm/yarn/bower, pip/python/pypi/poetry, nuget, maven/sbt/ivy/gradle, php/composer, ios/swift/swiftpm/carthage/cocoapods, go/golang/gomodules, conan/cpp/deb, gem/ruby/rubygems, unity, perl/cpan, dart/pub.
- **Silently skip hone wale:** `rpm`, `apk`, `generic`, `docker`, `cargo`, `hex`, aur list ke bahar ka har type (jaise `github`, `oci`). Upload ho jaata hai par ye packages result mein nahi aate, aur koi error bhi nahi dikhta.
- `deb` ko Checkmarx **C++ (Conan)** maanta hai, OS package nahi.
- **Fix:** `docs/checkmarx-version-purl-fix.md` (remap rules CXP-010..013, aur coverage report).

#### D4. Nested components [Inferred]
- CycloneDX mein `components[].components[]` (nested) valid hai, par kai importers sirf top-level `components` padhte hain → andar wale packages gayab ho jaate hain.
- **Fix:** Sabko top-level par flatten karo (`SAN-050`).

#### D5. Duplicate `bom-ref` / tooti dependency graph [Inferred]
- Do components ka ek hi `bom-ref`, ya `dependencies[].ref` / `dependsOn` mein aisa ref jo document mein hai hi nahi. Strict parser poora file reject kar deta hai; lenient parser direct/transitive galat dikhata hai.
- **Fix:** `SAN-020` (duplicates rename), `SAN-021` (dangling edges hatao).

#### D6. Direct vs transitive galat (SPDX) [Docs]
- Main package par `DESCRIBES` / `DEPENDS_ON` nahi hai → Checkmarx saare packages ko "direct" dikhata hai. Upload fail nahi hota, par report galat hoti hai aur remediation guidance bigad jaati hai.
- **Fix:** `SPDXRef-DOCUMENT DESCRIBES SPDXRef-<root>` aur root se `DEPENDS_ON` edges do.

#### D7. Root component / metadata.component missing (CycloneDX) [Inferred]
- `metadata.component` nahi hai, to direct dependencies decide nahi ho paati, aur project/application ka naam bhi nahi aata.
- **Fix:** Generator mein root component set karo.

#### D8. Version missing ya "unknown" [Inferred]
- Bina version ke package ko vulnerability database se match karna mumkin nahi; CycloneDX 1.3 mein to version mandatory hi hai.
- **Fix:** Version purl se le lo (`CDX14-001`), ya source build se nikaalo.

---

### Category E — Signed / tampered files

#### E1. Signature wala SBOM edit kiya gaya [Inferred]
- CycloneDX `signature` (JSF) ya enveloped signature hai aur kisi ne file edit kar di → signature invalid. Kuch pipelines isse reject kar deti hain.
- **Fix:** Edit ke baad signature hatao ya dobara sign karo (`SAN-060`).

---

## 4. "Correct SBOM phir bhi fail" — top 10 suspects (priority order)

Field mein sabse zyada yahi milte hain:

1. **Project manual nahi hai** ya scanner mein SCA ke alawa bhi kuch selected hai (A1, A2)
2. **purl missing** — kuch ya saare components par (D1)
3. **CycloneDX 1.7 file CLI/pipeline se** upload ki (A3)
4. **UTF-8 BOM / UTF-16** — Windows/PowerShell se bani file (B1)
5. **Version-specific field galat version mein** — jaise 1.4 file mein tools object (C4)
6. **Invalid purl** — scoped npm packages ka `@` encode nahi (D2)
7. **Nested components** — top-level par kuch nahi (D4)
8. **Duplicate bom-ref / dangling dependency refs** (D5)
9. **Unsupported format** — SPDX tag-value, SPDX 3.0, wrapper JSON (B3, B4)
10. **Purana CLI / tenant release** (A4)

---

## 5. Debug checklist (upload se pehle)

```bash
# 1. Encoding: pehle 3 bytes "EF BB BF" ya "FF FE" nahi hone chahiye
head -c 4 sbom.json | xxd

# 2. Valid JSON hai?
jq empty sbom.json

# 3. Format aur version
jq '{bomFormat, specVersion, spdxVersion, schema: ."$schema"}' sbom.json

# 4. Kitne components bina purl ke (CycloneDX)
jq '[.components[]? | select(.purl == null)] | length' sbom.json

# 5. Kitne packages bina purl ke (SPDX)
jq '[.packages[] | select(([.externalRefs[]? | select(.referenceType=="purl")] | length) == 0)] | length' sbom.json

# 6. Nested components hain?
jq '[.components[]? | select(.components != null)] | length' sbom.json

# 7. Duplicate bom-ref
jq '[.components[]."bom-ref"] | group_by(.) | map(select(length>1)) | length' sbom.json

# 8. Schema validation (official CycloneDX CLI)
cyclonedx validate --input-file sbom.json --fail-on-errors

# 9. Repo ka tool: errors cause ke hisaab se grouped, aur fix ka version path
sbom-fixer check sbom.json
```

Portal / CLI side:
- [ ] Project type **manual** hai
- [ ] Source to Scan = **SBOM**
- [ ] Scanner sirf **SCA**
- [ ] CLI hai to `cx version` latest hai aur file ≤ CycloneDX 1.6 hai
- [ ] Scan fail hone par **Scan → Logs / scan details** mein SCA ka exact error message dekho (CLI mein exit code 3 = SCA scanner fail)

Agar sab theek hai aur phir bhi fail ho raha hai, to `sbom-fixer bisect failing.json` chalao. Ye file ko chhota karte hue woh field dhoondhta hai jiski wajah se Checkmarx reject kar raha hai.

---

## 6. Recommendation

1. **Target format fix karo:** CycloneDX **1.5 JSON, UTF-8 without BOM, flat components, har component par valid purl.** Ye portal aur CLI dono par chalta hai.
2. **Pipeline mein `sbom-fixer fix` lagao** upload se pehle — ye upar ke Category B, C aur zyada tar D cases automatically theek karta hai aur har change rule ID ke saath report karta hai.
3. **`docs/checkmarx-matrix.md` bharo** — apne tenant par `corpus/minimal/` ki files upload karke. Docs aur release notes khud ek-dusre se match nahi karte (section 2), isliye sirf tenant ka actual behaviour bharosemand hai.
4. **"Completed but 0 packages" ko bhi failure maano** — `sbom-fixer fix --verify --expected-packages N` se package count check karo.

---

## Sources

- [Checkmarx One – Scanning SBOMs](https://docs.checkmarx.com/en/34965-728599-scanning-sboms.html)
- [Checkmarx One – Scanning Projects](https://docs.checkmarx.com/en/34965-68557-scanning-projects.html)
- [Checkmarx One CLI – scan command](https://docs.checkmarx.com/en/34965-68643-scan.html)
- [Running Scans via the CLI](https://docs.checkmarx.com/en/34965-350124-running-scans-via-the-cli.html)
- [Checkmarx One SBOM Reports](https://docs.checkmarx.com/en/34965-388392-checkmarx-one-sbom-reports.html)
- [Checkmarx One Release Notes – Version 3.45 (Sep 14, 2025)](https://docs.checkmarx.com/en/34965-433529-version-3-45---september-14,-2025.html)
- [Checkmarx One Release Notes – Version 3.48 (Nov 16, 2025)](https://docs.checkmarx.com/en/34965-481862-version-3-48---november-16,-2025.html)
- [Checkmarx One API – Upload Source](https://docs.checkmarx.com/en/34965-68781-checkmarx-one-api---upload-source.html)
- [Checkmarx SCA FAQ](https://docs.checkmarx.com/en/34965-19101-faq.html)
- [SCA Scanner](https://docs.checkmarx.com/en/34965-322318-sca-scanner.html)
- [CycloneDX Tool Center](https://cyclonedx.org/tool-center/)
- [CycloneDX CLI (validate)](https://github.com/CycloneDX/cyclonedx-cli)
