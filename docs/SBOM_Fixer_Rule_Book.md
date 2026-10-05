# SBOM Fixer Rule Book

Installation, daily use and rule reference for `sbom-fixer` 1.0.0. Follow the steps in order on a new machine; after that, Step 08 is the everyday workflow.

| Item | Value |
|---|---|
| Tool | `sbom-fixer` 1.0.0 (Python command-line tool) |
| What it does | Repairs SBOMs at their declared version, steps down one version only when needed, and explains every change |
| Works on | Windows 10/11, Linux, macOS, or any machine with Docker |
| Needs | Python 3.11 or newer (3.12 recommended); internet only for installing packages |
| Source folder | `sbom-fixer` (README.md, CHANGELOG.md, docs/ inside it) |

---

## Contents

---

## Step 01 – What sbom-fixer does

Checkmarx rejects many SBOMs without a clear error. The cause is almost always a schema mismatch, which can be one of three cases:

| Case | What is wrong | What the tool does |
|---|---|---|
| A. Same-version error | The file is invalid against the version it declares (wrong case, null values, bad dates, broken licenses) | Repairs it at the same version |
| B. Unsupported version | The file is valid, but Checkmarx does not import that version (for example CycloneDX 1.6) | Steps down one version at a time until a version is accepted |
| C. Importer needs | The file is valid and supported but still fails or imports nothing (no purls, duplicate refs, UTF-16) | Applies Checkmarx-specific clean-ups |

For every SBOM the tool runs this loop:

1. Start at the version the SBOM declares.
2. Repair what can be repaired, remove fields the schema does not allow, and apply the clean-ups.
3. If the file is now valid and the version is accepted, stop. The version does not change.
4. If not, go one version lower (for example 1.6 to 1.5), convert the fields that changed between those versions, and go back to step 2.
5. If even the lowest allowed version (the floor) is not OK, stop with exit code 2 and report every attempt.

Every change is recorded with a rule ID. The diff, the notes file and the change log are all generated from that record.

> **Golden rule:** The tool never guesses. When the correct value is not certain (for example the license name "BSD", which could mean two different licenses), it leaves the value and reports it for review.

---

## Step 02 – Check the prerequisites on the new machine

Open a terminal and run the checks below.

| Need | Check command | Expected |
|---|---|---|
| Python 3.11 or newer | `python --version` (Windows may also have `py --version`) | `Python 3.11.x` or higher |
| pip | `python -m pip --version` | A pip version is printed |
| Internet or an internal package mirror | `python -m pip download --no-deps -d %TEMP% typer` | Download succeeds |
| Git (only to clone the repository) | `git --version` | A git version is printed |
| Docker (optional, Step 06) | `docker --version` | A docker version is printed |
| Checkmarx `cx` CLI (optional, Step 12) | `cx version` | A cx version is printed |
| sbomqs (optional, Step 13) | `sbomqs version` | A sbomqs version is printed |

If Python is missing on Windows:

1. Download Python 3.12 from python.org, or install it from the company software portal.
2. In the installer, tick **Add python.exe to PATH**.
3. Close and reopen the terminal, then run `python --version` again.

> **Corporate proxy:** If pip cannot reach the internet, set the proxy for the session (`set HTTPS_PROXY=http://proxy.company:8080` in cmd) or use the offline install in Step 04.6.

---

## Step 03 – Get the code onto the machine

Use one of these options.

**Option A – Git (recommended once the repository is in Bitbucket):**

```bash
git clone <bitbucket-url>/sbom-fixer.git
cd sbom-fixer
```

**Option B – Copy the folder:**

1. On the machine that has the tool, zip the `sbom-fixer` folder **without** the `.venv` folder (and without `.mypy_cache`, `.ruff_cache`, `__pycache__`).
2. Copy the zip to the new machine and extract it, for example to `C:\Tools\sbom-fixer`.

> **Do not copy .venv:** A virtual environment contains absolute paths of the machine it was created on and does not work on another machine. Always create a new one (Step 04).

After this step the folder must contain at least: `pyproject.toml`, `README.md`, `sbom_fixer\`, `sbom_fixer\data\schemas\`, `sbom_fixer\data\profiles\`.

---

## Step 04 – Install on Windows

### 4.1 Open a terminal in the folder

Use **cmd** (Command Prompt) for the commands below. PowerShell and Git Bash variants are in 4.5.

```cmd
cd C:\Tools\sbom-fixer
```

### 4.2 Create a virtual environment

```cmd
python -m venv .venv
```

This creates a private Python environment in `.venv` so the tool's libraries do not change the system Python.

### 4.3 Activate it

```cmd
.venv\Scripts\activate.bat
```

The prompt now starts with `(.venv)`. Repeat this step in every new terminal window before using the tool.

### 4.4 Install the tool

```cmd
python -m pip install --upgrade pip
pip install .
```

Developers who will change the code use `pip install -e ".[dev]"` instead. That also installs the test and lint tools.

### 4.5 Activation in other terminals

| Terminal | Activate command |
|---|---|
| cmd | `.venv\Scripts\activate.bat` |
| PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Git Bash | `source .venv/Scripts/activate` |
| Without activating | Call the full path: `C:\Tools\sbom-fixer\.venv\Scripts\sbom-fixer.exe` |

If PowerShell says "running scripts is disabled on this system", run this once and activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 4.6 Offline install (machine without internet)

On a machine **with** internet and the same Python version:

```cmd
cd C:\Tools\sbom-fixer
python -m pip wheel . -w wheelhouse
```

Copy the `wheelhouse` folder to the offline machine together with the code, then on the offline machine:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install --no-index --find-links wheelhouse sbom-fixer
```

### 4.7 Make the command available everywhere (optional)

To use `sbom-fixer` from any folder without activating, add `C:\Tools\sbom-fixer\.venv\Scripts` to the user PATH (Windows Settings, search "Edit environment variables for your account", edit `Path`, add the folder), then open a new terminal.

---

## Step 05 – Install on Linux or macOS

```bash
cd ~/tools/sbom-fixer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install .
sbom-fixer --version
```

Repeat `source .venv/bin/activate` in every new shell, or call `~/tools/sbom-fixer/.venv/bin/sbom-fixer` directly.

---

## Step 06 – Install with Docker (no Python needed)

Build the image once from the folder that contains the `Dockerfile`:

```bash
docker build -t sbom-fixer:1.0.0 .
```

Run it with the current folder mounted as `/work`:

```bash
docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 fix sbom.json --out out
```

In Windows cmd, use `%cd%` instead of `$PWD`:

```cmd
docker run --rm -v "%cd%:/work" -w /work sbom-fixer:1.0.0 fix sbom.json --out out
```

The image also contains `sbomqs` for the quality score. Confirm the sbomqs download URL in the `Dockerfile` for the version you pin before the first build.

---

## Step 07 – Verify the installation

Run these commands from the `sbom-fixer` folder with the environment activated.

**Check 1 - Check the version:**

```cmd
sbom-fixer --version
```

Expected: `sbom-fixer 1.0.0`

**Check 2 - List the rules:**

```cmd
sbom-fixer rules
```

Expected: a list of rules starting with `CDX14-001`.

**Check 3 - Fix the demo file:**

```cmd
sbom-fixer fix examples\demo-broken.cdx.json --out examples\out
```

Expected: `level 1.6 : not accepted`, `level 1.5 : ACCEPTED`, `exit code : 1`, and six files in `examples\out`.

**Check 4 - (Developers only) Run the tests:**

```cmd
pytest
```

Expected: `124 passed`.

If all checks pass, the installation is complete.

---

## Step 08 – Daily workflow: fix an SBOM step by step

### 8.1 Generate the SBOM with your normal tool

Use the generator's own output option. Never write an SBOM with `>` in Windows PowerShell 5.1, because that creates a UTF-16 file.

```cmd
trivy fs --format cyclonedx --output build\sbom.json .
```

### 8.2 Check the file (changes nothing)

```cmd
sbom-fixer check build\sbom.json
```

The output shows:

- the detected format, version, encoding and generator;
- each version level the fix would try and whether it would be accepted;
- the schema errors against the declared version, grouped by cause.

### 8.3 Fix the file

```cmd
sbom-fixer fix build\sbom.json --out build\sbom-fixed
```

To create both the Checkmarx copy and the compliance copy (never downgraded) in one run:

```cmd
sbom-fixer fix build\sbom.json -p checkmarx -p compliance --out build\sbom-fixed
```

Several files at once:

```cmd
sbom-fixer fix build\a.json build\b.json --out build\sbom-fixed
```

### 8.4 Read the exit code

| Terminal | Command |
|---|---|
| cmd | `echo %ERRORLEVEL%` |
| PowerShell | `$LASTEXITCODE` |
| Git Bash / Linux | `echo $?` |

0 and 1 mean the file is ready. 2 or higher means it is not (Step 10).

### 8.5 Read the notes file

Open `build\sbom-fixed\sbom.checkmarx.notes.txt`. Step 09 explains every section.

### 8.6 Upload to Checkmarx

Upload `build\sbom-fixed\sbom.checkmarx.cdx.json`, never the original. Use the portal, or the `cx` CLI with the SBOM flag your CLI version documents (`cx scan create --help`).

### 8.7 Keep the original

Keep the original SBOM and the compliance copy for audits. The Checkmarx copy is a derived file for scanning only.

---

## Step 09 – Understand the output files

For an input `sbom.json` and profile `checkmarx`, the output folder contains:

| File | What it is | Who uses it |
|---|---|---|
| `sbom.checkmarx.cdx.json` | The fixed SBOM, UTF-8 without BOM | Upload to Checkmarx |
| `sbom.checkmarx.notes.txt` | Plain-language report | The SBOM owner; read this first |
| `sbom.checkmarx.diff.txt` | Human-readable diff, original vs fixed | Reviewers |
| `sbom.checkmarx.diff.patch.json` | RFC 6902 JSON Patch, original to fixed | Tools and audits |
| `sbom.checkmarx.changes.json` | Every change: rule ID, path, before, after, severity, version level | Tools and audits |
| `sbom.checkmarx.quality.json` | NTIA coverage and sbomqs score before and after | Compliance |

The notes file has these sections:

| Section | What it tells you |
|---|---|
| Header | Detected format, generator, fix type (A/B/C), the version path with the reason for each level, result, exit code |
| 1. Why the original failed | Encoding problems, rejected version, and the schema errors grouped by cause |
| 2. Changes made | Every rule that changed something, its severity, count and example paths |
| 3. Data loss | Information that could not be kept at the accepted version |
| 4. Scan coverage | Components in total, with a valid purl (scannable), without purl |
| 5. Recommended source fix | The cheapest permanent fixes, often one generator option |
| 6. Components without purl | The exact components Checkmarx will not scan |
| 7. Quality and compliance | NTIA minimum elements and sbomqs score, before and after |
| 8. Findings not changed | Things the tool noticed but did not change (no guessing) |
| 9. Checkmarx verification | Only when `--verify` was used |

Change severities:

| Severity | Meaning | Action |
|---|---|---|
| INFO | Fixed without changing meaning | None |
| WARN | Fixed, but an assumption was made (for example UTC assumed) | Review once |
| DATA_LOSS | Information was removed | Check it does not matter for scanning |

---

## Step 10 – Exit codes and what to do

| Code | Meaning | What to do |
|---|---|---|
| 0 | Already compatible; output identical to input | Upload the output |
| 1 | Fixed | Upload the output; read the notes once |
| 2 | Cannot fix | Read the notes header: unsupported format (XML, SPDX 3.0, tag-value), version below the floor, or no version down to the floor was OK |
| 3 | Data loss happened and the profile forbids it | Review section 3 of the notes, or allow data loss in the profile |
| 4 | Quality gate failed | Fix NTIA gaps (supplier, author) at the source |
| 5 | Checkmarx verification failed | Read section 9 of the notes; run `sbom-fixer bisect` |
| 6 | Bisect could not narrow the problem | Increase `--max-uploads` or send the file to the platform team |

---

## Step 11 – Profiles and configuration

A profile says what the consumer accepts. Two are built in:

| Profile | Use | Behaviour |
|---|---|---|
| `checkmarx` | File to upload to Checkmarx | Steps down until an accepted version (provisional list 1.3, 1.4, 1.5) |
| `compliance` | File for customers and auditors | Repairs and cleans, never downgrades (`floor: declared`) |

The built-in files are in `sbom_fixer\data\profiles\`. To change behaviour, copy one, edit it and pass its path:

```cmd
copy sbom_fixer\data\profiles\checkmarx.yaml my-profile.yaml
sbom-fixer fix build\sbom.json -p my-profile.yaml --out build\sbom-fixed
```

Profile keys:

| Key | Values | Effect |
|---|---|---|
| `cyclonedx.accepted_versions` | list, for example `["1.4", "1.5"]` | Versions the consumer accepts |
| `cyclonedx.floor` | a version or `declared` | Lowest version the tool may step down to |
| `spdx.accepted_versions`, `spdx.floor` | same for SPDX | Same for SPDX files |
| `acceptance` | `profile`, `checkmarx`, `schema-only` | How "accepted" is decided (list, real upload, or schema only) |
| `tools_form` | `as-is`, `legacy-array` | Write `metadata.tools` in the 1.4 array form even at 1.5 |
| `flatten_nested_components` | `true` / `false` | Move nested components to the top level |
| `require_purl` | `warn` / `fail` | `fail` gives exit 2 when a component has no purl |
| `allow_data_loss` | `true` / `false` | `false` gives exit 3 on any DATA_LOSS change |
| `provenance` | `true` / `false` | Record sbom-fixer details in the output metadata |
| `quality.audit` | `report`, `gate`, `off` | `gate` turns quality failures into exit 4 |
| `quality.min_score`, `quality.score_tolerance` | numbers | sbomqs thresholds |
| `frameworks` | list of `{id, gate}` | `ntia-2021`, `cisa-fsct-2024`, `bsi-tr-03183-2-v2` checks |

One-off override without editing a profile:

```cmd
sbom-fixer fix build\sbom.json --accepted 1.4,1.5 --out build\sbom-fixed
```

> **Provisional values:** The accepted versions in the `checkmarx` profile are an assumption until someone uploads the files in `corpus\minimal\` to your Checkmarx tenant and fills in `docs\checkmarx-matrix.md`. Do this once per tenant and update the profile.

Individual rules cannot be switched on or off by name. Profile keys control the rules that depend on them (`tools_form`, `flatten_nested_components`, `provenance`).

---

## Step 12 – Checkmarx integration (optional)

These commands talk to a real Checkmarx tenant. Use a dedicated test project (default name `sbom-fixer-verification`), never a product project.

### 12.1 Set up once

**Setup 1.** Install the Checkmarx One CLI (`cx`) and check `cx version`.
**Setup 2.** Set the credentials as environment variables (in Jenkins, use the credential store):

| Variable | Value |
|---|---|
| `CX_BASE_URI` | Your Checkmarx One URL |
| `CX_TENANT` | Your tenant name |
| `CX_CLIENT_ID` and `CX_CLIENT_SECRET` | Service account (or `CX_APIKEY` instead) |
| `SBOM_FIXER_CX_PROJECT` | Optional; default `sbom-fixer-verification` |
| `CX_BIN` | Optional; path to `cx` if it is not on PATH |

**Setup 3.** Confirm the SBOM upload flags with `cx scan create --help`. If they differ from the tool's defaults, set `SBOM_FIXER_CX_SCAN_ARGS` (see README).

> **Untested defaults:** The `cx` flags and the results fields used by sbom-fixer are defaults that have not yet been run against a real tenant. Verify them on the first use and adjust the environment variables if needed.

### 12.2 Commands

| Command | What it does |
|---|---|
| `sbom-fixer verify out\sbom.checkmarx.cdx.json --expected-packages 120` | Uploads a file and checks the import and package count (exit 5 on failure) |
| `sbom-fixer fix sbom.json --verify` | Fixes, then uploads the result and writes the outcome into the notes |
| `sbom-fixer fix sbom.json --verify-each-step --max-uploads 6` | Asks Checkmarx at each version level instead of the profile list |
| `sbom-fixer bisect failing.json --max-uploads 30` | Shrinks a rejected file step by step to find the field that breaks the import |

---

## Step 13 – Quality audit (NTIA and sbomqs)

```cmd
sbom-fixer audit build\sbom.json
```

This prints NTIA minimum elements coverage: supplier, component name, version, unique identifier, dependencies, SBOM author and timestamp. `--json` prints the same as JSON.

For the sbomqs score, install sbomqs (it is already in the Docker image) and either put it on PATH or set `SBOMQS_BIN` to its full path. Without sbomqs the audit still runs and shows the score as "n/a".

The two gaps seen most often are supplier name and SBOM author. Fix both at the source:

- **Author:** set `metadata.authors` to your team or organisation in the pipeline.
- **Supplier:** use a generator that reads package metadata.

---

## Step 14 – Use in Jenkins

Copy the stage from `jenkins\sbom-fix-stage.groovy` into the service Jenkinsfile, right after the SBOM is generated. It:

1. Runs `fix` with the `checkmarx` and `compliance` profiles.
2. Fails the build only for exit code 2 or higher.
3. Archives the original, the outputs, the diffs and the notes.

The nightly job in `jenkins\nightly-corpus.groovy` uploads the whole sample corpus to the verification project, so you notice when Checkmarx changes what it accepts. The full rollout guide is `docs\rollout.md`.

---

## Step 15 – Rule reference

### 15.1 How to read a rule ID

| Prefix | Case | When it runs | Meaning |
|---|---|---|---|
| `REP-` | A | At every version level | Repairs errors against the current version's schema |
| `CDX17-`, `CDX16-`, `CDX15-`, `CDX14-`, `SPDX23-` | B | Once, when stepping down from that version | Converts fields that changed between two versions |
| `SAN-` | C | At every version level (SAN-060 and SAN-090 once at the end) | Checkmarx clean-ups |
| `PRUNE-001` | – | At every version level | Removes a field the current schema does not allow (always DATA_LOSS) |
| `ENC-001/002/003` | – | At the start | File was UTF-8 with BOM, UTF-16, or not UTF-8 |
| `CDX-VER`, `SPDX-VER` | – | At each step down | The declared version was changed |

### 15.2 Rules every rule follows

1. **No guessing.** A value is changed only when the correct value is certain; otherwise it is reported in "Findings not changed".
2. **Keep before delete.** When a field has no place in the target version, it is moved to `properties` or a comment where possible; only then is it removed.
3. **Everything is logged.** Each change has a rule ID, a path, the old and new value, a severity and a reason.
4. **Same input, same output.** Running the tool twice gives the same result, and running it on its own output changes nothing.

### 15.3 Where the rules come from

The rule IDs are this tool's own naming. The rules are based on official sources, all stored in the tool folder:

| Source | Location |
|---|---|
| Official CycloneDX and SPDX JSON schemas (with GitHub commit IDs) | `sbom_fixer\data\schemas\`, `SOURCES.md` |
| Differences between schema versions, generated from those schemas | `docs\schema-diff-*.txt`, or `sbom-fixer schema-diff 1.5 1.6` |
| Full rule list generated from the code | `docs\rule-catalog.md`, or `sbom-fixer rules --markdown` |

Online references: CycloneDX specification (github.com/CycloneDX/specification), SPDX specification (spdx.github.io/spdx-spec), SPDX license list (spdx.org/licenses), package-url specification (github.com/package-url/purl-spec), and NTIA "Minimum Elements for a Software Bill of Materials" (ntia.gov).

### 15.4 All rules

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

---

## Step 16 – Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `'sbom-fixer' is not recognized` in cmd | The virtual environment is not activated | Run `.venv\Scripts\activate.bat`, or use the full path to `.venv\Scripts\sbom-fixer.exe` (Step 4.5) |
| PowerShell: "running scripts is disabled" | Execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `python` opens the Microsoft Store | Windows app alias | Install Python from python.org with "Add to PATH", or use `py -3.12 -m venv .venv` |
| pip: SSL or proxy errors | Corporate network | Set `HTTPS_PROXY`, use the internal mirror (`pip install --index-url ...`), or use the offline install (Step 4.6) |
| `.venv` copied from another machine does not work | Absolute paths inside `.venv` | Delete `.venv` and create it again (Step 4.2) |
| Exit 2 with "XML ... not supported" | CycloneDX XML input | Regenerate the SBOM as JSON |
| Exit 2 with "SPDX 3.0" or "tag-value" | Unsupported SPDX format | Regenerate as CycloneDX JSON or SPDX 2.3 JSON |
| Exit 2 with "below the floor" | Very old version such as 1.2 | Regenerate with a newer generator version |
| Exit 2 with "schema errors remain" at every level | An error no rule can fix | Run `sbom-fixer check` and look at the grouped errors; report them to the platform team |
| Output file looks unchanged but exit code is 1 | Only the encoding was fixed (BOM or UTF-16) | Nothing to do; the output is correct UTF-8 |
| Quality score shows "n/a" | sbomqs not installed | Install sbomqs or set `SBOMQS_BIN` (Step 13) |
| Checkmarx still rejects the fixed file | The importer needs something the schema does not require | Run `sbom-fixer bisect` (Step 12), then report the result so a rule can be added |
| A large SBOM is slow | Very large files | About 4 seconds for 5,000 components and about 40 seconds for 50,000 on a laptop; normal |

---

## Step 17 – Updating the tool

### 17.1 Install a newer version

```cmd
cd C:\Tools\sbom-fixer
git pull
.venv\Scripts\activate.bat
pip install .
sbom-fixer --version
```

Check `CHANGELOG.md`; any release that adds or changes rules can change outputs.

### 17.2 When CycloneDX releases a new version

1. `python tools\vendor_schemas.py` downloads the latest official schemas.
2. `sbom-fixer schema-diff 1.7 1.8` shows what changed.
3. Write the hop rules for the new version and add sample files to `corpus\`.

### 17.3 When Checkmarx supports a newer version

Add the version to `accepted_versions` in the `checkmarx` profile. Files at that version then stop stepping down. No code change is needed.

### 17.4 Adding a new rule (developers)

1. Add a file that shows the problem to `corpus\`.
2. Decide the case (A, B or C) and the next free rule ID.
3. Write a test with the file before and after the fix.
4. Implement the rule; edit the document only through the change log.
5. Write the plain-language description that appears in the notes.
6. Run `pytest` and the whole corpus.
7. Regenerate `docs\rule-catalog.md` with `sbom-fixer rules --markdown`.

---

## Step 18 – Command cheat sheet

| Task | Command |
|---|---|
| Activate (cmd) | `.venv\Scripts\activate.bat` |
| Version | `sbom-fixer --version` |
| Help | `sbom-fixer --help`, `sbom-fixer fix --help` |
| Check only | `sbom-fixer check sbom.json` |
| Fix | `sbom-fixer fix sbom.json --out out` |
| Fix, two copies | `sbom-fixer fix sbom.json -p checkmarx -p compliance --out out` |
| Fix with other accepted versions | `sbom-fixer fix sbom.json --accepted 1.4 --out out` |
| Quality only | `sbom-fixer audit sbom.json` |
| Rule list | `sbom-fixer rules` |
| Schema difference | `sbom-fixer schema-diff 1.5 1.6` |
| Upload and verify | `sbom-fixer verify out\sbom.checkmarx.cdx.json` |
| Find a breaking field | `sbom-fixer bisect failing.json` |
| Exit code (cmd) | `echo %ERRORLEVEL%` |
