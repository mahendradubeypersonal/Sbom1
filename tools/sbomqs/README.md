# sbomqs (vendored)

[sbomqs](https://github.com/interlynk-io/sbomqs) by Interlynk scores SBOM quality from 0 to 10. sbom-fixer uses it for the
"sbomqs score" before and after a fix (notes section 7, quality.json, quality gate). This folder holds a pinned copy,
so a checkout scores SBOMs **offline** without installing anything.

| File | Content |
|---|---|
| `VERSION` | Pinned version (the Dockerfile `ARG SBOMQS_VERSION` must match; a test checks it) |
| `windows-amd64/sbomqs.exe` | Windows x64 binary, used as is |
| `linux-amd64/sbomqs_<version>_Linux_x86_64.tar.gz` | Linux x64 release archive (the Dockerfile extracts it) |
| `checksums.txt` | Upstream checksums of the release archives |
| `SHA256SUMS` | sha256 of every file here; checked by `tests/test_sbomqs_vendored.py` and the Dockerfile |
| `LICENSE` | sbomqs licence (Apache-2.0), required when redistributing the binaries |

## How sbom-fixer finds sbomqs

1. `SBOMQS_BIN` (full path), if set
2. this folder: `windows-amd64/sbomqs.exe` on Windows x64, `linux-amd64/sbomqs` on Linux x64 (after extracting, see below)
3. `sbomqs` on `PATH` (the Docker image has it in `/usr/local/bin`)

Without any of them the audit still runs and shows the score as `n/a`.

Check which binary is used: `sbom-fixer audit some-sbom.json` prints `sbomqs binary: <path>`.

## Use it directly

```powershell
# Windows
tools\sbomqs\windows-amd64\sbomqs.exe version
tools\sbomqs\windows-amd64\sbomqs.exe score build\sbom.json
tools\sbomqs\windows-amd64\sbomqs.exe score build\sbom.json --json
```

```bash
# Linux x64: extract once next to the archive, then sbom-fixer finds it automatically
tar -xzf tools/sbomqs/linux-amd64/sbomqs_2.1.2_Linux_x86_64.tar.gz -C tools/sbomqs/linux-amd64 sbomqs
tools/sbomqs/linux-amd64/sbomqs score build/sbom.json
```

macOS and ARM machines: install sbomqs from the release page and set `SBOMQS_BIN`.

## Verify the copy

```bash
cd tools/sbomqs && sha256sum -c SHA256SUMS
```

```powershell
Get-FileHash tools\sbomqs\windows-amd64\sbomqs.exe -Algorithm SHA256   # compare with SHA256SUMS
```

## Upgrade

```bash
python tools/vendor_sbomqs.py 2.2.0     # downloads, checks against the release checksums.txt, replaces the files
```

Then set `ARG SBOMQS_VERSION` in the `Dockerfile` to the same version, run the tests (the score JSON can change between
sbomqs releases; `sbom_fixer/audit/sbomqs.py` reads `files[0].sbom_quality_score` (2.x) and `avg_score` (1.x)), and add a
CHANGELOG line. sbomqs scores can change between versions, so compare before/after scores only from the same version.
