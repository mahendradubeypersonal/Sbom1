"""Download a pinned sbomqs release into tools/sbomqs so sbom-fixer can score SBOMs offline.

Run only when upgrading sbomqs (the tool itself never touches the network):

    python tools/vendor_sbomqs.py 2.1.2

Every archive is checked against the release's checksums.txt before anything is written. Layout:

    tools/sbomqs/VERSION                       pinned version, e.g. 2.1.2
    tools/sbomqs/LICENSE                       sbomqs licence (Apache-2.0), shipped with the binaries
    tools/sbomqs/checksums.txt                 upstream checksums of the release archives
    tools/sbomqs/SHA256SUMS                    sha256 of the files committed here
    tools/sbomqs/windows-amd64/sbomqs.exe      extracted, runs as is (found automatically by sbom-fixer)
    tools/sbomqs/linux-amd64/sbomqs_<v>_Linux_x86_64.tar.gz   archive, extracted by the Dockerfile

Commit the result together with the version in Dockerfile (ARG SBOMQS_VERSION) and CHANGELOG.md.
"""

from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

DEST = Path(__file__).resolve().parent / "sbomqs"
REPO = "interlynk-io/sbomqs"


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as r:  # noqa: S310 - fixed https URLs
        return r.read()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _member(archive: bytes, name: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        f = tar.extractfile(name)
        if f is None:
            raise SystemExit(f"{name} not found in archive")
        return f.read()


def main(version: str) -> int:
    base = f"https://github.com/{REPO}/releases/download/v{version}"
    checksums = _get(f"{base}/checksums.txt").decode("utf-8")
    expected = {line.split()[1].lstrip("*"): line.split()[0] for line in checksums.splitlines() if line.strip()}
    archives = {}
    for name in (f"sbomqs_{version}_Windows_x86_64.tar.gz", f"sbomqs_{version}_Linux_x86_64.tar.gz"):
        data = _get(f"{base}/{name}")
        if expected.get(name) != _sha256(data):
            raise SystemExit(f"checksum mismatch for {name}: refusing to vendor it")
        archives[name] = data
        print(f"verified {name} ({len(data):,} bytes)")

    win = archives[f"sbomqs_{version}_Windows_x86_64.tar.gz"]
    linux_name = f"sbomqs_{version}_Linux_x86_64.tar.gz"
    for old in (DEST / "linux-amd64").glob("sbomqs_*_Linux_x86_64.tar.gz"):
        old.unlink()
    files = {
        "windows-amd64/sbomqs.exe": _member(win, "sbomqs.exe"),
        f"linux-amd64/{linux_name}": archives[linux_name],
        "LICENSE": _member(win, "LICENSE"),
        "checksums.txt": checksums.encode("utf-8"),
        "VERSION": f"{version}\n".encode(),
    }
    for rel, data in files.items():
        path = DEST / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    sums = "".join(f"{_sha256(files[rel])}  {rel}\n" for rel in sorted(files) if rel not in ("SHA256SUMS",))
    (DEST / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
    print(f"sbomqs {version} vendored into {DEST}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tools/vendor_sbomqs.py <version>   (e.g. 2.1.2)")
    sys.exit(main(sys.argv[1].lstrip("v")))
