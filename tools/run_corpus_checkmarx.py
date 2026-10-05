"""Nightly corpus job (SBOMFIX-703): fix every corpus file and upload the result to the verification project.

Exit 0 when every file meets its expectation, 1 otherwise. Needs the Checkmarx environment variables
described in README (CX_BASE_URI, CX_TENANT, CX_CLIENT_ID / CX_CLIENT_SECRET or CX_APIKEY).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import yaml

from sbom_fixer.checkmarx import CxCliClient, verify
from sbom_fixer.notes import scan_coverage
from sbom_fixer.pipeline import run_fix
from sbom_fixer.profile import load_profile

CORPUS = Path(__file__).resolve().parent.parent / "corpus"


def main() -> int:
    expected = yaml.safe_load((CORPUS / "expected.yaml").read_text(encoding="utf-8"))
    profile = load_profile("checkmarx")
    client = CxCliClient()
    missing = client.config.missing()
    if missing:
        print("Checkmarx not configured: " + ", ".join(missing))
        return 1
    rows, failed = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for rel, exp in sorted(expected.items()):
            r = run_fix(CORPUS / rel, profile, Path(tmp), audit=False)
            row = {"file": rel, "exit_code": r.exit_code, "final_version": r.final_version, "import": "skipped"}
            ok = r.exit_code == exp["exit_code"]
            if ok and r.ok and r.outputs.get("sbom"):
                _, scannable, _ = scan_coverage(r.fixed_doc, r.spec)
                good, res = verify(client, Path(r.outputs["sbom"]), exp.get("expected_packages") or scannable)
                row.update(res.to_dict(), expected_packages=exp.get("expected_packages") or scannable)
                row["import"] = "ok" if good else "FAILED"
                ok = good
            failed += 0 if ok else 1
            rows.append(row)
            print(f"{'OK  ' if ok else 'FAIL'} {rel}: exit {r.exit_code}, import {row['import']}")
    Path("corpus-import-report.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"{len(rows) - failed}/{len(rows)} files met expectations; report: corpus-import-report.json")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
