"""Generate corpus/: minimal reference SBOMs (SBOMFIX-101) and synthetic generator-like cases.

The synthetic files imitate typical generator output. Replace or extend them with real SBOMs from
your pipelines (SBOMFIX-103); every real file needs an expected.yaml entry.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent / "corpus"
SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
TS = "2026-10-02T10:00:00Z"
LODASH = {"bom-ref": "pkg:npm/lodash@4.17.20", "type": "library", "name": "lodash", "version": "4.17.20",
          "purl": "pkg:npm/lodash@4.17.20", "supplier": {"name": "OpenJS Foundation"}, "licenses": [{"license": {"id": "MIT"}}]}


def minimal(version: str, tools_form: str = "object") -> dict[str, Any]:
    doc: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": version, "serialNumber": SERIAL, "version": 1,
                           "metadata": {"timestamp": TS, "authors": [{"name": "Platform Team"}]},
                           "components": [dict(LODASH)],
                           "dependencies": [{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": []}]}
    if version in ("1.4", "1.5", "1.6", "1.7"):
        doc = {"$schema": f"http://cyclonedx.org/schema/bom-{version}.schema.json", **doc}
    if version >= "1.5" and tools_form == "object":
        doc["metadata"]["tools"] = {"components": [{"type": "application", "name": "corpus-generator", "version": "1.0"}]}
    else:
        doc["metadata"]["tools"] = [{"vendor": "sbom-fixer", "name": "corpus-generator", "version": "1.0"}]
    return doc


def spdx(version: str) -> dict[str, Any]:
    pkg: dict[str, Any] = {"SPDXID": "SPDXRef-Package-lodash", "name": "lodash", "versionInfo": "4.17.20",
                           "supplier": "Organization: OpenJS Foundation", "downloadLocation": "NOASSERTION",
                           "filesAnalyzed": False, "licenseConcluded": "MIT", "licenseDeclared": "MIT", "copyrightText": "NOASSERTION",
                           "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                             "referenceLocator": "pkg:npm/lodash@4.17.20"}]}
    doc: dict[str, Any] = {
        "spdxVersion": f"SPDX-{version}", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "corpus-app", "documentNamespace": "https://example.com/spdx/corpus-app-1",
        "creationInfo": {"created": TS, "creators": ["Tool: corpus-generator-1.0", "Organization: Platform Team"]},
        "packages": [pkg],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-lodash"},
                          {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-lodash"}],
    }
    return doc


CASES: dict[str, dict[str, Any]] = {}


def case(folder: str, name: str, doc: Any, expected: dict[str, Any], raw: bytes | None = None) -> None:
    CASES[f"{folder}/{name}"] = {"doc": doc, "expected": expected, "raw": raw}


def build() -> None:
    # Phase 0 minimal reference files (upload these for the Step 02 matrix)
    for v in ("1.3", "1.4", "1.5"):
        case("minimal", f"min-cdx-{v}.json", minimal(v), {"exit_code": 0, "final_version": v, "version_path": [v]})
    case("minimal", "min-cdx-1.5-tools-array.json", minimal("1.5", "array"),
         {"exit_code": 0, "final_version": "1.5", "version_path": ["1.5"]})
    for v in ("1.6", "1.7"):
        path = ["1.7", "1.6", "1.5"] if v == "1.7" else ["1.6", "1.5"]
        case("minimal", f"min-cdx-{v}.json", minimal(v), {"exit_code": 1, "final_version": "1.5", "version_path": path,
                                                         "rules": ["CDX-VER"]})
    text = json.dumps(minimal("1.5"), indent=2)
    case("minimal", "min-cdx-1.5-utf16.json", None, {"exit_code": 1, "final_version": "1.5", "rules": ["ENC-002"]},
         raw=codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
    case("minimal", "min-cdx-1.5-utf8bom.json", None, {"exit_code": 1, "final_version": "1.5", "rules": ["ENC-001"]},
         raw=codecs.BOM_UTF8 + text.encode("utf-8"))
    case("minimal", "min-spdx-2.2.json", spdx("2.2"), {"exit_code": 0, "final_version": "2.2", "version_path": ["2.2"]})
    case("minimal", "min-spdx-2.3.json", spdx("2.3"), {"exit_code": 0, "final_version": "2.3", "version_path": ["2.3"]})

    # Trivy-like 1.6: valid 1.6, needs one hop
    trivy = minimal("1.6")
    trivy["metadata"]["tools"] = {"components": [{"type": "application", "group": "aquasecurity", "name": "trivy", "version": "0.56.2"}]}
    trivy["metadata"].pop("authors")
    trivy["components"][0]["evidence"] = {"identity": [{"field": "purl", "confidence": 1}, {"field": "name", "confidence": 0.4}]}
    trivy["components"][0]["externalReferences"] = [{"type": "source-distribution", "url": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}]
    trivy["components"].append({"bom-ref": "deb-libssl", "type": "library", "name": "libssl3", "version": "3.0.2",
                                "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "ubuntu"}]})
    case("trivy", "payments-api.trivy.json", trivy,
         {"exit_code": 1, "final_version": "1.5", "version_path": ["1.6", "1.5"], "rules": ["CDX16-004", "CDX16-011", "CDX-VER"]})

    # Maven-like 1.5 with same-version errors only: must be repaired in place, no hop
    mvn = minimal("1.5")
    mvn["components"] = [{"bom-ref": "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar", "type": "Library",
                          "group": "org.apache.commons", "name": "commons-lang3", "version": 3.12, "publisher": "The Apache Software Foundation",
                          "purl": "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar",
                          "licenses": [{"license": {"id": "Apache 2.0"}}],
                          "hashes": [{"alg": "sha-256", "content": "d919d904486c037f8d193412da0c92e22a9fa24230b9d67a57855c5c31c5e94e"}]}]
    mvn["dependencies"] = [{"ref": "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar", "dependsOn": []}]
    mvn["metadata"]["timestamp"] = "2026-10-02 10:00:00"
    case("maven", "orders-service.bom.json", mvn,
         {"exit_code": 1, "final_version": "1.5", "version_path": ["1.5"], "rules": ["REP-003", "REP-004", "REP-008", "REP-010"]})

    # npm-like 1.4, already fine: exit 0, unchanged
    npm = minimal("1.4")
    case("npm", "web-ui.npm.json", npm, {"exit_code": 0, "final_version": "1.4", "version_path": ["1.4"]})

    # cdxgen-like 1.7 with 1.7-only fields: two hops
    cdxgen = minimal("1.7")
    cdxgen["components"][0]["isExternal"] = False
    cdxgen["components"][0]["tags"] = ["web", "util"]
    cdxgen["components"][0]["omniborId"] = ["gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64"]
    cdxgen["components"][0]["hashes"] = [{"alg": "Streebog-256", "content": "a" * 64},
                                         {"alg": "SHA-256", "content": "b" * 64}]
    cdxgen["metadata"]["lifecycles"] = [{"phase": "build"}]
    case("cdxgen", "analytics.cdxgen.json", cdxgen,
         {"exit_code": 1, "final_version": "1.5", "version_path": ["1.7", "1.6", "1.5"],
          "rules": ["CDX17-001", "CDX17-ENUM", "CDX16-006", "CDX16-007"]})

    # Vendor file 1.5 with junk keys, nulls, duplicate refs, dangling edges, bad purl
    vendor = minimal("1.5")
    vendor["serialNumber"] = "ACME-0001"
    vendor["components"] = [
        dict(LODASH, **{"x-scanner": {"id": 7}, "description": None}),
        dict(LODASH, purl="pkg:npm/lodash@4.17.20", **{"bom-ref": "pkg:npm/lodash@4.17.20"}),
        {"bom-ref": "left-pad", "type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left pad@1.3.0"},
        {"bom-ref": "pkg:pypi/requests@2.31.0", "type": "library", "name": "requests", "version": "2.31.0"},
    ]
    vendor["dependencies"] = [{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": ["ghost"]}, {"ref": "nobody", "dependsOn": []}]
    case("vendor", "acme-portal.cdx.json", vendor,
         {"exit_code": 1, "final_version": "1.5", "version_path": ["1.5"],
          "rules": ["REP-007", "REP-005", "PRUNE-001", "SAN-020", "SAN-021", "SAN-022", "SAN-011"]})

    # 1.6 with crypto asset and declarations: data loss on hop
    crypto = minimal("1.6")
    crypto["components"].append({"bom-ref": "crypto-aes", "type": "cryptographic-asset", "name": "AES-128-GCM",
                                 "cryptoProperties": {"assetType": "algorithm"}})
    crypto["dependencies"].append({"ref": "crypto-aes", "dependsOn": []})
    crypto["declarations"] = {"assessors": [{"bom-ref": "a1", "thirdParty": True}]}
    case("cdxgen", "crypto.cdx.json", crypto,
         {"exit_code": 1, "final_version": "1.5", "version_path": ["1.6", "1.5"], "rules": ["CDX16-010", "CDX16-008"]})

    # SPDX 2.3 with 2.3-only fields: valid and accepted, so no hop
    s23 = spdx("2.3")
    s23["packages"][0]["primaryPackagePurpose"] = "LIBRARY"
    case("sbom-tool", "service.spdx.json", s23, {"exit_code": 0, "final_version": "2.3", "version_path": ["2.3"]})

    # Below the floor (1.2) and unsupported formats -> exit 2
    old = minimal("1.3")
    old["specVersion"] = "1.2"
    case("unsupported", "legacy-1.2.cdx.json", old, {"exit_code": 2})
    case("unsupported", "spdx3.jsonld", {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}, {"exit_code": 2})
    case("unsupported", "bom.xml", None, {"exit_code": 2},
         raw=b'<?xml version="1.0"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1"/>\n')


def main() -> None:
    build()
    expected_all: dict[str, Any] = {}
    for rel, c in CASES.items():
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        data = c["raw"] if c["raw"] is not None else (json.dumps(c["doc"], indent=2) + "\n").encode("utf-8")
        path.write_bytes(data)
        expected_all[rel] = c["expected"]
    (ROOT / "expected.yaml").write_text(
        "# Expected outcome per corpus file (profile: checkmarx). Generated by tools/make_corpus.py.\n"
        + yaml.safe_dump(expected_all, sort_keys=True), encoding="utf-8")
    print(f"wrote {len(CASES)} corpus files to {ROOT}")


if __name__ == "__main__":
    main()
