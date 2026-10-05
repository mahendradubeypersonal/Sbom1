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
    # 1.6 and 1.7 are accepted by the checkmarx profile and kept (checkmarx-cli takes 1.7 down to 1.6)
    for v in ("1.6", "1.7"):
        case("minimal", f"min-cdx-{v}.json", minimal(v), {"exit_code": 0, "final_version": v, "version_path": [v]})
    text = json.dumps(minimal("1.5"), indent=2)
    case("minimal", "min-cdx-1.5-utf16.json", None, {"exit_code": 1, "final_version": "1.5", "rules": ["ENC-002"]},
         raw=codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
    case("minimal", "min-cdx-1.5-utf8bom.json", None, {"exit_code": 1, "final_version": "1.5", "rules": ["ENC-001"]},
         raw=codecs.BOM_UTF8 + text.encode("utf-8"))
    case("minimal", "min-spdx-2.2.json", spdx("2.2"), {"exit_code": 0, "final_version": "2.2", "version_path": ["2.2"]})
    case("minimal", "min-spdx-2.3.json", spdx("2.3"), {"exit_code": 0, "final_version": "2.3", "version_path": ["2.3"]})

    # Trivy-like 1.6: valid 1.6, kept at 1.6 (the OS package without purl is reported, not changed)
    trivy = minimal("1.6")
    trivy["metadata"]["tools"] = {"components": [{"type": "application", "group": "aquasecurity", "name": "trivy", "version": "0.56.2"}]}
    trivy["metadata"].pop("authors")
    trivy["components"][0]["evidence"] = {"identity": [{"field": "purl", "confidence": 1}, {"field": "name", "confidence": 0.4}]}
    trivy["components"][0]["externalReferences"] = [{"type": "source-distribution", "url": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}]
    trivy["components"].append({"bom-ref": "deb-libssl", "type": "library", "name": "libssl3", "version": "3.0.2",
                                "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "ubuntu"}]})
    case("trivy", "payments-api.trivy.json", trivy,
         {"exit_code": 0, "final_version": "1.6", "version_path": ["1.6"]})

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

    # cdxgen-like 1.7 with 1.7-only fields: valid 1.7, kept (checkmarx-cli: one hop to 1.6)
    cdxgen = minimal("1.7")
    cdxgen["components"][0]["isExternal"] = False
    cdxgen["components"][0]["tags"] = ["web", "util"]
    cdxgen["components"][0]["omniborId"] = ["gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64"]
    cdxgen["components"][0]["hashes"] = [{"alg": "Streebog-256", "content": "a" * 64},
                                         {"alg": "SHA-256", "content": "b" * 64}]
    cdxgen["metadata"]["lifecycles"] = [{"phase": "build"}]
    case("cdxgen", "analytics.cdxgen.json", cdxgen,
         {"exit_code": 0, "final_version": "1.7", "version_path": ["1.7"]})

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

    # 1.6 with crypto asset and declarations: valid 1.6, kept (the crypto asset has no purl and is reported)
    crypto = minimal("1.6")
    crypto["components"].append({"bom-ref": "crypto-aes", "type": "cryptographic-asset", "name": "AES-128-GCM",
                                 "cryptoProperties": {"assetType": "algorithm"}})
    crypto["dependencies"].append({"ref": "crypto-aes", "dependsOn": []})
    crypto["declarations"] = {"assessors": [{"bom-ref": "a1", "thirdParty": True}]}
    case("cdxgen", "crypto.cdx.json", crypto,
         {"exit_code": 0, "final_version": "1.6", "version_path": ["1.6"]})

    # SPDX 2.3 with 2.3-only fields: valid and accepted, so no hop
    s23 = spdx("2.3")
    s23["packages"][0]["primaryPackagePurpose"] = "LIBRARY"
    case("sbom-tool", "service.spdx.json", s23, {"exit_code": 0, "final_version": "2.3", "version_path": ["2.3"]})

    future_and_purl_cases()

    # Below the floor (1.2) and unsupported formats -> exit 2
    old = minimal("1.3")
    old["specVersion"] = "1.2"
    case("unsupported", "legacy-1.2.cdx.json", old, {"exit_code": 2})
    case("unsupported", "spdx3.jsonld", {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}, {"exit_code": 2})
    case("unsupported", "bom.xml", None, {"exit_code": 2},
         raw=b'<?xml version="1.0"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1"/>\n')


def comp(purl: str | None, name: str, version: str | None = "1.0.0", **extra: Any) -> dict[str, Any]:
    c: dict[str, Any] = {"bom-ref": f"ref-{name}-{version}", "type": "library", "name": name}
    if version is not None:
        c["version"] = version
    if purl is not None:
        c["purl"] = purl
    c.update(extra)
    return c


def with_components(version: str, comps: list[dict[str, Any]]) -> dict[str, Any]:
    doc = minimal(version)
    doc["components"] = comps
    doc["dependencies"] = [{"ref": c["bom-ref"], "dependsOn": []} for c in comps]
    return doc


def future_and_purl_cases() -> None:
    # CycloneDX 1.8 (newer than every vendored schema): generic future hop to 1.7
    fut = minimal("1.7")
    fut["$schema"] = "http://cyclonedx.org/schema/bom-1.8.schema.json"
    fut["specVersion"] = "1.8"
    fut["components"][0]["newField18"] = "some-value"
    fut["components"][0]["externalReferences"] = [{"type": "sbom-registry-v2", "url": "https://example.com/sbom"}]
    fut["metadata"]["distributionScope"] = {"level": "internal"}
    case("future", "min-cdx-1.8.json", fut,
         {"exit_code": 1, "final_version": "1.7", "version_path": ["1.8", "1.7"],
          "rules": ["CDX-FWD-001", "CDX-FWD-002", "CDX-FWD-003"]})
    major = minimal("1.7")
    major["specVersion"] = "2.0"
    major.pop("$schema")
    case("future", "min-cdx-2.0.json", major, {"exit_code": 2})

    # Every Checkmarx-supported alias plus types Checkmarx skips; nothing to change, everything reported
    supported = [("pkg:yarn/left-pad@1.3.0", "left-pad"), ("pkg:bower/jquery@3.7.1", "jquery"),
                 ("pkg:poetry/requests@2.31.0", "requests"), ("pkg:nuget/Newtonsoft.Json@13.0.3", "Newtonsoft.Json"),
                 ("pkg:gradle/com.google.guava/guava@32.1.3-jre", "guava"), ("pkg:composer/laravel/framework@10.0.0", "framework"),
                 ("pkg:swiftpm/github.com/apple/swift-nio@2.62.0", "swift-nio"), ("pkg:cocoapods/Alamofire@5.8.1", "Alamofire"),
                 ("pkg:gomodules/github.com/gorilla/mux@v1.8.0", "mux"), ("pkg:conan/zlib@1.3", "zlib"),
                 ("pkg:gem/rails@7.1.2", "rails"), ("pkg:unity/com.unity.textmeshpro@3.0.6", "com.unity.textmeshpro"),
                 ("pkg:cpan/Moose@2.2206", "Moose"), ("pkg:pub/http@1.1.0", "http")]
    skipped = [("pkg:rpm/redhat/openssl@3.0.7-18.el9", "openssl"), ("pkg:apk/alpine/musl@1.2.4-r2", "musl"),
               ("pkg:deb/debian/libc6@2.36-9?distro=debian-12", "libc6"), ("pkg:cargo/serde@1.0.197", "serde"),
               ("pkg:hex/phoenix@1.7.10", "phoenix"), ("pkg:docker/library/nginx@1.25", "nginx"),
               ("pkg:conda/numpy@1.26.2", "numpy")]
    mixed = [comp(p, n, p.rsplit("@", 1)[1].split("?")[0]) for p, n in supported + skipped]
    case("purl", "mixed-types.cdx.json", with_components("1.6", mixed),
         {"exit_code": 0, "final_version": "1.6", "version_path": ["1.6"]})

    # Supported types written in a form Checkmarx does not match
    fmt = with_components("1.6", [
        comp("pkg:npm/@angular/core@15.2.0", "@angular/core", "15.2.0"),
        comp("pkg:NPM/lodash@4.17.21", "lodash", "4.17.21"),
        comp("pkg:pypi/django", "django", "4.2.7"),
        comp("pkg:maven/commons-io@2.15.0", "commons-io", "2.15.0", group="commons-io"),
        comp("pkg:maven/org.slf4j/slf4j-api@2.0.9?repository_url=https://repo.example.com/maven2", "slf4j-api", "2.0.9",
             group="org.slf4j"),
        comp("pkg:npm/no-version-anywhere", "no-version-anywhere", None),
    ])
    case("purl", "format-fixes.cdx.json", fmt,
         {"exit_code": 1, "final_version": "1.6", "version_path": ["1.6"],
          "rules": ["CXP-001", "CXP-002", "CXP-003", "CXP-004", "CXP-005"]})

    # Unsupported types with hard evidence of the real ecosystem
    remap = with_components("1.6", [
        comp("pkg:github/gorilla/handlers@v1.5.2", "github.com/gorilla/handlers", "v1.5.2",
             properties=[{"name": "syft:package:type", "value": "go-module"}]),
        comp("pkg:github/actions/checkout@v4", "checkout", "v4"),
        comp("pkg:generic/jackson-databind@2.16.0", "jackson-databind", "2.16.0", group="com.fasterxml.jackson.core",
             properties=[{"name": "syft:package:type", "value": "java-archive"}]),
        comp("pkg:generic/flask@3.0.0?download_url=https://files.pythonhosted.org/packages/ab/cd/flask-3.0.0-py3-none-any.whl",
             "flask", "3.0.0"),
        comp("pkg:generic/internal-lib@1.0.0", "internal-lib", "1.0.0"),
        comp("pkg:nodejs/express@4.18.2", "express", "4.18.2"),
    ])
    case("purl", "remap.cdx.json", remap,
         {"exit_code": 1, "final_version": "1.6", "version_path": ["1.6"], "rules": ["CXP-010", "CXP-011", "CXP-012", "CXP-013"]})

    # purl field holding web URLs instead of purls
    urls = with_components("1.5", [
        comp("https://registry.npmjs.org/axios/-/axios-1.6.2.tgz", "axios", "1.6.2"),
        comp("https://repo1.maven.org/maven2/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar", "snakeyaml", "2.2"),
        comp("https://github.com/acme/widget", "widget", "2.0.0"),
        comp("https://downloads.example.com/tool-1.0.zip", "tool", "1.0"),
    ])
    case("purl", "url-purls.cdx.json", urls, {"exit_code": 1, "final_version": "1.5", "version_path": ["1.5"], "rules": ["SAN-009"]})

    # Nothing Checkmarx can scan: it would fail with "no valid PURLs" -> exit 7
    nothing = [comp("pkg:rpm/redhat/bash@5.1.8-6.el9", "bash", "5.1.8-6.el9"), comp("pkg:cargo/rand@0.8.5", "rand", "0.8.5")]
    case("purl", "none-supported.cdx.json", with_components("1.6", nothing),
         {"exit_code": 7, "final_version": "1.6", "version_path": ["1.6"]})

    # No tool named anywhere: sbom-fixer added as the default tool
    notools = minimal("1.6")
    notools["metadata"].pop("tools")
    case("purl", "no-tools.cdx.json", notools, {"exit_code": 1, "final_version": "1.6", "version_path": ["1.6"], "rules": ["SAN-013"]})

    # SPDX: purl type in upper case, no 'Tool:' creator, no DESCRIBES / DEPENDS_ON
    sp = spdx("2.3")
    sp["packages"][0]["externalRefs"][0]["referenceLocator"] = "pkg:NPM/lodash@4.17.20"
    sp["creationInfo"]["creators"] = ["Organization: Platform Team"]
    sp["relationships"] = []
    case("purl", "spdx-issues.spdx.json", sp, {"exit_code": 1, "final_version": "2.3", "version_path": ["2.3"],
                                               "rules": ["CXP-001", "SAN-013"]})


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
