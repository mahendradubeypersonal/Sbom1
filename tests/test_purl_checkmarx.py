"""Checkmarx purl handling (CXP-*), purl URLs (SAN-009), default tool (SAN-013), coverage and exit 7."""

from __future__ import annotations

import copy
import csv
import io
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sbom_fixer.changes import DATA_LOSS
from sbom_fixer.errors import ProfileError
from sbom_fixer.pipeline import EXIT_NO_SCANNABLE, run_fix
from sbom_fixer.profile import Profile, load_profile, parse_profile
from sbom_fixer.purlmap import classify, purl_from_url
from sbom_fixer.serialize import write_json

from .conftest import CORPUS, bom, ids, run


def comp(purl: str | None, name: str = "x", version: str | None = "1.0.0", **extra: Any) -> dict[str, Any]:
    c: dict[str, Any] = {"bom-ref": f"ref-{name}", "type": "library", "name": name}
    if version is not None:
        c["version"] = version
    if purl is not None:
        c["purl"] = purl
    c.update(extra)
    return c


def doc_with(*comps: dict[str, Any], version: str = "1.6") -> dict[str, Any]:
    d = bom(version)
    d["metadata"]["tools"] = {"components": [{"type": "application", "name": "gen", "version": "1"}]}
    d["components"] = list(comps)
    return d


def purls(doc: dict[str, Any]) -> list[Any]:
    return [c.get("purl") for c in doc["components"]]


def prop(c: dict[str, Any], name: str) -> str | None:
    return next((p["value"] for p in c.get("properties", []) if p["name"] == name), None)


# ------------------------------------------------------------------ supported types stay untouched


@pytest.mark.parametrize("purl", [
    "pkg:npm/lodash@4.17.21", "pkg:yarn/left-pad@1.3.0", "pkg:bower/jquery@3.7.1", "pkg:pypi/requests@2.31.0",
    "pkg:poetry/requests@2.31.0", "pkg:pip/requests@2.31.0", "pkg:nuget/Newtonsoft.Json@13.0.3",
    "pkg:maven/org.slf4j/slf4j-api@2.0.9", "pkg:gradle/com.google.guava/guava@32.1.3-jre", "pkg:sbt/org.scala-lang/scala-library@2.13.12",
    "pkg:composer/laravel/framework@10.0.0", "pkg:swiftpm/github.com/apple/swift-nio@2.62.0", "pkg:cocoapods/Alamofire@5.8.1",
    "pkg:golang/github.com/gorilla/mux@v1.8.0", "pkg:gomodules/github.com/gorilla/mux@v1.8.0", "pkg:conan/zlib@1.3",
    "pkg:gem/rails@7.1.2", "pkg:unity/com.unity.textmeshpro@3.0.6", "pkg:cpan/Moose@2.2206", "pkg:pub/http@1.1.0",
    "pkg:npm/%40angular/core@15.2.0", "pkg:maven/org.a/b@1.0?type=jar",
])
def test_supported_purls_are_not_rewritten(checkmarx: Profile, purl: str) -> None:
    out, res, log = run(doc_with(comp(purl)), checkmarx)
    assert res.ok and purls(out) == [purl]
    assert not {i for i in ids(log) if i.startswith("CXP-")}


def test_supported_aliases_map_to_checkmarx_package_managers(checkmarx: Profile) -> None:
    pm = checkmarx.purl.pm_for  # type: ignore[union-attr]
    assert pm("gradle") == pm("sbt") == pm("ivy") == pm("maven") == "Maven"
    assert pm("yarn") == pm("bower") == pm("npm") == "NPM"
    assert pm("cocoapods") == pm("carthage") == "Swift / iOS"
    assert pm("deb") == "C++ (Conan)" and pm("Poetry") == "Python (Pip)"
    for unsupported in ("rpm", "apk", "generic", "docker", "cargo", "hex", "github", "conda"):
        assert pm(unsupported) is None


# ------------------------------------------------------------------ format fixes CXP-001..005


def test_cxp001_type_lower_cased(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:NPM/lodash@4.17.21")), checkmarx)
    assert purls(out) == ["pkg:npm/lodash@4.17.21"] and "CXP-001" in ids(log)


def test_cxp002_npm_scope_encoded(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:npm/@angular/core@15.2.0"), comp("pkg:yarn/@babel/core@7.23.0", name="b")), checkmarx)
    assert purls(out) == ["pkg:npm/%40angular/core@15.2.0", "pkg:yarn/%40babel/core@7.23.0"]
    assert [c.rule_id for c in log.changes if c.rule_id.startswith("CXP")] == ["CXP-002", "CXP-002"]


def test_cxp003_version_from_component(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:pypi/django", version="4.2.7")), checkmarx)
    assert purls(out) == ["pkg:pypi/django@4.2.7"] and "CXP-003" in ids(log)


def test_cxp003_no_version_anywhere_is_reported_not_invented(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:npm/foo", version=None)), checkmarx)
    assert purls(out) == ["pkg:npm/foo"]
    assert any(f.rule_id == "CXP-003" and "latest version" in f.message for f in log.findings)


def test_cxp003_unknown_version_is_not_used(checkmarx: Profile) -> None:
    out, _, _ = run(doc_with(comp("pkg:npm/foo", version="unknown")), checkmarx)
    assert purls(out) == ["pkg:npm/foo"]


def test_cxp004_maven_group_from_component(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:gradle/guava@32.1.3", group="com.google.guava")), checkmarx)
    assert purls(out) == ["pkg:gradle/com.google.guava/guava@32.1.3"] and "CXP-004" in ids(log)


def test_cxp004_without_group_reported(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:maven/guava@32.1.3")), checkmarx)
    assert purls(out) == ["pkg:maven/guava@32.1.3"]
    assert any(f.rule_id == "CXP-004" for f in log.findings)


def test_cxp005_url_qualifiers_removed_original_kept(checkmarx: Profile) -> None:
    original = "pkg:maven/org.slf4j/slf4j-api@2.0.9?classifier=sources&repository_url=https://repo.example.com/maven2"
    out, _, log = run(doc_with(comp(original)), checkmarx)
    assert purls(out) == ["pkg:maven/org.slf4j/slf4j-api@2.0.9?classifier=sources"]
    assert prop(out["components"][0], "sbom-fixer:original-purl") == original and "CXP-005" in ids(log)


def test_cxp005_can_be_switched_off(checkmarx: Profile) -> None:
    prof = replace(checkmarx, purl=replace(checkmarx.purl, strip_url_qualifiers=False))  # type: ignore[type-var]
    p = "pkg:maven/org.a/b@1.0?repository_url=https://repo.example.com/maven2"
    out, _, _ = run(doc_with(comp(p)), prof)
    assert purls(out) == [p]


# ------------------------------------------------------------------ remaps CXP-010..013


def test_cxp010_github_go_module_with_evidence(checkmarx: Profile) -> None:
    c = comp("pkg:github/gorilla/handlers@v1.5.2", properties=[{"name": "syft:package:type", "value": "go-module"}])
    out, _, log = run(doc_with(c), checkmarx)
    assert purls(out) == ["pkg:golang/github.com/gorilla/handlers@v1.5.2"] and "CXP-010" in ids(log)
    assert prop(out["components"][0], "sbom-fixer:original-purl") == "pkg:github/gorilla/handlers@v1.5.2"


def test_cxp010_bom_ref_is_evidence(checkmarx: Profile) -> None:
    c = comp("pkg:github/gorilla/mux@v1.8.0", **{"bom-ref": "pkg:golang/github.com/gorilla/mux@v1.8.0"})
    out, _, _ = run(doc_with(c), checkmarx)
    assert purls(out) == ["pkg:golang/github.com/gorilla/mux@v1.8.0"]


def test_cxp010_github_without_evidence_is_kept(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:github/actions/checkout@v4")), checkmarx)
    assert purls(out) == ["pkg:github/actions/checkout@v4"] and "CXP-010" not in ids(log)
    assert any(f.rule_id == "CXP-020" for f in log.findings)


def test_cxp011_generic_with_generator_type(checkmarx: Profile) -> None:
    c = comp("pkg:generic/jackson-databind@2.16.0", name="jackson-databind", version="2.16.0", group="com.fasterxml.jackson.core",
             properties=[{"name": "syft:package:type", "value": "java-archive"}])
    out, _, log = run(doc_with(c), checkmarx)
    assert purls(out) == ["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.16.0"] and "CXP-011" in ids(log)


def test_cxp011_maven_without_group_is_not_guessed(checkmarx: Profile) -> None:
    c = comp("pkg:generic/jackson-databind@2.16.0", properties=[{"name": "syft:package:type", "value": "java-archive"}])
    out, _, _ = run(doc_with(c), checkmarx)
    assert purls(out) == ["pkg:generic/jackson-databind@2.16.0"]


def test_cxp011_target_must_be_supported(checkmarx: Profile) -> None:
    c = comp("pkg:generic/serde@1.0.0", properties=[{"name": "syft:package:type", "value": "cargo"}])
    out, _, _ = run(doc_with(c), checkmarx)
    assert purls(out) == ["pkg:generic/serde@1.0.0"]


def test_cxp012_generic_with_registry_download_url(checkmarx: Profile) -> None:
    c = comp("pkg:generic/flask@3.0.0?download_url=https://files.pythonhosted.org/packages/ab/cd/flask-3.0.0-py3-none-any.whl")
    out, _, log = run(doc_with(c), checkmarx)
    assert purls(out) == ["pkg:pypi/flask@3.0.0"] and "CXP-012" in ids(log)


def test_cxp012_unknown_host_is_kept(checkmarx: Profile) -> None:
    p = "pkg:generic/tool@1.0?download_url=https://downloads.example.com/tool-1.0.zip"
    out, _, _ = run(doc_with(comp(p)), checkmarx)
    assert purls(out) == [p]


def test_cxp013_nonstandard_types(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:nodejs/express@4.18.2", name="a"), comp("pkg:dotnet/Serilog@3.1.1", name="b"),
                               comp("pkg:jar/org.a/b@1.0", name="c"), comp("pkg:jar/b@1.0", name="d")), checkmarx)
    assert purls(out) == ["pkg:npm/express@4.18.2", "pkg:nuget/Serilog@3.1.1", "pkg:maven/org.a/b@1.0", "pkg:jar/b@1.0"]


def test_remap_can_be_switched_off(checkmarx: Profile) -> None:
    prof = replace(checkmarx, purl=replace(checkmarx.purl, remap=False))  # type: ignore[type-var]
    out, _, _ = run(doc_with(comp("pkg:nodejs/express@4.18.2")), prof)
    assert purls(out) == ["pkg:nodejs/express@4.18.2"]


# ------------------------------------------------------------------ unsupported and OS packages CXP-020/021


def test_unsupported_and_os_packages_kept_and_reported(checkmarx: Profile) -> None:
    d = doc_with(comp("pkg:cargo/serde@1.0.197", name="serde"), comp("pkg:rpm/redhat/bash@5.1", name="bash"),
                 comp("pkg:deb/debian/libc6@2.36-9?distro=debian-12", name="libc6"), comp("pkg:npm/a@1", name="a"))
    out, _, log = run(d, checkmarx)
    assert len(out["components"]) == 4 and not log.changes
    by_rule = {f.rule_id: [] for f in log.findings}
    for f in log.findings:
        by_rule[f.rule_id].append(f)
    assert len(by_rule["CXP-020"]) == 1 and len(by_rule["CXP-021"]) == 2
    deb = next(f for f in by_rule["CXP-021"] if "libc6" in f.message)
    assert deb.severity == "WARN" and "C++ (Conan)" in deb.message


def test_deb_cpp_library_is_scanned(checkmarx: Profile) -> None:
    out, _, log = run(doc_with(comp("pkg:deb/libcurl4-openssl-dev@7.88.1")), checkmarx)
    assert not any(f.rule_id == "CXP-021" for f in log.findings)
    cov = classify(out, "cyclonedx", checkmarx.purl)  # type: ignore[arg-type]
    assert cov.rows[0].status == "supported" and cov.rows[0].checkmarx_pm == "C++ (Conan)"


def test_remove_actions_drop_components_and_edges(checkmarx: Profile) -> None:
    prof = replace(checkmarx, purl=replace(checkmarx.purl, unsupported_action="remove", os_package_action="remove"))  # type: ignore[type-var]
    d = doc_with(comp("pkg:cargo/serde@1.0.197", name="serde"), comp("pkg:rpm/redhat/bash@5.1", name="bash"),
                 comp("pkg:npm/a@1", name="a"))
    d["dependencies"] = [{"ref": "ref-a", "dependsOn": ["ref-serde", "ref-bash"]}, {"ref": "ref-serde", "dependsOn": []}]
    out, res, log = run(d, prof)
    assert res.ok and [c["name"] for c in out["components"]] == ["a"]
    assert out["dependencies"] == [{"ref": "ref-a", "dependsOn": []}]
    removed = [c for c in log.changes if c.rule_id in ("CXP-020", "CXP-021") and c.severity == DATA_LOSS]
    assert len(removed) == 2


def test_cpe_only_component_reported(checkmarx: Profile) -> None:
    c = comp(None, name="openssl", cpe="cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*")
    _, _, log = run(doc_with(c, comp("pkg:npm/a@1", name="a")), checkmarx)
    assert any(f.rule_id == "CXP-030" for f in log.findings)


def test_cxp_rules_inactive_without_purl_policy() -> None:
    comp_profile = load_profile("compliance")
    out, _, log = run(doc_with(comp("pkg:npm/@angular/core@15.2.0"), comp("pkg:nodejs/x@1", name="n")), comp_profile)
    assert purls(out) == ["pkg:npm/@angular/core@15.2.0", "pkg:nodejs/x@1"]
    assert not any(i.startswith("CXP-") for i in ids(log))


# ------------------------------------------------------------------ SAN-009 purl as URL


@pytest.mark.parametrize("url,version,expected", [
    ("https://registry.npmjs.org/axios/-/axios-1.6.2.tgz", None, "pkg:npm/axios@1.6.2"),
    ("https://registry.npmjs.org/@types/node/-/node-20.10.0.tgz", None, "pkg:npm/%40types/node@20.10.0"),
    ("https://repo1.maven.org/maven2/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar", None, "pkg:maven/org.yaml/snakeyaml@2.2"),
    ("https://repo.maven.apache.org/maven2/com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.pom", None,
     "pkg:maven/com.google.guava/guava@32.1.3-jre"),
    ("https://files.pythonhosted.org/packages/a/b/requests-2.31.0.tar.gz", None, "pkg:pypi/requests@2.31.0"),
    ("https://files.pythonhosted.org/packages/a/b/typing_extensions-4.9.0-py3-none-any.whl", None, "pkg:pypi/typing-extensions@4.9.0"),
    ("https://pypi.org/project/Django/4.2.7/", None, "pkg:pypi/django@4.2.7"),
    ("https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", None,
     "pkg:nuget/newtonsoft.json@13.0.3"),
    ("https://www.nuget.org/packages/Serilog/3.1.1", None, "pkg:nuget/Serilog@3.1.1"),
    ("https://rubygems.org/gems/rails-7.1.2.gem", None, "pkg:gem/rails@7.1.2"),
    ("https://rubygems.org/gems/nokogiri-1.15.5-x86_64-linux.gem", None, "pkg:gem/nokogiri@1.15.5"),
    ("https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.3.2.zip", None, "pkg:golang/github.com/BurntSushi/toml@v1.3.2"),
    ("https://pub.dev/packages/http/versions/1.1.0", None, "pkg:pub/http@1.1.0"),
    ("https://github.com/acme/widget", "2.0.0", "pkg:github/acme/widget@2.0.0"),
    ("https://github.com/acme/widget/releases/tag/v3.1.0", None, "pkg:github/acme/widget@v3.1.0"),
    ("https://downloads.example.com/tool-1.0.zip", "1.0", None),
    ("https://registry.npmjs.org/axios", None, None),
])
def test_purl_from_url(url: str, version: str | None, expected: str | None) -> None:
    got = purl_from_url(url, version)
    assert (got.to_string() if got else None) == expected


def test_san009_registry_url_converted_other_url_moved(checkmarx: Profile) -> None:
    d = doc_with(comp("https://registry.npmjs.org/axios/-/axios-1.6.2.tgz", name="axios"),
                 comp("https://downloads.example.com/tool-1.0.zip", name="tool"), version="1.5")
    out, res, log = run(d, checkmarx)
    assert res.ok and purls(out) == ["pkg:npm/axios@1.6.2", None]
    assert out["components"][1]["externalReferences"] == [{"type": "distribution", "url": "https://downloads.example.com/tool-1.0.zip"}]
    assert [c.severity for c in log.changes if c.rule_id == "SAN-009"] == ["INFO", "WARN"]


def test_san009_runs_in_every_profile() -> None:
    out, _, log = run(doc_with(comp("https://rubygems.org/gems/rails-7.1.2.gem")), load_profile("compliance"))
    assert purls(out) == ["pkg:gem/rails@7.1.2"] and "SAN-009" in ids(log)


def test_san009_spdx(checkmarx: Profile) -> None:
    d = copy.deepcopy(_spdx())
    d["packages"][0]["externalRefs"][0]["referenceLocator"] = "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    out, res, log = run(d, checkmarx)
    assert res.ok and out["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:npm/lodash@4.17.20"


# ------------------------------------------------------------------ SAN-013 default tool


@pytest.mark.parametrize("version,expected", [
    ("1.6", {"components": [{"type": "application", "name": "sbom-fixer", "version": "1.0.0"}]}),
    ("1.4", [{"vendor": "sbom-fixer", "name": "sbom-fixer", "version": "1.0.0"}]),
])
def test_san013_default_tool_in_version_form(checkmarx: Profile, version: str, expected: Any) -> None:
    d = doc_with(comp("pkg:npm/a@1"), version=version)
    d["metadata"].pop("tools")
    out, res, log = run(d, checkmarx)
    assert res.ok and out["metadata"]["tools"] == expected and "SAN-013" in ids(log)


def test_san013_empty_tools_replaced_and_no_duplicate_with_provenance(tmp_path: Path) -> None:
    d = doc_with(comp("pkg:npm/a@1"))
    d["metadata"]["tools"] = {"components": []}
    src = tmp_path / "t.cdx.json"
    write_json(d, src)
    r = run_fix(src, load_profile("checkmarx"), tmp_path / "out", audit=False)
    tools = r.fixed_doc["metadata"]["tools"]["components"]
    assert [t["name"] for t in tools] == ["sbom-fixer"] and r.exit_code == 1


def test_san013_existing_tool_untouched(checkmarx: Profile) -> None:
    _, _, log = run(doc_with(comp("pkg:npm/a@1")), checkmarx)
    assert "SAN-013" not in ids(log)


def test_san013_spdx_creator(checkmarx: Profile) -> None:
    d = _spdx()
    d["creationInfo"]["creators"] = ["Organization: Platform Team"]
    out, res, log = run(d, checkmarx)
    assert res.ok and out["creationInfo"]["creators"] == ["Organization: Platform Team", "Tool: sbom-fixer-1.0.0"]


def test_san013_off_in_compliance() -> None:
    d = doc_with(comp("pkg:npm/a@1"))
    d["metadata"].pop("tools")
    _, _, log = run(d, load_profile("compliance"))
    assert "SAN-013" not in ids(log)


# ------------------------------------------------------------------ SPDX


def _spdx() -> dict[str, Any]:
    import json

    return json.loads((CORPUS / "minimal" / "min-spdx-2.3.json").read_text(encoding="utf-8"))


def test_spdx_purl_rules_and_relationships(checkmarx: Profile) -> None:
    d = _spdx()
    d["packages"][0]["externalRefs"][0]["referenceLocator"] = "pkg:nodejs/lodash@4.17.20"
    d["relationships"] = []
    out, res, log = run(d, checkmarx)
    assert res.ok and out["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:npm/lodash@4.17.20"
    assert "sbom-fixer:original-purl=pkg:nodejs/lodash@4.17.20" in out["packages"][0]["comment"]
    assert any(f.rule_id == "CXP-051" for f in log.findings)


# ------------------------------------------------------------------ coverage, CSV, exit 7


def test_coverage_statuses_and_csv(tmp_path: Path) -> None:
    r = run_fix(CORPUS / "purl" / "remap.cdx.json", load_profile("checkmarx"), tmp_path, audit=False)
    assert r.coverage is not None and r.coverage_before is not None
    assert r.coverage_before.scanned == 0 and r.coverage.scanned == 4
    assert r.coverage.by_status()["remapped"] == 4 and r.coverage.by_status()["unsupported"] == 2
    rows = list(csv.DictReader(io.StringIO(Path(r.outputs["coverage"]).read_text(encoding="utf-8"))))
    flask = next(x for x in rows if x["name"] == "flask")
    assert flask["status"] == "remapped" and flask["rule_ids"] == "CXP-012" and flask["final_purl"] == "pkg:pypi/flask@3.0.0"
    assert flask["original_purl"].startswith("pkg:generic/flask@3.0.0?download_url=")
    notes = Path(r.outputs["notes"]).read_text(encoding="utf-8")
    assert "Expected package count in Checkmarx results: about 4" in notes and "6. COMPONENTS CHECKMARX WILL SKIP" in notes
    import json

    summary = json.loads(Path(r.outputs["changes"]).read_text(encoding="utf-8"))["checkmarx_coverage"]
    assert summary["before"]["scanned"] == 0 and summary["after"]["scanned"] == 4


def test_coverage_chain_keeps_first_original(tmp_path: Path) -> None:
    d = doc_with(comp("pkg:generic/flask@3.0.0?download_url=https://files.pythonhosted.org/p/flask-3.0.0.tar.gz", name="flask"))
    d["components"][0]["purl"] = "pkg:NODEJS/express@4.18.2?repository_url=https://r.example.com"
    src = tmp_path / "c.cdx.json"
    write_json(d, src)
    r = run_fix(src, load_profile("checkmarx"), tmp_path / "o", audit=False)
    row = r.coverage.rows[0]  # type: ignore[union-attr]
    assert row.final_purl == "pkg:npm/express@4.18.2" and row.status == "remapped"
    assert row.original_purl == "pkg:NODEJS/express@4.18.2?repository_url=https://r.example.com"
    assert row.rule_ids.split() == ["CXP-001", "CXP-013", "CXP-005"]


def test_exit_7_when_nothing_is_scannable(tmp_path: Path) -> None:
    r = run_fix(CORPUS / "purl" / "none-supported.cdx.json", load_profile("checkmarx"), tmp_path, audit=False)
    assert r.exit_code == EXIT_NO_SCANNABLE and r.coverage is not None and r.coverage.scanned == 0
    assert "Checkmarx would fail the scan" in Path(r.outputs["notes"]).read_text(encoding="utf-8")


def test_min_supported_zero_disables_gate(tmp_path: Path) -> None:
    prof = load_profile("checkmarx")
    prof = replace(prof, purl=replace(prof.purl, min_supported=0))  # type: ignore[type-var]
    r = run_fix(CORPUS / "purl" / "none-supported.cdx.json", prof, tmp_path, audit=False)
    assert r.exit_code == 0


def test_exit_7_skips_cli_verify(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from sbom_fixer.cli import app

    res = CliRunner().invoke(app, ["fix", str(CORPUS / "purl" / "none-supported.cdx.json"), "--out", str(tmp_path), "--no-audit"])
    assert res.exit_code == 7, res.output


# ------------------------------------------------------------------ profile validation


@pytest.mark.parametrize("purl,msg", [
    ({"supported_types": {}}, "supported_types"),
    ({"supported_types": {"NPM": ["npm"]}, "unsupported_action": "drop"}, "unsupported_action"),
    ({"supported_types": {"NPM": ["npm"]}, "bogus": 1}, "Unknown key"),
])
def test_purl_profile_validation(purl: dict[str, Any], msg: str) -> None:
    with pytest.raises(ProfileError, match=msg):
        parse_profile({"name": "x", "cyclonedx": {"floor": "1.3", "accepted_versions": ["1.5"]}, "purl": purl})


def test_unencoded_npm_scope_counts_as_not_scanned_before_the_fix(tmp_path: Path) -> None:
    r = run_fix(CORPUS / "purl" / "format-fixes.cdx.json", load_profile("checkmarx"), tmp_path, audit=False)
    assert r.coverage_before is not None and r.coverage is not None
    before = {row.name: row.status for row in r.coverage_before.rows}
    assert before["@angular/core"] == "malformed" and r.coverage_before.scanned == 5
    after = {row.name: row.status for row in r.coverage.rows}
    assert after["@angular/core"] == "fixed" and after["no-version-anywhere"] == "versionless" and r.coverage.scanned == 6
