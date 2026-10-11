"""Version policy: 1.6 / 1.7 kept, 1.8+ generic future hop, 2.x refused, checkmarx-cli caps at 1.6."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sbom_fixer.changes import DATA_LOSS
from sbom_fixer.errors import ProfileError
from sbom_fixer.pipeline import run_fix
from sbom_fixer.profile import Profile, load_profile, parse_profile
from sbom_fixer.schemas import is_future
from sbom_fixer.serialize import write_json
from sbom_fixer.validate import validate

from .conftest import CORPUS, bom, ids, repair_only, run


def future_doc(version: str = "1.8", **comp_extra: Any) -> dict[str, Any]:
    d = bom("1.7")
    d["specVersion"] = version
    d["metadata"]["tools"] = {"components": [{"type": "application", "name": "gen", "version": "1"}]}
    d["components"][0].update(comp_extra)
    return d


def test_is_future() -> None:
    assert is_future("cyclonedx", "1.8") and is_future("cyclonedx", "1.10")
    assert not is_future("cyclonedx", "1.7") and not is_future("cyclonedx", "2.0") and not is_future("cyclonedx", "1.1")
    assert not is_future("cyclonedx", "abc")


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_16_and_17_are_kept(checkmarx: Profile, version: str) -> None:
    d = bom(version)
    d["metadata"]["tools"] = {"components": [{"type": "application", "name": "gen", "version": "1"}]}
    out, res, log = run(d, checkmarx)
    assert res.ok and res.final_version == version and res.path == [version] and not log.changes


def capped_cli(top: str = "1.6") -> Profile:
    """checkmarx-cli capped for one run, as with --accepted 1.3,1.4,1.5,1.6."""
    order = ["1.3", "1.4", "1.5", "1.6", "1.7"]
    return parse_profile({"name": "cli-capped", "cyclonedx": {"floor": "1.3", "accepted_versions": order[:order.index(top) + 1],
                                                              "max_version": "1.7", "future_versions": "downgrade"},
                          "provenance": False, "allow_downgrade": True})


@pytest.mark.parametrize("profile_name", ["checkmarx", "checkmarx-cli", "compliance"])
@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_no_profile_downgrades_16_or_17(profile_name: str, version: str, tmp_path: Path) -> None:
    src = CORPUS / "minimal" / f"min-cdx-{version}.json"
    r = run_fix(src, repair_only(load_profile(profile_name)), tmp_path, audit=False)
    assert r.final_version == version and r.descent is not None and r.descent.path == [version], r.descent
    assert r.exit_code == 0


@pytest.mark.parametrize("rel", ["cdxgen/analytics.cdxgen.json", "cdxgen/crypto.cdx.json", "trivy/payments-api.trivy.json"])
@pytest.mark.parametrize("profile_name", ["checkmarx", "checkmarx-cli"])
def test_generator_files_keep_their_version(rel: str, profile_name: str, tmp_path: Path) -> None:
    r = run_fix(CORPUS / rel, repair_only(load_profile(profile_name)), tmp_path, audit=False)
    assert r.final_version == r.declared and r.descent is not None and r.descent.path == [r.declared]


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_cli_commands_keep_16_and_17(version: str, tmp_path: Path) -> None:
    import json

    from typer.testing import CliRunner

    from sbom_fixer.cli import app

    src = CORPUS / "minimal" / f"min-cdx-{version}.json"
    runner = CliRunner()
    for profile_name in ("checkmarx", "checkmarx-cli"):
        res = runner.invoke(app, ["check", str(src), "-p", profile_name])
        assert res.exit_code == 1 and f"level {version}  : ACCEPTED" in res.output, res.output  # 1: canonical form
        res = runner.invoke(app, ["check", str(src), "-p", profile_name, "--no-canonical"])
        assert res.exit_code == 0 and f"level {version}  : ACCEPTED" in res.output, res.output
    res = runner.invoke(app, ["fix", str(src), "-p", "checkmarx", "-p", "checkmarx-cli", "-p", "compliance",
                              "--out", str(tmp_path), "--no-audit"])
    assert res.exit_code == 1, res.output  # the checkmarx copies are rewritten to the canonical form
    for profile_name in ("checkmarx", "checkmarx-cli", "compliance"):
        out = json.loads((tmp_path / f"min-cdx-{version}.{profile_name}.cdx.json").read_text(encoding="utf-8"))
        assert out["specVersion"] == version
    res = runner.invoke(app, ["audit", str(src), "--json"])
    assert res.exit_code == 0


def test_accepted_override_still_caps_17_to_16() -> None:
    d = bom("1.7")
    d["metadata"]["tools"] = {"components": [{"type": "application", "name": "gen", "version": "1"}]}
    out, res, _ = run(d, capped_cli("1.6"))
    assert res.final_version == "1.6" and res.path == ["1.7", "1.6"] and out["specVersion"] == "1.6"


def test_future_hop_to_17(checkmarx: Profile) -> None:
    out, res, log = run(future_doc(newField18="v"), checkmarx)
    assert res.ok and res.final_version == "1.7" and res.path == ["1.8", "1.7"]
    assert out["specVersion"] == "1.7" and validate(out, "cyclonedx", "1.7") == []
    assert {"name": "sbom-fixer:cdx18:newField18", "value": "v"} in out["components"][0]["properties"]
    assert {"CDX-FWD-001", "CDX-FWD-002"} <= ids(log)
    assert next(c for c in log.changes if c.rule_id == "CDX-FWD-001").level == "1.8->1.7"


def test_future_hop_schema_url_updated(checkmarx: Profile) -> None:
    d = future_doc()
    d["$schema"] = "http://cyclonedx.org/schema/bom-1.8.schema.json"
    out, _, _ = run(d, checkmarx)
    assert out["$schema"] == "http://cyclonedx.org/schema/bom-1.7.schema.json"


def test_future_hop_object_value_as_json_property(checkmarx: Profile) -> None:
    d = future_doc()
    d["metadata"]["distributionScope"] = {"level": "internal"}
    out, res, _ = run(d, checkmarx)
    assert res.ok and {"name": "sbom-fixer:cdx18:distributionScope", "value": '{"level": "internal"}'} in out["metadata"]["properties"]


def test_future_hop_field_where_no_properties_allowed_is_data_loss(checkmarx: Profile) -> None:
    d = future_doc()
    d["components"][0]["licenses"] = [{"license": {"id": "MIT", "newLicenseField": "x"}}]
    out, res, log = run(d, checkmarx)
    assert res.ok and "newLicenseField" not in out["components"][0]["licenses"][0]["license"]
    assert any(c.rule_id == "CDX-FWD-002" and c.severity == DATA_LOSS for c in log.changes)


def test_future_hop_huge_value_is_data_loss(checkmarx: Profile) -> None:
    out, res, log = run(future_doc(newBlob={"x": "a" * 5000}), checkmarx)
    assert res.ok and "newBlob" not in out["components"][0]
    assert any(c.rule_id == "CDX-FWD-002" and c.severity == DATA_LOSS for c in log.changes)


def test_future_hop_enum_to_other_with_comment(checkmarx: Profile) -> None:
    d = future_doc(externalReferences=[{"type": "sbom-registry-v2", "url": "https://example.com/sbom"}])
    out, res, log = run(d, checkmarx)
    ref = out["components"][0]["externalReferences"][0]
    assert res.ok and ref["type"] == "other" and ref["comment"] == "original type: sbom-registry-v2"
    assert any(c.rule_id == "CDX-FWD-003" and c.severity == "WARN" for c in log.changes)


def test_future_hop_enum_without_other_is_removed(checkmarx: Profile) -> None:
    d = future_doc()
    d["components"][0]["hashes"] = [{"alg": "SHA3-1024", "content": "a" * 64}, {"alg": "SHA-256", "content": "b" * 64}]
    out, res, log = run(d, checkmarx)
    assert res.ok and validate(out, "cyclonedx", "1.7") == []
    assert any(c.rule_id == "CDX-FWD-003" and c.severity == DATA_LOSS for c in log.changes)


def test_future_hop_lands_on_17_for_every_checkmarx_profile() -> None:
    for name in ("checkmarx", "checkmarx-cli"):
        _, res, _ = run(future_doc(newField18="v"), repair_only(load_profile(name)))
        assert res.path == ["1.8", "1.7"] and res.final_version == "1.7", name


def test_future_hop_then_one_off_cap() -> None:
    _, res, _ = run(future_doc(newField18="v"), capped_cli("1.6"))
    assert res.path == ["1.8", "1.7", "1.6"] and res.final_version == "1.6"


def test_future_reject_profile() -> None:
    prof = parse_profile({"name": "strict", "cyclonedx": {"floor": "1.3", "accepted_versions": ["1.5", "1.6", "1.7"]},
                          "provenance": False})
    _, res, _ = run(future_doc(), prof)
    assert not res.ok and "future_versions: reject" in res.attempts[0].reason


def test_major_2_refused(checkmarx: Profile) -> None:
    _, res, log = run(future_doc("2.0"), checkmarx)
    assert not res.ok and "VER-002" in res.attempts[0].reason and not log.changes


def test_future_end_to_end(tmp_path: Path) -> None:
    r = run_fix(CORPUS / "future" / "min-cdx-1.8.json", repair_only(load_profile("checkmarx")), tmp_path)
    assert r.exit_code == 1 and r.final_version == "1.7"
    notes = Path(r.outputs["notes"]).read_text(encoding="utf-8")
    assert "B (downgrade 1.8 -> 1.7)" in notes and "generic future hop to 1.7" in notes and "CDX-FWD-002" in notes
    again = run_fix(Path(r.outputs["sbom"]), repair_only(load_profile("checkmarx")), tmp_path / "again")
    assert again.exit_code == 0


def test_future_check_command_is_read_only(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from sbom_fixer.cli import app

    src = tmp_path / "f.json"
    write_json(future_doc(), src)
    res = CliRunner().invoke(app, ["check", str(src)])
    assert res.exit_code == 1 and "level 1.7  : ACCEPTED" in res.output
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.json"]


@pytest.mark.parametrize("sec,msg", [
    ({"floor": "1.3", "accepted_versions": ["1.5"], "future_versions": "downgrade"}, "needs max_version"),
    ({"floor": "1.3", "accepted_versions": ["1.5"], "future_versions": "maybe", "max_version": "1.7"}, "future_versions must be"),
    ({"floor": "1.3", "accepted_versions": ["1.5"], "future_versions": "downgrade", "max_version": "1.9"}, "not one of"),
])
def test_future_profile_validation(sec: dict[str, Any], msg: str) -> None:
    with pytest.raises(ProfileError, match=msg):
        parse_profile({"name": "x", "cyclonedx": sec})


def test_generator_hint_names_the_actual_target_version(tmp_path: Path) -> None:
    import json

    doc = json.loads((CORPUS / "cdxgen" / "analytics.cdxgen.json").read_text(encoding="utf-8"))
    doc["metadata"]["tools"] = {"components": [{"type": "application", "name": "cdxgen", "version": "11.0.0"}]}
    src = tmp_path / "gen.cdx.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    r = run_fix(src, capped_cli("1.6"), tmp_path / "out", audit=False)
    notes = Path(r.outputs["notes"]).read_text(encoding="utf-8")
    assert r.final_version == "1.6" and "--spec-version 1.6" in notes and "--spec-version 1.5" not in notes
