"""Detect encoding, format, spec version and generator from raw bytes (Guide Step 07)."""

from __future__ import annotations

import codecs
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .errors import DetectError


@dataclass
class EncodingIssue:
    rule_id: str
    message: str


@dataclass
class Detected:
    spec: str  # "cyclonedx" | "spdx"
    serialization: str  # "json"
    version: str
    generator: str | None
    encoding: str
    encoding_issues: list[EncodingIssue] = field(default_factory=list)


def decode(raw: bytes) -> tuple[str, str, list[EncodingIssue]]:
    issues: list[EncodingIssue] = []
    if raw.startswith(codecs.BOM_UTF8):
        issues.append(EncodingIssue("ENC-001", "File starts with a UTF-8 byte order mark (BOM)."))
        return raw[3:].decode("utf-8"), "utf-8-sig", issues
    if raw[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        issues.append(EncodingIssue("ENC-002", "File is UTF-16 encoded (typical of PowerShell 5.1 '>' redirection)."))
        return raw.decode("utf-16"), "utf-16", issues
    try:
        return raw.decode("utf-8"), "utf-8", issues
    except UnicodeDecodeError:
        issues.append(EncodingIssue("ENC-003", "File is not valid UTF-8; decoded as Windows-1252."))
        return raw.decode("cp1252"), "cp1252", issues


def _cdx_generator(doc: dict[str, Any]) -> str | None:
    tools: Any = (doc.get("metadata") or {}).get("tools")
    if isinstance(tools, dict):
        tools = tools.get("components", [])
    names = []
    for t in tools or []:
        if isinstance(t, dict) and t.get("name"):
            names.append(f"{t.get('name')} {t.get('version', '')}".strip())
    return ", ".join(names) or None


def _spdx_generator(doc: dict[str, Any]) -> str | None:
    creators = (doc.get("creationInfo") or {}).get("creators", []) or []
    tools = [c.removeprefix("Tool:").strip() for c in creators if isinstance(c, str) and c.startswith("Tool:")]
    return ", ".join(tools) or None


def detect(raw: bytes) -> tuple[Detected, Any]:
    if not raw.strip():
        raise DetectError("The file is empty.")
    text, encoding, issues = decode(raw)
    head = text.lstrip()[:4000]
    if head.startswith("{") or head.startswith("["):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DetectError(f"The file is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise DetectError("The JSON root is not an object.")
        if str(doc.get("bomFormat", "")).lower() == "cyclonedx":
            ver = doc.get("specVersion")
            if ver is None:
                raise DetectError("CycloneDX document has no specVersion.")
            return Detected("cyclonedx", "json", _norm_version(ver), _cdx_generator(doc), encoding, issues), doc
        if "spdxVersion" in doc:
            ver = str(doc["spdxVersion"]).removeprefix("SPDX-")
            return Detected("spdx", "json", _norm_version(ver), _spdx_generator(doc), encoding, issues), doc
        if "@context" in doc or "@graph" in doc:
            raise DetectError("SPDX 3.0 JSON-LD is not supported. Regenerate the SBOM as CycloneDX or SPDX 2.3.")
        raise DetectError("JSON file is neither CycloneDX (bomFormat) nor SPDX 2.x (spdxVersion).")
    if head.startswith("<"):
        m = re.search(r"cyclonedx\.org/schema/bom/(\d+\.\d+)", head)
        if m:
            raise DetectError(
                f"CycloneDX XML {m.group(1)} is not supported yet. Regenerate as JSON "
                "(for example cyclonedx-maven-plugin -DoutputFormat=json)."
            )
        raise DetectError("XML file is not a CycloneDX BOM.")
    if head.startswith("SPDXVersion:"):
        raise DetectError("SPDX tag-value is not supported. Convert it to JSON first (pyspdxtools).")
    raise DetectError("Unknown SBOM format.")


def _norm_version(v: Any) -> str:
    s = str(v).strip()
    m = re.match(r"^(\d+)\.(\d+)", s)
    return f"{m.group(1)}.{m.group(2)}" if m else s
