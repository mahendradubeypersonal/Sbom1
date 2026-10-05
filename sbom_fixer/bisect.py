"""Find the smallest change that makes a failing SBOM import (Guide Step 03, SBOMFIX-704).

Uploads only to the verification project, within a budget, with results cached by document hash.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .jsonutil import sha256_of
from .schemas import VERSION_ORDER, schema_url

Check = Callable[[Any], bool]
TOP_LEVEL = ["dependencies", "compositions", "vulnerabilities", "services", "formulation", "annotations",
             "declarations", "definitions", "properties", "externalReferences", "citations", "signature"]
COMPONENT_FIELDS = ["evidence", "licenses", "externalReferences", "hashes", "properties", "omniborId", "swhid",
                    "authors", "manufacturer", "supplier", "cryptoProperties", "tags", "pedigree", "releaseNotes"]


@dataclass
class Step:
    stage: str
    description: str
    accepted: bool | None  # None = not tried (budget)


@dataclass
class BisectReport:
    steps: list[Step] = field(default_factory=list)
    conclusions: list[str] = field(default_factory=list)
    uploads: int = 0
    inconclusive: bool = False


class _Runner:
    def __init__(self, check: Check, budget: int) -> None:
        self.check, self.budget, self.uploads = check, budget, 0
        self.cache: dict[str, bool] = {}

    def __call__(self, doc: Any) -> bool | None:
        key = sha256_of(doc)
        if key in self.cache:
            return self.cache[key]
        if self.uploads >= self.budget:
            return None
        self.uploads += 1
        self.cache[key] = bool(self.check(doc))
        return self.cache[key]


def _keep_components(doc: dict[str, Any], comps: list[Any]) -> dict[str, Any]:
    d = copy.deepcopy(doc)
    d["components"] = copy.deepcopy(comps)
    refs = {c.get("bom-ref") for c in comps if isinstance(c, dict)}
    if isinstance(d.get("dependencies"), list):
        d["dependencies"] = [
            dict(x, dependsOn=[r for r in x.get("dependsOn") or [] if r in refs]) if "dependsOn" in x else x
            for x in d["dependencies"] if isinstance(x, dict) and x.get("ref") in refs
        ]
    return d


def _relabel(doc: dict[str, Any], version: str | None) -> dict[str, Any]:
    d = copy.deepcopy(doc)
    if version:
        d["specVersion"] = version
        if "$schema" in d:
            d["$schema"] = schema_url(version)
    return d


def bisect(doc: dict[str, Any], check: Check, max_uploads: int = 30, base_version: str | None = None) -> BisectReport:
    """base_version: version label used for the content stages (normally the highest accepted version),
    so that a rejected declared version does not hide the field that really breaks the import."""
    rep = BisectReport()
    run = _Runner(check, max_uploads)

    def attempt(stage: str, desc: str, candidate: Any) -> bool | None:
        r = run(candidate)
        rep.steps.append(Step(stage, desc, r))
        return r

    first = attempt("baseline", "original file", doc)
    if first:
        rep.conclusions.append("The original file is accepted; nothing to bisect.")
        rep.uploads = run.uploads
        return rep
    if first is None:
        rep.inconclusive = True
        return rep

    spec_v = str(doc.get("specVersion", ""))
    order = VERSION_ORDER["cyclonedx"]
    if spec_v in order:
        for lower in reversed(order[: order.index(spec_v)]):
            cand = copy.deepcopy(doc)
            cand["specVersion"] = lower
            if "$schema" in cand:
                cand["$schema"] = schema_url(lower)
            r = attempt("version-only", f"declared version changed to {lower}, nothing else", cand)
            if r:
                rep.conclusions.append(f"The importer rejects specVersion {spec_v}; {lower} with the same content is accepted.")
                rep.uploads = run.uploads
                rep.inconclusive = False
                return rep

    doc = _relabel(doc, base_version)
    if base_version and base_version != spec_v:
        rep.conclusions.append(f"Content stages use version label {base_version} (declared {spec_v}).")

    for key in TOP_LEVEL:
        if key in doc:
            cand = copy.deepcopy(doc)
            cand.pop(key)
            if attempt("top-level", f"without '{key}'", cand):
                rep.conclusions.append(f"Removing top-level '{key}' makes the file import.")

    if isinstance(doc.get("metadata"), dict) and len(doc["metadata"]) > 1:
        cand = copy.deepcopy(doc)
        cand["metadata"] = {k: v for k, v in doc["metadata"].items() if k == "timestamp"}
        if attempt("metadata", "metadata reduced to timestamp", cand):
            for key in doc["metadata"]:
                if key == "timestamp":
                    continue
                c2 = copy.deepcopy(cand)
                c2["metadata"][key] = copy.deepcopy(doc["metadata"][key])
                if attempt("metadata", f"metadata timestamp + '{key}'", c2) is False:
                    rep.conclusions.append(f"metadata.{key} breaks the import.")

    comps = doc.get("components")
    if isinstance(comps, list) and comps:
        current = comps
        while len(current) > 1:
            half = len(current) // 2
            left, right = current[:half], current[half:]
            r_left = attempt("components", f"only components[{len(left)}] (first half)", _keep_components(doc, left))
            if r_left is False:
                current = left
                continue
            r_right = attempt("components", f"only components[{len(right)}] (second half)", _keep_components(doc, right))
            if r_right is False:
                current = right
                continue
            break
        narrowed = len(current) == 1 and (len(comps) > 1 or run(_keep_components(doc, current)) is False)
        if narrowed and isinstance(current[0], dict):
            c = current[0]
            rep.conclusions.append(f"Component '{c.get('bom-ref') or c.get('name')}' alone makes the import fail.")
            for key in COMPONENT_FIELDS:
                if key in c:
                    single = copy.deepcopy(c)
                    single.pop(key)
                    if attempt("component-field", f"that component without '{key}'", _keep_components(doc, [single])):
                        rep.conclusions.append(f"Field '{key}' of that component breaks the import.")

    rep.uploads = run.uploads
    findings = [c for c in rep.conclusions if not c.startswith("Content stages")]
    if any(s.accepted is None for s in rep.steps):
        rep.conclusions.append(f"Upload budget of {max_uploads} reached; result is the narrowest found so far.")
    rep.inconclusive = not findings
    return rep
