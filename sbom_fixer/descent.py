"""Version descent (ADR-02): repair at the declared version; if not OK, go one version lower and repeat."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .changes import INFO, ChangeLog
from .oracle import Oracle
from .profile import Profile
from .prune import prune_to
from .rules import Ctx, hop_rules, rules_of
from .rules.base import FINAL, REPAIR, SANITIZE, has_hop
from .schemas import VERSION_ORDER, schema_url
from .validate import Issue, validate

MAX_PASSES = 3


@dataclass
class Attempt:
    version: str
    schema_errors: int
    accepted: bool
    reason: str
    errors: list[Issue] = field(default_factory=list)


@dataclass
class DescentResult:
    final_version: str | None
    attempts: list[Attempt] = field(default_factory=list)
    final_errors: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.final_version is not None

    @property
    def path(self) -> list[str]:
        return [a.version for a in self.attempts]


def content_changed(log: ChangeLog) -> bool:
    return any(not c.rule_id.startswith("ENC-") for c in log.changes)


def set_version(doc: dict[str, Any], spec: str, version: str, log: ChangeLog) -> None:
    if spec == "cyclonedx":
        old = doc.get("specVersion")
        doc["specVersion"] = version
        log.add("CDX-VER", "/specVersion", "replaced", old, version, INFO, f"Spec version changed from {old} to {version}")
        if "$schema" in doc:
            doc["$schema"] = schema_url(version)
    else:
        old = doc.get("spdxVersion")
        doc["spdxVersion"] = f"SPDX-{version}"
        log.add("SPDX-VER", "/spdxVersion", "replaced", old, f"SPDX-{version}", INFO, f"SPDX version changed from {old}")


def process_level(doc: dict[str, Any], ctx: Ctx, initial: list[Issue] | None = None) -> list[Issue]:
    """Repair, prune and sanitize at ctx.version until nothing changes (max 3 passes); return remaining errors.

    `initial` lets the caller pass issues it already computed for this exact document and version.
    """
    issues = initial
    for _ in range(MAX_PASSES):
        mark = ctx.log.mark()
        ctx.issues = issues if issues is not None else validate(doc, ctx.spec, ctx.version)
        issues = None
        for rule in rules_of(REPAIR, ctx.spec):
            rule.apply(doc, ctx)
        ctx.apply_removals()
        prune_to(doc, ctx.spec, ctx.version, ctx.log)
        for rule in rules_of(SANITIZE, ctx.spec):
            rule.apply(doc, ctx)
        if ctx.log.mark() == mark:
            return ctx.issues
    return validate(doc, ctx.spec, ctx.version)


def descend(doc: dict[str, Any], spec: str, declared: str, profile: Profile, oracle: Oracle, log: ChangeLog,
            source_sha256: str, initial_issues: list[Issue] | None = None) -> DescentResult:
    order = VERSION_ORDER[spec]
    result = DescentResult(final_version=None)
    if declared not in order:
        result.attempts.append(Attempt(declared, -1, False, f"{spec} {declared} has no vendored schema"))
        return result
    rules = profile.rules_for(spec)
    floor = rules.floor_for(declared)
    if order.index(declared) < order.index(floor):
        result.attempts.append(Attempt(declared, -1, False,
                                       f"declared {declared} is below the floor {floor}; it needs an upgrade hop, which is not supported"))
        return result

    ctx = Ctx(log=log, spec=spec, version=declared, declared=declared, profile=profile, source_sha256=source_sha256)
    ctx._doc = doc
    version = declared
    first: list[Issue] | None = initial_issues
    while True:
        log.level = version
        ctx.version = version
        errors = process_level(doc, ctx, first)
        first = None
        if errors:
            accepted, reason = False, f"{len(errors)} schema errors remain at {version}"
        else:
            accepted, reason = oracle.accepts(doc, spec, version)
        result.attempts.append(Attempt(version, len(errors), accepted, reason, errors[:200]))
        if accepted:
            result.final_version = version
            break
        if version == floor:
            result.final_errors = errors
            break
        nxt = order[order.index(version) - 1]
        if not has_hop(spec, version, nxt):
            result.attempts[-1].reason += f"; no hop rules exist for {version} -> {nxt}"
            result.final_errors = errors
            break
        log.level = f"{version}->{nxt}"
        for rule in hop_rules(spec, version, nxt):
            rule.apply(doc, ctx)
        set_version(doc, spec, nxt, log)
        version = nxt

    if result.ok:
        log.level = result.final_version or ""
        ctx.version = result.final_version or version
        if content_changed(log):
            for rule in rules_of(FINAL, spec):
                rule.apply(doc, ctx)
            post = validate(doc, spec, ctx.version)
            if post:
                result.final_errors = post
                result.attempts[-1].reason += f"; {len(post)} errors after final rules"
                result.final_version = None
    return result
