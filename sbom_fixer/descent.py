"""Version descent (ADR-02): repair at the declared version; if not OK, go one version lower and repeat."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .changes import INFO, ChangeLog
from .oracle import Oracle
from .profile import Profile
from .prune import prune_to
from .rules import Ctx, hop_rules, rule_by_id, rules_of
from .rules.base import FINAL, REPAIR, SANITIZE, has_hop
from .rules.canonical import CANONICAL
from .rules.cdx_future import FUTURE_RULES
from .schemas import VERSION_ORDER, is_future, schema_url, version_key
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
    rules = profile.rules_for(spec)
    ctx = Ctx(log=log, spec=spec, version=declared, declared=declared, profile=profile, source_sha256=source_sha256)
    ctx._doc = doc
    start = declared
    if declared not in order:
        if not is_future(spec, declared):
            reason = f"{spec} {declared} has no vendored schema"
            key, newest = version_key(declared), version_key(order[-1])
            if spec == "cyclonedx" and key and newest and key[0] != newest[0]:
                reason += f" (VER-002: major version {key[0]} may change the document structure; not downgraded)"
            result.attempts.append(Attempt(declared, -1, False, reason))
            return result
        if spec != "cyclonedx" or rules.future_versions != "downgrade" or not rules.max_version:
            result.attempts.append(Attempt(declared, -1, False, f"{spec} {declared} is newer than the vendored schemas "
                                                                f"and profile '{profile.name}' sets future_versions: reject"))
            return result
        start = rules.max_version
        result.attempts.append(Attempt(declared, -1, False, f"{spec} {declared} is newer than this tool knows; "
                                                            f"generic future hop to {start}"))
        log.level = f"{declared}->{start}"
        ctx.version = start
        for rule_id in FUTURE_RULES:
            rule = rule_by_id(rule_id)
            if rule is not None:
                rule.apply(doc, ctx)
    if not profile.allow_downgrade:
        return _same_version(doc, spec, declared, start, oracle, log, ctx, result,
                             initial_issues if start == declared else None)
    floor = rules.floor_for(start)
    if order.index(start) < order.index(floor):
        result.attempts.append(Attempt(declared, -1, False,
                                       f"declared {declared} is below the floor {floor}; it needs an upgrade hop, which is not supported"))
        return result

    version = start
    first: list[Issue] | None = initial_issues
    while True:
        log.level = version
        ctx.version = version
        errors = process_level(doc, ctx, first)
        first = None
        if errors:  # same-version resolution first; a lower version is only for files the consumer does not accept
            errors = coerce_to_schema(doc, spec, version, log)
            if not errors:
                errors = process_level(doc, ctx)
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

    _final_rules(doc, spec, log, ctx, result)
    return result


def _final_rules(doc: dict[str, Any], spec: str, log: ChangeLog, ctx: Ctx, result: DescentResult) -> None:
    if not result.ok:
        return
    log.level = result.final_version or ""
    ctx.version = result.final_version or ctx.version
    if content_changed(log):
        for rule in rules_of(FINAL, spec):
            rule.apply(doc, ctx)
        post = validate(doc, spec, ctx.version)
        if post:
            result.final_errors = post
            result.attempts[-1].reason += f"; {len(post)} errors after final rules"
            result.final_version = None
            return
    _canonical(doc, spec, log, ctx, result)


def _canonical(doc: dict[str, Any], spec: str, log: ChangeLog, ctx: Ctx, result: DescentResult) -> None:
    """Checkmarx canonical form (CXN-*), last step and only when the profile asks for it; never changes the version."""
    canonical_rules = rules_of(CANONICAL, spec)
    if ctx.profile.canonical is None or not canonical_rules:
        return
    for rule in canonical_rules:
        rule.apply(doc, ctx)
    post = validate(doc, spec, ctx.version)
    if post:
        post = coerce_to_schema(doc, spec, ctx.version, log)
    if post:
        result.final_errors = post
        result.attempts[-1].reason += f"; {len(post)} errors after the canonical form"
        result.final_version = None


def _same_version(doc: dict[str, Any], spec: str, declared: str, version: str, oracle: Oracle, log: ChangeLog,
                  ctx: Ctx, result: DescentResult, initial: list[Issue] | None) -> DescentResult:
    """Default: repair at the document's own schema version and never step down (ADR-02 descent is opt-in).

    Errors the repair rules cannot fix are resolved on the same schema: a value of the wrong JSON type is converted
    when the meaning is clear (COERCE-001), otherwise the value the schema rejects is removed (COERCE-002, DATA_LOSS).
    """
    log.level = version
    ctx.version = version
    errors = process_level(doc, ctx, initial)
    if errors:
        errors = coerce_to_schema(doc, spec, version, log)
        if not errors:
            errors = process_level(doc, ctx)  # the repair rules once more on the coerced document
    if errors:
        result.attempts.append(Attempt(version, len(errors), False,
                                       f"{len(errors)} schema errors remain at {version} (same-version fix)", errors[:200]))
        result.final_errors = errors
        return result
    accepted, reason = oracle.accepts(doc, spec, version)
    if not accepted:
        reason += "; kept at this version (fix never downgrades; --allow-downgrade to step down)"
        log.note("VER-KEEP", "/", f"{spec} {version} is not in the profile's accepted_versions; the file stays at "
                                  f"{version} because fix does not downgrade", "WARN")
    result.attempts.append(Attempt(version, 0, accepted, reason))
    result.final_version = version
    _final_rules(doc, spec, log, ctx, result)
    return result


def coerce_to_schema(doc: dict[str, Any], spec: str, version: str, log: ChangeLog, rounds: int = 6) -> list[Issue]:
    """Last step of a same-version fix: make the remaining schema errors go away on this version's schema."""
    from .complete import NONE, _convert
    from .jsonutil import get_at, pointer

    issues = validate(doc, spec, version)
    for _ in range(rounds):
        if not issues:
            return issues
        targets: dict[tuple[Any, ...], Issue] = {}
        for issue in issues:
            if issue.parts:
                targets.setdefault(tuple(issue.parts), issue)
        changed = False
        for parts in sorted(targets, key=lambda t: (len(t), [str(x) for x in t]), reverse=True):
            try:
                container = get_at(doc, parts[:-1])
                old = container[parts[-1]]
            except (KeyError, IndexError, TypeError):
                continue
            issue = targets[parts]
            new = _convert(old, issue.expected) if issue.keyword == "type" else NONE
            if new is not NONE:
                container[parts[-1]] = new
                log.add("COERCE-001", pointer(parts), "converted", old, new, "WARN",
                        f"converted to the type the {version} schema expects ({issue.message[:100]})")
            else:
                container.pop(parts[-1])
                log.add("COERCE-002", pointer(parts), "removed", old, None, "DATA_LOSS",
                        f"value rejected by the {version} schema and no rule could repair it ({issue.keyword}: "
                        f"{issue.message[:100]})")
            changed = True
        if not changed:
            return issues
        issues = validate(doc, spec, version)
    return issues
