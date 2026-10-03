"""Rule base class, registry and the per-level context rules receive."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from ..changes import ChangeLog
from ..jsonutil import get_at, pointer
from ..profile import Profile
from ..validate import Issue

REPAIR, HOP, SANITIZE, FINAL = "repair", "hop", "sanitize", "final"


@dataclass
class Ctx:
    log: ChangeLog
    spec: str
    version: str  # the level the document is at right now
    declared: str
    profile: Profile
    source_sha256: str
    issues: list[Issue] = field(default_factory=list)
    _removals: list[tuple[tuple[Any, ...], int, str, str, str]] = field(default_factory=list)

    def schedule_removal(self, parts: tuple[Any, ...], rule_id: str, severity: str, reason: str) -> None:
        """Defer removal so list indexes in other issues stay valid; executed deepest/last-index first."""
        try:
            target = get_at_doc(self, parts)
        except LookupError:
            return
        self._removals.append((tuple(parts), id(target), rule_id, severity, reason))

    _doc: Any = None

    def apply_removals(self) -> None:
        def sort_key(item: tuple[tuple[Any, ...], int, str, str, str]) -> tuple[Any, ...]:
            return tuple((1, p) if isinstance(p, int) else (0, str(p)) for p in item[0])

        done: set[tuple[Any, ...]] = set()
        for parts, ident, rule_id, severity, reason in sorted(self._removals, key=sort_key, reverse=True):
            if parts in done:
                continue
            try:
                container = get_at(self._doc, parts[:-1])
                current = container[parts[-1]]
            except (KeyError, IndexError, TypeError):
                continue
            if id(current) != ident:
                continue
            if isinstance(container, list):
                container.pop(parts[-1])
            else:
                del container[parts[-1]]
            done.add(parts)
            self.log.add(rule_id, pointer(parts), "removed", current, None, severity, reason)
        self._removals.clear()


def get_at_doc(ctx: Ctx, parts: tuple[Any, ...]) -> Any:
    try:
        return get_at(ctx._doc, parts)
    except (KeyError, IndexError, TypeError) as exc:
        raise LookupError(str(parts)) from exc


class Rule:
    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""  # plain-language text used in notes.txt
    case: ClassVar[str] = "A"  # A same-version, B version, C importer-specific
    kind: ClassVar[str] = REPAIR
    specs: ClassVar[tuple[str, ...]] = ("cyclonedx",)
    hop: ClassVar[tuple[str, str] | None] = None
    source_fix: ClassVar[str | None] = None

    def apply(self, doc: Any, ctx: Ctx) -> None:
        raise NotImplementedError


RULES: list[Rule] = []


def register(cls: type[Rule]) -> type[Rule]:
    if any(r.id == cls.id for r in RULES):
        raise ValueError(f"Duplicate rule id {cls.id}")
    RULES.append(cls())
    return cls


def rules_of(kind: str, spec: str) -> list[Rule]:
    return [r for r in RULES if r.kind == kind and spec in r.specs]


def hop_rules(spec: str, src: str, dst: str) -> list[Rule]:
    return [r for r in RULES if r.kind == HOP and spec in r.specs and r.hop == (src, dst)]


def has_hop(spec: str, src: str, dst: str) -> bool:
    return bool(hop_rules(spec, src, dst))


def rule_by_id(rule_id: str) -> Rule | None:
    for r in RULES:
        if r.id == rule_id:
            return r
    return None


EXTRA_DESCRIPTIONS = {
    "ENC-001": "File started with a UTF-8 byte order mark; output is written without it.",
    "ENC-002": "File was UTF-16 encoded; output is written as UTF-8.",
    "ENC-003": "File was not valid UTF-8; it was decoded as Windows-1252 and written as UTF-8.",
    "CDX-VER": "Declared spec version changed by one level during descent.",
    "SPDX-VER": "Declared SPDX version changed by one level during descent.",
    "PRUNE-001": "Field is not allowed by the schema of the current version and was removed.",
}


def describe(rule_id: str) -> str:
    r = rule_by_id(rule_id)
    if r is not None:
        return r.description or r.title
    return EXTRA_DESCRIPTIONS.get(rule_id, rule_id)
