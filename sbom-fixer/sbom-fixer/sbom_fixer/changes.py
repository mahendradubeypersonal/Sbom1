"""Change log: the single record of every edit. Diff and notes are generated from it (ADR-11)."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from typing import Any

INFO, WARN, DATA_LOSS = "INFO", "WARN", "DATA_LOSS"
SEVERITIES = (INFO, WARN, DATA_LOSS)
SEVERITY_RANK = {INFO: 0, WARN: 1, DATA_LOSS: 2}


@dataclass(frozen=True)
class Change:
    rule_id: str
    path: str
    action: str  # removed | renamed | converted | added | replaced | moved
    before: Any
    after: Any
    severity: str
    reason: str
    level: str = ""  # spec version the document was at when the change was made

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """Something the tool noticed but did not (or could not) change."""

    rule_id: str
    path: str
    message: str
    severity: str = WARN


@dataclass
class ChangeLog:
    changes: list[Change] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    level: str = ""

    def add(self, rule_id: str, path: str, action: str, before: Any, after: Any, severity: str, reason: str) -> None:
        if severity not in SEVERITIES:
            raise ValueError(f"Unknown severity {severity}")
        self.changes.append(Change(rule_id, path, action, before, after, severity, reason, self.level))

    def note(self, rule_id: str, path: str, message: str, severity: str = WARN) -> None:
        f = Finding(rule_id, path, message, severity)
        if f not in self.findings:
            self.findings.append(f)

    def by_rule(self) -> OrderedDict[str, list[Change]]:
        out: OrderedDict[str, list[Change]] = OrderedDict()
        for c in self.changes:
            out.setdefault(c.rule_id, []).append(c)
        return out

    def count(self, severity: str) -> int:
        return sum(1 for c in self.changes if c.severity == severity)

    def __len__(self) -> int:
        return len(self.changes)

    def mark(self) -> int:
        return len(self.changes)

    def since(self, mark: int) -> list[Change]:
        return self.changes[mark:]
