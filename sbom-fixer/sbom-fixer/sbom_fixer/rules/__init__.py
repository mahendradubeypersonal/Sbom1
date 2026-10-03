"""Importing this package registers every rule."""

from . import (  # noqa: F401
    cdx_14_to_13,
    cdx_15_to_14,
    cdx_16_to_15,
    cdx_17_to_16,
    repair,
    sanitize,
    spdx_23_to_22,
)
from .base import RULES, Ctx, Rule, describe, hop_rules, rule_by_id, rules_of

__all__ = ["RULES", "Ctx", "Rule", "describe", "hop_rules", "rule_by_id", "rules_of"]
