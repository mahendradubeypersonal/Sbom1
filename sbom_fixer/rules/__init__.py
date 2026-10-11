"""Importing this package registers every rule."""

# Import order is execution order within a kind: sanitize_purl (CXP-*) runs after the generic sanitizers,
# canonical (CXN-*) runs last and only for profiles with a `canonical:` section.
from . import (  # noqa: F401
    canonical,
    cdx_14_to_13,
    cdx_15_to_14,
    cdx_16_to_15,
    cdx_17_to_16,
    cdx_future,
    repair,
    sanitize,
    sanitize_purl,
    spdx_23_to_22,
)
from .base import RULES, Ctx, Rule, describe, hop_rules, rule_by_id, rules_of

__all__ = ["RULES", "Ctx", "Rule", "describe", "hop_rules", "rule_by_id", "rules_of"]
