"""Credential-detection rules for tombstone.

As of the necromancer-patterns refactor, the rule definitions, pattern sets and
entropy heuristics live in the shared ``necromancer-patterns`` library — the
single source of truth for the whole suite. This module re-exports that public
API unchanged so existing tombstone import sites (``from .patterns import
Rule, get_rules`` etc.) keep working without modification.

See https://github.com/bugsyhewitt/necromancer-patterns for the implementation
and its NOTICE/attribution (gitleaks, Apache-2.0).
"""

from __future__ import annotations

from necromancer_patterns import (
    AWS_ACCESS_KEY,
    GENERIC_HIGH_ENTROPY,
    STRIPE_SECRET_KEY,
    Rule,
    available_pattern_sets,
    get_rules,
    shannon_entropy,
)

__all__ = [
    "Rule",
    "AWS_ACCESS_KEY",
    "STRIPE_SECRET_KEY",
    "GENERIC_HIGH_ENTROPY",
    "available_pattern_sets",
    "get_rules",
    "shannon_entropy",
]
