"""Credential-detection rules for tombstone.

As of the necromancer-patterns refactor, the rule definitions, pattern sets and
entropy heuristics live in the shared ``necromancer-patterns`` library — the
single source of truth for the whole suite. This module re-exports that public
API so existing tombstone import sites (``from .patterns import Rule,
get_rules`` etc.) keep working without modification.

On top of the shared library, tombstone layers a small set of *local* credential
rules for high-value credential types the library does not yet cover (Slack,
Google API key, GitLab PAT, SendGrid, npm, private-key blocks). Those live in
:mod:`tombstone.extra_patterns` and are merged into the broad pattern sets by the
:func:`get_rules` wrapper below. The library's ``get_rules`` is still the source
of truth for the cloud/AI provider keys; tombstone only *adds* to it, exactly as
:mod:`tombstone.workflow` keeps its workflow detection local.

See https://github.com/bugsyhewitt/necromancer-patterns for the library
implementation and its NOTICE/attribution (gitleaks, Apache-2.0).
"""

from __future__ import annotations

from necromancer_patterns import (
    ANTHROPIC_API_KEY,
    AWS_ACCESS_KEY,
    AZURE_DEVOPS_PAT,
    GCP_SERVICE_ACCOUNT_KEY,
    GENERIC_HIGH_ENTROPY,
    GITHUB_PAT,
    HUGGINGFACE_TOKEN,
    OPENAI_API_KEY,
    STRIPE_SECRET_KEY,
    Rule,
    available_pattern_sets,
    shannon_entropy,
)
from necromancer_patterns import get_rules as _library_get_rules

from .extra_patterns import EXTRA_RULES

# Pattern sets that provide broad, multi-provider credential coverage and so
# should also receive tombstone's local rules. The AWS-only ``minimal``/``aws``
# sets are intentionally narrow and are left untouched.
_BROAD_PATTERN_SETS: frozenset[str] = frozenset({"cloud", "full"})


def get_rules(pattern_set: str) -> list[Rule]:
    """Return the active rules for *pattern_set*, including tombstone-local ones.

    Delegates to :func:`necromancer_patterns.get_rules` for the shared library's
    rules, then appends tombstone's local :data:`~tombstone.extra_patterns.EXTRA_RULES`
    for the broad pattern sets (``cloud`` / ``full``). The narrow AWS-only sets
    (``minimal`` / ``aws``) are returned unchanged so callers that deliberately
    scope to AWS keys aren't surprised by extra matches.

    Library and local rule ids are disjoint, so the merge never produces a
    duplicate rule id. A fresh list is returned each call (the library returns a
    fresh list too) so callers may mutate the result safely.
    """
    rules = list(_library_get_rules(pattern_set))
    if pattern_set in _BROAD_PATTERN_SETS:
        rules.extend(EXTRA_RULES)
    return rules


__all__ = [
    "Rule",
    "AWS_ACCESS_KEY",
    "STRIPE_SECRET_KEY",
    "GENERIC_HIGH_ENTROPY",
    "GITHUB_PAT",
    "GCP_SERVICE_ACCOUNT_KEY",
    "AZURE_DEVOPS_PAT",
    "OPENAI_API_KEY",
    "HUGGINGFACE_TOKEN",
    "ANTHROPIC_API_KEY",
    "available_pattern_sets",
    "get_rules",
    "shannon_entropy",
]
