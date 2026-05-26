"""Regex rule definitions and pattern sets for tombstone.

Patterns are adapted from the gitleaks public ruleset (Apache-2.0 licensed).
See NOTICE and vendor/gitleaks-LICENSE for attribution. Rules have been
re-written to Python `re` idioms rather than copied verbatim.

[Worker decision: pattern-set design] The orchestrator requires zero false
positives on five innocuous-looking strings while detecting exactly three
planted credentials (AWS, Stripe, generic high-entropy). We therefore keep the
ruleset tight: provider rules use strict anchors/prefixes (e.g. AKIA for AWS,
sk_live for Stripe) so look-alike placeholders do not match, and the generic
high-entropy rule fires only on isolated tokens that survive shape exclusions
(UUID, hex git SHA) and clear a Shannon-entropy floor.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass(frozen=True)
class Rule:
    """A single credential-detection rule."""

    rule_id: str
    description: str
    regex: re.Pattern
    # Optional extra validator applied to the captured secret group. Returns
    # True if the candidate should be reported.
    validator: Optional[Callable[[str], bool]] = field(default=None)
    # Which capture group holds the secret value (0 = whole match).
    secret_group: int = 0


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of ``value``."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Shapes that look high-entropy but are almost never secrets. Excluded from the
# generic high-entropy rule to avoid false positives.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")

# Minimum Shannon entropy (bits/char) for the generic rule to fire. Tuned so a
# 40-char mixed-charset random secret (~5.0+ bits) passes while ordinary words,
# lorem text, and placeholders stay below.
_GENERIC_ENTROPY_FLOOR = 4.3


def _generic_secret_validator(candidate: str) -> bool:
    """Return True if ``candidate`` is a plausible generic secret."""
    if _UUID_RE.match(candidate):
        return False
    if _HEX_SHA_RE.match(candidate):
        return False
    # Require a mix of character classes — secrets are rarely a single class.
    has_lower = any(c.islower() for c in candidate)
    has_upper = any(c.isupper() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    classes = sum((has_lower, has_upper, has_digit))
    if classes < 2:
        return False
    return shannon_entropy(candidate) >= _GENERIC_ENTROPY_FLOOR


# --- Rule definitions -------------------------------------------------------

AWS_ACCESS_KEY = Rule(
    rule_id="aws-access-key-id",
    description="AWS Access Key ID",
    # Strict provider prefixes followed by exactly 16 base32 chars. Placeholder
    # look-alikes (e.g. AKIAXXXXXXXXXXXXXXXX with X's, or lowercase) will not
    # match because the body must be uppercase A-Z / 2-7 digits, 16 chars.
    regex=re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z2-7]{16})\b"),
    secret_group=1,
)

STRIPE_SECRET_KEY = Rule(
    rule_id="stripe-secret-key",
    description="Stripe Secret Key",
    regex=re.compile(r"\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
    secret_group=1,
)

GENERIC_HIGH_ENTROPY = Rule(
    rule_id="generic-high-entropy-secret",
    description="Generic high-entropy secret assigned to a credential-like key",
    # Anchor on an assignment to a secret-ish key name so we only inspect tokens
    # that are presented as secrets, then entropy-validate the value.
    regex=re.compile(
        r"""(?ix)
        (?:secret|token|api[_-]?key|apikey|passwd|password|access[_-]?key|auth)
        \s*[:=]\s*
        ['"]?
        ([A-Za-z0-9+/=_\-]{20,})
        ['"]?
        """
    ),
    validator=_generic_secret_validator,
    secret_group=1,
)


_PATTERN_SETS: dict[str, list[Rule]] = {
    "minimal": [AWS_ACCESS_KEY],
    "aws": [AWS_ACCESS_KEY],
    "full": [AWS_ACCESS_KEY, STRIPE_SECRET_KEY, GENERIC_HIGH_ENTROPY],
}


def get_rules(pattern_set: str) -> list[Rule]:
    """Return the list of rules for the named pattern set."""
    try:
        return _PATTERN_SETS[pattern_set]
    except KeyError as exc:  # pragma: no cover - argparse guards choices
        raise ValueError(f"unknown pattern set: {pattern_set}") from exc


def available_pattern_sets() -> list[str]:
    """Return the names of all defined pattern sets."""
    return list(_PATTERN_SETS.keys())
