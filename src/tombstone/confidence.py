"""Confidence scoring for credential findings.

A rule match alone does not tell a researcher whether a finding is a
near-certain live credential or a likely false positive. Confidence scoring
adds that signal so triage is fast: ``high`` → file immediately, ``low`` →
review by hand first.

The scoring is deterministic and entirely offline — no ML, no network calls.
Three inputs combine into a single label:

1. **Rule specificity.** A rule with a fixed prefix and length constraint (an
   AWS access key, a GitHub PAT, a Stripe key) is structurally hard to match by
   accident, so a hit starts ``high``. The catch-all
   ``generic-high-entropy-secret`` rule has no such structure, so it starts
   ``medium`` and is graded up or down by entropy.

2. **Known test-credential blocklist.** Strings that are obviously placeholders
   or vendor-published examples (``AKIAIOSFODNN7EXAMPLE``, ``sk_test_…``,
   ``PLACEHOLDER``, all-zeros, single-char runs) are forced to ``low`` no matter
   which rule matched — they are never live.

3. **Shannon entropy.** For generic matches, high entropy pushes toward
   ``high`` and low entropy pulls toward ``low``.

The labels are ``"high"``, ``"medium"`` and ``"low"``.
"""

from __future__ import annotations

from .patterns import Rule, shannon_entropy

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Rule ids that have no structural constraint (no fixed prefix / length) and so
# rely entirely on entropy + key-name context. These start at MEDIUM rather
# than HIGH and are graded by entropy.
_GENERIC_RULE_IDS = frozenset({"generic-high-entropy-secret"})

# Entropy thresholds (Shannon bits/char) used to grade generic matches.
# A 5.0 ceiling corresponds to a uniformly random alphanumeric string.
_ENTROPY_HIGH = 4.0
_ENTROPY_LOW = 3.0

# Substrings that mark a value as a published example or placeholder. Matched
# case-insensitively against the raw secret. These are never live credentials.
_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "dummy",
    "sample",
    "your-",
    "your_",
    "xxxx",
    "test_key",
    "redacted",
    "notreal",
    "fake",
)

# Stripe (and similar) explicit test-mode key infixes — a live key never carries
# these, so any match is a guaranteed false positive for report purposes.
_TEST_MODE_MARKERS: tuple[str, ...] = (
    "sk_test_",
    "pk_test_",
    "rk_test_",
)

# A run of one repeated character (e.g. all zeros, "aaaaaaaa") is never a real
# secret. We treat any secret whose distinct-character count is <= 2 and length
# >= 8 as a low-entropy placeholder.
_MIN_DISTINCT_CHARS = 3


def _is_test_credential(secret: str) -> bool:
    """Return True if *secret* is an obvious placeholder / vendor example."""
    if not secret:
        return True
    lowered = secret.lower()
    for marker in _TEST_MODE_MARKERS:
        if marker in lowered:
            return True
    for marker in _PLACEHOLDER_MARKERS:
        if marker in lowered:
            return True
    # All-zeros, repeated single char, or near-constant runs.
    if len(secret) >= 8 and len(set(secret)) < _MIN_DISTINCT_CHARS:
        return True
    # Sequential filler such as "0123456789" / "abcdefgh" — low real-world odds.
    if len(secret) >= 8 and _is_sequential(secret):
        return True
    return False


def _is_sequential(secret: str) -> bool:
    """Heuristic: True if the secret is a monotonic run of consecutive codepoints."""
    deltas = {ord(b) - ord(a) for a, b in zip(secret, secret[1:])}
    return deltas in ({1}, {-1})


def score_confidence(rule: Rule, secret: str) -> str:
    """Return a confidence label (``high`` / ``medium`` / ``low``) for a match.

    Parameters
    ----------
    rule:
        The detection rule that produced the match.
    secret:
        The raw matched secret value (never emitted; used only to score).
    """
    # 1. Known test / placeholder credentials are always low confidence.
    if _is_test_credential(secret):
        return LOW

    # 2. Structurally-constrained rules (fixed prefix + length) are high.
    if rule.rule_id not in _GENERIC_RULE_IDS:
        return HIGH

    # 3. Generic high-entropy rule: grade by Shannon entropy.
    entropy = shannon_entropy(secret)
    if entropy >= _ENTROPY_HIGH:
        return HIGH
    if entropy < _ENTROPY_LOW:
        return LOW
    return MEDIUM
