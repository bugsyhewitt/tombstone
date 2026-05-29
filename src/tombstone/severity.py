"""Severity labelling for credential findings (POST_V01 item 9).

Confidence answers "is this a real secret?"; severity answers "how badly does
it hurt if it is?". A live AWS access key or GitHub PAT grants broad, immediate
account access and is Critical/P1 on both the HackerOne and Bugcrowd taxonomies;
a generic high-entropy match is Medium until the target service is confirmed.

The severity of a credential *type* is a property of the detection rule, not of
this tool. As of the necromancer-patterns refactor, every :class:`Rule` carries
a structured ``severity`` field (``CRITICAL`` / ``HIGH``). This module is the
single place that maps that library value onto tombstone's finding-severity
labels, so the rest of the codebase reads ``finding.severity`` without caring
how the rule declared it.

Labels are lowercase to match the existing ``confidence`` field style:
``"critical" | "high" | "medium" | "low"``.
"""

from __future__ import annotations

from .patterns import Rule

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Severity assigned to workflow secret-exposure findings, which are pattern
# matches rather than rule-backed credential matches (no Rule to read). A leaked
# secret in a CI run log mirrors the 2025 tj-actions/changed-files exposure and
# is rated High/P2 pending confirmation of which secret and who can read the logs.
WORKFLOW_SEVERITY = HIGH

# Map the necromancer-patterns Rule.severity tokens (case-insensitive) onto
# tombstone's lowercase finding-severity labels. Unknown / missing values fall
# back to HIGH so a leaked credential is never under-reported as low priority.
_LIBRARY_SEVERITY: dict[str, str] = {
    "critical": CRITICAL,
    "high": HIGH,
    "medium": MEDIUM,
    "low": LOW,
}

_DEFAULT_SEVERITY = HIGH


# Ordered most-severe → least-severe. Used to compare a finding's severity
# against a ``--fail-on`` threshold: a finding "meets" a threshold when its own
# severity is at least as severe as the threshold. The list order *is* the
# ranking, so a lower index means more severe.
SEVERITY_ORDER: tuple[str, ...] = (CRITICAL, HIGH, MEDIUM, LOW)

# The set of valid threshold tokens a user may pass to ``--fail-on``.
SEVERITY_CHOICES: tuple[str, ...] = SEVERITY_ORDER


def _severity_rank(severity: str) -> int:
    """Return a sort rank for *severity* (0 = most severe).

    Unknown values rank as the least severe so an unexpected label never
    accidentally trips a stricter ``--fail-on`` gate.
    """
    try:
        return SEVERITY_ORDER.index(str(severity).strip().lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def meets_threshold(finding_severity: str, threshold: str) -> bool:
    """Return True if *finding_severity* is at least as severe as *threshold*.

    Severity ordering is ``critical > high > medium > low``. With a threshold of
    ``"high"``, both ``"critical"`` and ``"high"`` findings meet it; ``"medium"``
    and ``"low"`` do not. This is the comparison that drives the ``--fail-on``
    CI-gating exit code.
    """
    return _severity_rank(finding_severity) <= _severity_rank(threshold)


def rule_severity(rule: Rule) -> str:
    """Return the finding-severity label for a matched *rule*.

    Reads the rule's declared ``severity`` (from necromancer-patterns) and
    normalises it to a lowercase tombstone label. A rule with no severity, or an
    unrecognised value, defaults to ``"high"`` — leaked credentials are never
    silently downgraded to low priority.
    """
    raw = getattr(rule, "severity", None)
    if not raw:
        return _DEFAULT_SEVERITY
    return _LIBRARY_SEVERITY.get(str(raw).strip().lower(), _DEFAULT_SEVERITY)
