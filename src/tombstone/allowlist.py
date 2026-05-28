"""Suppression allowlist for known test / placeholder credentials.

The ``generic-high-entropy-secret`` rule — and even structured rules — match
realistic-looking but known-fake values that ship in test fixtures and vendor
docs (``AKIAIOSFODNN7EXAMPLE``, Stripe ``sk_test_…`` keys, ``PLACEHOLDER``).
Confidence scoring already *labels* these ``low``; the allowlist goes further
and *removes* them from output so a scan of any repo that ships tests is
report-ready without manual filtering.

Two layers combine:

1. **Built-in default allowlist** (:func:`default_allowlist`) — suppresses
   well-known vendor examples and placeholder strings. Enabled by default;
   disable with the CLI ``--no-allowlist`` flag.
2. **User allowlist file** (:func:`load_allowlist`) — a TOML file with two
   optional keys::

       secrets = ["exact-value", "another-value"]   # matched case-insensitively
       regexes = ["^TEST_[A-Z0-9]+$"]               # matched against the raw secret

   Loaded with ``--allowlist <file>``; merged with the default unless
   ``--no-allowlist`` is also given.

Matching is performed against the raw secret value carried on each
:class:`~tombstone.scanner.Finding` (``finding._secret``) — the value is never
emitted, only used to decide suppression.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Pattern

from .scanner import Finding

# Exact secret values that are always suppressed by the default allowlist.
# Stored lowercased; matching is case-insensitive.
_DEFAULT_EXACT: frozenset[str] = frozenset(
    {
        # AWS's own published example access key id.
        "akiaiosfodnn7example",
    }
)

# Regexes that suppress whole families of known test / placeholder values.
# Matched (search) against the raw secret. Kept deliberately conservative so
# real credentials are never silently dropped.
_DEFAULT_REGEX_SOURCES: tuple[str, ...] = (
    # Stripe / similar explicit test-mode keys: sk_test_, pk_test_, rk_test_.
    r"(?:sk|pk|rk)_test_[0-9A-Za-z]+",
    # Common placeholder / instructional markers anywhere in the value.
    r"(?i)placeholder",
    r"(?i)changeme",
    r"(?i)change_me",
    r"(?i)dummy",
    r"(?i)example",
    r"(?i)redacted",
    r"(?i)your[-_]",
    r"(?i)xxxx",
)


@dataclass
class Allowlist:
    """A set of suppression rules applied to findings.

    Parameters
    ----------
    exact:
        Lowercased exact secret values to suppress (case-insensitive match).
    regexes:
        Compiled regex patterns; a finding is suppressed if any pattern
        ``search``-matches its raw secret.
    """

    exact: set[str] = field(default_factory=set)
    regexes: list[Pattern[str]] = field(default_factory=list)

    def is_suppressed(self, finding: Finding) -> bool:
        """Return True if *finding*'s secret matches any allowlist rule."""
        secret = finding._secret
        if not secret:
            return False
        if secret.lower() in self.exact:
            return True
        for pattern in self.regexes:
            if pattern.search(secret):
                return True
        return False

    def filter_findings(self, findings: Iterable[Finding]) -> list[Finding]:
        """Return only the findings that are NOT suppressed by this allowlist."""
        return [f for f in findings if not self.is_suppressed(f)]


def default_allowlist() -> Allowlist:
    """Return the built-in default allowlist of well-known test credentials."""
    return Allowlist(
        exact=set(_DEFAULT_EXACT),
        regexes=[re.compile(src) for src in _DEFAULT_REGEX_SOURCES],
    )


def load_allowlist(path: str, include_default: bool = True) -> Allowlist:
    """Load a user allowlist TOML file, optionally merged with the default.

    The TOML file may define ``secrets`` (a list of exact values, matched
    case-insensitively) and/or ``regexes`` (a list of regex strings).

    Parameters
    ----------
    path:
        Path to the TOML allowlist file.
    include_default:
        When True (the default), the built-in default allowlist entries are
        merged in so user entries *extend* rather than replace the defaults.

    Raises
    ------
    ValueError
        If the file is missing, is not valid TOML, has the wrong shape, or
        contains an invalid regular expression.
    """
    p = Path(path)
    if not p.exists():
        raise ValueError(f"allowlist file not found: {path}")
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid allowlist TOML in {path}: {exc}") from exc
    except OSError as exc:  # pragma: no cover - unreadable file
        raise ValueError(f"could not read allowlist {path}: {exc}") from exc

    base = default_allowlist() if include_default else Allowlist()
    exact = set(base.exact)
    regexes = list(base.regexes)

    raw_secrets = data.get("secrets", [])
    if not isinstance(raw_secrets, list):
        raise ValueError(f"allowlist '{path}': 'secrets' must be a list")
    for value in raw_secrets:
        if not isinstance(value, str):
            raise ValueError(f"allowlist '{path}': 'secrets' entries must be strings")
        exact.add(value.lower())

    raw_regexes = data.get("regexes", [])
    if not isinstance(raw_regexes, list):
        raise ValueError(f"allowlist '{path}': 'regexes' must be a list")
    for src in raw_regexes:
        if not isinstance(src, str):
            raise ValueError(f"allowlist '{path}': 'regexes' entries must be strings")
        try:
            regexes.append(re.compile(src))
        except re.error as exc:
            raise ValueError(
                f"allowlist '{path}': invalid regex {src!r}: {exc}"
            ) from exc

    return Allowlist(exact=exact, regexes=regexes)
