"""Entropy-based secret detection for tombstone.

Finds high-entropy strings in source lines regardless of whether they match any
known pattern regex.  Pattern matching misses secrets in custom formats; entropy
analysis catches API keys, tokens, and passwords by their statistical
randomness.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


# Charset character sets used for token filtering.
_HEX_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF")
_BASE64_CHARS: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)
_HEX_BASE64_CHARS: frozenset[str] = _HEX_CHARS | _BASE64_CHARS

_CHARSET_MAP: dict[str, frozenset[str]] = {
    "hex": _HEX_CHARS,
    "base64": _BASE64_CHARS,
    "hex+base64": _HEX_BASE64_CHARS,
}

# Delimiters used to split a line into candidate tokens.
_SPLIT_RE = re.compile(r'[\s=:"\'`]+')


@dataclass
class EntropyFinding:
    value: str            # the high-entropy token
    entropy: float        # Shannon entropy bits/char
    line: str             # full line containing the token
    file_path: str
    commit_sha: str
    confidence: str       # "high" (>4.5) | "medium" (3.5-4.5) | "low" (<3.5)


def shannon_entropy(s: str) -> float:
    """Return Shannon entropy of string s in bits/character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((p / n) * math.log2(p / n) for p in freq.values())


def _confidence(entropy: float) -> str:
    if entropy > 4.5:
        return "high"
    if entropy >= 3.5:
        return "medium"
    return "low"


def scan_line_for_entropy(
    line: str,
    min_length: int = 20,
    min_entropy: float = 3.5,
    charset: str = "hex+base64",
) -> list[str]:
    """Extract high-entropy tokens from a line.

    charset: "hex" (0-9a-fA-F), "base64" (0-9a-zA-Z+/=), "hex+base64" (union)
    Returns list of tokens that exceed min_entropy threshold, sorted by entropy
    descending.
    """
    allowed = _CHARSET_MAP.get(charset, _HEX_BASE64_CHARS)
    tokens = _SPLIT_RE.split(line)
    results: list[tuple[float, str]] = []
    for token in tokens:
        if len(token) < min_length:
            continue
        charset_count = sum(1 for c in token if c in allowed)
        if charset_count / len(token) < 0.8:
            continue
        e = shannon_entropy(token)
        if e > min_entropy:
            results.append((e, token))
    results.sort(key=lambda x: x[0], reverse=True)
    return [tok for _, tok in results]


def scan_blob_for_entropy(
    blob_data: bytes,
    file_path: str,
    commit_sha: str,
    min_length: int = 20,
    min_entropy: float = 3.5,
    charset: str = "hex+base64",
) -> list[EntropyFinding]:
    """Scan decoded text bytes for high-entropy tokens.

    Returns one EntropyFinding per unique high-entropy token (deduplicated by
    value within this blob).
    """
    try:
        text = blob_data.decode("utf-8")
    except UnicodeDecodeError:
        return []

    seen: set[str] = set()
    findings: list[EntropyFinding] = []
    for line in text.splitlines():
        for token in scan_line_for_entropy(
            line,
            min_length=min_length,
            min_entropy=min_entropy,
            charset=charset,
        ):
            if token in seen:
                continue
            seen.add(token)
            findings.append(
                EntropyFinding(
                    value=token,
                    entropy=shannon_entropy(token),
                    line=line,
                    file_path=file_path,
                    commit_sha=commit_sha,
                    confidence=_confidence(shannon_entropy(token)),
                )
            )
    return findings
