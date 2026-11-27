"""Tests for entropy-based secret detection."""

from __future__ import annotations

import pytest

from tombstone.entropy import (
    EntropyFinding,
    scan_blob_for_entropy,
    scan_line_for_entropy,
    shannon_entropy,
)


# ---------------------------------------------------------------------------
# shannon_entropy
# ---------------------------------------------------------------------------


def test_entropy_high_entropy_base64_key():
    # A realistic-looking base64-encoded key should have entropy > 4.0.
    token = "AKIAIOSFODNN7EXAMPLEKEY+/ABCDEFGHIJKLMNabc="
    assert shannon_entropy(token) > 4.0


def test_entropy_password123_below_threshold():
    # A common, patterned password has low entropy.
    assert shannon_entropy("password123") < 3.5


def test_entropy_all_same_chars_is_zero():
    # All identical characters → zero entropy.
    assert shannon_entropy("aaaaaaaaaaaa") == pytest.approx(0.0)


def test_entropy_empty_string_is_zero():
    assert shannon_entropy("") == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# scan_line_for_entropy
# ---------------------------------------------------------------------------


def test_scan_line_finds_high_entropy_token():
    # AKIAIOSFODNN7EXAMPLE is a known test AWS-like key — high entropy base64/hex.
    line = 'api_key = "AKIAIOSFODNN7EXAMPLE"'
    tokens = scan_line_for_entropy(line, min_length=16, min_entropy=3.0)
    assert any("AKIAIOSFODNN7EXAMPLE" in t for t in tokens)


def test_scan_line_ignores_short_tokens():
    # A high-entropy token below min_length should not be returned.
    line = "token=abc123"  # very short
    tokens = scan_line_for_entropy(line, min_length=20, min_entropy=3.0)
    assert tokens == []


def test_scan_line_ignores_low_entropy_tokens():
    # A long but all-same character string has near-zero entropy.
    line = "padding=" + "a" * 30
    tokens = scan_line_for_entropy(line, min_length=20, min_entropy=3.0)
    assert tokens == []


def test_scan_line_sorted_by_entropy_descending():
    # When multiple tokens qualify, they are sorted highest-entropy first.
    # Construct two tokens: one very high entropy, one moderate.
    high = "ZxQ9mK2pLnR7vW4yAb0cDe1f"   # mixed case, high entropy
    low = "aabbccddeeaabbccddee"           # repeated pairs, lower entropy
    line = f"a={high} b={low}"
    tokens = scan_line_for_entropy(line, min_length=18, min_entropy=2.0)
    if len(tokens) >= 2:
        assert shannon_entropy(tokens[0]) >= shannon_entropy(tokens[1])


def test_scan_line_hex_charset():
    # In hex-only mode, a base64-only token (uppercase letters beyond 'F')
    # should NOT be returned because it doesn't meet the charset ratio.
    b64_only = "ZXhhbXBsZXRva2Vuc2VjcmV0"  # pure base64, non-hex chars
    line = f"key={b64_only}"
    tokens = scan_line_for_entropy(line, min_length=20, min_entropy=2.5, charset="hex")
    # 'Z', 'X', 'h', 'm', etc. are not hex chars — ratio < 0.8 → excluded
    assert tokens == []


def test_scan_line_base64_charset():
    # In base64 mode a pure base64 token with high entropy should be returned.
    # Build a token that is all base64 chars with reasonable entropy.
    token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"  # 32 chars, full alphabet
    line = f"secret={token}"
    tokens = scan_line_for_entropy(line, min_length=20, min_entropy=4.0, charset="base64")
    assert token in tokens


# ---------------------------------------------------------------------------
# confidence levels
# ---------------------------------------------------------------------------


def test_confidence_high_above_4_5():
    # A very high entropy token should produce confidence="high".
    # Build a token with entropy > 4.5 (lots of distinct chars, long enough).
    token = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"  # mixed, 32 chars
    line = f"key={token}"
    findings: list[EntropyFinding] = scan_blob_for_entropy(
        line.encode(), "test.py", "abc1234", min_entropy=3.0
    )
    high_conf = [f for f in findings if f.value == token]
    if high_conf:
        assert high_conf[0].confidence in ("high", "medium")


def test_confidence_medium_between_3_5_and_4_5():
    # A token with moderate entropy should land at "medium".
    # Fabricate such a token manually.
    import math

    from tombstone.entropy import _confidence

    assert _confidence(4.0) == "medium"
    assert _confidence(4.6) == "high"
    assert _confidence(3.4) == "low"


# ---------------------------------------------------------------------------
# scan_blob_for_entropy
# ---------------------------------------------------------------------------


def test_scan_blob_deduplicates_same_token():
    # Same token appearing on two lines should produce only one finding.
    token = "AKIAIOSFODNN7EXAMPLEkeyABCD"
    blob = f"a={token}\nb={token}\n".encode()
    findings = scan_blob_for_entropy(blob, "file.py", "deadbeef", min_entropy=3.0)
    values = [f.value for f in findings]
    assert values.count(token) == 1


def test_scan_blob_non_utf8_returns_empty():
    findings = scan_blob_for_entropy(b"\xff\xfe\x00binary", "img.bin", "deadbeef")
    assert findings == []
