"""Tests for confidence scoring on findings (POST_V01 item 4)."""

import os

import pytest

from tombstone.confidence import HIGH, LOW, MEDIUM, score_confidence
from tombstone.patterns import get_rules
from tombstone.report import format_findings
from tombstone.scanner import scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")


def _rule(rule_id: str):
    for r in get_rules("full"):
        if r.rule_id == rule_id:
            return r
    raise AssertionError(f"rule not found: {rule_id}")


# --- score_confidence: rule specificity -----------------------------------


def test_structured_rule_is_high():
    # A real-looking AWS access key id (structured prefix + length) → high.
    rule = _rule("aws-access-key-id")
    assert score_confidence(rule, "AKIA1234567890ABCDEF") == HIGH


def test_github_pat_is_high():
    rule = _rule("github-pat")
    assert score_confidence(rule, "ghp_" + "a1B2c3D4" * 4 + "abcd") == HIGH


def test_new_extra_rules_are_high():
    # The Rotation-23 tombstone-local rules are all structurally constrained
    # (fixed prefix / exact length), so a non-placeholder match scores high.
    hex32 = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    cases = {
        "shopify-token": "shp" + "at_" + hex32,
        "twilio-account-sid": "AC" + hex32,
        "discord-bot-token": "MjI4NDg1OTE5NTI1NjY1NjEx.Gxh7Pq."
        + "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St",
        # ghs_ — the GitHub App installation / Actions GITHUB_TOKEN shape; the
        # github-token rule is fixed-prefix + exact length → high confidence.
        "github-token": "ghs_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    }
    for rule_id, secret in cases.items():
        assert score_confidence(_rule(rule_id), secret) == HIGH, rule_id


# --- score_confidence: known test / placeholder credentials ---------------


def test_aws_example_key_is_low():
    rule = _rule("aws-access-key-id")
    assert score_confidence(rule, "AKIAIOSFODNN7EXAMPLE") == LOW


def test_stripe_test_key_is_low():
    rule = _rule("stripe-secret-key")
    # Construct the test-mode key at runtime so the literal never lands in the
    # repo (avoids GitHub secret-scanning push protection on a known prefix).
    test_key = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
    assert score_confidence(rule, test_key) == LOW


def test_placeholder_strings_are_low():
    rule = _rule("generic-high-entropy-secret")
    for value in ("PLACEHOLDER", "CHANGEME", "your-secret-here", "DUMMY_VALUE"):
        assert score_confidence(rule, value) == LOW, value


def test_all_zeros_is_low():
    rule = _rule("generic-high-entropy-secret")
    assert score_confidence(rule, "0" * 32) == LOW


def test_repeated_char_is_low():
    rule = _rule("generic-high-entropy-secret")
    assert score_confidence(rule, "a" * 24) == LOW


def test_sequential_is_low():
    rule = _rule("generic-high-entropy-secret")
    assert score_confidence(rule, "0123456789") == LOW
    assert score_confidence(rule, "abcdefghijklmnop") == LOW


def test_empty_secret_is_low():
    rule = _rule("generic-high-entropy-secret")
    assert score_confidence(rule, "") == LOW


# --- score_confidence: entropy grading of generic matches -----------------


def test_generic_high_entropy_is_high():
    rule = _rule("generic-high-entropy-secret")
    # Uniformly random alphanumeric → entropy ~5.0 → high.
    assert score_confidence(rule, "aZ9kP2mQ7xL4vR8nB1cF6tH3wE5yU0iO") == HIGH


def test_generic_low_entropy_is_low():
    rule = _rule("generic-high-entropy-secret")
    # Low-entropy but not a placeholder marker → graded low by entropy.
    assert score_confidence(rule, "abababababababab") == LOW


def test_generic_medium_entropy_is_medium():
    rule = _rule("generic-high-entropy-secret")
    # Entropy in the [3.0, 4.0) band → medium.
    value = "passwordpass1234"  # 8 distinct chars over 16 → ~3.0–3.9 bits
    assert score_confidence(rule, value) == MEDIUM


# --- end-to-end: confidence flows through Finding and reports --------------


@pytest.fixture(scope="module")
def findings():
    return scan_repo(LEAKY, pattern_set="full")


def test_finding_carries_confidence(findings):
    for f in findings:
        assert f.confidence in {HIGH, MEDIUM, LOW}


def test_example_aws_key_scored_low_in_repo(findings):
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws, "expected an aws finding in the fixture"
    # The fixture uses the canonical AWS EXAMPLE key → low confidence.
    assert all(f.confidence == LOW for f in aws)


def test_confidence_in_to_dict(findings):
    for f in findings:
        assert f.to_dict()["confidence"] == f.confidence


def test_confidence_in_json_output(findings):
    out = format_findings(findings, "json")
    assert '"confidence"' in out


def test_confidence_in_h1md_output(findings):
    out = format_findings(findings, "h1md")
    assert "**Confidence:**" in out


def test_confidence_in_bcmd_output(findings):
    out = format_findings(findings, "bcmd")
    assert "Confidence:" in out
