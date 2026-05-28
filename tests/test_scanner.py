"""Tests for git-history scanning against the leaky-repo fixture."""

import os

import pytest

from tombstone.scanner import redact, scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")


@pytest.fixture(scope="module")
def findings():
    return scan_repo(LEAKY, pattern_set="full")


def test_exactly_three_findings(findings):
    assert len(findings) == 3, [f.to_dict() for f in findings]


def test_detects_aws_key(findings):
    rules = {f.rule_id for f in findings}
    assert "aws-access-key-id" in rules


def test_detects_stripe_key(findings):
    rules = {f.rule_id for f in findings}
    assert "stripe-secret-key" in rules


def test_detects_generic_secret(findings):
    rules = {f.rule_id for f in findings}
    assert "generic-high-entropy-secret" in rules


def test_zero_false_positives(findings):
    # Only the three expected rule ids may appear.
    expected = {"aws-access-key-id", "stripe-secret-key", "generic-high-entropy-secret"}
    assert {f.rule_id for f in findings} == expected


def test_findings_carry_commit_hash(findings):
    assert all(len(f.commit) >= 7 for f in findings)


def test_findings_carry_file_and_line(findings):
    for f in findings:
        assert f.file_path
        assert f.line_number >= 1


def test_redaction_hides_secret(findings):
    for f in findings:
        assert f._secret not in f.redacted_context


def test_aws_key_found_in_history_only():
    # deploy.sh was removed in the final commit; the key must still be found.
    fs = scan_repo(LEAKY, pattern_set="aws")
    assert any(f.rule_id == "aws-access-key-id" for f in fs)
    assert "deploy.sh" not in os.listdir(LEAKY)


def test_redact_preserves_prefix_suffix():
    out = redact('api_key = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"', "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es")
    assert out.startswith("api_key")
    assert "Zx" in out and "Es" in out
    assert "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es" not in out


def test_findings_carry_author_and_date(findings):
    # Every history finding records who introduced the credential and when, so
    # a researcher can triage by recency without re-running git.
    for f in findings:
        assert f.author, f.to_dict()
        assert "<" in f.author and ">" in f.author  # "Name <email>" form
        assert f.committed_at, f.to_dict()


def test_committed_at_is_iso8601_with_offset(findings):
    # The timestamp must round-trip through datetime.fromisoformat and carry a
    # timezone so downstream sorting/recency comparisons are unambiguous.
    from datetime import datetime

    for f in findings:
        parsed = datetime.fromisoformat(f.committed_at)
        assert parsed.tzinfo is not None, f.committed_at


def test_metadata_present_in_to_dict(findings):
    keys = set(findings[0].to_dict())
    assert "author" in keys
    assert "committed_at" in keys


def test_worktree_findings_have_empty_commit_metadata():
    # Working-tree findings have no backing commit, so author/date are blank
    # rather than carrying stale or fabricated attribution.
    from tombstone.scanner import WORKTREE_COMMIT, scan_worktree

    fs = scan_worktree(LEAKY, pattern_set="full")
    for f in fs:
        assert f.commit == WORKTREE_COMMIT
        assert f.author == ""
        assert f.committed_at == ""
