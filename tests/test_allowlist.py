"""Tests for the suppression allowlist (POST_V01 item 7).

The allowlist removes findings whose secret matches a known test credential,
a user-supplied exact value, or a user-supplied regex. A built-in default
allowlist suppresses well-known vendor examples and placeholders (the AWS
EXAMPLE key, Stripe ``sk_test_`` keys, ``PLACEHOLDER`` / ``CHANGEME`` / ``DUMMY``)
so tombstone output on any repo that ships tests is report-ready by default.
"""

import json
import os
import subprocess
import sys

import pytest

from tombstone.allowlist import Allowlist, default_allowlist, load_allowlist
from tombstone.scanner import Finding, scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")

# The canonical AWS example key shipped by AWS in its own docs.
AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"


def _finding(secret: str, rule_id: str = "generic-high-entropy-secret") -> Finding:
    return Finding(
        rule_id=rule_id,
        description="test finding",
        commit="deadbeef",
        file_path="x.py",
        line_number=1,
        redacted_context="redacted",
        confidence="high",
        _secret=secret,
    )


# --- default allowlist ----------------------------------------------------


def test_default_allowlist_suppresses_aws_example():
    al = default_allowlist()
    assert al.is_suppressed(_finding(AWS_EXAMPLE, "aws-access-key-id"))


def test_default_allowlist_suppresses_stripe_test_key():
    al = default_allowlist()
    test_key = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
    assert al.is_suppressed(_finding(test_key, "stripe-secret-key"))


def test_default_allowlist_suppresses_placeholders():
    al = default_allowlist()
    for value in ("PLACEHOLDER", "CHANGEME", "a-DUMMY-value", "your-secret-here"):
        assert al.is_suppressed(_finding(value)), value


def test_default_allowlist_keeps_real_secret():
    al = default_allowlist()
    real = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"
    assert not al.is_suppressed(_finding(real))


# --- user-supplied allowlist ----------------------------------------------


def test_user_allowlist_exact_secret(tmp_path):
    f = tmp_path / "allow.toml"
    f.write_text('secrets = ["Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"]\n')
    al = load_allowlist(str(f), include_default=False)
    assert al.is_suppressed(_finding("Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"))
    assert not al.is_suppressed(_finding("SomethingElseEntirely1234567890"))


def test_user_allowlist_exact_is_case_insensitive(tmp_path):
    f = tmp_path / "allow.toml"
    f.write_text('secrets = ["MyTestSecret"]\n')
    al = load_allowlist(str(f), include_default=False)
    assert al.is_suppressed(_finding("mytestsecret"))


def test_user_allowlist_regex(tmp_path):
    f = tmp_path / "allow.toml"
    f.write_text('regexes = ["^TEST_[A-Z0-9]+$"]\n')
    al = load_allowlist(str(f), include_default=False)
    assert al.is_suppressed(_finding("TEST_ABC123"))
    assert not al.is_suppressed(_finding("PROD_ABC123"))


def test_user_allowlist_merges_with_default(tmp_path):
    f = tmp_path / "allow.toml"
    f.write_text('secrets = ["Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"]\n')
    al = load_allowlist(str(f), include_default=True)
    # User entry suppressed...
    assert al.is_suppressed(_finding("Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"))
    # ...and the built-in default entries still apply.
    assert al.is_suppressed(_finding(AWS_EXAMPLE, "aws-access-key-id"))


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(ValueError):
        load_allowlist(str(tmp_path / "nope.toml"), include_default=False)


def test_load_invalid_regex_raises(tmp_path):
    f = tmp_path / "allow.toml"
    f.write_text('regexes = ["([unterminated"]\n')
    with pytest.raises(ValueError):
        load_allowlist(str(f), include_default=False)


def test_empty_allowlist_suppresses_nothing():
    al = Allowlist(exact=set(), regexes=[])
    assert not al.is_suppressed(_finding(AWS_EXAMPLE, "aws-access-key-id"))


# --- filter_findings -------------------------------------------------------


def test_filter_findings_removes_suppressed():
    al = default_allowlist()
    findings = [
        _finding(AWS_EXAMPLE, "aws-access-key-id"),
        _finding("Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"),
    ]
    kept = al.filter_findings(findings)
    assert len(kept) == 1
    assert kept[0]._secret == "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"


# --- end-to-end through the CLI -------------------------------------------


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
    )


def test_cli_default_suppresses_aws_example():
    # By default the AWS EXAMPLE key is suppressed → 2 findings, no aws rule.
    result = _run_cli(["--repo-path", LEAKY, "--format", "json"])
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert "aws-access-key-id" not in rule_ids
    assert payload["finding_count"] == 2


def test_cli_no_allowlist_restores_aws_example():
    # --no-allowlist disables suppression → the AWS EXAMPLE key reappears.
    result = _run_cli(["--repo-path", LEAKY, "--format", "json", "--no-allowlist"])
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert "aws-access-key-id" in rule_ids
    assert payload["finding_count"] == 3


def test_cli_user_allowlist_suppresses_named_secret(tmp_path):
    f = tmp_path / "allow.toml"
    # Suppress the generic api_key secret planted in the fixture.
    f.write_text('secrets = ["Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"]\n')
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--allowlist", str(f)]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    # Default still suppresses AWS example; user allowlist suppresses generic.
    assert "aws-access-key-id" not in rule_ids
    assert "generic-high-entropy-secret" not in rule_ids
    assert "stripe-secret-key" in rule_ids


def test_cli_allowlist_flags_in_help():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--allowlist" in result.stdout
    assert "--no-allowlist" in result.stdout


def test_cli_missing_allowlist_file_errors():
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--allowlist", "/no/such.toml"]
    )
    assert result.returncode != 0
    assert "allowlist" in result.stderr.lower()
