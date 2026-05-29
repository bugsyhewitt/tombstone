"""Tests for per-finding severity rating (POST_V01 item 9).

Severity is derived from the matched rule's declared ``severity`` in
necromancer-patterns and surfaced on every Finding, in JSON output, and in the
h1md / bcmd report headers. Confidence ("is it real?") and severity ("how bad if
it is?") are independent signals.
"""

import os

import pytest

from tombstone.patterns import get_rules
from tombstone.report import format_findings
from tombstone.scanner import scan_repo
from tombstone.severity import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    SEVERITY_CHOICES,
    SEVERITY_ORDER,
    WORKFLOW_SEVERITY,
    meets_threshold,
    rule_severity,
)

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")

_LABELS = {CRITICAL, HIGH, MEDIUM, LOW}


def _rule(rule_id: str):
    for r in get_rules("full"):
        if r.rule_id == rule_id:
            return r
    raise AssertionError(f"rule not found: {rule_id}")


# --- rule_severity: maps library Rule.severity onto tombstone labels -------


def test_aws_key_is_critical():
    assert rule_severity(_rule("aws-access-key-id")) == CRITICAL


def test_stripe_key_is_critical():
    assert rule_severity(_rule("stripe-secret-key")) == CRITICAL


def test_github_pat_is_critical():
    assert rule_severity(_rule("github-pat")) == CRITICAL


def test_gcp_key_is_critical():
    assert rule_severity(_rule("gcp-service-account-key")) == CRITICAL


def test_azure_devops_pat_is_critical():
    assert rule_severity(_rule("azure-devops-pat")) == CRITICAL


def test_generic_high_entropy_is_high():
    # The generic catch-all rule declares HIGH severity in the library.
    assert rule_severity(_rule("generic-high-entropy-secret")) == HIGH


def test_scoped_service_tokens_are_high():
    for rule_id in ("openai-api-key", "huggingface-token", "anthropic-api-key"):
        assert rule_severity(_rule(rule_id)) == HIGH, rule_id


def test_shopify_token_is_critical():
    # Full store API access → Critical, matching the rule's declared severity.
    assert rule_severity(_rule("shopify-token")) == CRITICAL


def test_twilio_and_discord_tokens_are_high():
    assert rule_severity(_rule("twilio-account-sid")) == HIGH
    assert rule_severity(_rule("discord-bot-token")) == HIGH


# --- rule_severity: normalisation + safe fallback --------------------------


class _FakeRule:
    def __init__(self, severity):
        self.severity = severity


def test_case_insensitive_normalisation():
    assert rule_severity(_FakeRule("CRITICAL")) == CRITICAL
    assert rule_severity(_FakeRule("Critical")) == CRITICAL
    assert rule_severity(_FakeRule(" high ")) == HIGH


def test_unknown_severity_defaults_to_high():
    # An unrecognised value must never silently downgrade to low.
    assert rule_severity(_FakeRule("bogus")) == HIGH


def test_missing_severity_defaults_to_high():
    assert rule_severity(_FakeRule(None)) == HIGH


# --- end-to-end: severity flows through Finding and reports -----------------


@pytest.fixture(scope="module")
def findings():
    return scan_repo(LEAKY, pattern_set="full")


def test_every_finding_carries_a_severity(findings):
    assert findings, "fixture should produce findings"
    for f in findings:
        assert f.severity in _LABELS, f


def test_aws_finding_severity_is_critical(findings):
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws, "expected an aws finding in the fixture"
    assert all(f.severity == CRITICAL for f in aws)


def test_severity_in_to_dict(findings):
    for f in findings:
        assert f.to_dict()["severity"] == f.severity


def test_severity_in_json_output(findings):
    out = format_findings(findings, "json")
    assert '"severity"' in out


def test_severity_in_h1md_output(findings):
    out = format_findings(findings, "h1md")
    assert "**Severity:**" in out


def test_severity_in_bcmd_output(findings):
    out = format_findings(findings, "bcmd")
    # The structured per-finding severity appears in parentheses in the Overview.
    assert f"({CRITICAL})" in out or f"({HIGH})" in out


def test_severity_independent_of_confidence(findings):
    # The example AWS key in the fixture is low *confidence* (it's the published
    # EXAMPLE key) but still critical *severity* — the two signals are separate.
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws
    for f in aws:
        assert f.severity == CRITICAL
        assert f.confidence == LOW


def test_workflow_finding_severity_is_high():
    # Workflow secret-exposure findings have no backing Rule; they get the
    # module's WORKFLOW_SEVERITY (high).
    assert WORKFLOW_SEVERITY == HIGH


def test_new_rules_have_dedicated_bcmd_rationale():
    # The Rotation-23 rules carry their own Bugcrowd "Demonstrated Impact"
    # rationale rather than falling back to the generic default — so a report on
    # one of these credentials reads accurately.
    from tombstone.scanner import Finding

    expected = {
        "shopify-token": ("Shopify", CRITICAL),
        "twilio-account-sid": ("Twilio", HIGH),
        "discord-bot-token": ("Discord", HIGH),
    }
    for rule_id, (needle, sev) in expected.items():
        finding = Finding(
            rule_id=rule_id,
            description="test",
            commit="deadbeef",
            file_path="config.yml",
            line_number=1,
            redacted_context="x=***",
            confidence="high",
            severity=sev,
        )
        out = format_findings([finding], "bcmd")
        # The credential-specific impact paragraph mentions the platform name and
        # is not the generic fallback text.
        assert needle in out, rule_id
        assert "Severity should be finalized against the Bugcrowd VRT" not in out


# --- meets_threshold: ordering for the --fail-on CI gate --------------------


def test_severity_order_is_most_to_least_severe():
    assert SEVERITY_ORDER == (CRITICAL, HIGH, MEDIUM, LOW)
    # The CLI exposes exactly this ordering as --fail-on choices.
    assert SEVERITY_CHOICES == SEVERITY_ORDER


def test_finding_meets_its_own_threshold():
    # A finding always meets a threshold equal to its own severity.
    for sev in (CRITICAL, HIGH, MEDIUM, LOW):
        assert meets_threshold(sev, sev), sev


def test_more_severe_finding_meets_lower_threshold():
    # critical meets every threshold; high meets high/medium/low; etc.
    assert meets_threshold(CRITICAL, HIGH)
    assert meets_threshold(CRITICAL, LOW)
    assert meets_threshold(HIGH, MEDIUM)
    assert meets_threshold(MEDIUM, LOW)


def test_less_severe_finding_does_not_meet_higher_threshold():
    assert not meets_threshold(HIGH, CRITICAL)
    assert not meets_threshold(MEDIUM, HIGH)
    assert not meets_threshold(LOW, MEDIUM)
    assert not meets_threshold(LOW, CRITICAL)


def test_meets_threshold_is_case_insensitive():
    assert meets_threshold("CRITICAL", "high")
    assert meets_threshold("High", "HIGH")


def test_unknown_finding_severity_never_trips_a_gate():
    # An unrecognised finding-severity label ranks below every known level, so
    # it never trips a --fail-on gate — including the least-severe "low"
    # threshold. This is the safe default: a malformed severity must not cause a
    # spurious CI failure. (In practice rule_severity never emits such a value;
    # this guards the comparison directly.)
    for threshold in SEVERITY_ORDER:
        assert not meets_threshold("bogus", threshold), threshold
