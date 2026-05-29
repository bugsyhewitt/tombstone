"""Tests for the SARIF 2.1.0 output format.

SARIF (Static Analysis Results Interchange Format) is the OASIS-standard JSON
schema consumed by GitHub code scanning, VS Code's SARIF viewer, and most CI
dashboards. The `--format sarif` formatter lets a researcher push tombstone
findings straight into those tools instead of hand-translating JSON.

These tests verify the document shape, the severity→level mapping, rule
deduplication, location/fingerprint emission, and that the raw secret never
leaks into the output.
"""

import json

from tombstone.report import format_findings, to_sarif
from tombstone.scanner import WORKTREE_COMMIT, Finding


def _history_finding(**overrides) -> Finding:
    base = dict(
        rule_id="aws-access-key-id",
        description="AWS access key ID",
        commit="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        file_path="config/prod.env",
        line_number=7,
        redacted_context='aws_key = "AK****EF"',
        confidence="high",
        severity="critical",
        author="Jane Dev <jane@acme-corp.example>",
        committed_at="2026-05-20T14:03:11+00:00",
        _secret="AKIAEXAMPLEEXAMPLE01",
    )
    base.update(overrides)
    return Finding(**base)


def _worktree_finding(**overrides) -> Finding:
    base = dict(
        rule_id="stripe-secret-key",
        description="Stripe secret key",
        commit=WORKTREE_COMMIT,
        file_path=".env.local",
        line_number=2,
        redacted_context='stripe = "sk****99"',
        confidence="high",
        severity="critical",
        author="",
        committed_at="",
        _secret="sk_live_worktreeonly99",
    )
    base.update(overrides)
    return Finding(**base)


# --------------------------------------------------------------------------- #
# Document structure
# --------------------------------------------------------------------------- #


def test_sarif_is_valid_json_with_required_top_level_fields():
    doc = json.loads(to_sarif([_history_finding()]))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1


def test_sarif_driver_identifies_tombstone():
    doc = json.loads(to_sarif([_history_finding()]))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "tombstone"
    assert driver["version"]  # version string present
    assert "github.com/bugsyhewitt/tombstone" in driver["informationUri"]


def test_sarif_empty_findings_produces_empty_run():
    doc = json.loads(to_sarif([]))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


# --------------------------------------------------------------------------- #
# Rules and results
# --------------------------------------------------------------------------- #


def test_sarif_one_result_per_finding():
    findings = [_history_finding(), _worktree_finding()]
    doc = json.loads(to_sarif(findings))
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_deduplicates_rules_but_keeps_results():
    # Two findings of the same rule → one rule descriptor, two results.
    findings = [
        _history_finding(file_path="a.env", _secret="AKIAFIRST00000000001"),
        _history_finding(file_path="b.env", _secret="AKIASECOND0000000002"),
    ]
    doc = json.loads(to_sarif(findings))
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2


def test_sarif_result_references_rule_by_index():
    findings = [_worktree_finding(), _history_finding()]
    doc = json.loads(to_sarif(findings))
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        idx = result["ruleIndex"]
        assert 0 <= idx < len(rules)
        # The referenced rule's id must match the result's ruleId.
        assert rules[idx]["id"] == result["ruleId"]


# --------------------------------------------------------------------------- #
# Severity → level mapping
# --------------------------------------------------------------------------- #


def test_sarif_severity_maps_to_level():
    cases = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    for severity, expected_level in cases.items():
        f = _history_finding(severity=severity, _secret=f"AKIA{severity}0001")
        doc = json.loads(to_sarif([f]))
        result = doc["runs"][0]["results"][0]
        assert result["level"] == expected_level
        # The rule's defaultConfiguration mirrors the same level.
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == expected_level


def test_sarif_security_severity_score_present():
    doc = json.loads(to_sarif([_history_finding(severity="critical")]))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    score = rule["properties"]["security-severity"]
    # GitHub code scanning treats >= 9.0 as critical.
    assert float(score) >= 9.0


# --------------------------------------------------------------------------- #
# Location, fingerprint, attribution
# --------------------------------------------------------------------------- #


def test_sarif_location_carries_file_and_line():
    f = _history_finding(file_path="src/secrets.py", line_number=42)
    doc = json.loads(to_sarif([f]))
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/secrets.py"
    assert loc["region"]["startLine"] == 42


def test_sarif_partial_fingerprint_is_stable_across_commit_change():
    a = _history_finding(commit="a" * 40)
    b = _history_finding(commit="b" * 40)  # same rule/file/secret, new commit
    fp_a = json.loads(to_sarif([a]))["runs"][0]["results"][0][
        "partialFingerprints"
    ]
    fp_b = json.loads(to_sarif([b]))["runs"][0]["results"][0][
        "partialFingerprints"
    ]
    assert fp_a == fp_b


def test_sarif_emits_commit_attribution_for_history_findings():
    doc = json.loads(to_sarif([_history_finding()]))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["author"] == "Jane Dev <jane@acme-corp.example>"
    assert props["committed_at"] == "2026-05-20T14:03:11+00:00"
    assert props["commit"] == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def test_sarif_worktree_finding_omits_empty_attribution():
    doc = json.loads(to_sarif([_worktree_finding()]))
    props = doc["runs"][0]["results"][0]["properties"]
    # Empty author/date are not emitted as keys.
    assert "author" not in props
    assert "committed_at" not in props
    assert props["commit"] == WORKTREE_COMMIT


def test_sarif_confidence_and_severity_in_properties():
    doc = json.loads(to_sarif([_history_finding(confidence="medium")]))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["confidence"] == "medium"
    assert props["severity"] == "critical"


# --------------------------------------------------------------------------- #
# Security: the raw secret must never appear
# --------------------------------------------------------------------------- #


def test_sarif_never_leaks_raw_secret():
    secret = "AKIAREALSECRET1234567"
    out = to_sarif([_history_finding(_secret=secret)])
    assert secret not in out
    # The redacted context (which masks the secret) is what gets emitted.
    assert "AK****EF" in out


# --------------------------------------------------------------------------- #
# Dispatch integration
# --------------------------------------------------------------------------- #


def test_format_findings_dispatches_sarif():
    out = format_findings([_history_finding()], "sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
