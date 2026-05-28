"""Tests for GitHub Actions workflow secret-exposure scanning (--workflow-scan).

The leaky-repo fixture ships ``.github/workflows/deploy.yml`` containing two
dangerous secret-exposure patterns (a ``${{ secrets.X }}`` interpolated into a
``run:`` command, and an ``echo`` of a secret-derived env var) plus two SAFE
constructs (the recommended ``env:`` mapping from a secret, and an ``echo`` of a
non-secret variable). Workflow scanning must flag exactly the two dangerous
lines and leave the safe ones alone, and must only run when --workflow-scan is
requested.
"""

import os

from tombstone.report import to_bcmd, to_json
from tombstone.scanner import WORKFLOW_RULE_ID, scan_repo
from tombstone.workflow import (
    is_workflow_file,
    redact_workflow_line,
    scan_workflow_text,
)

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")


# --------------------------------------------------------------------------- #
# Unit: path classification
# --------------------------------------------------------------------------- #


def test_is_workflow_file_matches_yml_and_yaml():
    assert is_workflow_file(".github/workflows/deploy.yml")
    assert is_workflow_file(".github/workflows/ci.yaml")
    assert is_workflow_file("sub/dir/.github/workflows/x.yml")


def test_is_workflow_file_rejects_non_workflow_paths():
    assert not is_workflow_file(".github/dependabot.yml")
    assert not is_workflow_file("workflows/deploy.yml")
    assert not is_workflow_file("deploy.yml")
    assert not is_workflow_file(".github/workflows/notes.txt")


# --------------------------------------------------------------------------- #
# Unit: anti-pattern detection over raw YAML text
# --------------------------------------------------------------------------- #


def test_flags_secret_interpolated_into_run_command():
    text = '      - run: curl -H "${{ secrets.API_TOKEN }}" https://x\n'
    hits = list(scan_workflow_text(text))
    assert len(hits) == 1
    assert hits[0].pattern_key == "secret-in-run"
    assert "API_TOKEN" in hits[0].description


def test_does_not_flag_safe_env_mapping_from_secret():
    # The recommended pattern: map a secret into env, never echo it. Must be safe.
    text = "    env:\n      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
    hits = list(scan_workflow_text(text))
    assert hits == []


def test_flags_echo_of_secret_derived_variable():
    text = '      - run: echo "$DEPLOY_TOKEN"\n'
    hits = list(scan_workflow_text(text))
    keys = {h.pattern_key for h in hits}
    assert "echo-secret-env" in keys


def test_does_not_flag_echo_of_non_secret_variable():
    text = '      - run: echo "$HOME building project"\n'
    hits = list(scan_workflow_text(text))
    assert all(h.pattern_key != "echo-secret-env" for h in hits)


def test_flags_secret_passed_as_command_line_flag():
    text = "      - run: deploy --token=${{ secrets.DEPLOY_KEY }}\n"
    hits = list(scan_workflow_text(text))
    assert any(h.pattern_key == "secret-in-run" for h in hits)


def test_redact_workflow_line_trims_and_caps_length():
    assert redact_workflow_line("   echo hi   ") == "echo hi"
    long = "x" * 500
    assert len(redact_workflow_line(long)) <= 200
    assert redact_workflow_line(long).endswith("...")


# --------------------------------------------------------------------------- #
# Integration: scan_repo gated on workflow_scan
# --------------------------------------------------------------------------- #


def test_workflow_findings_absent_without_flag():
    findings = scan_repo(LEAKY, pattern_set="full")
    assert all(f.rule_id != WORKFLOW_RULE_ID for f in findings)


def test_workflow_findings_present_with_flag():
    findings = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    wf = [f for f in findings if f.rule_id == WORKFLOW_RULE_ID]
    assert wf, "expected workflow secret-exposure findings"
    # Both dangerous lines (the run: interpolation and the echo) are flagged.
    assert len(wf) == 2
    assert all(f.file_path == ".github/workflows/deploy.yml" for f in wf)


def test_workflow_scan_is_superset_of_credential_scan():
    creds = scan_repo(LEAKY, pattern_set="full")
    both = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    cred_keys = {(f.rule_id, f._secret) for f in creds}
    both_keys = {(f.rule_id, f._secret) for f in both}
    assert cred_keys <= both_keys


def test_workflow_findings_carry_medium_confidence():
    findings = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    wf = [f for f in findings if f.rule_id == WORKFLOW_RULE_ID]
    assert wf
    assert all(f.confidence == "medium" for f in wf)


def test_workflow_findings_deduplicate():
    findings = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    keys = [(f.rule_id, f._secret) for f in findings]
    assert len(keys) == len(set(keys))


def test_workflow_redacted_context_is_present():
    findings = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    wf = [f for f in findings if f.rule_id == WORKFLOW_RULE_ID]
    for f in wf:
        assert f.redacted_context.strip()


# --------------------------------------------------------------------------- #
# Integration: report formatters render workflow findings
# --------------------------------------------------------------------------- #


def test_json_includes_workflow_rule():
    findings = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    out = to_json(findings)
    assert WORKFLOW_RULE_ID in out


def test_bcmd_assigns_severity_to_workflow_finding():
    findings = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    wf = [f for f in findings if f.rule_id == WORKFLOW_RULE_ID]
    md = to_bcmd(wf)
    # Workflow findings get a concrete severity, not the generic fallback default
    # rationale phrasing.
    assert "High (P2)" in md
    assert "run log" in md
