"""Tests for working-tree (uncommitted) credential scanning.

The leaky-repo fixture contains ``local.env`` — a file written into the working
copy but never committed. History scanning must NOT see it; working-tree
scanning MUST. When both run, the combined result deduplicates by
(rule_id, secret) so a credential present in both history and the working tree
is reported once.
"""

import os

import pytest

from tombstone.scanner import WORKTREE_COMMIT, scan_repo, scan_worktree

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")

WORKTREE_SECRET = "Qw8Er5Ty2Ui9Op3As6Df1Gh4Jk7Lz0Mn"


def test_worktree_file_present_on_disk():
    # Sanity: the fixture really has an uncommitted file.
    assert os.path.isfile(os.path.join(LEAKY, "local.env"))


def test_history_scan_misses_uncommitted_secret():
    # The classic gap: a secret only in the working copy is invisible to a
    # history-only scan.
    findings = scan_repo(LEAKY, pattern_set="full")
    assert all(WORKTREE_SECRET not in f._secret for f in findings)
    assert all(f.file_path != "local.env" for f in findings)


def test_worktree_scan_finds_uncommitted_secret():
    findings = scan_worktree(LEAKY, pattern_set="full")
    paths = {f.file_path for f in findings}
    assert "local.env" in paths
    secrets = {f._secret for f in findings}
    assert WORKTREE_SECRET in secrets


def test_worktree_findings_marked_with_worktree_commit():
    findings = scan_worktree(LEAKY, pattern_set="full")
    env_findings = [f for f in findings if f.file_path == "local.env"]
    assert env_findings
    assert all(f.commit == WORKTREE_COMMIT for f in env_findings)


def test_worktree_scan_skips_git_internal_dir():
    # .git/ must never be walked — its blobs are history, not the working tree,
    # and contain packed objects that would produce garbage findings.
    findings = scan_worktree(LEAKY, pattern_set="full")
    assert all(not f.file_path.startswith(".git/") for f in findings)
    assert all(".git/" not in f.file_path for f in findings)


def test_worktree_findings_carry_confidence():
    findings = scan_worktree(LEAKY, pattern_set="full")
    for f in findings:
        assert f.confidence in {"high", "medium", "low"}


def test_combined_scan_includes_worktree_and_history():
    history = scan_repo(LEAKY, pattern_set="full")
    combined = scan_repo(LEAKY, pattern_set="full", include_worktree=True)
    # Combined must be a superset of history and must include the worktree secret.
    history_keys = {(f.rule_id, f._secret) for f in history}
    combined_keys = {(f.rule_id, f._secret) for f in combined}
    assert history_keys <= combined_keys
    assert any(f._secret == WORKTREE_SECRET for f in combined)


def test_combined_scan_deduplicates_across_history_and_worktree():
    combined = scan_repo(LEAKY, pattern_set="full", include_worktree=True)
    keys = [(f.rule_id, f._secret) for f in combined]
    assert len(keys) == len(set(keys)), "duplicate (rule_id, secret) in combined scan"


def test_worktree_redaction_hides_secret():
    findings = scan_worktree(LEAKY, pattern_set="full")
    for f in findings:
        assert f._secret not in f.redacted_context


def test_h1md_worktree_reproduction_is_not_git_show():
    from tombstone.report import to_h1md

    findings = scan_worktree(LEAKY, pattern_set="full")
    md = to_h1md(findings)
    # A worktree finding must NOT be described with a `git show WORKTREE:` line.
    assert "git -C <repo> show WORKTREE" not in md
    assert "uncommitted" in md


def test_bcmd_worktree_walkthrough_uses_cat_not_git_show():
    from tombstone.report import to_bcmd

    findings = scan_worktree(LEAKY, pattern_set="full")
    md = to_bcmd(findings)
    assert "git show WORKTREE" not in md
    assert "uncommitted working tree" in md
    assert "cat local.env" in md
