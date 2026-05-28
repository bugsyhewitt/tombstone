"""Tests for --since/--until incremental scanning and --save-state/--load-state."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tombstone.scanner import load_state, resolve_state_file, save_state, scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
    )


def _leaky_commits() -> list[str]:
    """Return all commit SHAs for the leaky-repo fixture, newest first."""
    import git

    repo = git.Repo(LEAKY)
    return [c.hexsha for c in repo.iter_commits(rev="HEAD")]


# ---------------------------------------------------------------------------
# scan_repo with --since / --until
# ---------------------------------------------------------------------------


def test_since_head_returns_zero_commits():
    """Scanning since HEAD means 'new commits beyond HEAD' — should yield nothing."""
    findings = scan_repo(LEAKY, since="HEAD")
    assert findings == []


def test_since_oldest_commit_scans_all():
    """Since the oldest commit, every *later* commit is in range — should find all 3."""
    commits = _leaky_commits()
    oldest = commits[-1]  # last in newest-first order
    findings = scan_repo(LEAKY, since=oldest)
    # Credentials were introduced in commits 2 and 3 (0-indexed from oldest),
    # which are after the oldest commit, so we get findings for stripe + generic + aws
    # minus any that were already in the oldest commit itself.
    # At minimum we should get the credentials introduced after the initial commit.
    assert len(findings) >= 2


def test_until_oldest_commit_returns_nothing_or_only_benign():
    """Scanning only the very first (oldest) commit contains no credentials."""
    commits = _leaky_commits()
    oldest = commits[-1]
    findings = scan_repo(LEAKY, until=oldest)
    # First commit has only benign config — no real secrets.
    assert all(f.rule_id not in ("aws-access-key-id", "stripe-secret-key") for f in findings)


def test_since_and_until_range():
    """Scanning a single-commit range by specifying the same commit for since and until."""
    commits = _leaky_commits()
    # HEAD..HEAD is an empty range — no commits.
    findings = scan_repo(LEAKY, since="HEAD", until="HEAD")
    assert findings == []


def test_since_second_commit_sees_later_credentials():
    """Since the second commit, the Stripe key (commit 3) should be found."""
    commits = _leaky_commits()
    # commits are newest-first; index -3 is the 2nd commit (0-based from oldest)
    second_commit = commits[-3]  # 2nd oldest: introduces AWS key
    findings = scan_repo(LEAKY, since=second_commit)
    rule_ids = {f.rule_id for f in findings}
    # Stripe key and generic secret were introduced AFTER commit 2
    assert "stripe-secret-key" in rule_ids
    assert "generic-high-entropy-secret" in rule_ids


def test_no_range_args_still_finds_all():
    """With no since/until, scan_repo returns all 3 findings as before."""
    findings = scan_repo(LEAKY)
    assert len(findings) == 3


# ---------------------------------------------------------------------------
# State-file helpers
# ---------------------------------------------------------------------------


def test_resolve_state_file_default():
    path = resolve_state_file("/some/repo", None)
    assert path == Path("/some/repo/.tombstone-state")


def test_resolve_state_file_override():
    path = resolve_state_file("/some/repo", "/tmp/my-state")
    assert path == Path("/tmp/my-state")


def test_load_state_missing_file(tmp_path):
    assert load_state(tmp_path / "nonexistent") is None


def test_load_state_empty_file(tmp_path):
    f = tmp_path / "state"
    f.write_text("", encoding="utf-8")
    assert load_state(f) is None


def test_save_and_load_state_round_trip(tmp_path):
    state_path = tmp_path / "state"
    sha = save_state(state_path, LEAKY)
    assert len(sha) == 40  # full SHA
    loaded = load_state(state_path)
    assert loaded == sha


def test_save_state_invalid_repo(tmp_path):
    with pytest.raises(ValueError, match="not a git repository"):
        save_state(tmp_path / "state", str(tmp_path))


# ---------------------------------------------------------------------------
# CLI integration for --since / --save-state / --load-state
# ---------------------------------------------------------------------------


def test_cli_since_head_returns_empty(tmp_path):
    """--since HEAD → no new commits → empty findings list."""
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--since", "HEAD"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0


def test_cli_save_state_writes_file(tmp_path):
    state_file = str(tmp_path / "state")
    result = _run_cli(
        [
            "--repo-path", LEAKY,
            "--format", "json",
            "--save-state",
            "--state-file", state_file,
        ]
    )
    assert result.returncode == 0
    assert "state saved:" in result.stderr
    loaded = load_state(Path(state_file))
    assert loaded and len(loaded) == 40


def test_cli_load_state_after_save_scans_nothing_new(tmp_path):
    """Save state at HEAD, then load-state → no new commits → 0 findings."""
    state_file = str(tmp_path / "state")
    # First run: full scan + save state (--no-allowlist for the full count)
    r1 = _run_cli(
        [
            "--repo-path", LEAKY,
            "--format", "json",
            "--no-allowlist",
            "--save-state",
            "--state-file", state_file,
        ]
    )
    assert r1.returncode == 0
    p1 = json.loads(r1.stdout)
    assert p1["finding_count"] == 3

    # Second run: load state → since HEAD → nothing new
    r2 = _run_cli(
        [
            "--repo-path", LEAKY,
            "--format", "json",
            "--load-state",
            "--state-file", state_file,
        ]
    )
    assert r2.returncode == 0
    p2 = json.loads(r2.stdout)
    assert p2["finding_count"] == 0


def test_cli_load_state_with_no_state_file_scans_all(tmp_path):
    """--load-state when no state file exists falls back to full scan."""
    state_file = str(tmp_path / "nonexistent-state")
    result = _run_cli(
        [
            "--repo-path", LEAKY,
            "--format", "json",
            "--no-allowlist",
            "--load-state",
            "--state-file", state_file,
        ]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 3


def test_cli_since_overrides_load_state(tmp_path):
    """When both --since and --load-state are given, --since wins (warning emitted)."""
    state_file = str(tmp_path / "state")
    # Save a state first
    _run_cli(
        [
            "--repo-path", LEAKY,
            "--format", "json",
            "--save-state",
            "--state-file", state_file,
        ]
    )
    # Now use both --since HEAD and --load-state; since wins → 0 findings
    result = _run_cli(
        [
            "--repo-path", LEAKY,
            "--format", "json",
            "--since", "HEAD",
            "--load-state",
            "--state-file", state_file,
        ]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0
    assert "warning" in result.stderr.lower()


def test_cli_help_lists_new_flags():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    for flag in ("--since", "--until", "--save-state", "--load-state", "--state-file"):
        assert flag in result.stdout
