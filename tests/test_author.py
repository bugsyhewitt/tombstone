"""Tests for the --author finding scoping filter.

``--author`` narrows the reported findings to commits made by a single
committer, matched case-insensitively as a substring against the finding's
``"Name <email>"`` author field. It composes with the existing history scan
(every commit is still traversed for deduplication accuracy; only the reported
set is narrowed) and mirrors seance's committer-scoping flags.

These tests cover the pure matcher (:func:`matches_author`), the scanner-level
filter against a purpose-built two-author git fixture, and the CLI integration.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from tombstone.scanner import matches_author, scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Pure matcher
# --------------------------------------------------------------------------- #


def test_matches_author_by_name_substring():
    assert matches_author("Jane Dev <jane@acme-corp.example>", "jane")


def test_matches_author_by_email_substring():
    assert matches_author("Jane Dev <jane@acme-corp.example>", "jane@acme")


def test_matches_author_is_case_insensitive():
    assert matches_author("Jane Dev <jane@acme-corp.example>", "JANE DEV")
    assert matches_author("JANE DEV <JANE@ACME.EXAMPLE>", "jane")


def test_matches_author_non_match_returns_false():
    assert not matches_author("Jane Dev <jane@acme-corp.example>", "bob")


def test_empty_needle_matches_everything():
    # Defensive: callers gate on truthiness, but an empty needle is a no-op.
    assert matches_author("Jane Dev <jane@acme-corp.example>", "")
    assert matches_author("", "")


def test_empty_author_never_matches_nonempty_needle():
    # Working-tree / workflow findings have no commit author.
    assert not matches_author("", "jane")


# --------------------------------------------------------------------------- #
# Two-author git fixture
# --------------------------------------------------------------------------- #


def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def two_author_repo(tmp_path):
    """A repo where two different committers each plant one AWS key.

    Alice commits an AWS access key, then removes the file in a later (still
    Alice-authored) commit so the key lives only in history attributed to her.
    Bob then commits a *different* AWS access key. Because the scanner anchors a
    deduplicated finding to the newest commit the secret appears in, removing
    Alice's file before Bob's commit guarantees Alice's key is attributed to
    Alice and Bob's to Bob — exactly the condition the author filter scopes on.
    Both keys are syntactically valid for the ``aws-access-key-id`` rule, so
    author filtering — not rule differences — is what the tests exercise.
    """
    repo = tmp_path / "two-author-repo"
    repo.mkdir()
    _run(["git", "init", "-q"], cwd=repo)

    def _set_identity(name, email):
        _run(["git", "config", "user.name", name], cwd=repo)
        _run(["git", "config", "user.email", email], cwd=repo)

    def _commit(message):
        _run(["git", "add", "-A"], cwd=repo)
        _run(
            ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", message],
            cwd=repo,
        )

    # Two distinct, valid AWS access key IDs (20 chars: AKIA + 16 base32
    # chars [A-Z2-7], which is what the aws-access-key-id rule requires).
    _set_identity("Alice Smith", "alice@acme.example")
    (repo / "alice.sh").write_text(
        "export AWS_ACCESS_KEY_ID=AKIA22222222ALICE234\n", encoding="utf-8"
    )
    _commit("alice adds a key")
    # Alice removes her file so the key is history-only and stays attributed to
    # her (it never appears in Bob's later commit tree).
    (repo / "alice.sh").unlink()
    _commit("alice removes the key file")

    _set_identity("Bob Jones", "bob@other.example")
    (repo / "bob.sh").write_text(
        "export AWS_ACCESS_KEY_ID=AKIA33333333BOBJONES\n", encoding="utf-8"
    )
    _commit("bob adds a key")
    return str(repo)


def test_no_author_filter_returns_both(two_author_repo):
    findings = scan_repo(two_author_repo, pattern_set="full")
    authors = {f.author for f in findings if f.rule_id == "aws-access-key-id"}
    assert any("alice" in a.lower() for a in authors)
    assert any("bob" in a.lower() for a in authors)


def test_author_filter_by_name_scopes_to_one(two_author_repo):
    findings = scan_repo(two_author_repo, pattern_set="full", author_filter="Alice")
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws, "expected at least one AWS finding for Alice"
    assert all("alice" in f.author.lower() for f in aws)
    assert all("bob" not in f.author.lower() for f in aws)


def test_author_filter_by_email_scopes_to_one(two_author_repo):
    findings = scan_repo(two_author_repo, pattern_set="full", author_filter="bob@other")
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws
    assert all("bob@other" in f.author.lower() for f in aws)


def test_author_filter_case_insensitive(two_author_repo):
    findings = scan_repo(two_author_repo, pattern_set="full", author_filter="ALICE SMITH")
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws
    assert all("alice" in f.author.lower() for f in aws)


def test_author_filter_no_match_returns_empty(two_author_repo):
    findings = scan_repo(two_author_repo, pattern_set="full", author_filter="nobody")
    assert findings == []


def test_author_filter_excludes_worktree_findings(two_author_repo):
    # Drop an uncommitted credential into the working tree.
    with open(os.path.join(two_author_repo, "local.env"), "w", encoding="utf-8") as fh:
        fh.write("AWS_ACCESS_KEY_ID=AKIA44444444WORKTREE\n")
    # With an author filter active, the worktree finding (no commit author)
    # must be excluded even though --include-worktree is set.
    findings = scan_repo(
        two_author_repo,
        pattern_set="full",
        include_worktree=True,
        author_filter="Alice",
    )
    assert all(f.author for f in findings), "worktree (blank-author) finding leaked through"
    assert all("alice" in f.author.lower() for f in findings)


# --------------------------------------------------------------------------- #
# CLI integration
# --------------------------------------------------------------------------- #


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
    )


def test_cli_author_filter_scopes_findings(two_author_repo):
    result = _run_cli(
        ["--repo-path", two_author_repo, "--format", "json", "--author", "Alice"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    authors = {f["author"] for f in payload["findings"]}
    assert authors
    assert all("alice" in a.lower() for a in authors)


def test_cli_author_filter_no_match_empty(two_author_repo):
    result = _run_cli(
        ["--repo-path", two_author_repo, "--format", "json", "--author", "carol"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0


def test_cli_help_lists_author_flag():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--author" in result.stdout
