"""Tests for the --committer finding scoping filter.

``--committer`` narrows the reported findings to commits whose git *committer*
matches a string, case-insensitively, as a substring against the finding's
``"Name <email>"`` committer field. It is distinct from ``--author``: git
records both who *wrote* a change (author) and who *applied* it (committer), and
the two diverge under rebase, cherry-pick, and patch-application / squash-merge
workflows. ``--committer`` composes with ``--author`` (both must match) and,
like the author filter, narrows only the reported set — the full history
traversal and dedup are unchanged.

These tests cover the pure matcher (:func:`matches_committer`), the
scanner-level filter against a fixture where author and committer differ, the
author/committer composition, and the CLI integration.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from tombstone.scanner import matches_committer, scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Pure matcher
# --------------------------------------------------------------------------- #


def test_matches_committer_by_name_substring():
    assert matches_committer("CI Bot <bot@ci.example>", "ci bot")


def test_matches_committer_by_email_substring():
    assert matches_committer("CI Bot <bot@ci.example>", "bot@ci")


def test_matches_committer_is_case_insensitive():
    assert matches_committer("CI Bot <bot@ci.example>", "CI BOT")
    assert matches_committer("CI BOT <BOT@CI.EXAMPLE>", "ci bot")


def test_matches_committer_non_match_returns_false():
    assert not matches_committer("CI Bot <bot@ci.example>", "alice")


def test_empty_needle_matches_everything():
    assert matches_committer("CI Bot <bot@ci.example>", "")
    assert matches_committer("", "")


def test_empty_committer_never_matches_nonempty_needle():
    # Working-tree / workflow findings have no commit committer.
    assert not matches_committer("", "ci bot")


# --------------------------------------------------------------------------- #
# Author-≠-committer git fixture
# --------------------------------------------------------------------------- #


def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def split_identity_repo(tmp_path):
    """A repo where the author and committer of each commit differ.

    The repo's configured identity (the *committer* git records) is "Maintainer
    Bot". Two commits are made with an explicit ``--author`` override so the
    *author* is a different person than the committer — exactly the rebase /
    patch-apply / squash-merge situation that distinguishes the two identities.

    Alice authors a commit (committed by Maintainer Bot) planting an AWS key,
    then her file is removed in a follow-up commit so her key lives only in
    history. Bob then authors a commit (also committed by Maintainer Bot)
    planting a *different* AWS key. Because the scanner anchors a deduplicated
    finding to the commit the secret appears in, each key is attributed to its
    distinct author while sharing the single committer — letting the tests prove
    that ``--committer`` filters on the committer identity, not the author.
    """
    repo = tmp_path / "split-identity-repo"
    repo.mkdir()
    _run(["git", "init", "-q"], cwd=repo)

    # The configured identity is the COMMITTER for every commit below.
    _run(["git", "config", "user.name", "Maintainer Bot"], cwd=repo)
    _run(["git", "config", "user.email", "maint@bot.example"], cwd=repo)

    def _commit(message, author):
        _run(["git", "add", "-A"], cwd=repo)
        _run(
            [
                "git",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--author",
                author,
                "-m",
                message,
            ],
            cwd=repo,
        )

    # Two distinct, valid AWS access key IDs (AKIA + 16 base32 chars).
    (repo / "alice.sh").write_text(
        "export AWS_ACCESS_KEY_ID=AKIA22222222ALICE234\n", encoding="utf-8"
    )
    _commit("alice's change", author="Alice Smith <alice@acme.example>")
    # Remove Alice's file so her key is history-only, attributed to her authorship
    # but committed by Maintainer Bot.
    (repo / "alice.sh").unlink()
    _commit("remove alice's key file", author="Alice Smith <alice@acme.example>")

    (repo / "bob.sh").write_text(
        "export AWS_ACCESS_KEY_ID=AKIA33333333BOBJONES\n", encoding="utf-8"
    )
    _commit("bob's change", author="Bob Jones <bob@other.example>")
    return str(repo)


def test_findings_carry_distinct_author_and_committer(split_identity_repo):
    findings = scan_repo(split_identity_repo, pattern_set="full")
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws, "expected AWS findings"
    # Every finding shares the single committer...
    assert all("maintainer bot" in f.committer.lower() for f in aws)
    # ...but the authors differ from the committer.
    assert any("alice" in f.author.lower() for f in aws)
    assert any("bob" in f.author.lower() for f in aws)
    assert all("maintainer bot" not in f.author.lower() for f in aws)


def test_committer_filter_matches_shared_committer(split_identity_repo):
    findings = scan_repo(
        split_identity_repo, pattern_set="full", committer_filter="Maintainer Bot"
    )
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    # Both keys share the committer, so both survive the committer filter.
    assert any("alice" in f.author.lower() for f in aws)
    assert any("bob" in f.author.lower() for f in aws)


def test_committer_filter_by_email(split_identity_repo):
    findings = scan_repo(
        split_identity_repo, pattern_set="full", committer_filter="maint@bot"
    )
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws
    assert all("maint@bot" in f.committer.lower() for f in aws)


def test_committer_filter_no_match_returns_empty(split_identity_repo):
    findings = scan_repo(
        split_identity_repo, pattern_set="full", committer_filter="nobody"
    )
    assert findings == []


def test_committer_filter_does_not_match_an_author_name(split_identity_repo):
    # "Alice" is an AUTHOR, not the committer — a committer filter on her name
    # must not surface her finding, proving the filter keys on committer.
    findings = scan_repo(
        split_identity_repo, pattern_set="full", committer_filter="Alice"
    )
    assert findings == []


def test_author_and_committer_filters_compose(split_identity_repo):
    # Author=Alice AND committer=Maintainer Bot → Alice's key only.
    findings = scan_repo(
        split_identity_repo,
        pattern_set="full",
        author_filter="Alice",
        committer_filter="Maintainer Bot",
    )
    aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
    assert aws
    assert all("alice" in f.author.lower() for f in aws)
    assert all("maintainer bot" in f.committer.lower() for f in aws)
    assert all("bob" not in f.author.lower() for f in aws)


def test_author_and_committer_filters_compose_to_empty(split_identity_repo):
    # Author=Alice but committer=nobody → no finding satisfies both.
    findings = scan_repo(
        split_identity_repo,
        pattern_set="full",
        author_filter="Alice",
        committer_filter="nobody",
    )
    assert findings == []


def test_committer_filter_excludes_worktree_findings(split_identity_repo):
    # An uncommitted credential has no committer and must be excluded when the
    # committer filter is active, even with --include-worktree.
    with open(
        os.path.join(split_identity_repo, "local.env"), "w", encoding="utf-8"
    ) as fh:
        fh.write("AWS_ACCESS_KEY_ID=AKIA44444444WORKTREE\n")
    findings = scan_repo(
        split_identity_repo,
        pattern_set="full",
        include_worktree=True,
        committer_filter="Maintainer Bot",
    )
    assert all(f.committer for f in findings), "worktree finding leaked through"
    assert all("maintainer bot" in f.committer.lower() for f in findings)


def test_to_dict_includes_committer(split_identity_repo):
    findings = scan_repo(split_identity_repo, pattern_set="full")
    d = findings[0].to_dict()
    assert "committer" in d


# --------------------------------------------------------------------------- #
# CLI integration
# --------------------------------------------------------------------------- #


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
    )


def test_cli_committer_filter_scopes_findings(split_identity_repo):
    result = _run_cli(
        [
            "--repo-path",
            split_identity_repo,
            "--format",
            "json",
            "--committer",
            "Maintainer Bot",
        ]
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    committers = {f["committer"] for f in payload["findings"]}
    assert committers
    assert all("maintainer bot" in c.lower() for c in committers)


def test_cli_committer_filter_no_match_empty(split_identity_repo):
    result = _run_cli(
        [
            "--repo-path",
            split_identity_repo,
            "--format",
            "json",
            "--committer",
            "alice",
        ]
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0


def test_cli_help_lists_committer_flag():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--committer" in result.stdout
