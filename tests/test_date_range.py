"""Tests for --since-date/--until-date calendar-date commit filtering.

These narrow a scan by commit *date* (gitpython's iter_commits after/before),
distinct from the refspec-based --since/--until range. The most common
bug-bounty use is scoping an investigation to a breach window, e.g.
``--since-date 2025-03-01 --until-date 2025-03-15``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from tombstone.scanner import scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")

# A real Stripe-key literal must not appear in committed source (push
# protection), so assemble the planted key from fragments, same as the main
# fixture builder.
_STRIPE_KEY = "sk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
    )


def _git(cwd, *cmd, date=None):
    env = dict(os.environ)
    if date is not None:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    subprocess.run(
        ["git", *cmd], cwd=cwd, check=True, capture_output=True, env=env
    )


@pytest.fixture
def dated_repo(tmp_path):
    """A repo with three credential-bearing commits on distinct, fixed dates.

    - 2024-01-15 : AWS access key   (file removed in the next commit)
    - 2025-06-10 : Stripe key       (file removed in the next commit)
    - 2025-12-20 : generic high-entropy secret

    Each credential lives in its OWN commit only: the prior secret-bearing file
    is deleted before the next commit, so a date window that excludes a commit
    genuinely excludes that credential (the blob is not carried forward into a
    surviving file). This isolates the date-filter semantics under test.
    """
    repo = tmp_path / "dated"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "fixture@tombstone.test")
    _git(repo, "config", "user.name", "tombstone fixture")

    secret = repo / "secret.conf"

    secret.write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m",
         "aws", date="2024-01-15T12:00:00")

    secret.write_text(
        f'STRIPE_SECRET_KEY = "{_STRIPE_KEY}"\n', encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m",
         "stripe", date="2025-06-10T12:00:00")

    secret.write_text(
        'api_key = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"\n', encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m",
         "generic", date="2025-12-20T12:00:00")

    return str(repo)


# ---------------------------------------------------------------------------
# scan_repo date narrowing
# ---------------------------------------------------------------------------


def test_no_date_args_scans_all(dated_repo):
    findings = scan_repo(dated_repo)
    rule_ids = {f.rule_id for f in findings}
    assert "aws-access-key-id" in rule_ids
    assert "stripe-secret-key" in rule_ids
    assert "generic-high-entropy-secret" in rule_ids


def test_since_date_excludes_earlier_commits(dated_repo):
    """since-date after the AWS commit drops the AWS key, keeps the later two."""
    findings = scan_repo(dated_repo, since_date="2025-01-01")
    rule_ids = {f.rule_id for f in findings}
    assert "aws-access-key-id" not in rule_ids
    assert "stripe-secret-key" in rule_ids
    assert "generic-high-entropy-secret" in rule_ids


def test_until_date_excludes_later_commits(dated_repo):
    """until-date before the generic commit drops it, keeps the earlier two."""
    findings = scan_repo(dated_repo, until_date="2025-07-01")
    rule_ids = {f.rule_id for f in findings}
    assert "aws-access-key-id" in rule_ids
    assert "stripe-secret-key" in rule_ids
    assert "generic-high-entropy-secret" not in rule_ids


def test_date_window_isolates_single_commit(dated_repo):
    """A window bracketing only the Stripe commit yields just that key."""
    findings = scan_repo(
        dated_repo, since_date="2025-03-01", until_date="2025-09-01"
    )
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"stripe-secret-key"}


def test_date_window_with_no_commits_returns_empty(dated_repo):
    """A window before any commit yields nothing."""
    findings = scan_repo(
        dated_repo, since_date="2020-01-01", until_date="2020-12-31"
    )
    assert findings == []


def test_future_since_date_returns_empty(dated_repo):
    findings = scan_repo(dated_repo, since_date="2099-01-01")
    assert findings == []


# ---------------------------------------------------------------------------
# Composition with the refspec --since/--until range
# ---------------------------------------------------------------------------


def test_since_date_composes_with_refspec_since(dated_repo):
    """Refspec range and date window intersect — both narrowings apply."""
    import git

    repo = git.Repo(dated_repo)
    commits = [c.hexsha for c in repo.iter_commits("HEAD")]  # newest-first
    oldest = commits[-1]  # AWS commit
    # Refspec since=oldest -> stripe + generic; date window also caps to <=2025-07-01
    findings = scan_repo(dated_repo, since=oldest, until_date="2025-07-01")
    rule_ids = {f.rule_id for f in findings}
    assert "aws-access-key-id" not in rule_ids  # excluded by refspec range
    assert "stripe-secret-key" in rule_ids
    assert "generic-high-entropy-secret" not in rule_ids  # excluded by date


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_since_date_future_returns_empty():
    """--since-date in the far future → no commits in range → 0 findings."""
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--since-date", "2099-01-01"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0


def test_cli_until_date_past_returns_empty():
    """--until-date in the far past → no commits in range → 0 findings."""
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--until-date", "2000-01-01"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0


def test_cli_wide_date_window_scans_all():
    """A window spanning the fixture's build time finds all 3 history secrets."""
    result = _run_cli(
        [
            "--repo-path", LEAKY,
            "--format", "json",
            "--no-allowlist",
            "--since-date", "2000-01-01",
            "--until-date", "2099-01-01",
        ]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 3


def test_cli_help_lists_date_flags():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--since-date" in result.stdout
    assert "--until-date" in result.stdout
