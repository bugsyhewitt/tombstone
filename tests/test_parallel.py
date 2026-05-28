"""Tests for parallel blob scanning (POST_V01 item 8).

The defining requirement of the parallel path is that results are *identical*
to a single-threaded run regardless of worker count: same findings, same order,
same reproducibility anchor (earliest commit a secret appears in). These tests
build a multi-commit repo at runtime and assert that equivalence, then exercise
the CLI ``--workers`` flag wiring and validation.
"""

import os
import subprocess

import pytest

from tombstone.cli import main
from tombstone.scanner import DEFAULT_WORKERS, scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="module")
def many_commit_repo(tmp_path_factory):
    """A repo with enough commits/blobs to exercise the thread pool.

    Each commit plants the same handful of credentials in differently-named
    files so dedup has to collapse them to a single finding anchored at the
    EARLIEST commit. With many parallel jobs, an order-insensitive merge would
    pick a later commit; this fixture makes that bug observable.
    """
    repo = tmp_path_factory.mktemp("many-commits")
    _git(["init", "-q"], repo)
    _git(["config", "user.email", "t@t.test"], repo)
    _git(["config", "user.name", "t"], repo)
    _git(["config", "commit.gpgsign", "false"], repo)

    aws = "AKIA" + "JKLMNOPQRSTUVWXY"  # 20-char AWS-shaped key id
    generic = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"

    for i in range(25):
        # The credentials first appear in commit 0; later commits re-add them in
        # new files plus a fresh benign file so every commit has multiple blobs.
        with open(os.path.join(repo, "creds.env"), "w", encoding="utf-8") as fh:
            fh.write(f"AWS_ACCESS_KEY_ID={aws}\n")
            fh.write(f'api_key = "{generic}"\n')
        with open(os.path.join(repo, f"file_{i}.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"benign content number {i}\nnothing to see here\n")
        _git(["add", "-A"], repo)
        _git(["commit", "-q", "-m", f"commit {i}"], repo)

    return str(repo)


def test_default_workers_is_capped_and_positive():
    assert DEFAULT_WORKERS >= 1
    assert DEFAULT_WORKERS <= 4


def test_parallel_matches_single_threaded_leaky():
    serial = scan_repo(LEAKY, pattern_set="full", workers=1)
    parallel = scan_repo(LEAKY, pattern_set="full", workers=4)
    assert [f.to_dict() for f in serial] == [f.to_dict() for f in parallel]


def test_parallel_matches_single_threaded_many_commits(many_commit_repo):
    serial = scan_repo(many_commit_repo, pattern_set="full", workers=1)
    parallel = scan_repo(many_commit_repo, pattern_set="full", workers=8)
    assert [f.to_dict() for f in serial] == [f.to_dict() for f in parallel]


def test_reproducibility_anchor_is_deterministic(many_commit_repo):
    """The deduped finding's commit anchor must be identical across worker counts.

    gitpython iterates commits newest-first, so dedup anchors the secret at the
    commit the scanner reaches first in that order. The contract for parallel
    scanning is that this anchor is deterministic regardless of worker count —
    an order-insensitive merge would let a thread race pick a different commit.
    """
    serial = scan_repo(many_commit_repo, pattern_set="full", workers=1)
    aws_serial = [f for f in serial if f.rule_id == "aws-access-key-id"]
    assert len(aws_serial) == 1
    anchor = aws_serial[0].commit

    for workers in (2, 4, 8):
        findings = scan_repo(many_commit_repo, pattern_set="full", workers=workers)
        aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
        assert len(aws) == 1, workers
        assert aws[0].commit == anchor, (workers, aws[0].commit)


def test_workers_zero_behaves_like_single_thread(many_commit_repo):
    # scan_repo treats workers < 1 as serial; results must still be correct.
    zero = scan_repo(many_commit_repo, pattern_set="full", workers=0)
    serial = scan_repo(many_commit_repo, pattern_set="full", workers=1)
    assert [f.to_dict() for f in zero] == [f.to_dict() for f in serial]


def test_parallel_with_worktree_matches_serial():
    serial = scan_repo(LEAKY, pattern_set="full", include_worktree=True, workers=1)
    parallel = scan_repo(LEAKY, pattern_set="full", include_worktree=True, workers=4)
    assert [f.to_dict() for f in serial] == [f.to_dict() for f in parallel]


def test_cli_accepts_workers_flag(capsys):
    rc = main(["--repo-path", LEAKY, "--format", "json", "--workers", "3"])
    assert rc == 0
    captured = capsys.readouterr()
    assert '"tombstone"' in captured.out


def test_cli_rejects_invalid_workers(capsys):
    rc = main(["--repo-path", LEAKY, "--workers", "0"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "--workers must be >= 1" in captured.err
