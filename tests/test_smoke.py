"""End-to-end smoke test exercising the CLI as a user would invoke it."""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")
OOS = os.path.join(HERE, "fixtures", "out-of-scope-repo")
SCOPE = os.path.join(HERE, "fixtures", "scope.txt")


def _run_cli(args):
    """Invoke the CLI via the installed module entry point."""
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
    )


def test_help_exits_zero_and_lists_flags():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    for flag in ("--repo-path", "--scope-file", "--format", "--pattern-set"):
        assert flag in result.stdout
    assert "json" in result.stdout and "h1md" in result.stdout
    assert "minimal" in result.stdout and "full" in result.stdout


def test_json_scan_emits_three_findings():
    # --no-allowlist disables default suppression so the AWS EXAMPLE key (a
    # known test credential) is reported alongside the real ones — the full
    # unfiltered scan returns all three planted findings.
    result = _run_cli(["--repo-path", LEAKY, "--format", "json", "--no-allowlist"])
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 3
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert rule_ids == {
        "aws-access-key-id",
        "stripe-secret-key",
        "generic-high-entropy-secret",
    }
    for finding in payload["findings"]:
        assert finding["commit"]
        assert finding["file_path"]
        assert finding["line_number"] >= 1
        assert "redacted_context" in finding


def test_h1md_scan_produces_markdown():
    result = _run_cli(["--repo-path", LEAKY, "--format", "h1md", "--no-allowlist"])
    assert result.returncode == 0
    assert "# tombstone credential findings" in result.stdout
    assert "**Total findings:** 3" in result.stdout
    assert "**Commit:**" in result.stdout


def test_bcmd_format():
    result = _run_cli(["--repo-path", LEAKY, "--format", "bcmd", "--no-allowlist"])
    assert result.returncode == 0
    out = result.stdout
    # Bugcrowd report section headers must be present.
    assert "## Overview" in out
    assert "## Walkthrough & PoC" in out
    assert "## Vulnerability Evidence" in out
    assert "## Demonstrated Impact" in out
    # Walkthrough must contain reproducible git commands.
    assert "git show" in out
    assert "git log --all -p" in out
    # All three findings rendered.
    assert out.count("## Overview") == 3
    # Severity rationale must appear (AWS key is critical).
    assert "Critical" in out


def test_include_worktree_surfaces_uncommitted_secret():
    # Without --include-worktree the uncommitted local.env credential is invisible.
    base = _run_cli(["--repo-path", LEAKY, "--format", "json"])
    assert base.returncode == 0
    base_payload = json.loads(base.stdout)
    assert all(f["file_path"] != "local.env" for f in base_payload["findings"])

    # With --include-worktree it appears, tagged with the WORKTREE commit marker.
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--include-worktree"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] > base_payload["finding_count"]
    worktree_findings = [
        f for f in payload["findings"] if f["file_path"] == "local.env"
    ]
    assert worktree_findings
    assert all(f["commit"] == "WORKTREE" for f in worktree_findings)


def test_include_worktree_listed_in_help():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--include-worktree" in result.stdout


def test_out_of_scope_refused_nonzero():
    result = _run_cli(
        ["--scope-file", SCOPE, "--repo-path", OOS, "--format", "json"]
    )
    assert result.returncode != 0
    assert "out of scope" in result.stderr.lower()
