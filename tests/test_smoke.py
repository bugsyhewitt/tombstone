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


def test_sarif_format():
    result = _run_cli(["--repo-path", LEAKY, "--format", "sarif", "--no-allowlist"])
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    # Valid SARIF 2.1.0 envelope.
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "tombstone"
    # All three planted findings rendered as results.
    assert len(run["results"]) == 3
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {
        "aws-access-key-id",
        "stripe-secret-key",
        "generic-high-entropy-secret",
    }
    # Each result carries a SARIF level and a physical location.
    for res in run["results"]:
        assert res["level"] in {"error", "warning", "note"}
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1


def test_sarif_listed_in_help():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "sarif" in result.stdout


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


# --- --fail-on CI gating ----------------------------------------------------


def test_fail_on_listed_in_help():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--fail-on" in result.stdout


def test_no_fail_on_exits_zero_despite_findings():
    # Default behaviour is unchanged: a scan with findings still exits 0 when
    # --fail-on is not supplied, so existing pipelines are not broken.
    result = _run_cli(["--repo-path", LEAKY, "--format", "json", "--no-allowlist"])
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 3


def test_fail_on_critical_exits_three():
    # The fixture contains critical-severity findings (AWS + Stripe keys), so a
    # --fail-on critical gate trips and returns the dedicated exit code 3.
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist",
         "--fail-on", "critical"]
    )
    assert result.returncode == 3
    # The machine-readable report is still emitted before the non-zero exit so
    # CI can capture it.
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 3
    assert "fail-on" in result.stderr.lower()


def test_fail_on_low_trips_on_any_finding():
    # The least-severe threshold catches every finding present.
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist",
         "--fail-on", "low"]
    )
    assert result.returncode == 3


def test_fail_on_does_not_count_suppressed_findings(tmp_path):
    # Findings removed by the allowlist must not trip the gate. Suppress every
    # planted secret via a user allowlist; with nothing surviving, even the
    # strictest --fail-on returns 0 — proving the scan ran and the gate was
    # evaluated against the post-allowlist finding set.
    allow = tmp_path / "allow.toml"
    allow.write_text('regexes = [".*"]\n', encoding="utf-8")
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--allowlist", str(allow),
         "--fail-on", "critical"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0


def test_fail_on_rejects_unknown_severity():
    result = _run_cli(
        ["--repo-path", LEAKY, "--fail-on", "bogus"]
    )
    # argparse rejects an out-of-choice value with its usage error (exit 2),
    # never silently accepting an unknown threshold.
    assert result.returncode != 0
    assert "fail-on" in result.stderr.lower() or "invalid choice" in result.stderr.lower()
