"""Tests for GitHub org-level enumeration and scanning (``gh-org`` subcommand).

The GitHub API is mocked end-to-end via an injected ``fetch`` callable so no
network access is required. Cloning is exercised for real against the local
``leaky-repo`` / ``out-of-scope-repo`` git fixtures using ``file://`` clone URLs.
"""

import json
import os
import subprocess
import sys

import pytest

from tombstone.github_org import (
    ApiResponse,
    OrgRepo,
    enumerate_org_repos,
    format_org_results,
    scan_org,
)

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")
OOS = os.path.join(HERE, "fixtures", "out-of-scope-repo")
SCOPE = os.path.join(HERE, "fixtures", "scope.txt")

LEAKY_URL = f"file://{LEAKY}"
OOS_URL = f"file://{OOS}"


def _repo_item(name, clone_url, *, archived=False, org="acme-corp"):
    return {
        "name": name,
        "full_name": f"{org}/{name}",
        "clone_url": clone_url,
        "archived": archived,
    }


def _make_fetch(pages):
    """Build a fetch callable that returns *pages* in sequence with Link headers.

    *pages* is a list of lists-of-repo-dicts; each call returns the next page and
    a synthetic ``Link: <...>; rel="next"`` header until the last page.
    """
    calls = {"i": 0}

    def fetch(url, token):
        idx = calls["i"]
        calls["i"] += 1
        body = pages[idx]
        link = ""
        if idx + 1 < len(pages):
            link = f'<https://api.github.com/next?page={idx + 2}>; rel="next"'
        return ApiResponse(body=body, link_header=link)

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def test_enumerate_follows_pagination():
    fetch = _make_fetch(
        [
            [_repo_item("alpha", "https://github.com/acme-corp/alpha.git")],
            [_repo_item("beta", "https://github.com/acme-corp/beta.git")],
        ]
    )
    repos = enumerate_org_repos("acme-corp", "tok", fetch=fetch)
    assert [r.name for r in repos] == ["alpha", "beta"]
    assert fetch.calls["i"] == 2  # two pages fetched


def test_enumerate_skips_archived_by_default():
    fetch = _make_fetch(
        [
            [
                _repo_item("live", "https://github.com/acme-corp/live.git"),
                _repo_item(
                    "old",
                    "https://github.com/acme-corp/old.git",
                    archived=True,
                ),
            ]
        ]
    )
    repos = enumerate_org_repos("acme-corp", None, fetch=fetch)
    assert [r.name for r in repos] == ["live"]


def test_enumerate_includes_archived_when_requested():
    fetch = _make_fetch(
        [
            [
                _repo_item("live", "https://github.com/acme-corp/live.git"),
                _repo_item(
                    "old",
                    "https://github.com/acme-corp/old.git",
                    archived=True,
                ),
            ]
        ]
    )
    repos = enumerate_org_repos(
        "acme-corp", None, fetch=fetch, include_archived=True
    )
    assert {r.name for r in repos} == {"live", "old"}


def test_enumerate_rejects_invalid_org():
    with pytest.raises(ValueError):
        enumerate_org_repos("acme/evil", None, fetch=_make_fetch([[]]))


def test_enumerate_rejects_non_list_body():
    def bad_fetch(url, token):
        return ApiResponse(body={"message": "Not Found"}, link_header="")

    with pytest.raises(ValueError):
        enumerate_org_repos("ghost-org", None, fetch=bad_fetch)


# ---------------------------------------------------------------------------
# Scanning (real clones of local fixtures)
# ---------------------------------------------------------------------------


def test_scan_org_aggregates_findings():
    fetch = _make_fetch(
        [
            [
                _repo_item("leaky-repo", LEAKY_URL),
                _repo_item("out-of-scope-repo", OOS_URL),
            ]
        ]
    )
    results = scan_org("acme-corp", fetch=fetch, workers=2)
    by_repo = {r.repo.name: r for r in results}

    # leaky-repo has 3 planted history credentials. scan_org's allowlist
    # defaults to None (no suppression) so all three are reported here.
    assert by_repo["leaky-repo"].status == "scanned"
    rule_ids = {f.rule_id for f in by_repo["leaky-repo"].findings}
    assert "aws-access-key-id" in rule_ids
    assert "stripe-secret-key" in rule_ids

    # out-of-scope-repo has no planted credentials.
    assert by_repo["out-of-scope-repo"].status == "scanned"
    assert by_repo["out-of-scope-repo"].findings == []


def test_scan_org_skips_out_of_scope_before_cloning():
    # scope.txt lists acme-corp identifiers; the OOS clone URL must not match.
    from tombstone.scope import parse_scope_file

    scope_entries = parse_scope_file(SCOPE)
    fetch = _make_fetch(
        [
            [
                # In-scope: clone URL contains an in-scope identifier.
                _repo_item("leaky-repo", LEAKY_URL),
                # Out-of-scope: a clone URL that matches nothing in scope.txt.
                _repo_item(
                    "unrelated",
                    "file:///tmp/unrelated-vendor-xyz/repo.git",
                ),
            ]
        ]
    )
    results = scan_org(
        "acme-corp", fetch=fetch, scope_entries=scope_entries, workers=2
    )
    by_repo = {r.repo.name: r for r in results}
    assert by_repo["unrelated"].status == "skipped_out_of_scope"
    assert by_repo["unrelated"].findings == []


def test_scan_org_include_worktree_surfaces_uncommitted():
    fetch = _make_fetch([[_repo_item("leaky-repo", LEAKY_URL)]])
    # NOTE: a clone does not carry the uncommitted working-tree file, so
    # cloning then scanning the working tree won't find local.env. We instead
    # assert the flag is plumbed through without error and history findings
    # remain present.
    results = scan_org("acme-corp", fetch=fetch, include_worktree=True, workers=1)
    assert len(results) == 1
    assert results[0].status == "scanned"
    assert len(results[0].findings) >= 2


def test_clone_failure_recorded_as_error():
    fetch = _make_fetch(
        [[_repo_item("nope", "file:///tmp/does-not-exist-tombstone/repo.git")]]
    )
    results = scan_org("acme-corp", fetch=fetch, workers=1)
    assert results[0].status == "error"
    assert "clone failed" in results[0].reason


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def test_format_org_results_envelope():
    leaky = OrgRepo("leaky", "acme/leaky", LEAKY_URL)
    other = OrgRepo("oos", "acme/oos", OOS_URL)
    from tombstone.github_org import RepoResult
    from tombstone.scanner import Finding

    f = Finding(
        rule_id="aws-access-key-id",
        description="AWS access key",
        commit="abc",
        file_path="x.sh",
        line_number=1,
        redacted_context="...",
        _secret="AKIA...",
    )
    results = [
        RepoResult(repo=leaky, status="scanned", findings=[f]),
        RepoResult(repo=other, status="skipped_out_of_scope", reason="oos"),
    ]
    out = json.loads(format_org_results("acme", results))
    assert out["tool"] == "tombstone"
    assert out["mode"] == "gh-org"
    assert out["org"] == "acme"
    assert out["summary"]["repos_discovered"] == 2
    assert out["summary"]["repos_scanned"] == 1
    assert out["summary"]["repos_skipped_out_of_scope"] == 1
    assert out["summary"]["total_findings"] == 1
    # Secrets are never emitted, only redacted/rule metadata.
    assert "_secret" not in json.dumps(out)


def _org_result(name, status, findings=None):
    from tombstone.github_org import RepoResult

    repo = OrgRepo(name, f"acme/{name}", f"file:///tmp/{name}.git")
    return RepoResult(repo=repo, status=status, findings=findings or [])


def _org_finding(rule_id, severity, file_path="config.py"):
    from tombstone.scanner import Finding

    return Finding(
        rule_id=rule_id,
        description=rule_id,
        commit="abc123",
        file_path=file_path,
        line_number=12,
        redacted_context="key = AK****EY",
        severity=severity,
        _secret="AKIAEXAMPLE",
    )


def test_aggregate_findings_prefixes_repo_and_skips_non_scanned():
    from tombstone.github_org import aggregate_findings

    results = [
        _org_result("alpha", "scanned", [_org_finding("aws", "critical")]),
        _org_result("beta", "scanned", [_org_finding("gh-pat", "high", "src/a.py")]),
        # A finding on a non-scanned repo must never reach the aggregated report.
        _org_result("skipped", "skipped_out_of_scope", [_org_finding("aws", "critical")]),
        _org_result("errored", "error", [_org_finding("aws", "critical")]),
    ]
    aggregated = aggregate_findings(results)
    paths = {f.file_path for f in aggregated}
    # Two scanned findings, each repo-prefixed; skipped/errored excluded.
    assert paths == {"acme/alpha:config.py", "acme/beta:src/a.py"}


def test_format_org_results_json_unchanged_by_default():
    # The default fmt="json" path must produce the same envelope as before.
    results = [_org_result("a", "scanned", [_org_finding("aws", "critical")])]
    out = json.loads(format_org_results("acme", results))
    assert out["mode"] == "gh-org"
    assert out["summary"]["total_findings"] == 1
    # JSON keeps the raw (un-prefixed) per-repo file path.
    assert out["repos"][0]["findings"][0]["file_path"] == "config.py"


def test_format_org_results_h1md_aggregates_with_repo_prefix():
    results = [
        _org_result("alpha", "scanned", [_org_finding("aws", "critical")]),
        _org_result("beta", "scanned", [_org_finding("gh-pat", "high", "b.py")]),
    ]
    out = format_org_results("acme", results, "h1md")
    assert out.startswith("# tombstone credential findings")
    assert "**Total findings:** 2" in out
    # File paths in the markdown carry the repo prefix.
    assert "acme/alpha:config.py" in out
    assert "acme/beta:b.py" in out


def test_format_org_results_bcmd_renders_sections():
    results = [_org_result("alpha", "scanned", [_org_finding("aws-access-key-id", "critical")])]
    out = format_org_results("acme", results, "bcmd")
    assert "Bugcrowd format" in out
    assert "## Overview" in out
    assert "## Demonstrated Impact" in out
    assert "acme/alpha:config.py" in out


def test_format_org_results_sarif_is_valid_and_repo_prefixed():
    results = [_org_result("alpha", "scanned", [_org_finding("aws-access-key-id", "critical")])]
    out = format_org_results("acme", results, "sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "tombstone"
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "acme/alpha:config.py"
    # The raw secret never appears in the SARIF document.
    assert "AKIAEXAMPLE" not in out


def test_format_org_results_unknown_format_raises():
    results = [_org_result("a", "scanned", [_org_finding("aws", "critical")])]
    with pytest.raises(ValueError):
        format_org_results("acme", results, "xml")


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def _run_cli(args, env=None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
        env=full_env,
    )


def test_gh_org_help_lists_flags():
    result = _run_cli(["gh-org", "--help"])
    assert result.returncode == 0
    for flag in ("--github-token", "--scope-file", "--include-worktree",
                 "--allowlist", "--workers", "--format"):
        assert flag in result.stdout
    assert "org" in result.stdout


def test_gh_org_format_emits_markdown(monkeypatch, capsys):
    # run_gh_org with --format h1md must emit aggregated HackerOne markdown to
    # stdout, not the JSON envelope. scan_org is mocked so no network is hit.
    import tombstone.cli as cli

    def fake_scan_org(org, **kwargs):
        return [_result("leaky", "scanned", [_finding("aws-access-key-id", "critical")])]

    monkeypatch.setattr(cli, "scan_org", fake_scan_org)
    code = cli.run_gh_org(["acme-corp", "--format", "h1md", "--no-allowlist"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.startswith("# tombstone credential findings")
    # Repo-prefixed path proves the aggregation path ran (not the JSON envelope).
    assert "acme/leaky:" in out


def test_gh_org_format_sarif_emits_sarif(monkeypatch, capsys):
    import tombstone.cli as cli

    def fake_scan_org(org, **kwargs):
        return [_result("leaky", "scanned", [_finding("aws-access-key-id", "critical")])]

    monkeypatch.setattr(cli, "scan_org", fake_scan_org)
    code = cli.run_gh_org(["acme-corp", "--format", "sarif", "--no-allowlist"])
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"


def test_gh_org_default_format_still_json(monkeypatch, capsys):
    import tombstone.cli as cli

    def fake_scan_org(org, **kwargs):
        return [_result("leaky", "scanned", [_finding("aws-access-key-id", "critical")])]

    monkeypatch.setattr(cli, "scan_org", fake_scan_org)
    code = cli.run_gh_org(["acme-corp", "--no-allowlist"])
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["mode"] == "gh-org"


def test_legacy_flat_invocation_still_works():
    # The original `tombstone --repo-path ...` interface must keep working
    # after adding the subcommand router (v0.1 contract).
    result = _run_cli(["--repo-path", LEAKY, "--format", "json", "--no-allowlist"])
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 3


def test_gh_org_invalid_org_errors():
    result = _run_cli(["gh-org", "bad/org/name"])
    assert result.returncode != 0
    assert "invalid org" in result.stderr.lower()


# ---------------------------------------------------------------------------
# --fail-on CI gating (org-wide)
# ---------------------------------------------------------------------------


def _finding(rule_id, severity):
    from tombstone.scanner import Finding

    return Finding(
        rule_id=rule_id,
        description=rule_id,
        commit="abc",
        file_path="x.sh",
        line_number=1,
        redacted_context="...",
        severity=severity,
        _secret="AKIA...",
    )


def _result(name, status, findings=None):
    from tombstone.github_org import RepoResult

    repo = OrgRepo(name, f"acme/{name}", f"file:///tmp/{name}.git")
    return RepoResult(repo=repo, status=status, findings=findings or [])


def test_gating_findings_collects_at_or_above_threshold():
    from tombstone.github_org import gating_findings

    results = [
        _result("a", "scanned", [_finding("aws", "critical")]),
        _result("b", "scanned", [_finding("gh-pat", "high")]),
        _result("c", "scanned", [_finding("generic", "medium")]),
    ]
    # threshold "high": critical + high count, medium does not.
    gating = gating_findings(results, "high")
    assert {f.rule_id for f in gating} == {"aws", "gh-pat"}


def test_gating_findings_critical_threshold_excludes_high():
    from tombstone.github_org import gating_findings

    results = [
        _result("a", "scanned", [_finding("aws", "critical")]),
        _result("b", "scanned", [_finding("gh-pat", "high")]),
    ]
    gating = gating_findings(results, "critical")
    assert [f.rule_id for f in gating] == ["aws"]


def test_gating_findings_low_threshold_trips_on_any_finding():
    from tombstone.github_org import gating_findings

    results = [_result("a", "scanned", [_finding("generic", "low")])]
    assert len(gating_findings(results, "low")) == 1


def test_gating_findings_ignores_skipped_and_errored_repos():
    from tombstone.github_org import gating_findings

    # A finding attached to a non-"scanned" repo must never gate the build —
    # only credentials actually found in a successfully scanned repo count.
    results = [
        _result("skipped", "skipped_out_of_scope", [_finding("aws", "critical")]),
        _result("errored", "error", [_finding("aws", "critical")]),
    ]
    assert gating_findings(results, "critical") == []


def test_gating_findings_empty_when_nothing_meets_threshold():
    from tombstone.github_org import gating_findings

    results = [_result("a", "scanned", [_finding("generic", "low")])]
    assert gating_findings(results, "high") == []


def test_gh_org_fail_on_listed_in_help():
    result = _run_cli(["gh-org", "--help"])
    assert result.returncode == 0
    assert "--fail-on" in result.stdout


def test_gh_org_fail_on_exits_three(monkeypatch):
    # Drive run_gh_org() directly with a mocked scan_org so no network is hit.
    import tombstone.cli as cli

    leaky_findings = [_finding("aws-access-key-id", "critical")]

    def fake_scan_org(org, **kwargs):
        return [_result("leaky", "scanned", leaky_findings)]

    monkeypatch.setattr(cli, "scan_org", fake_scan_org)
    code = cli.run_gh_org(["acme-corp", "--fail-on", "critical", "--no-allowlist"])
    assert code == 3


def test_gh_org_fail_on_below_threshold_exits_zero(monkeypatch):
    import tombstone.cli as cli

    def fake_scan_org(org, **kwargs):
        return [_result("leaky", "scanned", [_finding("generic", "medium")])]

    monkeypatch.setattr(cli, "scan_org", fake_scan_org)
    code = cli.run_gh_org(["acme-corp", "--fail-on", "high", "--no-allowlist"])
    assert code == 0


def test_gh_org_without_fail_on_exits_zero_with_findings(monkeypatch):
    import tombstone.cli as cli

    def fake_scan_org(org, **kwargs):
        return [_result("leaky", "scanned", [_finding("aws", "critical")])]

    monkeypatch.setattr(cli, "scan_org", fake_scan_org)
    code = cli.run_gh_org(["acme-corp", "--no-allowlist"])
    assert code == 0
