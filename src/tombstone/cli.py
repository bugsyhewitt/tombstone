"""tombstone command-line interface.

Offensive-side credential extraction for bug-bounty engagements. Scans the full
git history of a target repository and emits structured findings. Honors
H1/Bugcrowd scope enforcement: when a scope file is supplied, repositories
outside scope are refused.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from . import __version__
from .allowlist import default_allowlist, load_allowlist
from .github_org import (
    DEFAULT_WORKERS,
    build_allowlist,
    format_org_results,
    gating_findings,
    load_scope_entries,
    resolve_token,
    scan_org,
)
from .patterns import available_pattern_sets
from .report import format_findings
from .scanner import (
    DEFAULT_WORKERS,
    is_git_repo,
    load_state,
    resolve_state_file,
    save_state,
    scan_repo,
)
from .scope import check_scope, parse_scope_file
from .severity import SEVERITY_CHOICES, meets_threshold

# Exit codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_OUT_OF_SCOPE = 2
# Returned when --fail-on is set and at least one surviving finding is at or
# above the requested severity threshold. Lets tombstone gate a CI pipeline:
# the scan succeeded (distinct from EXIT_ERROR) but the policy was violated.
EXIT_FINDINGS = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tombstone",
        description=(
            "Offensive-side credential extraction for bug-bounty engagements. "
            "Scans git history for leaked credentials with scope enforcement."
        ),
    )
    parser.add_argument(
        "--repo-path",
        required=True,
        help="path to the target git repository to scan",
    )
    parser.add_argument(
        "--scope-file",
        default=None,
        help=(
            "path to a bug-bounty scope file; when supplied, repos outside "
            "scope are refused (one in-scope identifier per line, # comments)"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["json", "h1md", "bcmd", "sarif"],
        default="json",
        help=(
            "output format: json (default), h1md (HackerOne markdown), "
            "bcmd (Bugcrowd markdown), or sarif (SARIF 2.1.0 for GitHub code "
            "scanning / CI dashboards)"
        ),
    )
    parser.add_argument(
        "--pattern-set",
        choices=available_pattern_sets(),
        default="full",
        help="which detection rules to apply (default: full)",
    )
    parser.add_argument(
        "--include-worktree",
        action="store_true",
        default=False,
        help=(
            "also scan the working tree (uncommitted files), not just git "
            "history. Catches credentials present only in the working copy "
            "(e.g. a stray .env). Findings are deduplicated against history."
        ),
    )
    parser.add_argument(
        "--workflow-scan",
        action="store_true",
        default=False,
        help=(
            "also flag GitHub Actions workflow files "
            "(.github/workflows/*.yml) for secret-exposure anti-patterns: a "
            "${{ secrets.X }} interpolated into a shell command, or an echo of "
            "a secret-derived variable — both leak the secret into the run "
            "log. Emitted under the 'workflow-secret-exposure' rule."
        ),
    )
    parser.add_argument(
        "--since",
        default=None,
        metavar="REF",
        help=(
            "restrict scanning to commits reachable from HEAD but not from REF "
            "(equivalent to `git log REF..HEAD`). Useful for incremental rescans."
        ),
    )
    parser.add_argument(
        "--until",
        default=None,
        metavar="REF",
        help=(
            "restrict scanning to commits up to and including REF "
            "(equivalent to `git log REF`). Combine with --since for a range."
        ),
    )
    parser.add_argument(
        "--save-state",
        action="store_true",
        default=False,
        help=(
            "after scanning, write HEAD's SHA to the state file so the next "
            "run with --load-state automatically rescans only new commits."
        ),
    )
    parser.add_argument(
        "--load-state",
        action="store_true",
        default=False,
        help=(
            "before scanning, read the SHA from the state file and use it as "
            "--since (only new commits since the last saved state are scanned)."
        ),
    )
    parser.add_argument(
        "--state-file",
        default=None,
        metavar="PATH",
        help=(
            f"path to the state file (default: <repo-path>/.tombstone-state). "
            "Used by --save-state and --load-state."
        ),
    )
    parser.add_argument(
        "--allowlist",
        default=None,
        metavar="FILE",
        help=(
            "path to a TOML allowlist file suppressing known test credentials. "
            "Supports 'secrets = [...]' (exact, case-insensitive) and "
            "'regexes = [...]'. Merged with the built-in default allowlist "
            "unless --no-allowlist is given."
        ),
    )
    parser.add_argument(
        "--no-allowlist",
        action="store_true",
        default=False,
        help=(
            "disable all suppression, including the built-in default allowlist "
            "of well-known test credentials (AWS EXAMPLE key, sk_test_ keys, "
            "PLACEHOLDER/CHANGEME/DUMMY). Reports every match verbatim."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=(
            "number of threads used to scan blobs in parallel "
            f"(default: {DEFAULT_WORKERS}, capped at CPU count). Speeds up large "
            "repos; results are identical regardless of worker count. Use 1 to "
            "force a single-threaded scan."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_CHOICES),
        default=None,
        metavar="SEVERITY",
        help=(
            "exit with code 3 if any reported finding is at or above this "
            "severity (critical > high > medium > low). Off by default — the "
            "scan always exits 0 unless this is set. Use in CI to fail a build "
            "on leaked credentials, e.g. --fail-on high. Findings suppressed by "
            "the allowlist do not count toward the gate."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"tombstone {__version__}",
    )
    return parser


def build_gh_org_parser() -> argparse.ArgumentParser:
    """Build the parser for the ``tombstone gh-org <org>`` subcommand.

    Enumerates every repo in a GitHub org, clones each, and runs the same scan
    logic as a single-repo run. Honours --include-worktree, --allowlist, and a
    --scope-file; out-of-scope repos are skipped before any clone happens.
    """
    parser = argparse.ArgumentParser(
        prog="tombstone gh-org",
        description=(
            "Enumerate all repositories in a GitHub organization and scan each "
            "for leaked credentials. Aggregates per-repo findings into a single "
            "JSON envelope with a summary."
        ),
    )
    parser.add_argument("org", help="GitHub organization name to enumerate and scan")
    parser.add_argument(
        "--github-token",
        default=None,
        metavar="TOKEN",
        help=(
            "GitHub token for API enumeration and cloning private repos. "
            "Defaults to the GITHUB_TOKEN environment variable when unset."
        ),
    )
    parser.add_argument(
        "--scope-file",
        default=None,
        help=(
            "path to a bug-bounty scope file; discovered repos whose clone URL "
            "matches no in-scope entry are skipped (never cloned)."
        ),
    )
    parser.add_argument(
        "--pattern-set",
        choices=available_pattern_sets(),
        default="full",
        help="which detection rules to apply (default: full)",
    )
    parser.add_argument(
        "--include-worktree",
        action="store_true",
        default=False,
        help="also scan each clone's working tree, not just git history.",
    )
    parser.add_argument(
        "--allowlist",
        default=None,
        metavar="FILE",
        help=(
            "path to a TOML allowlist file suppressing known test credentials, "
            "merged with the built-in default allowlist."
        ),
    )
    parser.add_argument(
        "--no-allowlist",
        action="store_true",
        default=False,
        help="disable all suppression, including the built-in default allowlist.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=(
            f"number of repos to scan in parallel (default: {DEFAULT_WORKERS})."
        ),
    )
    parser.add_argument(
        "--include-archived",
        action="store_true",
        default=False,
        help="also scan archived repositories (skipped by default).",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_CHOICES),
        default=None,
        metavar="SEVERITY",
        help=(
            "exit with code 3 if any finding in any scanned repo is at or above "
            "this severity (critical > high > medium > low). Off by default — "
            "the sweep always exits 0 unless this is set. Use in CI to fail an "
            "org-wide sweep on a leaked credential, e.g. --fail-on high. "
            "Findings suppressed by the allowlist, and repos skipped or errored, "
            "do not count toward the gate."
        ),
    )
    return parser


def run_gh_org(argv: Sequence[str]) -> int:
    """Handle the ``gh-org`` subcommand."""
    parser = build_gh_org_parser()
    args = parser.parse_args(argv)

    if args.workers < 1:
        print("error: --workers must be >= 1", file=sys.stderr)
        return EXIT_ERROR

    token = resolve_token(args.github_token)

    try:
        allowlist = build_allowlist(args.allowlist, args.no_allowlist)
    except ValueError as exc:
        print(f"error: allowlist: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        scope_entries = load_scope_entries(args.scope_file)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.allowlist and args.no_allowlist:
        print(
            "warning: --allowlist ignored because --no-allowlist was also given",
            file=sys.stderr,
        )

    try:
        results = scan_org(
            args.org,
            token=token,
            pattern_set=args.pattern_set,
            include_worktree=args.include_worktree,
            allowlist=allowlist,
            scope_entries=scope_entries,
            workers=args.workers,
            include_archived=args.include_archived,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(format_org_results(args.org, results))

    # CI gating: with --fail-on, return EXIT_FINDINGS (3) when any finding in any
    # scanned repo meets the severity threshold. The aggregated JSON envelope is
    # emitted first so the pipeline can still capture the full report before the
    # non-zero exit aborts the build. Mirrors the single-repo --fail-on gate.
    if args.fail_on:
        gating = gating_findings(results, args.fail_on)
        if gating:
            print(
                f"fail-on: {len(gating)} finding"
                f"{'s' if len(gating) != 1 else ''} at or above severity "
                f"'{args.fail_on}' across the org — exiting {EXIT_FINDINGS}",
                file=sys.stderr,
            )
            return EXIT_FINDINGS

    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)

    # Subcommand routing: the first positional token selects a mode. The legacy
    # flat invocation (`tombstone --repo-path ...`) is preserved as the default
    # so the v0.1 interface keeps working unchanged.
    if args_list and args_list[0] == "gh-org":
        return run_gh_org(args_list[1:])

    parser = build_parser()
    args = parser.parse_args(args_list)

    # Scope enforcement happens BEFORE any scanning.
    if args.scope_file:
        try:
            scope_entries = parse_scope_file(args.scope_file)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        decision = check_scope(args.repo_path, scope_entries)
        if not decision.in_scope:
            print(
                f"out of scope: {decision.reason}",
                file=sys.stderr,
            )
            print(
                f"refusing to scan '{args.repo_path}' — not in bug-bounty scope.",
                file=sys.stderr,
            )
            return EXIT_OUT_OF_SCOPE

    if args.workers < 1:
        print("error: --workers must be >= 1", file=sys.stderr)
        return EXIT_ERROR

    if not is_git_repo(args.repo_path):
        print(
            f"error: not a git repository: {args.repo_path}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Resolve the effective --since refspec, honouring --load-state.
    since_ref = args.since
    state_path = resolve_state_file(args.repo_path, args.state_file)
    if args.load_state:
        loaded = load_state(state_path)
        if loaded:
            if since_ref:
                # --since takes precedence; --load-state is a no-op here.
                print(
                    f"warning: --load-state ignored because --since was also given",
                    file=sys.stderr,
                )
            else:
                since_ref = loaded

    try:
        findings = scan_repo(
            args.repo_path,
            pattern_set=args.pattern_set,
            since=since_ref,
            until=args.until,
            include_worktree=args.include_worktree,
            workers=args.workers,
            workflow_scan=args.workflow_scan,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Apply suppression allowlist (built-in default + optional user file).
    # --no-allowlist disables suppression entirely so every match is reported.
    if not args.no_allowlist:
        try:
            if args.allowlist:
                allowlist = load_allowlist(args.allowlist, include_default=True)
            else:
                allowlist = default_allowlist()
        except ValueError as exc:
            print(f"error: allowlist: {exc}", file=sys.stderr)
            return EXIT_ERROR
        before = len(findings)
        findings = allowlist.filter_findings(findings)
        suppressed = before - len(findings)
        if suppressed:
            print(
                f"allowlist: suppressed {suppressed} known test credential"
                f"{'s' if suppressed != 1 else ''}",
                file=sys.stderr,
            )
    elif args.allowlist:
        print(
            "warning: --allowlist ignored because --no-allowlist was also given",
            file=sys.stderr,
        )

    # Persist HEAD SHA for future incremental runs.
    if args.save_state:
        try:
            saved = save_state(state_path, args.repo_path)
            print(f"state saved: {saved} → {state_path}", file=sys.stderr)
        except ValueError as exc:
            print(f"warning: could not save state: {exc}", file=sys.stderr)

    print(format_findings(findings, args.format))

    # CI gating: with --fail-on, return a dedicated exit code when any surviving
    # finding (post-allowlist) meets the severity threshold. The formatted output
    # is emitted first so the pipeline can still capture the report before the
    # non-zero exit aborts the build.
    if args.fail_on:
        gating = [f for f in findings if meets_threshold(f.severity, args.fail_on)]
        if gating:
            print(
                f"fail-on: {len(gating)} finding"
                f"{'s' if len(gating) != 1 else ''} at or above severity "
                f"'{args.fail_on}' — exiting {EXIT_FINDINGS}",
                file=sys.stderr,
            )
            return EXIT_FINDINGS

    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
