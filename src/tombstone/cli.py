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
from .patterns import available_pattern_sets
from .report import format_findings
from .scanner import is_git_repo, load_state, resolve_state_file, save_state, scan_repo
from .scope import check_scope, parse_scope_file

# Exit codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_OUT_OF_SCOPE = 2


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
        choices=["json", "h1md", "bcmd"],
        default="json",
        help=(
            "output format: json (default), h1md (HackerOne markdown), or "
            "bcmd (Bugcrowd markdown)"
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
        "--version",
        action="version",
        version=f"tombstone {__version__}",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Persist HEAD SHA for future incremental runs.
    if args.save_state:
        try:
            saved = save_state(state_path, args.repo_path)
            print(f"state saved: {saved} → {state_path}", file=sys.stderr)
        except ValueError as exc:
            print(f"warning: could not save state: {exc}", file=sys.stderr)

    print(format_findings(findings, args.format))
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
