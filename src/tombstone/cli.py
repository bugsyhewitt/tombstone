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
from .scanner import is_git_repo, scan_repo
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
        choices=["json", "h1md"],
        default="json",
        help="output format: json (default) or h1md (HackerOne markdown)",
    )
    parser.add_argument(
        "--pattern-set",
        choices=available_pattern_sets(),
        default="full",
        help="which detection rules to apply (default: full)",
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

    try:
        findings = scan_repo(args.repo_path, pattern_set=args.pattern_set)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(format_findings(findings, args.format))
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
