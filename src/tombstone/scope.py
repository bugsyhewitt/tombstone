"""Bug-bounty scope enforcement.

[Worker decision: scope-file format] The orchestrator did not specify a scope
file schema beyond "tier-aware scope checking". We use a simple, auditable
line-based format compatible with quick copy-paste from H1/Bugcrowd scope
tables:

    # comments start with hash, blank lines ignored
    github.com/acme-corp        # an in-scope GitHub org or repo URL fragment
    acme-corp                   # a bare org/identifier
    backups.acme.internal       # an in-scope artifact host

A repository is in scope when any non-comment scope entry is a substring of the
repository's resolved identifier (its absolute path and, if present, its git
`origin` remote URL). This is intentionally conservative: if no scope file is
supplied, scanning is unrestricted (operator's responsibility); if a scope file
IS supplied, anything not explicitly listed is refused.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from git import Repo
from git.exc import GitError


@dataclass(frozen=True)
class ScopeDecision:
    in_scope: bool
    reason: str


def parse_scope_file(path: str) -> list[str]:
    """Parse a scope file into a list of in-scope identifiers."""
    if not os.path.isfile(path):
        raise ValueError(f"scope file not found: {path}")
    entries: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if line:
                entries.append(line.lower())
    return entries


def _repo_identifiers(repo_path: str) -> list[str]:
    """Return identifiers used to match a repo against scope entries."""
    identifiers = [os.path.abspath(repo_path).lower()]
    identifiers.append(os.path.basename(os.path.abspath(repo_path)).lower())
    try:
        repo = Repo(repo_path)
        for remote in repo.remotes:
            for url in remote.urls:
                identifiers.append(url.lower())
    except GitError:
        pass
    except Exception:  # pragma: no cover - defensive
        pass
    return identifiers


def check_scope(repo_path: str, scope_entries: list[str]) -> ScopeDecision:
    """Decide whether ``repo_path`` is permitted by ``scope_entries``."""
    if not scope_entries:
        return ScopeDecision(True, "no scope entries; scanning unrestricted")
    identifiers = _repo_identifiers(repo_path)
    for entry in scope_entries:
        for identifier in identifiers:
            if entry in identifier:
                return ScopeDecision(
                    True, f"matched scope entry '{entry}'"
                )
    return ScopeDecision(
        False,
        "repository does not match any in-scope entry; "
        "refusing to scan out-of-scope target",
    )
