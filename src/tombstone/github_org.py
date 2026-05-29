"""GitHub org-level enumeration and scanning.

Turns tombstone from a single-repo tool into an org-sweep tool. The ``gh-org``
subcommand:

1. enumerates every repository in a target GitHub organization via the GitHub
   REST API (paginated),
2. (optionally) enforces a bug-bounty scope file against each repo's clone URL,
3. clones each in-scope repo to a temporary directory,
4. runs tombstone's existing :func:`~tombstone.scanner.scan_repo` logic against
   it (honouring ``--include-worktree`` and the allowlist), and
5. aggregates per-repo findings into a single JSON envelope with a summary.

Repos are scanned in parallel with a thread pool (default 4 workers). Cloning
and the GitHub API both honour ``GITHUB_TOKEN`` (or an explicit ``--github-token``).

[Worker decision: API injection for testability] The enumeration step is split
from the network call so tests can supply a mock ``fetch`` callable returning
canned GitHub API pages without hitting the network. The default fetch uses the
stdlib ``urllib`` — no new third-party dependency is introduced.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

from git import Repo
from git.exc import GitError

from .allowlist import Allowlist, default_allowlist, load_allowlist
from .scanner import Finding, scan_repo
from .scope import ScopeDecision, check_scope, parse_scope_file
from .severity import meets_threshold

GITHUB_API_ROOT = "https://api.github.com"
DEFAULT_WORKERS = 4
DEFAULT_PER_PAGE = 100

# A callable that takes a URL + optional token and returns the decoded JSON body
# plus the Link header (for pagination). Injected so tests can avoid the network.
FetchFn = Callable[[str, Optional[str]], "ApiResponse"]


@dataclass(frozen=True)
class ApiResponse:
    """Decoded GitHub API response: parsed JSON body and the raw Link header."""

    body: object
    link_header: str = ""


@dataclass(frozen=True)
class OrgRepo:
    """A repository discovered in an organization."""

    name: str
    full_name: str
    clone_url: str
    archived: bool = False


@dataclass
class RepoResult:
    """Outcome of scanning a single org repository."""

    repo: OrgRepo
    status: str  # "scanned" | "skipped_out_of_scope" | "error"
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "repo": self.repo.full_name,
            "clone_url": self.repo.clone_url,
            "status": self.status,
            "reason": self.reason,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# GitHub API enumeration
# ---------------------------------------------------------------------------


def _default_fetch(url: str, token: Optional[str]) -> ApiResponse:
    """Fetch *url* from the GitHub API using the stdlib, returning JSON + Link."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "tombstone",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request) as response:  # nosec B310 - https only
            raw = response.read().decode("utf-8")
            link = response.headers.get("Link", "") or ""
    except urllib.error.HTTPError as exc:  # pragma: no cover - network failure path
        detail = exc.read().decode("utf-8", "replace") if exc.fp else ""
        raise ValueError(
            f"GitHub API error {exc.code} for {url}: {detail.strip() or exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:  # pragma: no cover - network failure path
        raise ValueError(f"GitHub API request failed for {url}: {exc.reason}") from exc
    return ApiResponse(body=json.loads(raw), link_header=link)


def _next_link(link_header: str) -> Optional[str]:
    """Extract the ``rel="next"`` URL from a GitHub ``Link`` header, if any."""
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        url = section[0].strip().strip("<>")
        for param in section[1:]:
            if param.strip() == 'rel="next"':
                return url
    return None


def enumerate_org_repos(
    org: str,
    token: Optional[str] = None,
    *,
    fetch: FetchFn = _default_fetch,
    per_page: int = DEFAULT_PER_PAGE,
    include_archived: bool = False,
) -> list[OrgRepo]:
    """Enumerate all repositories in *org* via the GitHub REST API.

    Follows ``Link``-header pagination until exhausted. Archived repositories
    are skipped unless *include_archived* is True (archived repos are read-only
    but their history is still scannable — surfaced behind a flag to keep the
    default sweep focused on live targets).
    """
    if not org or "/" in org:
        raise ValueError(f"invalid org name: {org!r}")
    url: Optional[str] = (
        f"{GITHUB_API_ROOT}/orgs/{org}/repos?per_page={per_page}&type=all"
    )
    repos: list[OrgRepo] = []
    while url:
        response = fetch(url, token)
        body = response.body
        if not isinstance(body, list):
            raise ValueError(
                f"unexpected GitHub API response for org '{org}': expected a list "
                f"of repositories"
            )
        for item in body:
            archived = bool(item.get("archived", False))
            if archived and not include_archived:
                continue
            clone_url = item.get("clone_url") or ""
            name = item.get("name") or ""
            full_name = item.get("full_name") or f"{org}/{name}"
            if not clone_url:
                continue
            repos.append(
                OrgRepo(
                    name=name,
                    full_name=full_name,
                    clone_url=clone_url,
                    archived=archived,
                )
            )
        url = _next_link(response.link_header)
    return repos


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _authenticated_clone_url(clone_url: str, token: Optional[str]) -> str:
    """Embed *token* into an https clone URL so private repos can be cloned."""
    if not token:
        return clone_url
    prefix = "https://"
    if clone_url.startswith(prefix):
        # x-access-token is the conventional username for a token-auth clone.
        return f"{prefix}x-access-token:{token}@{clone_url[len(prefix):]}"
    return clone_url


def _scan_one_repo(
    repo: OrgRepo,
    *,
    token: Optional[str],
    pattern_set: str,
    include_worktree: bool,
    allowlist: Optional[Allowlist],
    scope_entries: Optional[list[str]],
) -> RepoResult:
    """Clone and scan a single repo, returning a :class:`RepoResult`."""
    # Scope enforcement: validate the clone URL against the scope file before
    # we clone or scan anything. An out-of-scope repo is never fetched.
    if scope_entries:
        decision = _scope_check_url(repo.clone_url, scope_entries)
        if not decision.in_scope:
            return RepoResult(
                repo=repo,
                status="skipped_out_of_scope",
                reason=decision.reason,
            )

    tmpdir = tempfile.mkdtemp(prefix="tombstone-gh-")
    try:
        clone_url = _authenticated_clone_url(repo.clone_url, token)
        try:
            Repo.clone_from(clone_url, tmpdir)
        except GitError as exc:
            # Strip any embedded token from the error text before surfacing.
            msg = str(exc)
            if token:
                msg = msg.replace(token, "***")
            return RepoResult(
                repo=repo, status="error", reason=f"clone failed: {msg}"
            )
        try:
            findings = scan_repo(
                tmpdir,
                pattern_set=pattern_set,
                include_worktree=include_worktree,
            )
        except ValueError as exc:
            return RepoResult(repo=repo, status="error", reason=f"scan failed: {exc}")
        if allowlist is not None:
            findings = allowlist.filter_findings(findings)
        return RepoResult(repo=repo, status="scanned", findings=findings)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _scope_check_url(clone_url: str, scope_entries: list[str]) -> ScopeDecision:
    """Decide whether a clone URL is in scope (substring match, like check_scope)."""
    identifier = clone_url.lower()
    for entry in scope_entries:
        if entry in identifier:
            return ScopeDecision(True, f"matched scope entry '{entry}'")
    return ScopeDecision(
        False,
        "clone URL does not match any in-scope entry; "
        "refusing to clone out-of-scope target",
    )


def scan_org(
    org: str,
    *,
    token: Optional[str] = None,
    pattern_set: str = "full",
    include_worktree: bool = False,
    allowlist: Optional[Allowlist] = None,
    scope_entries: Optional[list[str]] = None,
    workers: int = DEFAULT_WORKERS,
    fetch: FetchFn = _default_fetch,
    include_archived: bool = False,
) -> list[RepoResult]:
    """Enumerate and scan every repository in *org*.

    Repos are scanned in parallel with a thread pool (``workers`` threads).
    Each repo is cloned to its own temp directory, scanned, and the clone is
    removed. Out-of-scope repos (when *scope_entries* is supplied) are skipped
    before any network clone happens.
    """
    repos = enumerate_org_repos(
        org, token, fetch=fetch, include_archived=include_archived
    )
    results: list[RepoResult] = []
    worker_count = max(1, min(workers, len(repos))) if repos else 1

    def _work(repo: OrgRepo) -> RepoResult:
        return _scan_one_repo(
            repo,
            token=token,
            pattern_set=pattern_set,
            include_worktree=include_worktree,
            allowlist=allowlist,
            scope_entries=scope_entries,
        )

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        results = list(pool.map(_work, repos))
    return results


def format_org_results(org: str, results: list[RepoResult]) -> str:
    """Serialize org-scan results to a single JSON envelope with a summary."""
    total_findings = sum(len(r.findings) for r in results)
    scanned = [r for r in results if r.status == "scanned"]
    skipped = [r for r in results if r.status == "skipped_out_of_scope"]
    errored = [r for r in results if r.status == "error"]
    payload = {
        "tool": "tombstone",
        "mode": "gh-org",
        "org": org,
        "summary": {
            "repos_discovered": len(results),
            "repos_scanned": len(scanned),
            "repos_skipped_out_of_scope": len(skipped),
            "repos_errored": len(errored),
            "total_findings": total_findings,
        },
        "repos": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2)


def gating_findings(
    results: list[RepoResult], threshold: str
) -> list[Finding]:
    """Return every finding across *results* at or above *threshold* severity.

    This is the org-wide analogue of the single-repo ``--fail-on`` gate: a CI
    pipeline running an org sweep should fail the build when *any* repo in the
    org leaks a credential at or above the requested severity. Only findings on
    ``status == "scanned"`` repos count — a clone error or an out-of-scope skip
    is an operational outcome, not a leaked-credential policy violation, and
    must not silently gate the build. Allowlist suppression has already been
    applied to each ``RepoResult.findings`` upstream in :func:`_scan_one_repo`,
    so suppressed test credentials never reach this gate.
    """
    gating: list[Finding] = []
    for result in results:
        if result.status != "scanned":
            continue
        gating.extend(
            f for f in result.findings if meets_threshold(f.severity, threshold)
        )
    return gating


def resolve_token(explicit: Optional[str]) -> Optional[str]:
    """Return the GitHub token: explicit flag wins, else ``GITHUB_TOKEN`` env."""
    if explicit:
        return explicit
    return os.environ.get("GITHUB_TOKEN") or None


def build_allowlist(
    allowlist_path: Optional[str], no_allowlist: bool
) -> Optional[Allowlist]:
    """Construct the effective allowlist for an org scan (or None to disable)."""
    if no_allowlist:
        return None
    if allowlist_path:
        return load_allowlist(allowlist_path, include_default=True)
    return default_allowlist()


def load_scope_entries(scope_file: Optional[str]) -> Optional[list[str]]:
    """Parse a scope file into entries, or return None when no file is given."""
    if not scope_file:
        return None
    return parse_scope_file(scope_file)
