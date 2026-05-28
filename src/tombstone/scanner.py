"""Git-history credential scanner.

Traverses every commit of a repository (and the working tree) using gitpython,
applies the active rule set to added/changed text, and emits deduplicated
findings with reproducibility evidence: commit hash, file path, line number,
and a redacted context line.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

from git import Repo
from git.exc import InvalidGitRepositoryError, NoSuchPathError

from .confidence import score_confidence
from .patterns import Rule, get_rules
from .severity import WORKFLOW_SEVERITY, rule_severity
from .workflow import (
    WORKFLOW_RULE_ID,
    is_workflow_file,
    redact_workflow_line,
    scan_workflow_text,
)

# Default state file name placed in the root of the scanned repo.
DEFAULT_STATE_FILENAME = ".tombstone-state"

# Default worker count for parallel blob scanning. A small pool is plenty:
# the work is a mix of git object reads (I/O-bound, releases the GIL) and regex
# scanning, and gitpython object access is not safe to oversubscribe. Capped at
# the CPU count so single-core boxes stay single-threaded.
DEFAULT_WORKERS = min(4, os.cpu_count() or 1)

# Synthetic commit identifier used for findings that come from the working tree
# rather than from a committed object. Reported in place of a real commit SHA so
# downstream consumers (JSON/h1md/bcmd) can distinguish uncommitted leaks.
WORKTREE_COMMIT = "WORKTREE"


@dataclass(frozen=True)
class Finding:
    """A single credential finding with reproducibility evidence."""

    rule_id: str
    description: str
    commit: str
    file_path: str
    line_number: int
    redacted_context: str
    # Confidence that this is a live credential: "high" | "medium" | "low".
    confidence: str = "high"
    # Severity of the leaked credential type, derived from the matched rule's
    # declared severity in necromancer-patterns: "critical" | "high" | "medium"
    # | "low". Tells a researcher what to prioritise (a critical AWS/GitHub key
    # before a medium generic match) independently of confidence.
    severity: str = "high"
    # The raw secret is kept internally for dedupe only; it is never emitted.
    _secret: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "commit": self.commit,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "redacted_context": self.redacted_context,
            "confidence": self.confidence,
            "severity": self.severity,
        }


def redact(line: str, secret: str) -> str:
    """Return ``line`` with ``secret`` replaced by a redacted token.

    The first and last two characters of the secret are preserved so an analyst
    can correlate the finding without exposing the credential.
    """
    line = line.rstrip("\n")
    if not secret:
        return line.strip()
    if len(secret) <= 4:
        masked = "*" * len(secret)
    else:
        masked = f"{secret[:2]}{'*' * (len(secret) - 4)}{secret[-2:]}"
    return line.replace(secret, masked).strip()


def _iter_text_lines(blob_data: bytes) -> Iterator[tuple[int, str]]:
    """Yield (1-based line number, text) for decodable text content."""
    try:
        text = blob_data.decode("utf-8")
    except UnicodeDecodeError:
        return
    for idx, line in enumerate(text.splitlines(), start=1):
        yield idx, line


def _scan_text(
    rules: Iterable[Rule],
    commit_hash: str,
    file_path: str,
    blob_data: bytes,
) -> Iterator[Finding]:
    for line_number, line in _iter_text_lines(blob_data):
        for rule in rules:
            for match in rule.regex.finditer(line):
                secret = match.group(rule.secret_group)
                if not secret:
                    continue
                if rule.validator and not rule.validator(secret):
                    continue
                yield Finding(
                    rule_id=rule.rule_id,
                    description=rule.description,
                    commit=commit_hash,
                    file_path=file_path,
                    line_number=line_number,
                    redacted_context=redact(line, secret),
                    confidence=score_confidence(rule, secret),
                    severity=rule_severity(rule),
                    _secret=secret,
                )


def _scan_workflow_text(
    commit_hash: str,
    file_path: str,
    blob_data: bytes,
) -> Iterator[Finding]:
    """Yield workflow secret-exposure findings for a workflow file's bytes.

    Only ``.github/workflows/*.yml|*.yaml`` files are examined (the caller is
    expected to gate on :func:`is_workflow_file`, but we re-check for safety).
    Each hit becomes a :class:`Finding` under the
    :data:`~tombstone.workflow.WORKFLOW_RULE_ID` rule. These findings carry a
    synthetic dedupe token in ``_secret`` (no real credential is present in the
    file) and are emitted at ``confidence="medium"`` since they flag a dangerous
    *pattern* rather than a confirmed live credential.
    """
    if not is_workflow_file(file_path):
        return
    try:
        text = blob_data.decode("utf-8")
    except UnicodeDecodeError:
        return
    for hit in scan_workflow_text(text):
        yield Finding(
            rule_id=WORKFLOW_RULE_ID,
            description=hit.description,
            commit=commit_hash,
            file_path=file_path,
            line_number=hit.line_number,
            redacted_context=redact_workflow_line(hit.line),
            confidence="medium",
            severity=WORKFLOW_SEVERITY,
            # Dedupe key is the construct, scoped to the file so the same risky
            # pattern in two different workflow files is reported separately.
            _secret=f"{file_path}::{hit.dedupe_token}",
        )


def scan_repo(
    repo_path: str,
    pattern_set: str = "full",
    since: Optional[str] = None,
    until: Optional[str] = None,
    include_worktree: bool = False,
    workers: int = 1,
    workflow_scan: bool = False,
) -> list[Finding]:
    """Scan commits of the git repo at ``repo_path`` for credentials.

    Findings are deduplicated by (rule_id, secret value) so a credential present
    across multiple commits counts once. The earliest commit in which the secret
    appears (in iteration order) is recorded as the reproducibility anchor.

    Parameters
    ----------
    repo_path:
        Path to the target git repository.
    pattern_set:
        Which detection rule set to apply.
    since:
        If given, only commits reachable from HEAD but NOT from this refspec are
        scanned.  Equivalent to ``git log <since>..HEAD``.
    until:
        If given, only commits reachable from this refspec are scanned.
        Equivalent to ``git log HEAD..<until>`` (commits up to and including
        <until> but not beyond). Combined with *since* this forms a range.
    include_worktree:
        If True, also scan the current working tree (uncommitted files) after
        history. Worktree findings are deduplicated against history findings by
        (rule_id, secret): a credential already seen in history is not reported
        again, so the working-tree pass only surfaces credentials that are not
        present in any committed object.
    workers:
        Number of threads used to scan blobs in parallel. The default of ``1``
        scans serially. Higher values speed up large repos (many commits / many
        blobs) by running the CPU-bound regex matching across a thread pool.
        Results are **identical** to a single-threaded run regardless of worker
        count: blobs are gathered in commit-iteration order and reassembled in
        that same order before deduplication, so the reproducibility anchor (the
        earliest commit a secret appears in) is deterministic. Values < 1 are
        treated as 1.
    workflow_scan:
        If True, additionally flag GitHub Actions workflow files
        (``.github/workflows/*.yml|*.yaml``) for secret-exposure anti-patterns —
        e.g. a ``${{ secrets.X }}`` interpolated into a ``run:`` shell command,
        or an ``echo`` of a secret-derived environment variable, both of which
        leak the secret into the workflow run log. These workflow findings are
        emitted under the ``workflow-secret-exposure`` rule and reuse the same
        gathered history blobs (and, with *include_worktree*, the working tree).
    """
    try:
        repo = Repo(repo_path)
    except (InvalidGitRepositoryError, NoSuchPathError) as exc:
        raise ValueError(f"not a git repository: {repo_path}") from exc

    # Build a revision range for iter_commits.
    # gitpython accepts the same revision range syntax as `git log`:
    #   "<since>..<until>" → commits reachable from <until> but not <since>
    # When only --since is supplied we use "<since>..HEAD".
    # When only --until is supplied we use "<until>" (all history up to that point).
    # When both are supplied we use "<since>..<until>".
    if since and until:
        rev = f"{since}..{until}"
    elif since:
        rev = f"{since}..HEAD"
    elif until:
        rev = until
    else:
        rev = "HEAD"

    rules = get_rules(pattern_set)
    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []

    # Gather (commit_hash, file_path, bytes) jobs in commit-iteration order.
    # Reading blob bytes is done serially because gitpython object access over a
    # single Repo is not thread-safe; the parallelism is applied to the
    # CPU-bound regex scanning, which is the actual hot path on large repos.
    jobs: list[tuple[str, str, bytes]] = []
    for commit in repo.iter_commits(rev=rev):
        for blob in _iter_commit_blobs(commit):
            try:
                data = blob.data_stream.read()
            except Exception:  # pragma: no cover - unreadable blob
                continue
            jobs.append((commit.hexsha, blob.path, data))

    for blob_findings in _scan_jobs(rules, jobs, workers):
        for finding in blob_findings:
            _add_finding(findings, seen, finding)

    # Workflow secret-exposure scan reuses the same gathered blob jobs so it
    # honours --since/--until and adds no extra git traversal. It runs over the
    # history blobs first, then (when requested) the working tree.
    if workflow_scan:
        for commit_hash, file_path, data in jobs:
            for finding in _scan_workflow_text(commit_hash, file_path, data):
                _add_finding(findings, seen, finding)

    if include_worktree:
        for finding in _iter_worktree_findings(repo_path, rules):
            _add_finding(findings, seen, finding)
        if workflow_scan:
            for finding in _iter_worktree_workflow_findings(repo_path):
                _add_finding(findings, seen, finding)

    return findings


def scan_worktree(repo_path: str, pattern_set: str = "full") -> list[Finding]:
    """Scan only the working tree (uncommitted files) of ``repo_path``.

    Walks the filesystem under ``repo_path``, skipping the ``.git`` directory,
    and applies the active rule set to every decodable text file. Findings are
    marked with the synthetic :data:`WORKTREE_COMMIT` identifier and
    deduplicated by (rule_id, secret).

    This catches credentials that exist only in the working copy — e.g. a
    ``.env`` left on a staging box, or a secret removed from history but still
    present on disk — which a history-only scan misses entirely.
    """
    # Validate that this is a git repository for consistency with scan_repo,
    # even though the walk itself is filesystem-based.
    if not is_git_repo(repo_path):
        raise ValueError(f"not a git repository: {repo_path}")

    rules = get_rules(pattern_set)
    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []
    for finding in _iter_worktree_findings(repo_path, rules):
        _add_finding(findings, seen, finding)
    return findings


def _scan_jobs(
    rules: Iterable[Rule],
    jobs: list[tuple[str, str, bytes]],
    workers: int,
) -> Iterator[list[Finding]]:
    """Scan a list of (commit, path, bytes) jobs, yielding per-job finding lists.

    Results are yielded in the **same order** as *jobs* regardless of worker
    count, so downstream deduplication produces a deterministic reproducibility
    anchor. With ``workers <= 1`` (or an empty job list) the scan runs inline
    with no thread-pool overhead; otherwise the CPU-bound regex matching is
    spread across a :class:`~concurrent.futures.ThreadPoolExecutor`.

    Materialising ``rules`` once avoids re-consuming a generator per job.
    """
    rule_list = list(rules)

    def _scan_one(job: tuple[str, str, bytes]) -> list[Finding]:
        commit_hash, file_path, data = job
        return list(_scan_text(rule_list, commit_hash, file_path, data))

    if workers <= 1 or len(jobs) <= 1:
        for job in jobs:
            yield _scan_one(job)
        return

    # executor.map preserves input order, which is exactly the ordering
    # guarantee we need; score_confidence and the regex scan are pure functions
    # of their inputs, so no shared mutable state crosses threads here.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        yield from pool.map(_scan_one, jobs)


def _add_finding(
    findings: list[Finding],
    seen: set[tuple[str, str]],
    finding: Finding,
) -> None:
    """Append *finding* to *findings* unless its (rule_id, secret) was seen."""
    key = (finding.rule_id, finding._secret)
    if key in seen:
        return
    seen.add(key)
    findings.append(finding)


def _iter_worktree_findings(repo_path: str, rules) -> Iterator[Finding]:
    """Yield findings from every decodable text file in the working tree.

    The ``.git`` directory is skipped — its packed objects are history, not the
    working tree, and would otherwise produce garbage matches. File paths are
    reported relative to ``repo_path`` (POSIX separators) to match the relative
    paths used for committed blobs.
    """
    root = Path(repo_path)
    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune the .git directory in place so os.walk never descends into it.
        if ".git" in dirnames:
            dirnames.remove(".git")
        for name in filenames:
            abs_path = Path(dirpath) / name
            try:
                data = abs_path.read_bytes()
            except OSError:  # pragma: no cover - unreadable/special file
                continue
            rel_path = abs_path.relative_to(root).as_posix()
            yield from _scan_text(rules, WORKTREE_COMMIT, rel_path, data)


def _iter_worktree_workflow_findings(repo_path: str) -> Iterator[Finding]:
    """Yield workflow secret-exposure findings from working-tree workflow files.

    Walks the working tree (skipping ``.git``) like
    :func:`_iter_worktree_findings`, but only feeds
    ``.github/workflows/*.yml|*.yaml`` files into the workflow anti-pattern
    detector. Findings carry the synthetic :data:`WORKTREE_COMMIT` identifier.
    """
    root = Path(repo_path)
    for dirpath, dirnames, filenames in os.walk(repo_path):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for name in filenames:
            abs_path = Path(dirpath) / name
            rel_path = abs_path.relative_to(root).as_posix()
            if not is_workflow_file(rel_path):
                continue
            try:
                data = abs_path.read_bytes()
            except OSError:  # pragma: no cover - unreadable/special file
                continue
            yield from _scan_workflow_text(WORKTREE_COMMIT, rel_path, data)


# ---------------------------------------------------------------------------
# State-file helpers
# ---------------------------------------------------------------------------


def resolve_state_file(repo_path: str, state_file: Optional[str]) -> Path:
    """Return the Path to the state file, defaulting to ``<repo>/.tombstone-state``."""
    if state_file:
        return Path(state_file)
    return Path(repo_path) / DEFAULT_STATE_FILENAME


def load_state(state_path: Path) -> Optional[str]:
    """Return the SHA saved in *state_path*, or ``None`` if the file doesn't exist."""
    if not state_path.exists():
        return None
    sha = state_path.read_text(encoding="utf-8").strip()
    return sha if sha else None


def save_state(state_path: Path, repo_path: str) -> str:
    """Write HEAD's hexsha to *state_path* and return it."""
    try:
        repo = Repo(repo_path)
    except (InvalidGitRepositoryError, NoSuchPathError) as exc:
        raise ValueError(f"not a git repository: {repo_path}") from exc
    head_sha = repo.head.commit.hexsha
    state_path.write_text(head_sha + "\n", encoding="utf-8")
    return head_sha


def _iter_commit_blobs(commit) -> Iterator:
    """Yield all blobs in a commit's tree."""
    for blob in commit.tree.traverse():
        if getattr(blob, "type", None) == "blob":
            yield blob


def is_git_repo(repo_path: str) -> bool:
    """Return True if ``repo_path`` is a valid git repository."""
    if not os.path.isdir(repo_path):
        return False
    try:
        Repo(repo_path)
        return True
    except (InvalidGitRepositoryError, NoSuchPathError):
        return False
