"""Git-history credential scanner.

Traverses every commit of a repository (and the working tree) using gitpython,
applies the active rule set to added/changed text, and emits deduplicated
findings with reproducibility evidence: commit hash, file path, line number,
and a redacted context line.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
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
    # Authorship metadata for the commit the secret was first seen in. These
    # turn a finding into a self-contained triage signal: *who* leaked the
    # credential and — crucially — *when*. A secret committed last week is far
    # more likely still live than one from years ago, so recency drives which
    # findings a researcher chases first. Empty for working-tree findings (which
    # have no commit) and for the synthetic workflow-exposure rule.
    author: str = ""
    # The git *committer* of the commit the secret was first seen in, rendered as
    # ``"Name <email>"``. Distinct from ``author``: git records both, and they
    # diverge whenever a commit is applied by someone other than its writer — a
    # maintainer who lands a contributor's patch, a rebase/cherry-pick, or a
    # squash-merge bot. For leak triage that distinction matters: the author wrote
    # the secret, but the committer is who actually pushed it into the tree. Empty
    # for working-tree findings and the synthetic workflow-exposure rule (no
    # backing commit).
    committer: str = ""
    # ISO 8601 timestamp (with timezone offset) of the authored commit, e.g.
    # "2026-05-20T14:03:11+00:00". Empty when there is no backing commit.
    committed_at: str = ""
    # Whether this credential is still present in the repository's current HEAD
    # tree, as opposed to existing only in older history. This is a *liveness*
    # triage signal independent of confidence and severity: a secret still in
    # HEAD is far more likely to be a live, in-use credential than one that was
    # committed once and later removed. A researcher chases still-present
    # criticals first. Defaults to True — a finding is assumed current unless the
    # scanner proves it was removed from HEAD (history-only). Working-tree
    # findings are present on disk by definition, so they are always True.
    still_present: bool = True
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
            "author": self.author,
            "committer": self.committer,
            "committed_at": self.committed_at,
            "still_present": self.still_present,
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
    author: str = "",
    committed_at: str = "",
    committer: str = "",
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
                    author=author,
                    committer=committer,
                    committed_at=committed_at,
                    _secret=secret,
                )


def _scan_workflow_text(
    commit_hash: str,
    file_path: str,
    blob_data: bytes,
    author: str = "",
    committed_at: str = "",
    committer: str = "",
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
            author=author,
            committer=committer,
            committed_at=committed_at,
            # Dedupe key is the construct, scoped to the file so the same risky
            # pattern in two different workflow files is reported separately.
            _secret=f"{file_path}::{hit.dedupe_token}",
        )


def matches_author(finding_author: str, needle: str) -> bool:
    """Return True if *needle* matches *finding_author* (case-insensitive substring).

    The finding's author is rendered as ``"Name <email>"`` (see
    :func:`_commit_meta`), so a single substring test lets an operator scope by
    a committer's name *or* their email — ``--author jane`` and
    ``--author jane@acme`` both match ``"Jane Dev <jane@acme-corp.example>"``.
    Matching is case-insensitive because git names and emails are
    inconsistently cased in the wild.

    An empty *finding_author* (working-tree findings, or the synthetic
    workflow-exposure rule, which have no backing commit) never matches a
    non-empty needle: there is no committer to attribute, so an author filter
    legitimately excludes it. An empty *needle* matches everything (callers gate
    on truthiness before filtering, so this is a defensive convenience).
    """
    if not needle:
        return True
    if not finding_author:
        return False
    return needle.casefold() in finding_author.casefold()


def matches_committer(finding_committer: str, needle: str) -> bool:
    """Return True if *needle* matches *finding_committer* (case-insensitive substring).

    The committer is rendered as ``"Name <email>"`` (see :func:`_commit_meta`),
    so a single substring test scopes by the committer's name *or* email —
    ``--committer ci-bot`` and ``--committer bot@ci.example`` both match
    ``"CI Bot <bot@ci.example>"``. Matching semantics are identical to
    :func:`matches_author` (case-insensitive, empty-needle is a no-op, empty
    committer never matches a non-empty needle); the two are kept as separate
    named functions because they filter on git's distinct *author* and
    *committer* identities, which diverge under rebase, cherry-pick, and
    patch-application workflows.
    """
    return matches_author(finding_committer, needle)


def scan_repo(
    repo_path: str,
    pattern_set: str = "full",
    since: Optional[str] = None,
    until: Optional[str] = None,
    include_worktree: bool = False,
    workers: int = 1,
    workflow_scan: bool = False,
    author_filter: Optional[str] = None,
    committer_filter: Optional[str] = None,
    since_date: Optional[str] = None,
    until_date: Optional[str] = None,
) -> list[Finding]:
    """Scan commits of the git repo at ``repo_path`` for credentials.

    Findings are deduplicated by (rule_id, secret value) so a credential present
    across multiple commits counts once. The earliest commit in which the secret
    appears (in iteration order) is recorded as the reproducibility anchor.

    Each credential finding is also tagged with a ``still_present`` liveness
    flag: True if the credential's ``(rule_id, secret)`` is still found in the
    current HEAD tree, False if it was removed and survives only in older
    history. This is a triage signal — a still-present secret is far more likely
    to be a live, in-use credential than one that was committed once and later
    deleted. Working-tree findings and workflow secret-exposure findings keep the
    default ``still_present=True``. The liveness flag reflects the *true* HEAD
    state regardless of any ``--since``/``--until`` range used to scope which
    commits are reported.

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
    author_filter:
        If given, restrict the returned findings to those whose committing
        author matches this string (case-insensitive substring against the
        finding's ``"Name <email>"`` author field — so it matches by name or by
        email). Scopes a scan to a single committer of interest. Working-tree
        findings and the synthetic workflow-exposure rule have no backing commit
        and so are always excluded when an author filter is active. The history
        traversal is unchanged — every commit is still scanned for
        deduplication accuracy, then findings are filtered — so the
        reproducibility anchor (the earliest commit a secret appears in) is
        unaffected by the filter.
    committer_filter:
        If given, restrict the returned findings to those whose git *committer*
        matches this string (case-insensitive substring against the finding's
        ``"Name <email>"`` committer field — so it matches by name or by email).
        Distinct from *author_filter*: git records both an author (who wrote the
        change) and a committer (who applied it), and they diverge under rebase,
        cherry-pick, and patch-application/squash-merge workflows. Use this to
        scope a scan to whoever actually landed a secret into the tree — e.g. a
        release bot or the maintainer who merged a contributor's branch. Composes
        with *author_filter*: when both are set a finding must match both.
        Working-tree findings and the synthetic workflow-exposure rule have no
        backing commit and so are always excluded when a committer filter is
        active. Like the author filter, this narrows only the *reported* set; the
        full history traversal and dedup are unchanged.
    since_date:
        If given, restrict scanning to commits **authored on or after** this
        calendar date/time. Accepts any date string git's ``--since`` understands
        (e.g. ``"2025-01-01"``, ``"2 weeks ago"``, ``"2025-06-01 12:00"``).
        Maps to gitpython's ``iter_commits(after=...)``. Composes with the
        refspec *since*/*until* range — both narrowings apply.
    until_date:
        If given, restrict scanning to commits **authored on or before** this
        calendar date/time (gitpython's ``iter_commits(before=...)``). Combine
        with *since_date* to bound an investigation to a breach window, e.g.
        ``since_date="2025-03-01" until_date="2025-03-15"``.
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

    # Calendar-date narrowing maps directly to gitpython's after/before kwargs,
    # which forward to `git log --since/--until`. These compose with the refspec
    # *rev* range above: git applies both, so e.g. a refspec range plus a date
    # window intersect. Empty/None dates are omitted so the kwargs stay absent
    # and behaviour is unchanged for callers that don't use them.
    commit_kwargs: dict[str, str] = {}
    if since_date:
        commit_kwargs["after"] = since_date
    if until_date:
        commit_kwargs["before"] = until_date

    rules = get_rules(pattern_set)
    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []

    # Gather (commit_hash, file_path, bytes, author, committed_at, committer)
    # jobs in commit-iteration order. Reading blob bytes is done serially because
    # gitpython object access over a single Repo is not thread-safe; the
    # parallelism is applied to the CPU-bound regex scanning, which is the
    # actual hot path on large repos. The author/committer/date are read once per
    # commit (not per blob) so the overhead is negligible.
    jobs: list[tuple[str, str, bytes, str, str, str]] = []
    for commit in repo.iter_commits(rev=rev, **commit_kwargs):
        author, committed_at, committer = _commit_meta(commit)
        for blob in _iter_commit_blobs(commit):
            try:
                data = blob.data_stream.read()
            except Exception:  # pragma: no cover - unreadable blob
                continue
            jobs.append(
                (commit.hexsha, blob.path, data, author, committed_at, committer)
            )

    for blob_findings in _scan_jobs(rules, jobs, workers):
        for finding in blob_findings:
            _add_finding(findings, seen, finding)

    # Liveness pass: determine which credential findings are still present in the
    # current HEAD tree versus existing only in older history. We re-scan HEAD's
    # blobs (which are already in *jobs* when the scan reaches HEAD, but a
    # range-restricted scan via --since/--until may not include HEAD at all, so
    # we compute the HEAD key set independently and robustly). A history finding
    # whose (rule_id, secret) is absent from HEAD was removed — a far weaker
    # liveness signal — so its ``still_present`` is flipped to False. The default
    # is True, so any error here leaves findings marked present rather than
    # silently downgrading a live leak.
    head_keys = _head_credential_keys(repo, rules)
    if head_keys is not None:
        findings = [
            _apply_liveness(f, head_keys) for f in findings
        ]

    # Workflow secret-exposure scan reuses the same gathered blob jobs so it
    # honours --since/--until and adds no extra git traversal. It runs over the
    # history blobs first, then (when requested) the working tree.
    if workflow_scan:
        for commit_hash, file_path, data, author, committed_at, committer in jobs:
            for finding in _scan_workflow_text(
                commit_hash, file_path, data, author, committed_at, committer
            ):
                _add_finding(findings, seen, finding)

    if include_worktree:
        for finding in _iter_worktree_findings(repo_path, rules):
            _add_finding(findings, seen, finding)
        if workflow_scan:
            for finding in _iter_worktree_workflow_findings(repo_path):
                _add_finding(findings, seen, finding)

    # Author scoping is applied last, after the full traversal and dedup, so the
    # reproducibility anchor is computed over the complete history and only the
    # *reported* set is narrowed to the committer of interest.
    if author_filter:
        findings = [f for f in findings if matches_author(f.author, author_filter)]

    # Committer scoping is applied the same way and composes with the author
    # filter: when both are set a finding must satisfy both. Applied after the
    # full traversal/dedup so the reproducibility anchor is unaffected.
    if committer_filter:
        findings = [
            f for f in findings if matches_committer(f.committer, committer_filter)
        ]

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
    jobs: list[tuple[str, str, bytes, str, str, str]],
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

    def _scan_one(job: tuple[str, str, bytes, str, str, str]) -> list[Finding]:
        commit_hash, file_path, data, author, committed_at, committer = job
        return list(
            _scan_text(
                rule_list,
                commit_hash,
                file_path,
                data,
                author,
                committed_at,
                committer,
            )
        )

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


def _format_actor(actor) -> str:
    """Render a gitpython actor as ``"Name <email>"``.

    Falls back to whichever of name/email is present, and returns an empty
    string for a missing actor — read defensively so a malformed or actor-less
    commit never aborts a scan.
    """
    try:
        name = (getattr(actor, "name", "") or "").strip()
        email = (getattr(actor, "email", "") or "").strip()
    except Exception:  # pragma: no cover - defensive
        return ""
    if name and email:
        return f"{name} <{email}>"
    return name or email


def _commit_meta(commit) -> tuple[str, str, str]:
    """Return ``(author, committed_at_iso, committer)`` for a gitpython commit.

    *author* and *committer* are each rendered as ``"Name <email>"`` when both
    are available, falling back to whichever is present. They are git's two
    distinct identities — author wrote the change, committer applied it — and
    diverge under rebase, cherry-pick, and patch-application workflows.
    *committed_at* is the authored timestamp in ISO 8601 with timezone offset
    (e.g. ``2026-05-20T14:03:11+00:00``). All are read defensively: a malformed
    or actor-less commit yields empty strings rather than raising, so scanning
    never aborts on bad metadata.
    """
    author = ""
    try:
        author = _format_actor(commit.author)
    except Exception:  # pragma: no cover - defensive
        author = ""

    committer = ""
    try:
        committer = _format_actor(commit.committer)
    except Exception:  # pragma: no cover - defensive
        committer = ""

    committed_at = ""
    try:
        committed_at = commit.authored_datetime.isoformat()
    except Exception:  # pragma: no cover - defensive
        committed_at = ""

    return author, committed_at, committer


def _apply_liveness(
    finding: Finding, head_keys: set[tuple[str, str]]
) -> Finding:
    """Set *finding*'s ``still_present`` from the HEAD credential-key set.

    A credential finding is still present when its ``(rule_id, secret)`` key is
    in *head_keys*; otherwise it was removed from HEAD and lives only in older
    history, so ``still_present`` is set to False.

    Two finding kinds are *not* re-evaluated and keep their default
    ``still_present=True``:

    * **Workflow secret-exposure findings** (rule
      :data:`~tombstone.workflow.WORKFLOW_RULE_ID`) expose a dangerous *pattern*
      rather than a literal credential; their ``_secret`` is a synthetic,
      file-scoped dedupe token that has no counterpart in *head_keys*, so a key
      comparison would always (wrongly) say "removed".
    * **Working-tree findings** (commit :data:`WORKTREE_COMMIT`) are present on
      disk right now by definition — they describe the current state, not
      history — so they are always still present.

    Both are appended/kept as ``True``; only history-backed credential findings
    can be downgraded to history-only.
    """
    if finding.rule_id == WORKFLOW_RULE_ID:
        return finding
    if finding.commit == WORKTREE_COMMIT:
        return finding
    if (finding.rule_id, finding._secret) in head_keys:
        return finding
    return replace(finding, still_present=False)


def _head_credential_keys(
    repo: Repo, rules: Iterable[Rule]
) -> Optional[set[tuple[str, str]]]:
    """Return the set of ``(rule_id, secret)`` keys present in the HEAD tree.

    Scans every blob of the current ``HEAD`` commit with the active *rules* and
    collects the ``(rule_id, secret)`` of each match — the same key the scanner
    uses for deduplication. A history finding whose key is in this set is still
    present in the repository's current state; one whose key is absent was
    removed and lives only in older history.

    Returns ``None`` (rather than an empty set) when HEAD cannot be resolved —
    e.g. an unborn branch with no commits — so the caller can leave findings at
    their default ``still_present=True`` rather than mis-marking everything as
    removed. An empty set is a valid result (HEAD has no credentials) and is
    distinct from ``None``.
    """
    try:
        head_commit = repo.head.commit
    except Exception:  # pragma: no cover - unborn branch / detached/no commits
        return None

    rule_list = list(rules)
    keys: set[tuple[str, str]] = set()
    for blob in _iter_commit_blobs(head_commit):
        try:
            data = blob.data_stream.read()
        except Exception:  # pragma: no cover - unreadable blob
            continue
        for finding in _scan_text(rule_list, head_commit.hexsha, blob.path, data):
            keys.add((finding.rule_id, finding._secret))
    return keys


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
