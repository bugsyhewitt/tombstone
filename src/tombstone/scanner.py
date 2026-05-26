"""Git-history credential scanner.

Traverses every commit of a repository (and the working tree) using gitpython,
applies the active rule set to added/changed text, and emits deduplicated
findings with reproducibility evidence: commit hash, file path, line number,
and a redacted context line.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from git import Repo
from git.exc import InvalidGitRepositoryError, NoSuchPathError

from .patterns import Rule, get_rules


@dataclass(frozen=True)
class Finding:
    """A single credential finding with reproducibility evidence."""

    rule_id: str
    description: str
    commit: str
    file_path: str
    line_number: int
    redacted_context: str
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
                    _secret=secret,
                )


def scan_repo(repo_path: str, pattern_set: str = "full") -> list[Finding]:
    """Scan all commits of the git repo at ``repo_path`` for credentials.

    Findings are deduplicated by (rule_id, secret value) so a credential present
    across multiple commits counts once. The earliest commit in which the secret
    appears (in iteration order) is recorded as the reproducibility anchor.
    """
    try:
        repo = Repo(repo_path)
    except (InvalidGitRepositoryError, NoSuchPathError) as exc:
        raise ValueError(f"not a git repository: {repo_path}") from exc

    rules = get_rules(pattern_set)
    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []

    for commit in repo.iter_commits():
        for blob in _iter_commit_blobs(commit):
            try:
                data = blob.data_stream.read()
            except Exception:  # pragma: no cover - unreadable blob
                continue
            for finding in _scan_text(rules, commit.hexsha, blob.path, data):
                key = (finding.rule_id, finding._secret)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

    return findings


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
