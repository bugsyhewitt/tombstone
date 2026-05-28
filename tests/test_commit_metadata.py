"""Tests for commit-metadata enrichment (author + authored date) on findings.

Every history-backed finding carries the *author* and *committed_at* of the
commit the secret was first seen in. This adds a recency triage signal (a
secret committed last week is far more likely still live than one from years
ago) and strengthens the report's reproducibility evidence with who/when.

Working-tree findings have no backing commit, so their metadata is blank.
"""

from tombstone.report import to_bcmd, to_h1md, to_json
from tombstone.scanner import WORKTREE_COMMIT, Finding


def _history_finding(**overrides) -> Finding:
    base = dict(
        rule_id="aws-access-key-id",
        description="AWS access key ID",
        commit="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        file_path="config/prod.env",
        line_number=7,
        redacted_context='aws_key = "AK****EF"',
        confidence="high",
        severity="critical",
        author="Jane Dev <jane@acme-corp.example>",
        committed_at="2026-05-20T14:03:11+00:00",
        _secret="AKIAEXAMPLEEXAMPLE01",
    )
    base.update(overrides)
    return Finding(**base)


def _worktree_finding() -> Finding:
    return Finding(
        rule_id="stripe-secret-key",
        description="Stripe secret key",
        commit=WORKTREE_COMMIT,
        file_path=".env.local",
        line_number=2,
        redacted_context='stripe = "sk****99"',
        confidence="high",
        severity="critical",
        # No commit backs a worktree finding, so author/date stay empty.
        author="",
        committed_at="",
        _secret="sk_live_worktreeonly99",
    )


# --------------------------------------------------------------------------- #
# Finding / JSON
# --------------------------------------------------------------------------- #


def test_to_dict_emits_author_and_committed_at():
    d = _history_finding().to_dict()
    assert d["author"] == "Jane Dev <jane@acme-corp.example>"
    assert d["committed_at"] == "2026-05-20T14:03:11+00:00"


def test_json_payload_carries_metadata():
    out = to_json([_history_finding()])
    assert "Jane Dev <jane@acme-corp.example>" in out
    assert "2026-05-20T14:03:11+00:00" in out


def test_worktree_finding_has_blank_metadata_in_json():
    out = to_json([_worktree_finding()])
    # The fields are present (stable schema) but empty for worktree findings.
    assert '"author": ""' in out
    assert '"committed_at": ""' in out


# --------------------------------------------------------------------------- #
# HackerOne markdown
# --------------------------------------------------------------------------- #


def test_h1md_shows_author_and_date():
    md = to_h1md([_history_finding()])
    assert "**Author:** Jane Dev <jane@acme-corp.example>" in md
    assert "**Committed:** 2026-05-20T14:03:11+00:00" in md


def test_h1md_omits_metadata_lines_when_absent():
    md = to_h1md([_worktree_finding()])
    # No empty "Author:"/"Committed:" lines clutter the report when blank.
    assert "**Author:**" not in md
    assert "**Committed:**" not in md


# --------------------------------------------------------------------------- #
# Bugcrowd markdown
# --------------------------------------------------------------------------- #


def test_bcmd_includes_attribution_for_history_finding():
    md = to_bcmd([_history_finding()])
    assert "Introduced on 2026-05-20T14:03:11+00:00 by Jane Dev" in md


def test_bcmd_omits_attribution_for_worktree_finding():
    md = to_bcmd([_worktree_finding()])
    assert "Introduced on" not in md


def test_bcmd_attribution_with_date_only():
    # A commit with a date but no resolvable author still produces a clean line.
    f = _history_finding(author="")
    md = to_bcmd([f])
    assert "Introduced on 2026-05-20T14:03:11+00:00." in md
