"""Tests for bug-bounty scope enforcement."""

import os

from tombstone.scope import check_scope, parse_scope_file

HERE = os.path.dirname(os.path.abspath(__file__))
SCOPE = os.path.join(HERE, "fixtures", "scope.txt")
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")
OOS = os.path.join(HERE, "fixtures", "out-of-scope-repo")


def test_parse_scope_file_skips_comments_and_blanks():
    entries = parse_scope_file(SCOPE)
    assert "leaky-repo" in entries
    assert all(not e.startswith("#") for e in entries)


def test_in_scope_repo_permitted():
    entries = parse_scope_file(SCOPE)
    decision = check_scope(LEAKY, entries)
    assert decision.in_scope is True


def test_out_of_scope_repo_refused():
    entries = parse_scope_file(SCOPE)
    decision = check_scope(OOS, entries)
    assert decision.in_scope is False
    assert "out-of-scope" in decision.reason or "not match" in decision.reason


def test_empty_scope_allows_everything():
    decision = check_scope(OOS, [])
    assert decision.in_scope is True
