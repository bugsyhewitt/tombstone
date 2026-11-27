"""Tests for the custom regex pattern file loader (tombstone v0.2 feature)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tombstone.pattern_loader import load_patterns_from_file, list_builtin_patterns


def _yaml_file(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "patterns.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# 1. Valid YAML with patterns returns Rule objects
def test_valid_yaml_returns_rules(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: Acme API Key
            regex: 'acme-[a-z0-9]{32}'
            severity: high
            description: Acme Corp API key
          - name: Internal Token
            regex: 'Bearer (tok_[a-zA-Z0-9]{40})'
            group: 1
            severity: critical
            description: Internal bearer token
    """)
    rules = load_patterns_from_file(f)
    assert len(rules) == 2

    r0 = rules[0]
    assert r0.rule_id == "acme-api-key"
    assert r0.description == "Acme Corp API key"
    assert r0.severity == "HIGH"
    assert r0.secret_group == 0

    r1 = rules[1]
    assert r1.rule_id == "internal-token"
    assert r1.severity == "CRITICAL"
    assert r1.secret_group == 1


# 2. Missing required fields raise ValueError
def test_missing_name_raises(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - regex: 'foo-[0-9]+'
            severity: high
            description: missing name
    """)
    with pytest.raises(ValueError, match="missing required field 'name'"):
        load_patterns_from_file(f)


def test_missing_regex_raises(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: MyPattern
            severity: high
            description: no regex here
    """)
    with pytest.raises(ValueError, match="missing required field 'regex'"):
        load_patterns_from_file(f)


def test_missing_severity_raises(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: MyPattern
            regex: 'tok-[a-z]+'
            description: no severity
    """)
    with pytest.raises(ValueError, match="missing required field 'severity'"):
        load_patterns_from_file(f)


def test_invalid_severity_raises(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: MyPattern
            regex: 'tok-[a-z]+'
            severity: extreme
            description: bad severity value
    """)
    with pytest.raises(ValueError, match="invalid severity"):
        load_patterns_from_file(f)


# 3. Invalid regex raises ValueError with pattern name
def test_invalid_regex_raises_with_name(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: BrokenPattern
            regex: '[unclosed'
            severity: medium
            description: bad regex
    """)
    with pytest.raises(ValueError, match="BrokenPattern"):
        load_patterns_from_file(f)


def test_invalid_regex_error_mentions_invalid_regex(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: AnotherBroken
            regex: '(?P<name>(?P<name>dup))'
            severity: low
            description: duplicate group name
    """)
    with pytest.raises(ValueError, match="invalid regex"):
        load_patterns_from_file(f)


# 4. Custom pattern produces a matching rule
def test_custom_pattern_rule_matches_text(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: Acme Internal Key
            regex: 'acme-int-[a-z0-9]{16}'
            severity: high
            description: Acme internal service key
    """)
    rules = load_patterns_from_file(f)
    assert len(rules) == 1
    text = 'api_key = "acme-int-deadbeef01234567"'
    matches = list(rules[0].regex.finditer(text))
    assert matches
    assert matches[0].group(0) == "acme-int-deadbeef01234567"


def test_custom_pattern_with_capture_group(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: Bearer Token
            regex: 'Bearer (tok_[A-Za-z0-9]{20})'
            group: 1
            severity: critical
            description: Internal bearer token format
    """)
    rules = load_patterns_from_file(f)
    rule = rules[0]
    text = "Authorization: Bearer tok_AbCdEfGhIjKlMnOpQrSt"
    m = rule.regex.search(text)
    assert m is not None
    assert m.group(rule.secret_group) == "tok_AbCdEfGhIjKlMnOpQrSt"


# 5. --list-patterns returns built-in patterns
def test_list_builtin_patterns_returns_rules():
    rules = list_builtin_patterns()
    assert len(rules) > 0
    ids = {r.rule_id for r in rules}
    assert "aws-access-key-id" in ids
    assert "github-pat" in ids
    assert "stripe-secret-key" in ids


def test_list_builtin_patterns_no_duplicates():
    rules = list_builtin_patterns()
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids))


# 6. Empty YAML returns empty list (OK, uses only built-ins)
def test_empty_patterns_list_returns_empty(tmp_path):
    f = _yaml_file(tmp_path, "patterns: []\n")
    assert load_patterns_from_file(f) == []


def test_yaml_with_no_patterns_key_returns_empty(tmp_path):
    f = _yaml_file(tmp_path, "version: 1\n")
    assert load_patterns_from_file(f) == []


def test_empty_yaml_file_returns_empty(tmp_path):
    f = tmp_path / "empty.yaml"
    f.write_text("", encoding="utf-8")
    assert load_patterns_from_file(f) == []


# Extra: rule_id slugification
def test_rule_id_is_slugified(tmp_path):
    f = _yaml_file(tmp_path, """
        patterns:
          - name: "My Custom Secret (v2)!"
            regex: 'sec-[a-z]+'
            severity: medium
            description: slugification test
    """)
    rules = load_patterns_from_file(f)
    assert rules[0].rule_id == "my-custom-secret-v2"


# All severity values are accepted
def test_all_severities_accepted(tmp_path):
    for sev in ("low", "medium", "high", "critical"):
        f = _yaml_file(tmp_path, f"""
            patterns:
              - name: Test {sev.capitalize()}
                regex: 'tok-[a-z]+'
                severity: {sev}
                description: severity test
        """)
        rules = load_patterns_from_file(f)
        assert rules[0].severity == sev.upper()
