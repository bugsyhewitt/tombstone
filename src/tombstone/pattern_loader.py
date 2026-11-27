"""Custom regex pattern file loader for tombstone.

Allows users to define target-specific credential patterns in a YAML file
and pass them to ``tombstone scan`` via ``--patterns-file``. Custom patterns
are merged with (or replace) the built-in rule library depending on whether
``--patterns-only`` is set.

YAML format::

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

Fields:
  name        required — human-readable label; becomes the rule_id (slugified)
  regex       required — Python regex string; must compile without error
  severity    required — one of: low, medium, high, critical
  description required — single-sentence description for the report
  group       optional — capture group index for the secret value (default: 0)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from necromancer_patterns import Rule

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass
class CustomPattern:
    """A user-defined credential pattern parsed from a YAML file."""

    name: str
    regex: str
    severity: str
    description: str
    group: int = field(default=0)


def _slugify(name: str) -> str:
    """Convert a human-readable name to a lowercase-hyphenated rule_id."""
    return re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")


def _parse_pattern(raw: object, index: int) -> CustomPattern:
    """Parse one entry from the patterns list, raising ValueError on bad input."""
    if not isinstance(raw, dict):
        raise ValueError(f"patterns[{index}]: expected a mapping, got {type(raw).__name__}")

    for required in ("name", "regex", "severity", "description"):
        if required not in raw:
            entry = raw.get("name", f"[index {index}]")
            raise ValueError(
                f"pattern '{entry}': missing required field '{required}'"
            )

    name = str(raw["name"]).strip()
    if not name:
        raise ValueError(f"patterns[{index}]: 'name' must not be empty")

    severity = str(raw["severity"]).strip().lower()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"pattern '{name}': invalid severity '{raw['severity']}'; "
            f"must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
        )

    regex_str = str(raw["regex"])
    try:
        re.compile(regex_str)
    except re.error as exc:
        raise ValueError(f"pattern '{name}': invalid regex: {exc}") from exc

    group = int(raw.get("group", 0))
    description = str(raw["description"]).strip()

    return CustomPattern(
        name=name,
        regex=regex_str,
        severity=severity,
        description=description,
        group=group,
    )


def _custom_pattern_to_rule(cp: CustomPattern) -> Rule:
    """Convert a :class:`CustomPattern` to a :class:`~necromancer_patterns.Rule`."""
    return Rule(
        rule_id=_slugify(cp.name),
        description=cp.description,
        regex=re.compile(cp.regex),
        severity=cp.severity.upper(),
        secret_group=cp.group,
    )


def load_patterns_from_file(path: Path) -> list[Rule]:
    """Load custom patterns from a YAML file and return them as Rule objects.

    Parameters
    ----------
    path:
        Path to the YAML file.

    Returns
    -------
    list[Rule]
        A fresh list of :class:`~necromancer_patterns.Rule` objects. An empty
        ``patterns`` list is accepted and returns an empty list — the caller
        can safely merge that with the built-in rules.

    Raises
    ------
    ValueError
        If the file cannot be parsed as YAML, if the top-level structure is
        wrong, if a required field is missing, if a regex does not compile, or
        if a severity value is not one of the accepted tokens.
    OSError
        If the file cannot be read.
    """
    text = path.read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"could not parse YAML from '{path}': {exc}") from exc

    if doc is None:
        return []

    if not isinstance(doc, dict):
        raise ValueError(
            f"'{path}': expected a YAML mapping at the top level, got {type(doc).__name__}"
        )

    raw_patterns = doc.get("patterns")
    if raw_patterns is None:
        return []

    if not isinstance(raw_patterns, list):
        raise ValueError(
            f"'{path}': 'patterns' must be a list, got {type(raw_patterns).__name__}"
        )

    rules: list[Rule] = []
    for i, entry in enumerate(raw_patterns):
        cp = _parse_pattern(entry, i)
        rules.append(_custom_pattern_to_rule(cp))
    return rules


def list_builtin_patterns() -> list[Rule]:
    """Return all built-in rules from the full pattern set."""
    from .patterns import get_rules

    return get_rules("full")
