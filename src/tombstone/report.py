"""Output formatters: JSON and HackerOne markdown."""

from __future__ import annotations

import json
from typing import Iterable

from .scanner import Finding


def to_json(findings: Iterable[Finding]) -> str:
    """Serialize findings to a JSON document."""
    payload = {
        "tool": "tombstone",
        "finding_count": 0,
        "findings": [],
    }
    items = [f.to_dict() for f in findings]
    payload["findings"] = items
    payload["finding_count"] = len(items)
    return json.dumps(payload, indent=2)


def to_h1md(findings: Iterable[Finding]) -> str:
    """Serialize findings to HackerOne-style markdown."""
    items = list(findings)
    lines: list[str] = []
    lines.append("# tombstone credential findings")
    lines.append("")
    lines.append(f"**Total findings:** {len(items)}")
    lines.append("")
    if not items:
        lines.append("_No credentials detected._")
        return "\n".join(lines) + "\n"
    for i, f in enumerate(items, start=1):
        lines.append(f"## Finding {i}: {f.description}")
        lines.append("")
        lines.append(f"- **Rule:** `{f.rule_id}`")
        lines.append(f"- **Commit:** `{f.commit}`")
        lines.append(f"- **File:** `{f.file_path}`")
        lines.append(f"- **Line:** {f.line_number}")
        lines.append("")
        lines.append("**Redacted context:**")
        lines.append("")
        lines.append("```")
        lines.append(f.redacted_context)
        lines.append("```")
        lines.append("")
        lines.append(
            "**Reproduction:** "
            f"`git -C <repo> show {f.commit}:{f.file_path}` "
            f"and inspect line {f.line_number}."
        )
        lines.append("")
    return "\n".join(lines) + "\n"


def format_findings(findings: Iterable[Finding], fmt: str) -> str:
    """Dispatch to the requested formatter."""
    items = list(findings)
    if fmt == "json":
        return to_json(items)
    if fmt == "h1md":
        return to_h1md(items)
    raise ValueError(f"unknown format: {fmt}")
