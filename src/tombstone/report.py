"""Output formatters: JSON, HackerOne markdown, and Bugcrowd markdown."""

from __future__ import annotations

import json
from typing import Iterable

from .scanner import WORKTREE_COMMIT, Finding


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
        lines.append(f"- **Confidence:** {f.confidence}")
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
        if f.commit == WORKTREE_COMMIT:
            lines.append(
                "**Reproduction:** this credential is uncommitted — it exists "
                f"only in the working tree. Inspect `{f.file_path}` line "
                f"{f.line_number} directly in the checked-out repository."
            )
        else:
            lines.append(
                "**Reproduction:** "
                f"`git -C <repo> show {f.commit}:{f.file_path}` "
                f"and inspect line {f.line_number}."
            )
        lines.append("")
    return "\n".join(lines) + "\n"


# Severity rationale keyed by rule_id. Drives the Bugcrowd "Demonstrated
# Impact" section. Unknown rules fall back to the generic entry.
_SEVERITY: dict[str, tuple[str, str]] = {
    "aws-access-key-id": (
        "Critical (P1)",
        "A live AWS access key ID grants programmatic access to the target's "
        "AWS account. Depending on the attached IAM policy this can range from "
        "data exfiltration to full account takeover. AWS keys are treated as "
        "Critical/P1 on Bugcrowd's Vulnerability Rating Taxonomy.",
    ),
    "stripe-secret-key": (
        "Critical (P1)",
        "A Stripe secret key permits charges, refunds, and access to customer "
        "payment data via the Stripe API. A live secret key is a Critical/P1 "
        "financial exposure under the Bugcrowd VRT.",
    ),
    "generic-high-entropy-secret": (
        "High (P2)",
        "A high-entropy value assigned to a credential-like key is very likely "
        "a live secret (API token, password, or private key). Concrete impact "
        "depends on the service it authenticates to; rated High/P2 pending "
        "confirmation of the target system.",
    ),
    "github-pat": (
        "Critical (P1)",
        "A GitHub Personal Access Token grants programmatic access to the "
        "target's repositories and, depending on scope, organization settings "
        "and CI. Source-code exfiltration and supply-chain tampering make a "
        "live PAT a Critical/P1 exposure under the Bugcrowd VRT.",
    ),
    "gcp-service-account-key": (
        "Critical (P1)",
        "A GCP service-account key JSON authenticates as that service account, "
        "inheriting all of its IAM bindings — frequently broad project-level "
        "roles. This can enable data exfiltration or full project takeover; "
        "rated Critical/P1.",
    ),
    "azure-devops-pat": (
        "Critical (P1)",
        "An Azure DevOps Personal Access Token grants access to repositories, "
        "pipelines, and artifacts within the organization per the token's "
        "scope, enabling source theft and build tampering. Critical/P1.",
    ),
    "openai-api-key": (
        "High (P2)",
        "An OpenAI API key permits billed model usage and access to any "
        "fine-tunes, files, or assistants on the account. Direct financial "
        "exposure plus potential data access; rated High/P2.",
    ),
    "huggingface-token": (
        "High (P2)",
        "A Hugging Face access token can read or write the account's models, "
        "datasets, and Spaces per its scope, enabling private-asset theft or "
        "supply-chain tampering. Rated High/P2.",
    ),
    "anthropic-api-key": (
        "High (P2)",
        "An Anthropic (Claude) API key permits billed model usage on the "
        "account. Direct financial exposure; rated High/P2.",
    ),
    "workflow-secret-exposure": (
        "High (P2)",
        "A GitHub Actions workflow construct leaks a configured secret into the "
        "run log (e.g. a `${{ secrets.X }}` interpolated into a shell command, "
        "or an `echo` of a secret-derived variable). Anyone able to read the "
        "Actions logs — or trigger the workflow — can recover the secret. This "
        "mirrors the 2025 tj-actions/changed-files supply-chain exposure; rated "
        "High/P2 pending confirmation of which secret and who can read the logs.",
    ),
}

_DEFAULT_SEVERITY = (
    "High (P2)",
    "Leaked credentials grant unauthorized access to the associated service. "
    "Severity should be finalized against the Bugcrowd VRT once the credential "
    "type and blast radius are confirmed.",
)


def to_bcmd(findings: Iterable[Finding]) -> str:
    """Serialize findings to Bugcrowd-style markdown.

    Bugcrowd's preferred submission format uses fixed sections per finding:
    Overview, Walkthrough & PoC, Vulnerability Evidence, and Demonstrated
    Impact. Each finding below renders that schema.
    """
    items = list(findings)
    lines: list[str] = []
    lines.append("# tombstone credential findings (Bugcrowd format)")
    lines.append("")
    lines.append(f"**Total findings:** {len(items)}")
    lines.append("")
    if not items:
        lines.append("_No credentials detected._")
        return "\n".join(lines) + "\n"
    for i, f in enumerate(items, start=1):
        severity, rationale = _SEVERITY.get(f.rule_id, _DEFAULT_SEVERITY)
        is_worktree = f.commit == WORKTREE_COMMIT
        lines.append(f"# Finding {i}")
        lines.append("")
        # Overview — one-line description.
        lines.append("## Overview")
        lines.append("")
        location = (
            "the uncommitted working tree"
            if is_worktree
            else "the git history"
        )
        lines.append(
            f"{f.description} (`{f.rule_id}`) leaked in {location} at "
            f"`{f.file_path}`:{f.line_number}. Severity: {severity}. "
            f"Confidence: {f.confidence}."
        )
        lines.append("")
        # Walkthrough & PoC — commands to reproduce.
        lines.append("## Walkthrough & PoC")
        lines.append("")
        if is_worktree:
            lines.append(
                "The credential exists only in the working tree (it was never "
                "committed). Reproduce with:"
            )
            lines.append("")
            lines.append("```sh")
            lines.append("# Inspect the uncommitted file in the working copy")
            lines.append(f"cat {f.file_path}")
            lines.append("")
            lines.append("# Confirm it is not tracked in git history")
            lines.append(f"git log --all -p -- {f.file_path}")
            lines.append("```")
            lines.append("")
            lines.append(
                f"The credential appears on line {f.line_number} of the "
                "uncommitted file."
            )
        else:
            lines.append(
                "The credential is recoverable from the repository's git "
                "history. Reproduce with:"
            )
            lines.append("")
            lines.append("```sh")
            lines.append("# Inspect the file as it existed in the flagged commit")
            lines.append(f"git show {f.commit}:{f.file_path}")
            lines.append("")
            lines.append("# Or trace the credential across all history for this file")
            lines.append(f"git log --all -p -- {f.file_path}")
            lines.append("```")
            lines.append("")
            lines.append(
                f"The credential appears on line {f.line_number} of the file at "
                f"commit `{f.commit}`."
            )
        lines.append("")
        # Vulnerability Evidence — redacted context block.
        lines.append("## Vulnerability Evidence")
        lines.append("")
        lines.append(
            "Redacted context (the secret is masked to avoid exposing the live "
            "credential in this report):"
        )
        lines.append("")
        lines.append("```")
        lines.append(f.redacted_context)
        lines.append("```")
        lines.append("")
        # Demonstrated Impact — severity rationale by credential type.
        lines.append("## Demonstrated Impact")
        lines.append("")
        lines.append(f"**Severity:** {severity}")
        lines.append("")
        lines.append(rationale)
        lines.append("")
    return "\n".join(lines) + "\n"


def format_findings(findings: Iterable[Finding], fmt: str) -> str:
    """Dispatch to the requested formatter."""
    items = list(findings)
    if fmt == "json":
        return to_json(items)
    if fmt == "h1md":
        return to_h1md(items)
    if fmt == "bcmd":
        return to_bcmd(items)
    raise ValueError(f"unknown format: {fmt}")
