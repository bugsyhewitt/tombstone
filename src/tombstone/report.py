"""Output formatters: JSON, HackerOne markdown, Bugcrowd markdown, and SARIF."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable

from . import __version__
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
        lines.append(f"- **Severity:** {f.severity}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"- **Commit:** `{f.commit}`")
        if f.author:
            lines.append(f"- **Author:** {f.author}")
        if f.committed_at:
            lines.append(f"- **Committed:** {f.committed_at}")
        # Liveness is reported only for history findings — worktree findings are
        # present on disk by definition, so the line would be noise there.
        if f.commit != WORKTREE_COMMIT:
            present = (
                "yes — still in current HEAD"
                if f.still_present
                else "no — removed from HEAD, only in history"
            )
            lines.append(f"- **Still present:** {present}")
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
    "shopify-token": (
        "Critical (P1)",
        "A Shopify access token authenticates to a store's Admin or Storefront "
        "API per the token class, granting read/write access to orders, "
        "customers, and products — and, for an admin token, to PII and payouts. "
        "A live token is a Critical/P1 exposure under the Bugcrowd VRT.",
    ),
    "twilio-account-sid": (
        "High (P2)",
        "A Twilio Account SID is the account identifier that, paired with an "
        "auth token, sends SMS and places calls billed to the target — a "
        "toll-fraud and smishing primitive. Rated High/P2; escalates to "
        "Critical when a matching auth token is also recovered.",
    ),
    "twilio-api-key-sid": (
        "High (P2)",
        "A Twilio API Key SID (`SK…`) is the credential half of Twilio's "
        "recommended auth scheme — used as the HTTP basic-auth username, paired "
        "with the API Key Secret, to authenticate to the Twilio REST API. Unlike "
        "the Account SID (`AC…`), which is only the account identifier, a live "
        "API Key SID is the thing you authenticate with: it sends SMS, places "
        "calls, and reads account resources billed to the target — a toll-fraud "
        "and smishing primitive. Rated High/P2; escalates to Critical when the "
        "matching API Key Secret is also recovered.",
    ),
    "discord-bot-token": (
        "High (P2)",
        "A Discord bot token authenticates as the bot, allowing it to read "
        "guild messages, manage members, and post as the integration per its "
        "gateway intents and permissions. Rated High/P2 pending confirmation of "
        "the bot's privileges in the target's servers.",
    ),
    "github-token": (
        "Critical (P1)",
        "A GitHub OAuth / user-to-server / GitHub App installation (`ghs_`, the "
        "shape of the Actions `GITHUB_TOKEN`) / refresh token grants programmatic "
        "access to the target's repositories and, per the app or installation "
        "scope, organization settings and CI. Source-code exfiltration and "
        "supply-chain tampering make a live token a Critical/P1 exposure under "
        "the Bugcrowd VRT, on par with a classic personal access token.",
    ),
    "aws-sts-temp-key": (
        "High (P2)",
        "An AWS STS temporary access key id (`ASIA…`) is the credential id minted "
        "by `AssumeRole` / `GetSessionToken` / the instance-metadata service. "
        "Paired with the matching `aws_session_token` it authenticates to AWS for "
        "the assumed role's full permission set until the token expires, enabling "
        "data exfiltration or lateral movement scoped to that role. Rated High/P2; "
        "escalates to Critical when a still-valid session token is also recovered "
        "or the role carries broad privileges.",
    ),
    "pypi-token": (
        "Critical (P1)",
        "A PyPI API token (`pypi-…`) is an upload credential that publishes or "
        "overwrites releases of the owner's Python packages. A leaked token is a "
        "direct software-supply-chain compromise: an attacker can ship a "
        "backdoored release that every downstream `pip install` then pulls. The "
        "npm analogue (`npm-token`) is treated the same way; rated Critical/P1 "
        "under the Bugcrowd VRT, escalating with the popularity of the account's "
        "packages.",
    ),
    "docker-hub-pat": (
        "Critical (P1)",
        "A Docker Hub personal access token (`dckr_pat_…`) authenticates as the "
        "owning user to `docker login` and the Docker Hub API. With write scope, "
        "a leaked token publishes — and overwrites — images under the owner's "
        "repositories: a direct container supply-chain compromise where every "
        "downstream `docker pull` of the affected tag ships the attacker's "
        "image. The npm and PyPI analogues (`npm-token`, `pypi-token`) are "
        "treated the same way; rated Critical/P1 under the Bugcrowd VRT, "
        "escalating with the pull popularity of the account's images.",
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
            f"`{f.file_path}`:{f.line_number}. "
            f"Severity: {severity} ({f.severity}). "
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
            if f.author or f.committed_at:
                attribution = "Introduced"
                if f.committed_at:
                    attribution += f" on {f.committed_at}"
                if f.author:
                    attribution += f" by {f.author}"
                lines.append("")
                lines.append(f"{attribution}.")
            # Liveness note: whether the credential survives to current HEAD. A
            # still-present secret is a stronger live-credential signal than one
            # removed from the latest code, so call it out explicitly.
            lines.append("")
            if f.still_present:
                lines.append(
                    "This credential is **still present in the current HEAD** "
                    "of the repository, not merely in older history — a strong "
                    "indicator it is in active use and likely live."
                )
            else:
                lines.append(
                    "This credential was **removed from the current HEAD** and "
                    "survives only in git history. It may have been rotated; "
                    "verify before relying on it."
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


# SARIF 2.1.0 result levels keyed by tombstone's severity label. SARIF has only
# three levels (error / warning / note); critical and high both map to "error"
# so they surface as failures in GitHub code scanning and CI, medium becomes a
# warning, and low a note. Unknown values fall back to "warning".
_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/"
    "schema/sarif-schema-2.1.0.json"
)
_SARIF_INFO_URI = "https://github.com/bugsyhewitt/tombstone"


def to_sarif(findings: Iterable[Finding]) -> str:
    """Serialize findings to SARIF 2.1.0 (Static Analysis Results Interchange Format).

    SARIF is the OASIS-standard JSON schema for static-analysis results,
    consumed natively by GitHub code scanning, VS Code's SARIF viewer, Azure
    DevOps, and most CI dashboards. Emitting SARIF lets a researcher push
    tombstone output straight into those tools instead of hand-translating JSON.

    Each distinct ``rule_id`` becomes a ``reportingDescriptor`` under
    ``tool.driver.rules``; each finding becomes a ``result`` referencing its rule
    by index, carrying a SARIF ``level`` derived from the finding's severity, a
    physical location (file + 1-based line), and ``partialFingerprints`` so
    re-runs deduplicate stably across commits. The redacted context — never the
    raw secret — is included in the result message and as a region snippet.
    """
    items = list(findings)

    # Build a stable, ordered rule index. Rules appear in first-seen order so the
    # output is deterministic for a given finding list.
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    for f in items:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append(
                {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": ["security", "credential", "secret"],
                        "security-severity": _security_severity(f.severity),
                    },
                }
            )

    results: list[dict] = []
    for f in items:
        is_worktree = f.commit == WORKTREE_COMMIT
        if is_worktree:
            commit_note = "uncommitted working tree"
        else:
            commit_note = f"commit {f.commit}"
        message = (
            f"{f.description} ({f.rule_id}) leaked in {commit_note} at "
            f"{f.file_path}:{f.line_number}. "
            f"severity={f.severity} confidence={f.confidence} "
            f"still_present={str(f.still_present).lower()}. "
            f"context: {f.redacted_context}"
        )
        result = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": max(f.line_number, 1),
                            "snippet": {"text": f.redacted_context},
                        },
                    }
                }
            ],
            # Stable across runs: same secret in the same rule/file dedupes even
            # if the anchoring commit changes between scans. The secret itself is
            # SHA-256 hashed so the raw credential never appears in the output.
            "partialFingerprints": {
                "tombstone/v1": _fingerprint(f.rule_id, f.file_path, f._secret)
            },
            "properties": {
                "confidence": f.confidence,
                "severity": f.severity,
                "commit": f.commit,
                "still_present": f.still_present,
            },
        }
        # Surface commit attribution when present (history findings only).
        if f.author:
            result["properties"]["author"] = f.author
        if f.committed_at:
            result["properties"]["committed_at"] = f.committed_at
        results.append(result)

    document = {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tombstone",
                        "version": __version__,
                        "informationUri": _SARIF_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)


def _fingerprint(rule_id: str, file_path: str, secret: str) -> str:
    """Return a stable dedupe fingerprint that never embeds the raw secret.

    The secret is SHA-256 hashed (truncated to 16 hex chars — ample for
    collision-free dedupe) so two scans of the same credential in the same
    rule/file produce an identical fingerprint without the live credential ever
    appearing in the SARIF document.
    """
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
    return f"{rule_id}:{file_path}:{digest}"


def _security_severity(severity: str) -> str:
    """Map a tombstone severity label to a SARIF ``security-severity`` score.

    GitHub code scanning reads ``security-severity`` (a 0.0–10.0 CVSS-style
    string) to bucket alerts. The mapping mirrors GitHub's own thresholds:
    critical >= 9.0, high >= 7.0, medium >= 4.0, low >= 0.1.
    """
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.0",
        "low": "2.0",
    }.get(severity, "5.0")


def format_findings(findings: Iterable[Finding], fmt: str) -> str:
    """Dispatch to the requested formatter."""
    items = list(findings)
    if fmt == "json":
        return to_json(items)
    if fmt == "h1md":
        return to_h1md(items)
    if fmt == "bcmd":
        return to_bcmd(items)
    if fmt == "sarif":
        return to_sarif(items)
    raise ValueError(f"unknown format: {fmt}")
