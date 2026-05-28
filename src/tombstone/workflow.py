"""GitHub Actions workflow secret-exposure detection.

tombstone's core scan extracts *committed credentials*. This module adds a
complementary, workflow-specific signal: it flags GitHub Actions workflow files
(``.github/workflows/*.yml`` / ``*.yaml``) that contain constructs known to
**leak secrets into CI logs** — even when no literal credential is present in the
file. These are dangerous *patterns*, not credentials, so they live here in
tombstone rather than in the shared necromancer-patterns credential library.

The 2025 ``tj-actions/changed-files`` supply-chain incident made workflow-log
secret exposure a standard bug-bounty target: a researcher who can read a
public repo's Actions logs (or trigger a workflow) can often recover secrets the
maintainers believed were protected. The anti-patterns detected here are the
ones that produce those exposures:

* a secret interpolated directly into a ``run:`` shell line (``${{ secrets.X }}``
  expands to plaintext in the rendered command, which Actions prints to the log);
* a shell ``echo`` of an environment variable that was populated from a secret
  (``run: echo "$TOKEN"``);
* a secret passed as a command-line flag value (``--token=${{ secrets.X }}``),
  which is visible both in the log and in the process table on the runner;
* ``${{ secrets.X }}`` used in ``actions/github-script`` / ``run:`` JS where it
  is concatenated into a string that may be logged.

Findings are emitted as ordinary :class:`~tombstone.scanner.Finding` objects so
they flow through the existing JSON / h1md / bcmd formatters unchanged. The
``_secret`` field carries a stable dedupe key derived from the matched
construct (not a real credential — workflow findings expose a *pattern*, and the
actual secret value is never present in the file).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

# Workflow files live under .github/workflows/ with a .yml or .yaml extension.
# Matched against the POSIX-style relative path used elsewhere in the scanner.
_WORKFLOW_PATH_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")

# A single rule_id family so downstream severity / report logic can treat all
# workflow exposures consistently while the human-readable description varies.
WORKFLOW_RULE_ID = "workflow-secret-exposure"


@dataclass(frozen=True)
class WorkflowPattern:
    """A workflow secret-exposure anti-pattern."""

    key: str
    description: str
    regex: re.Pattern[str]


# ${{ secrets.NAME }} interpolated anywhere on a `run:`-context shell line.
# We detect the secrets reference; the surrounding `run:` heuristic is applied
# by the line classifier below (a secret in `env:` mapping is normal and safe).
_SECRETS_REF = r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"

WORKFLOW_PATTERNS: tuple[WorkflowPattern, ...] = (
    WorkflowPattern(
        key="secret-in-run",
        description=(
            "GitHub Actions secret interpolated into a shell command "
            "(expands to plaintext in the workflow run log)"
        ),
        # secrets.X reference that we will only accept on shell-command lines.
        regex=re.compile(_SECRETS_REF),
    ),
    WorkflowPattern(
        key="echo-secret-env",
        description=(
            "shell `echo` of a secret-derived environment variable in a "
            "workflow step (prints the secret to the run log)"
        ),
        # echo of $VAR / ${VAR} / "$VAR" where VAR looks secret-ish.
        regex=re.compile(
            r"echo\b[^\n]*\$\{?\"?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\}?",
        ),
    ),
)

# A variable name is treated as "secret-ish" for the echo heuristic if it
# contains any of these tokens (case-insensitive). Keeps `echo "$HOME"` etc. out.
_SECRETISH_TOKENS = (
    "secret",
    "token",
    "key",
    "passwd",
    "password",
    "pass",
    "credential",
    "cred",
    "auth",
    "api",
    "pat",
)


def is_workflow_file(file_path: str) -> bool:
    """Return True if *file_path* is a GitHub Actions workflow file."""
    return bool(_WORKFLOW_PATH_RE.search(file_path))


def _is_shell_command_line(line: str) -> bool:
    """Heuristic: does *line* belong to a `run:`/shell context (vs `env:`)?

    A ``${{ secrets.X }}`` reference is only dangerous when it lands inside a
    shell command that Actions renders and logs. The same reference inside an
    ``env:`` mapping (``MY_TOKEN: ${{ secrets.X }}``) is the *recommended* safe
    pattern and must not be flagged. We approximate "shell context" as: the line
    is an inline ``run:`` step, or it contains a shell command verb / pipe /
    redirection, or it is a flag-style assignment passing the secret as an
    argument — and it is NOT a bare ``KEY: ${{ secrets.X }}`` env mapping.
    """
    stripped = line.strip()
    # `run: <command>` inline form, or a continuation line of a block `run: |`.
    if re.match(r"run\s*:", stripped):
        return True
    # Flag-style argument passing: --token=${{ secrets.X }} or --token ${{...}}.
    if re.search(r"--?[A-Za-z][\w-]*[=\s]\S*\$\{\{\s*secrets\.", line):
        return True
    # Common shell verbs / operators that indicate a command, not a mapping.
    if re.search(r"\b(echo|curl|wget|printf|export|eval|cat)\b", line):
        return True
    if re.search(r"[|&><]", line):
        return True
    # A bare YAML mapping `KEY: ${{ secrets.X }}` (env-style) is safe — skip it.
    if re.match(r"[A-Za-z_][\w-]*\s*:\s*" + _SECRETS_REF + r"\s*$", stripped):
        return False
    return False


def _var_is_secretish(name: str) -> bool:
    lowered = name.lower()
    return any(tok in lowered for tok in _SECRETISH_TOKENS)


@dataclass(frozen=True)
class WorkflowHit:
    """A raw workflow anti-pattern hit, before conversion to a Finding."""

    pattern_key: str
    description: str
    line_number: int
    line: str
    dedupe_token: str


def scan_workflow_text(text: str) -> Iterator[WorkflowHit]:
    """Yield :class:`WorkflowHit`\\ s for secret-exposure anti-patterns in *text*.

    *text* is the full content of a workflow YAML file. Lines are examined
    independently; the heuristics intentionally err toward *precision* (avoid
    flagging the safe ``env:``-mapping pattern) since false positives in a
    bug-bounty report erode trust.
    """
    for idx, line in enumerate(text.splitlines(), start=1):
        # 1. secrets.X interpolated into a shell command line.
        for m in re.finditer(_SECRETS_REF, line):
            if _is_shell_command_line(line):
                secret_name = m.group(1)
                yield WorkflowHit(
                    pattern_key="secret-in-run",
                    description=(
                        "GitHub Actions secret `secrets."
                        f"{secret_name}` interpolated into a shell command "
                        "(expands to plaintext in the workflow run log)"
                    ),
                    line_number=idx,
                    line=line,
                    dedupe_token=f"secret-in-run:{secret_name}",
                )

        # 2. echo of a secret-ish env var.
        for m in re.finditer(
            r"echo\b[^\n]*?\$\{?\"?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\}?",
            line,
        ):
            var = m.group("var")
            if _var_is_secretish(var):
                yield WorkflowHit(
                    pattern_key="echo-secret-env",
                    description=(
                        f"shell `echo` of secret-derived variable `${var}` in a "
                        "workflow step (prints the secret to the run log)"
                    ),
                    line_number=idx,
                    line=line,
                    dedupe_token=f"echo-secret-env:{var}",
                )


def redact_workflow_line(line: str) -> str:
    """Return a trimmed, log-safe rendering of a workflow line for evidence.

    Workflow hits expose a *pattern*, not a literal credential, so the line is
    safe to show — but we still strip surrounding whitespace and cap length so
    the report evidence block stays tidy.
    """
    trimmed = line.strip()
    if len(trimmed) > 200:
        trimmed = trimmed[:197] + "..."
    return trimmed
