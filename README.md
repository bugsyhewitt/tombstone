# tombstone

Offensive-side credential extraction for bug-bounty engagements.

The defender-side credential-scanning space is crowded (gitleaks, trufflehog,
gitguardian, detect-secrets). `tombstone` is built for the other side of the
engagement: extracting leaked credentials from in-scope targets during
authorized bug-bounty work. It scans the **full git history** of a repository —
not just the working tree — and emits structured findings with reproducibility
evidence (commit hash, file path, line number, redacted context), with
H1/Bugcrowd scope enforcement baked in.

> tombstone is for **authorized** offensive security work only. When you supply
> a `--scope-file`, tombstone refuses to scan anything outside the declared
> scope.

## Install

```sh
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires Python 3.13+.

## Usage

Scan a repository's full history and emit JSON findings:

```sh
tombstone --repo-path ./path/to/target-repo --format json
```

Emit HackerOne-ready markdown for a report instead:

```sh
tombstone --repo-path ./path/to/target-repo --format h1md
```

Emit Bugcrowd-ready markdown (Overview / Walkthrough & PoC / Vulnerability
Evidence / Demonstrated Impact sections, matching Bugcrowd's submission schema):

```sh
tombstone --repo-path ./path/to/target-repo --format bcmd
```

Emit SARIF 2.1.0 for GitHub code scanning, the VS Code SARIF viewer, or any CI
dashboard that ingests static-analysis results:

```sh
tombstone --repo-path ./path/to/target-repo --format sarif > tombstone.sarif
```

SARIF is the OASIS-standard JSON schema for analysis results. The output is a
single `runs` entry whose `tool.driver.rules` lists each matched detection rule
once and whose `results` carry a SARIF `level` (critical/high → `error`,
medium → `warning`, low → `note`), a `security-severity` score for GitHub
alert bucketing, a physical location (file + line), the redacted context as the
region snippet, and a `partialFingerprints` entry that dedupes the same
credential across re-scans even when the anchoring commit changes. The raw
secret is never emitted — the fingerprint is a SHA-256 hash. Upload the file via
`github/codeql-action/upload-sarif` to surface findings as code-scanning alerts.

Also scan the working tree (uncommitted files), not just git history:

```sh
tombstone --repo-path ./path/to/target-repo --include-worktree
```

By default tombstone scans only committed history. `--include-worktree`
additionally walks the checked-out files (skipping `.git/`), catching
credentials that exist **only** in the working copy — the classic "removed from
history but left in a stray `.env`" pattern. Working-tree findings are reported
with the commit field set to `WORKTREE` and are deduplicated against history
findings by `(rule, secret)`, so a credential present in both is reported once.

Flag GitHub Actions workflows that leak secrets into CI logs:

```sh
tombstone --repo-path ./path/to/target-repo --workflow-scan
```

See [Workflow secret-exposure scanning](#workflow-secret-exposure-scanning)
below.

Suppress known test credentials with an allowlist:

```sh
# Built-in default allowlist is on automatically — known fakes are dropped.
tombstone --repo-path ./target-repo

# Add your own suppressions on top of the default.
tombstone --repo-path ./target-repo --allowlist ./allow.toml

# Report everything verbatim, including known fakes.
tombstone --repo-path ./target-repo --no-allowlist
```

See [Suppression allowlist](#suppression-allowlist) below for the file format.

### Org-wide sweep: `tombstone gh-org`

Bug-bounty scopes are frequently defined at the **organization** level, not a
single repo. The `gh-org` subcommand enumerates every repository in a GitHub
organization, clones each, runs the same history scan, and aggregates the
findings into one report:

```sh
tombstone gh-org acme-corp
```

It honours the same scanning options as a single-repo run:

```sh
# Scope-filter the org sweep: repos whose clone URL matches no in-scope entry
# are skipped before any clone happens (no out-of-scope network fetch).
tombstone gh-org acme-corp --scope-file ./scope.txt

# Also scan each clone's working tree, add a user allowlist, and tune parallelism.
tombstone gh-org acme-corp --include-worktree --allowlist ./allow.toml --workers 8
```

Authentication uses the `GITHUB_TOKEN` environment variable by default (the same
token the rest of the suite uses), or an explicit `--github-token`:

```sh
export GITHUB_TOKEN=ghp_...
tombstone gh-org acme-corp
```

Repos are scanned in parallel (default 4 workers). Archived repositories are
skipped unless you pass `--include-archived`. The output envelope contains a
`summary` (repos discovered / scanned / skipped / errored, total findings) and a
`repos` array with per-repo findings:

```json
{
  "tool": "tombstone",
  "mode": "gh-org",
  "org": "acme-corp",
  "summary": {
    "repos_discovered": 12,
    "repos_scanned": 10,
    "repos_skipped_out_of_scope": 1,
    "repos_errored": 1,
    "total_findings": 4
  },
  "repos": [ { "repo": "acme-corp/payments", "finding_count": 2, "findings": [ ... ] } ]
}
```

The legacy single-repo invocation (`tombstone --repo-path ...`) is unchanged;
`gh-org` is an additional mode.

##### Report formats for an org sweep

By default `gh-org` emits the JSON envelope above. Pass `--format` to render the
sweep in a submission- or dashboard-ready format instead — the same four formats
the single-repo scan supports:

```sh
# HackerOne / Bugcrowd markdown for a whole org, ready to paste into a report
tombstone gh-org acme-corp --scope-file ./scope.txt --format h1md -o acme.md
tombstone gh-org acme-corp --scope-file ./scope.txt --format bcmd -o acme.md

# SARIF 2.1.0 for a code-scanning dashboard, aggregated across the org
tombstone gh-org acme-corp --format sarif -o acme.sarif
```

The `h1md`, `bcmd`, and `sarif` formats flatten findings from every **scanned**
repo into one report (skipped and errored repos contribute nothing, just like the
`--fail-on` gate). Because those formats have no per-repo dimension on their own,
each finding's file path is prefixed with its source repository as
`owner/repo:path` — e.g. `acme-corp/payments:src/config.py` — so the report stays
unambiguous and the reproduction commands point at the right clone. `--format
json` is unchanged and remains the only format carrying the scope/skip/error
bookkeeping.

#### `gh-org` flags

| Flag | Description |
|------|-------------|
| `org` (positional) | GitHub organization name to enumerate and scan |
| `--format {json,h1md,bcmd,sarif}` | Output format. `json` (default; per-repo envelope with scope/error bookkeeping), `h1md` (HackerOne markdown), `bcmd` (Bugcrowd markdown), or `sarif` (SARIF 2.1.0). The report formats aggregate findings across scanned repos and prefix each finding's file path with its repo (`owner/repo:path`) |
| `--github-token TOKEN` | GitHub token for API + cloning; defaults to `GITHUB_TOKEN` env var |
| `--scope-file FILE` | Skip discovered repos whose clone URL matches no in-scope entry |
| `--pattern-set {minimal,aws,full}` | Detection rule set (default: `full`) |
| `--include-worktree` | Also scan each clone's working tree |
| `--allowlist FILE` | TOML allowlist merged with the built-in default |
| `--no-allowlist` | Disable all suppression |
| `--workers N` | Repos scanned in parallel (default: 4) |
| `--include-archived` | Also scan archived repositories (skipped by default) |
| `--fail-on SEVERITY` | Exit with code `3` if any finding in any scanned repo is at or above this severity (`critical` > `high` > `medium` > `low`). Off by default. Use in CI to fail an org-wide sweep on a leaked credential. Allowlist-suppressed findings, and repos skipped (out of scope) or errored, do not count |
| `--output-file PATH`, `-o PATH` | Write the aggregated JSON envelope to `PATH` instead of stdout. Parent directories are created if needed; status lines stay on stderr. Default: write to stdout |

Enforce bug-bounty scope (refuses out-of-scope repos, exits non-zero):

```sh
tombstone --scope-file ./scope.txt --repo-path ./path/to/target-repo
```

Choose a pattern set:

```sh
tombstone --repo-path ./target-repo --pattern-set aws   # AWS keys only
tombstone --repo-path ./target-repo --pattern-set full  # all rules (default)
```

### Flags

| Flag | Description |
|------|-------------|
| `--repo-path` | Path to the target git repository to scan (required) |
| `--scope-file` | Path to a bounty scope file; out-of-scope repos are refused |
| `--format {json,h1md,bcmd,sarif}` | Output format. `json` (default), `h1md` (HackerOne markdown), `bcmd` (Bugcrowd markdown), or `sarif` (SARIF 2.1.0 for GitHub code scanning / CI) |
| `--pattern-set {minimal,aws,full}` | Which detection rules to apply (default: `full`) |
| `--include-worktree` | Also scan the working tree (uncommitted files), not just git history. Worktree findings carry commit `WORKTREE` and are deduplicated against history |
| `--workflow-scan` | Also flag GitHub Actions workflow files (`.github/workflows/*.yml`) for secret-exposure anti-patterns. Emitted under the `workflow-secret-exposure` rule |
| `--since REF` | Restrict scanning to commits reachable from HEAD but not from `REF` (`git log REF..HEAD`). Useful for incremental rescans |
| `--until REF` | Restrict scanning to commits up to and including `REF` (`git log REF`). Combine with `--since` for a range |
| `--since-date DATE` | Restrict scanning to commits authored on or after `DATE` (any git date expression: `2025-01-01`, `'2 weeks ago'`, …). Filters by commit *date*, not refspec. Composes with `--since`/`--until` |
| `--until-date DATE` | Restrict scanning to commits authored on or before `DATE`. Combine with `--since-date` to bound an investigation to a date window |
| `--author NAME_OR_EMAIL` | Restrict reported findings to commits by this author (case-insensitive substring against the `Name <email>` field — matches by name or email). Scopes a scan to one committer. Working-tree findings (no commit author) are excluded when this filter is active |
| `--committer NAME_OR_EMAIL` | Restrict reported findings to commits with this git *committer* (case-insensitive substring against the `Name <email>` field). Distinct from `--author`: git records who *wrote* a change and who *applied* it, which diverge under rebase/cherry-pick/squash-merge. Composes with `--author` (both must match). Working-tree findings (no committer) are excluded when this filter is active |
| `--allowlist FILE` | Path to a TOML allowlist file suppressing known test credentials. Merged with the built-in default unless `--no-allowlist` is given |
| `--no-allowlist` | Disable all suppression, including the built-in default allowlist. Reports every match verbatim |
| `--workers N` | Threads used to scan blobs in parallel (default: `min(4, CPU count)`). Speeds up large repos; results are identical to a single-threaded run regardless of worker count. Use `1` to force serial scanning |
| `--fail-on SEVERITY` | Exit with code `3` if any reported finding is at or above this severity (`critical` > `high` > `medium` > `low`). Off by default. Use in CI to fail a build on leaked credentials. Allowlist-suppressed findings do not count |
| `--output-file PATH`, `-o PATH` | Write the formatted report to `PATH` instead of stdout. Parent directories are created if needed; status lines stay on stderr. Default: write to stdout |

Archive a scan's results to a file instead of stdout:

```sh
# Keep a JSON artifact of the engagement.
tombstone --repo-path ./target-repo --format json -o results/target.json

# Write SARIF straight to a file for a later code-scanning upload.
tombstone --repo-path ./target-repo --format sarif --output-file results/target.sarif
```

`--output-file` (short alias `-o`) writes only the report payload to the given
path, creating any missing parent directories. The confirmation and any
diagnostic lines (allowlist suppression counts, `--fail-on` gate messages) still
go to **stderr**, so the file holds a clean report you can commit as an
engagement artifact or feed to another tool. It composes with `--fail-on`: the
report is archived to the file first, then the gate trips the exit code. Without
`--output-file`, the report is printed to stdout exactly as before.

### Scoping findings to a committer: `--author`

`--author` narrows the reported findings to a single committer, matched
case-insensitively as a substring against each finding's `Name <email>` author
field. Because the field carries both the name and the email, you can scope by
either:

```sh
# Only credentials introduced by Jane (matches the name).
tombstone --repo-path ./target-repo --author jane

# Same, scoping by email instead.
tombstone --repo-path ./target-repo --author jane@acme-corp
```

This is a complement to the `--since` / `--until` history-range flags: where
those scope *when* a commit landed, `--author` scopes *who* made it. The full
history is still traversed for deduplication accuracy (so the reproducibility
anchor — the earliest commit a secret appears in — is unchanged); only the
reported set is narrowed. Working-tree findings (`--include-worktree`) and
workflow-exposure findings have no backing commit author and are therefore
excluded whenever an author filter is active.

### Scoping by committer: `--committer`

Git records **two** identities on every commit: the *author* (who wrote the
change) and the *committer* (who applied it). They are identical for a plain
`git commit`, but diverge whenever a commit is replayed or applied by someone
else — a rebase, a cherry-pick, a maintainer landing a contributor's patch, or a
squash-merge bot. `--author` keys on the former; `--committer` keys on the
latter, with the same case-insensitive substring match against the `Name
<email>` field (so it matches by name or email):

```sh
# Only credentials landed by the release bot (matches the committer name).
tombstone --repo-path ./target-repo --committer 'release-bot'

# Same, scoping by the committer's email.
tombstone --repo-path ./target-repo --committer bot@ci.example
```

The two filters **compose**: supplying both `--author` and `--committer`
requires a finding to satisfy *both* — e.g. "a secret Alice wrote that the CI
bot merged":

```sh
tombstone --repo-path ./target-repo --author alice --committer ci-bot
```

Like `--author`, this narrows only the *reported* set — the full history is
still traversed so the reproducibility anchor is unchanged — and working-tree /
workflow-exposure findings (no backing commit) are excluded whenever a committer
filter is active. The committer is also emitted on every history-backed finding
in the JSON output (see [Commit attribution](#commit-attribution-author--date)).

### Scoping by date: `--since-date` / `--until-date`

`--since` / `--until` scope a scan by *refspec* — commit SHAs or refs. In a
bug-bounty engagement you more often know a *date*: the day a breach was
disclosed, the week a target shipped a risky feature, the cutoff before a
credential-rotation event. `--since-date` and `--until-date` narrow the scan by
**commit date** instead, accepting any expression git understands:

```sh
# Only commits authored on or after a date (e.g. since a breach disclosure).
tombstone --repo-path ./target-repo --since-date 2025-01-01

# Bound an investigation to a date window — what leaked during this period?
tombstone --repo-path ./target-repo \
  --since-date 2025-03-01 --until-date 2025-03-15

# Relative expressions work too.
tombstone --repo-path ./target-repo --since-date '2 weeks ago'
```

These compose with the refspec range: `--since`/`--until` and
`--since-date`/`--until-date` are applied together, so a refspec range *and* a
date window **intersect**. As with `--author`, the date filter narrows *which
commits are scanned*; a credential carried forward in a surviving file still
appears in any in-window commit whose tree contains it.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed (findings, if any, written to stdout) |
| `1` | Error (e.g. not a git repository, missing scope file) |
| `2` | Repository refused — out of bug-bounty scope |
| `3` | `--fail-on` gate tripped — a finding at or above the requested severity was reported (scan itself succeeded) |

## CI gating with `--fail-on`

By default tombstone always exits `0` after a successful scan, even when it
finds credentials — the findings go to stdout and it's up to you what to do with
them. To wire tombstone into a CI pipeline as a **gate** that fails the build on
leaked credentials, pass `--fail-on <severity>`:

```sh
# Fail the build (exit 3) if any critical-severity credential is found.
tombstone --repo-path . --fail-on critical

# Stricter: fail on anything high or above.
tombstone --repo-path . --fail-on high
```

The severity ordering is `critical > high > medium > low`: a `--fail-on high`
gate trips on both `critical` and `high` findings, but not on `medium` or `low`.
The exit code is a dedicated `3` so a policy violation is distinguishable from a
real error (`1`) or an out-of-scope refusal (`2`).

Two things make this CI-friendly:

- **The report is still emitted before the non-zero exit.** The formatted output
  (`json`, `sarif`, etc.) is written to stdout first, so the pipeline can upload
  it even when the gate trips. Pairs naturally with `--format sarif` for GitHub
  code scanning: upload the SARIF *and* fail the build in one run.
- **Allowlist-suppressed findings do not count.** A finding removed by the
  built-in or user allowlist (a known test credential) never trips the gate, so
  the default allowlist keeps the gate from firing on fixtures.

`--fail-on` also works on the `gh-org` sweep, so a single CI job can scan an
entire organization and fail the build when *any* repo leaks a credential at or
above the threshold:

```sh
# Sweep every repo in the org; exit 3 if any repo has a high-or-above finding.
tombstone gh-org acme-corp --scope-file ./scope.txt --fail-on high
```

The aggregated JSON envelope is still printed first. Only findings on repos that
were actually **scanned** count toward the org gate — a repo skipped as
out-of-scope or one that failed to clone is an operational outcome, not a
credential leak, so it never trips the gate. Allowlist suppression applies
per-repo before the gate, exactly as in the single-repo case.

## Scope-file format

One in-scope identifier per line. Lines beginning with `#` and blank lines are
ignored. A repository is considered in scope when any entry is a substring of
the repository's resolved path or its git `origin` remote URL.

```
# bug-bounty scope for the acme engagement
github.com/acme-corp        # any repo under the acme-corp GitHub org
acme-corp                   # a bare org identifier
backups.acme.internal       # an in-scope artifact host
```

If no `--scope-file` is supplied, scanning is unrestricted and is the operator's
responsibility. If a scope file **is** supplied, anything not explicitly listed
is refused.

## Detection rules

The `full` pattern set applies every rule below. Most come from the shared
[`necromancer-patterns`](https://github.com/bugsyhewitt/necromancer-patterns)
library (the suite-wide source of truth); the credential types marked
*(tombstone)* are defined locally in `tombstone.extra_patterns` to cover
high-value providers the library does not yet ship.

**Cloud / AI provider keys** (from `necromancer-patterns`):

- `aws-access-key-id` — AWS access key IDs (`AKIA…` and related prefixes)
- `stripe-secret-key` — Stripe secret keys (`sk_live_…` / `sk_test_…`)
- `github-pat` — GitHub personal access tokens (classic and fine-grained)
- `gcp-service-account-key` — GCP service-account key JSON blobs
- `azure-devops-pat` — Azure DevOps personal access tokens
- `openai-api-key` — OpenAI API keys (legacy and project-scoped)
- `huggingface-token` — Hugging Face access tokens
- `anthropic-api-key` — Anthropic (Claude) API keys
- `generic-high-entropy-secret` — high-entropy values assigned to credential-like
  keys (`api_key`, `secret`, `token`, …), with UUID / git-SHA / low-entropy
  exclusions to suppress false positives

**Additional high-value credentials** *(tombstone)*:

- `slack-token` — Slack API tokens (`xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-`)
- `google-api-key` — Google API keys (`AIza…`; Maps / Cloud / Firebase)
- `gitlab-pat` — GitLab personal access tokens (`glpat-…`)
- `sendgrid-api-key` — SendGrid API keys (`SG.<id>.<secret>`)
- `npm-token` — npm access tokens (`npm_…`; automation / publish)
- `pypi-token` — PyPI / Test-PyPI upload tokens (`pypi-AgEIcHlwaS5vcmc…`), the
  Python-registry analogue of `npm-token`. A PyPI token is a macaroon: the
  `pypi-` prefix followed by a base64url body that always begins with the fixed
  string `AgEIcHlwaS5vcmc` (the base64 of the macaroon's `pypi.org` location id),
  which is what the rule anchors on so an arbitrary `pypi-`-prefixed string does
  not match. A leaked upload token publishes or overwrites releases of the
  owner's packages — a direct software-supply-chain compromise
- `docker-hub-pat` — Docker Hub personal access tokens (`dckr_pat_…`), the
  container-registry analogue of `npm-token` and `pypi-token`. A Docker Hub PAT
  authenticates as the owning user to `docker login` and the Hub API; with
  write scope, a leaked token pushes arbitrary tags to the owner's repositories
  — a direct container supply-chain compromise where every downstream
  `docker pull` ships the attacker's image. Docker has issued PATs at both
  ~27-char and ~36-char body lengths, so the rule anchors on the distinctive
  `dckr_pat_` prefix plus a 27–40-char base64url body window to cover both
  variants
- `private-key` — committed private-key material (RSA / EC / DSA / OpenSSH / PGP
  `-----BEGIN … PRIVATE KEY-----` blocks)
- `shopify-token` — Shopify access tokens (`shpat_` / `shpss_` / `shpca_` /
  `shppa_` + 32 hex; admin / shared-secret / custom / private app)
- `twilio-account-sid` — Twilio Account SIDs (`AC` + 32 hex)
- `twilio-api-key-sid` — Twilio API Key SIDs (`SK` + 32 hex), the credential half
  of Twilio's recommended auth scheme: used as the HTTP basic-auth username,
  paired with its API Key Secret, to authenticate to the Twilio REST API. Unlike
  the Account SID (`AC…`), which is only the account identifier, a leaked `SK…`
  key is the thing you authenticate *with* — it sends SMS, places calls, and
  reads account resources billed to the target. The `AC` prefix stays owned by
  `twilio-account-sid` so the two rules never double-report a single SID
- `discord-bot-token` — Discord bot tokens (`<id>.<timestamp>.<hmac>`; JWTs are
  excluded by a negative lookahead)
- `github-token` — the GitHub token types the library's `github-pat` rule does
  not cover: `gho_` (OAuth), `ghu_` (user-to-server), `ghs_` (server-to-server /
  GitHub App installation — the shape of the Actions `GITHUB_TOKEN`), and `ghr_`
  (refresh), each `+ 36` base62 chars. The classic `ghp_` PAT is deliberately
  excluded here so it stays owned by `github-pat`
- `aws-sts-temp-key` — AWS STS temporary access key ids (`ASIA` + 16 base32),
  minted by `AssumeRole` / `GetSessionToken` / the instance-metadata service.
  The library's `aws-access-key-id` rule covers only the long-lived `AKIA`
  prefix; this fills in the `ASIA` temporary-credential id, which — paired with
  its `aws_session_token` — authenticates for the assumed role until expiry. The
  `AKIA` prefix is deliberately excluded here so it stays owned by
  `aws-access-key-id`
- `hashicorp-vault-token` — HashiCorp Vault tokens in the modern (Vault 1.10+)
  format: `hvs.<base64url>` (service tokens — the default issued by every auth
  method), `hvb.<base64url>` (batch tokens — lightweight, non-renewable,
  issued at high volume by automated workflows), and `hvr.<base64url>`
  (recovery tokens — root-equivalent, minted during disaster recovery). A
  leaked Vault token authenticates to the Vault API as the bound entity and
  inherits its full policy set — a single hop from the organization's broader
  secret estate (database credentials, cloud keys, TLS material). The library
  ships no Vault rule; this closes the secret-manager-token gap. The rule
  anchors on the `hv[sbr].` prefix plus a ≥24-char base64url body so no short
  `hvs.` lookalike can match
- `azure-storage-sas` — Azure Storage Shared Access Signature tokens (`sig=` +
  a SAS companion query param: `sv` / `sp` / `se` / `st` / `sr` / `ss` / `srt`),
  the standalone, time-boxed credential Azure mints to delegate scoped access to
  Blob / Queue / Table / File storage. The library ships an `azure-devops-pat`
  rule but no Storage SAS rule, so a SAS committed in a connection string,
  download URL, or SDK call was previously caught only by the low-confidence
  generic fallback. A leaked SAS grants its full permission set against the
  targeted resource until `se` expiry and cannot be revoked without rotating the
  storage account key. The rule anchors on `sig=` (a URL-encoded base64 HMAC,
  raw or percent-encoded) plus a required SAS companion param so an unrelated
  `sig=` field does not match

The tombstone-local rules apply in the broad `cloud` and `full` pattern sets; the
narrow `minimal` / `aws` sets stay AWS-only. Detection patterns are adapted from
the gitleaks public ruleset (Apache-2.0). See [`NOTICE`](./NOTICE) and
[`vendor/gitleaks-LICENSE`](./vendor/gitleaks-LICENSE).

## Confidence scoring

Every finding carries a `confidence` label — `high`, `medium`, or `low` — so you
can triage before filing:

- `high` — a near-certain live credential. File immediately.
- `medium` — plausible; worth a quick manual look first.
- `low` — likely a placeholder or vendor example (e.g. `AKIAIOSFODNN7EXAMPLE`,
  Stripe `sk_test_…` keys, all-zeros, `PLACEHOLDER`). Review before reporting.

Scoring is deterministic and offline — no ML, no network calls. Three signals
combine:

1. **Rule specificity.** Structurally-constrained rules (AWS key, GitHub PAT,
   Stripe key — fixed prefix + length) start at `high`. The catch-all
   `generic-high-entropy-secret` rule starts at `medium`.
2. **Known test-credential blocklist.** Published examples and placeholders are
   forced to `low` regardless of which rule matched — they are never live.
3. **Shannon entropy.** For generic matches, high entropy promotes to `high`,
   low entropy demotes to `low`.

The `confidence` field appears in JSON output, in the `h1md` / `bcmd` report
headers, and in each SARIF result's `properties`.

## Severity rating

Alongside confidence, every finding carries a `severity` label — `critical`,
`high`, `medium`, or `low`. Confidence answers *"is this a real secret?"*;
severity answers *"how bad is it if it is?"* — and the two are independent. A
finding can be low confidence but critical severity (e.g. the published AWS
`EXAMPLE` key matches the AWS rule, so it is critical severity even though
confidence scoring flags it as a likely fake).

Severity is a property of the credential *type*, taken directly from the matched
rule's declared severity in the shared `necromancer-patterns` library:

- `critical` — broad, immediate account access or direct key material. AWS access
  keys, Stripe secret keys, GitHub PATs, the GitHub OAuth / user-to-server /
  Actions-installation / refresh token family (`github-token`), GCP
  service-account keys, Azure DevOps PATs, GitLab PATs, npm tokens, PyPI upload
  tokens, Docker Hub PATs, HashiCorp Vault tokens, Shopify access tokens, and
  committed private keys.
  Critical/P1 on the HackerOne and Bugcrowd taxonomies.
- `high` — scoped service tokens and generic high-entropy matches whose blast
  radius depends on the target system (OpenAI, Hugging Face, Anthropic, Slack,
  Google API, SendGrid keys, Twilio Account SIDs, Twilio API Key SIDs, Discord
  bot tokens, `generic-high-entropy-secret`, and workflow secret-exposure
  findings).

Sort by `severity` to triage critical findings first, then use `confidence` to
decide which to file immediately versus review by hand.

The `severity` field appears in JSON output, in the `h1md` / `bcmd` report
headers, and in SARIF as both the result `level` (critical/high → `error`,
medium → `warning`, low → `note`) and a `security-severity` score. The `bcmd`
"Demonstrated Impact" section still carries the full Bugcrowd VRT rationale per
credential type.

## Commit attribution (author + date)

Every history-backed finding records **who** introduced the credential and
**when** — the `author` and the `committer` (both `"Name <email>"`) plus
`committed_at` (ISO 8601 with timezone offset) of the commit the secret was first
seen in:

```json
{
  "rule_id": "aws-access-key-id",
  "commit": "deadbeef…",
  "author": "Jane Dev <jane@acme-corp.example>",
  "committer": "Release Bot <bot@ci.example>",
  "committed_at": "2026-05-20T14:03:11+00:00",
  ...
}
```

This adds a **recency** triage signal that complements `confidence` and
`severity`: a secret committed last week is far more likely to still be live
than one from years ago, so you chase the freshest critical findings first.
Sort findings by `committed_at` descending to surface the most recently leaked
credentials. The `author` also strengthens the impact narrative in a report
(which developer leaked it, and from where), while the `committer` records who
actually *applied* the commit — the two diverge under rebase, cherry-pick, and
squash-merge workflows, and each can be scoped independently with `--author`
and [`--committer`](#scoping-by-committer---committer).

`author` and `committed_at` appear in JSON output, in the `h1md` / `bcmd`
reports (the Bugcrowd "Walkthrough & PoC" section gains an "Introduced on … by …"
line), and in each SARIF result's `properties`. The `committer` is carried in the
JSON output (it backs the `--committer` filter); the markdown and SARIF reports
keep their existing author-centric attribution line unchanged.
Working-tree findings (commit `WORKTREE`) have no backing commit, so their
`author`, `committer`, and `committed_at` are empty and the markdown reports omit
the lines rather than print blanks.

## Liveness: still present in HEAD?

Knowing **when** a credential was introduced is only half the recency story; the
other half is **whether it is still there**. A secret committed years ago and
later removed from the code is far less likely to be live than one still sitting
in the current `HEAD`. Every credential finding therefore carries a
`still_present` boolean:

- `still_present: true` — the credential's `(rule, secret)` is still found in
  the repository's current `HEAD` tree. A strong indicator it is in active use
  and likely live. **Chase these first.**
- `still_present: false` — the credential was **removed from `HEAD`** and
  survives only in older git history. It may have been rotated; tombstone still
  reports it (deep-history extraction is the point), but it is a weaker liveness
  signal — verify before relying on it.

```json
{
  "rule_id": "aws-access-key-id",
  "commit": "deadbeef…",
  "still_present": false,
  ...
}
```

The flag reflects the **true** `HEAD` state regardless of any `--since` /
`--until` / `--since-date` range used to scope *which* commits are reported, so
a windowed scan still tells you correctly whether each finding survives to the
current code. Liveness combines with `confidence` ("is it a real secret?") and
`severity` ("how bad if it is?") to give three orthogonal triage axes: a
`still_present: true`, `confidence: high`, `severity: critical` finding is the
top of the queue.

`still_present` appears in JSON output, in the `h1md` report (a **Still
present** line), in the `bcmd` "Walkthrough & PoC" section (an explicit
in-HEAD / removed-from-HEAD note), and in each SARIF result's `properties` and
message. Working-tree findings (commit `WORKTREE`) and workflow secret-exposure
findings are present by definition and are always `still_present: true`; the
`h1md` report omits the line for working-tree findings to avoid noise.

## Suppression allowlist

Confidence scoring *labels* known fakes `low`; the allowlist goes further and
**removes** them from output, so a scan of any repo that ships tests is
report-ready without manual filtering.

A **built-in default allowlist is enabled automatically** and suppresses
well-known test credentials:

- the AWS published example key `AKIAIOSFODNN7EXAMPLE`
- Stripe-style test keys (`sk_test_…`, `pk_test_…`, `rk_test_…`)
- placeholder markers (`PLACEHOLDER`, `CHANGEME`, `DUMMY`, `EXAMPLE`,
  `your-…`, `xxxx`, `REDACTED`)

To turn suppression off entirely and report every match verbatim, pass
`--no-allowlist`.

To suppress additional values, supply your own TOML allowlist with
`--allowlist <file>`. Your entries are **merged with** the built-in default
(use `--no-allowlist` together with `--allowlist` is *not* supported — the
file is ignored and a warning is printed; `--no-allowlist` always wins).

```toml
# allow.toml
# Exact secret values to suppress. Matched case-insensitively.
secrets = [
  "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es",
  "MyKnownTestSecret",
]

# Regular expressions matched against the raw secret value. A finding is
# suppressed if any pattern matches.
regexes = [
  "^TEST_[A-Z0-9]+$",
  "fixture-.*",
]
```

```sh
tombstone --repo-path ./target-repo --allowlist ./allow.toml
```

When findings are suppressed, tombstone prints a count to stderr (e.g.
`allowlist: suppressed 1 known test credential`) so the suppression is visible
without polluting the machine-readable stdout payload.

## Workflow secret-exposure scanning

GitHub Actions workflow files (`.github/workflows/*.yml` / `*.yaml`) are a
high-yield bug-bounty target. The 2025 `tj-actions/changed-files` supply-chain
incident showed that a workflow can leak a configured secret into the run log
even when no literal credential is committed — and anyone who can read a public
repo's Actions logs (or trigger a workflow) can then recover that secret.

`--workflow-scan` adds a complementary pass that flags the workflow constructs
known to produce those exposures:

```sh
tombstone --repo-path ./target-repo --workflow-scan
```

It detects:

- **`${{ secrets.X }}` interpolated into a `run:` shell command** — the
  expression expands to plaintext in the rendered command, which Actions prints
  to the log (`run: curl -H "${{ secrets.API_TOKEN }}" …`).
- **`echo` of a secret-derived environment variable** — `run: echo "$DEPLOY_TOKEN"`
  prints the secret straight to the log.
- **A secret passed as a command-line flag value** — `--token=${{ secrets.X }}`
  is visible in the log *and* in the runner's process table.

The detector is precision-tuned: the **recommended safe pattern** — mapping a
secret into `env:` (`DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}`) without echoing
it — is **not** flagged, and an `echo` of a non-secret variable (`echo "$HOME"`)
is left alone.

Workflow findings flow through every output format (`json`, `h1md`, `bcmd`,
`sarif`) under the `workflow-secret-exposure` rule at `confidence: medium` (they flag a
dangerous *pattern*, not a confirmed live credential). Because they expose a
construct rather than a literal secret, the evidence line is shown in full.
`--workflow-scan` reuses the history blobs already gathered for the credential
scan (so it honours `--since` / `--until` and adds no extra git traversal), and
with `--include-worktree` it also checks workflow files in the working tree.

## Parallel scanning

Large target repos — monorepos, long-lived open-source projects — can carry
tens of thousands of commits. tombstone scans blobs across a thread pool to keep
those scans fast:

```sh
# Default: min(4, CPU count) workers.
tombstone --repo-path ./big-monorepo

# Tune parallelism explicitly.
tombstone --repo-path ./big-monorepo --workers 8

# Force a single-threaded scan (e.g. for reproducible benchmarking).
tombstone --repo-path ./big-monorepo --workers 1
```

Output is **identical regardless of `--workers`**. Blob bytes are read in
commit-iteration order, the CPU-bound regex matching is distributed across the
pool, and per-blob results are reassembled in that same order before
deduplication — so the reproducibility anchor (the commit a deduped secret is
reported against) is deterministic. A parallel scan never changes *which*
findings you get or which commit they point to; it only changes how fast you get
them.

The `gh-org` subcommand has its own `--workers` flag that controls how many
**repositories** are scanned in parallel; each individual repo scan within an
org sweep currently runs single-threaded.

## Not in v0.1

ML true/false-positive classification, live API verification of credentials,
scanning of S3 / Docker images / Slack, a web UI, and a custom rule-authoring
DSL are all out of scope for v0.1.

## Development

```sh
pip install -e '.[dev]'
python tests/build_fixtures.py   # regenerate test git repos if needed
pytest
```

## License

tombstone is released under the MIT License (see [`LICENSE`](./LICENSE)).
Bundled gitleaks-derived patterns are attributed under Apache-2.0 in
[`NOTICE`](./NOTICE).
