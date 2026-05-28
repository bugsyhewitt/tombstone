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
findings into one JSON envelope:

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

#### `gh-org` flags

| Flag | Description |
|------|-------------|
| `org` (positional) | GitHub organization name to enumerate and scan |
| `--github-token TOKEN` | GitHub token for API + cloning; defaults to `GITHUB_TOKEN` env var |
| `--scope-file FILE` | Skip discovered repos whose clone URL matches no in-scope entry |
| `--pattern-set {minimal,aws,full}` | Detection rule set (default: `full`) |
| `--include-worktree` | Also scan each clone's working tree |
| `--allowlist FILE` | TOML allowlist merged with the built-in default |
| `--no-allowlist` | Disable all suppression |
| `--workers N` | Repos scanned in parallel (default: 4) |
| `--include-archived` | Also scan archived repositories (skipped by default) |

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
| `--format {json,h1md,bcmd}` | Output format. `json` (default), `h1md` (HackerOne markdown), or `bcmd` (Bugcrowd markdown) |
| `--pattern-set {minimal,aws,full}` | Which detection rules to apply (default: `full`) |
| `--include-worktree` | Also scan the working tree (uncommitted files), not just git history. Worktree findings carry commit `WORKTREE` and are deduplicated against history |
| `--allowlist FILE` | Path to a TOML allowlist file suppressing known test credentials. Merged with the built-in default unless `--no-allowlist` is given |
| `--no-allowlist` | Disable all suppression, including the built-in default allowlist. Reports every match verbatim |
| `--workers N` | Threads used to scan blobs in parallel (default: `min(4, CPU count)`). Speeds up large repos; results are identical to a single-threaded run regardless of worker count. Use `1` to force serial scanning |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed (findings, if any, written to stdout) |
| `1` | Error (e.g. not a git repository, missing scope file) |
| `2` | Repository refused — out of bug-bounty scope |

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

The `full` pattern set ships three rules in v0.1:

- `aws-access-key-id` — AWS access key IDs (`AKIA…` and related prefixes)
- `stripe-secret-key` — Stripe secret keys (`sk_live_…` / `sk_test_…`)
- `generic-high-entropy-secret` — high-entropy values assigned to credential-like
  keys (`api_key`, `secret`, `token`, …), with UUID / git-SHA / low-entropy
  exclusions to suppress false positives

Detection patterns are adapted from the gitleaks public ruleset (Apache-2.0).
See [`NOTICE`](./NOTICE) and [`vendor/gitleaks-LICENSE`](./vendor/gitleaks-LICENSE).

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

The `confidence` field appears in JSON output and in the `h1md` / `bcmd` report
headers.

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
