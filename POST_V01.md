# tombstone — Post-v0.1 Improvement Directions

Research lap completed 2026-05-26. Grounded in:

- Betterleaks (Gitleaks successor, Feb 2026) developments
- TruffleHog 2025–2026 feature set and CVE-2025-41390
- GitGuardian 2026 State of Secrets Sprawl report
- Bug-bounty community git-recon techniques (2025)
- GitHub secret scanning November 2025 additions (24 new types)

Items are ranked by **offensive bug-bounty value** — how directly they improve a researcher's
yield and report quality, weighted by implementation cost.

---

## Ranked improvement list

### 1. Expand credential patterns: GitHub PATs, GCP, Azure, AI keys `[M]` — ✅ IMPLEMENTED (Phase 2, Rotation 21)

The original list (GitHub PAT, GCP SA key, Azure DevOps PAT, OpenAI, Hugging Face, Anthropic) shipped via the `necromancer-patterns` library refactor and is available to tombstone in the `cloud` / `full` pattern sets. Rotation 21 then added a tombstone-local tranche of high-value credentials the library does not yet cover — Slack tokens, Google API keys, GitLab PATs, SendGrid keys, npm tokens, and committed private-key blocks — defined in `tombstone.extra_patterns` and merged into the broad pattern sets. Each carries a true-positive + true-negative test. Rotation 23 extended that tombstone-local tranche with three more high-value, structurally-rigid SaaS-platform credentials: **Shopify access tokens** (`shpat_`/`shpss_`/`shpca_`/`shppa_` + 32 hex, Critical — full store API access), **Twilio Account SIDs** (`AC` + 32 hex, High — SMS/voice toll-fraud primitive), and **Discord bot tokens** (dot-segmented, High; a negative lookahead excludes JWTs to keep the FP rate near zero). Each carries a true-positive + true-negative test, a confidence assertion (all score `high`), a severity assertion, and a Bugcrowd `bcmd` "Demonstrated Impact" rationale. Rotation 24 closed the GitHub-token gap inside this same tranche: the library's `github-pat` rule matches only `ghp_` and the fine-grained `github_pat_`, leaving the rest of the GitHub token family — `gho_` (OAuth), `ghu_` (user-to-server), **`ghs_` (server-to-server / GitHub App installation — the shape of the Actions `GITHUB_TOKEN`)**, and `ghr_` (refresh) — caught only by the low-confidence generic fallback. A new tombstone-local **`github-token`** rule (`gh[ousr]_` + 36 base62, Critical) detects them at `high` confidence while deliberately excluding `ghp_` so it never double-matches `github-pat`. (The Stripe secret key named in the rotation brief was already covered by the library's `stripe-secret-key` rule, so the GitHub-token gap was the open one.) Carries the standard true-positive + classic-PAT-disjointness + true-negative tests, a `high`-confidence assertion, a `Critical` severity assertion, and a Bugcrowd `bcmd` rationale. Rotation 25 added the AWS analogue of that same gap: the library's `aws-access-key-id` rule anchors on the long-lived `AKIA` prefix only, leaving the **AWS STS temporary access key id** (`ASIA` + 16 base32) — minted by `AssumeRole` / `GetSessionToken` / the EC2 & ECS instance-metadata service, and the shape CI runners and Lambda layers routinely leak into logs and bundles — caught only by the low-confidence generic fallback. A new tombstone-local **`aws-sts-temp-key`** rule (`ASIA` + 16 base32, High) detects them at `high` confidence while deliberately excluding `AKIA` so it never double-matches `aws-access-key-id`. Rated High (not Critical) on its own because the id is inert without its matching `aws_session_token`; it escalates to Critical when a still-valid session token is also recovered. Carries the standard true-positive + long-lived-`AKIA`-disjointness + short/lowercase true-negative tests, a `high`-confidence assertion, a `High` severity assertion, and a Bugcrowd `bcmd` rationale. (The Azure SAS-token candidate in the rotation brief was deferred: SAS tokens are query-string blobs with no fixed prefix, so a low-FP anchored rule needs more design than a single focused improvement allows — `aws-sts-temp-key` was the clean, structurally-rigid gap.) Rotation 28 was dispatched to add a Slack Bot token or SendGrid API key detector, but both were already shipped in this tranche (`slack-token` covers the `xoxb-` bot prefix; `sendgrid-api-key` covers `SG.<id>.<secret>`), so per the dispatch's "if both are shipped, pick the next best unshipped pattern" instruction it added the **PyPI API token** (`pypi-AgEIcHlwaS5vcmc…` + base64url body, Critical) — the Python-registry analogue of the already-shipped `npm-token`, closing the package-registry supply-chain gap for the other half of the ecosystem. A PyPI upload token is a macaroon: the `pypi-` prefix followed by a base64url body that *always* begins with the fixed string `AgEIcHlwaS5vcmc` (the base64 of the macaroon's `pypi.org` location id). Anchoring on that fixed prefix-of-the-body (not merely `pypi-`) keeps the false-positive rate near zero; a leaked upload token publishes / overwrites releases of the owner's packages — a direct software-supply-chain compromise, rated Critical exactly like `npm-token`. Carries the standard true-positive + arbitrary-`pypi-`-prefix true-negative + short-body true-negative tests, a `high`-confidence assertion, a `Critical` severity assertion, and a Bugcrowd `bcmd` "Demonstrated Impact" rationale.


**Why:** GitHub PATs (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) and GCP service-account JSON blobs
are among the highest-severity findings on H1/Bugcrowd programs — instant critical/P1 if still
valid. AI service keys (Hugging Face, OpenAI, Azure OpenAI, Weights & Biases) grew 81% YoY in
2025 leaks. MCP config files alone had 24 000 unique exposed secrets on public GitHub in 2025.
Azure DevOps PATs have a distinctive `AZDO` signature at positions 76–80. All of these are
well-studied, have stable regex patterns, and belong in necromancer-patterns.

**What to build:** Add rules to `necromancer-patterns` for:
- GitHub PAT (`ghp_[0-9a-zA-Z]{36}` and fine-grained PAT `github_pat_[0-9A-Za-z_]{82}`)
- GCP service account key (JSON block containing `"type": "service_account"`)
- Azure client secret / Azure DevOps PAT (`AZDO` fixed-position signature)
- OpenAI API key (`sk-[a-zA-Z0-9]{48}` and newer `sk-proj-` prefix)
- Hugging Face token (`hf_[a-zA-Z0-9]{37}`)
- Anthropic / Claude API key (`sk-ant-[a-zA-Z0-9-_]{93}`)

Each rule added to necromancer-patterns is immediately available to tombstone via `--pattern-set`.

**Bug-bounty impact:** Directly widens the net for the fastest-growing credential categories.
GitHub PAT alone can lead to org-level repo access — P1 on virtually every program.

---

### 2. Bugcrowd report format output (`--format bcmd`) `[S]` — ✅ IMPLEMENTED (Phase 2, Rotation 2)

**Why:** tombstone ships `h1md` but Bugcrowd is the other major platform. Bugcrowd's preferred
report format differs from HackerOne's: it uses **Overview / Walkthrough & PoC / Vulnerability
Evidence / Demonstrated Impact** sections rather than H1's free-form markdown. Generating
platform-native markdown reduces researcher friction from finding → filed report.

**What to build:**
- `to_bcmd()` formatter in `report.py` following Bugcrowd's section schema
- Each finding maps to: Overview (one-line), Walkthrough (git commands to reproduce),
  Evidence (the redacted context block), Impact (severity rationale based on credential type)
- Add `bcmd` to `--format` choices in `cli.py`
- Tests: add `test_bcmd_format` to `test_smoke.py`

**Bug-bounty impact:** Reduces time from scan output → submitted report on Bugcrowd programs.

---

### 3. Incremental scanning (`--since <commit-or-date>`) `[M]` — ✅ IMPLEMENTED (refspec `--since`/`--until` + `--save-state`/`--load-state`; calendar-date `--since-date`/`--until-date` shipped Phase 2, Rotation 19)

**Why:** On long-running engagements, re-scanning a large repo's entire history is wasteful.
The most common bug-bounty workflow is: initial full scan → then re-scan only new commits as the
target pushes code. Incremental CodeQL (GA March 2026) proved that incremental analysis yields
80% scan-time reduction for ongoing work. The same principle applies here.

**What to build:**
- `--since <refspec>` flag: restrict `repo.iter_commits()` to commits reachable from HEAD
  but not from `<refspec>` (i.e., `git log HEAD ^<since>` semantics using gitpython)
- `--until <refspec>` for symmetric date-range control
- Persist last-scanned commit to `.tombstone-state` file in the repo root (optional, operator-
  controlled with `--save-state` / `--load-state`) so repeat runs are automatic

**Bug-bounty impact:** Makes tombstone viable for monitoring target repos over weeks of a
program; reduces runtime on repos with years of history by 80%+ on subsequent runs.

---

### 4. Confidence scoring on findings `[M]`

**Why:** Betterleaks (the Gitleaks successor) achieves 98.6% recall vs. 70.4% for entropy-only
methods by adding BPE tokenization. TruffleHog's `--only-verified` filter is its most-praised
UX feature. tombstone currently has no confidence signal beyond rule match. For a researcher
filing a report, knowing that a finding is a near-certain real credential vs. a possible false
positive changes triage time significantly.

**What to build:**
- Add `confidence: "high" | "medium" | "low"` field to `Finding`
- Score heuristics (implementable without ML): entropy of matched secret, rule specificity
  (AWS key has prefix constraint → high; generic-high-entropy → starts at medium), known
  test-credential blocklist (all-zeros, repeated chars, `EXAMPLE`, `PLACEHOLDER`)
- Emit `confidence` in JSON output; show indicator in h1md/bcmd report headers
- Tests: verify high-confidence rules produce `high`, test-credential strings produce `low`

**Bug-bounty impact:** Researcher sees `confidence: high` → files immediately. `confidence: low`
→ manual review first. Directly reduces wasted report submissions.

---

### 5. GitHub org-level enumeration (`tombstone gh-org <org>`) `[L]`

**Why:** Bug-bounty researchers routinely enumerate all repos in a target org. TruffleHog
supports `--github-org` scanning including PRs, issues, wikis, and gist comments. GitHound
automates breadth-first org scanning. For tombstone's offensive positioning, a `gh-org` subcommand
that: (a) enumerates org repos via GitHub API, (b) clones each, (c) scans history, (d) aggregates
findings into a single report — is a force multiplier for scope-wide engagements.

**What to build:**
- New `tombstone gh-org <org>` subcommand (or `--github-org <org>` flag)
- GitHub token support (`--github-token` or `GITHUB_TOKEN` env var)
- Scope enforcement: validate each discovered repo URL against the active scope file before scanning
- Aggregate output: single JSON envelope with per-repo findings and a summary table
- Parallel repo scanning (thread pool, default 4 workers)
- Tests: mock GitHub API responses, verify scope filtering skips out-of-scope repos

**Bug-bounty impact:** Turns tombstone from a single-repo tool into an org-sweep tool. The
hardest engagements (org-level scopes) require exactly this.

---

### 6. Working-tree + staged-changes scan (not just history) `[S]` — ✅ IMPLEMENTED (Phase 2, Rotation 6)

**Why:** tombstone currently scans commit history only. A researcher who has cloned a target's
repo may also want to scan the current working tree and index (staged but not committed). This
catches credentials that have been added but not yet committed, or that exist only in the working
copy (e.g., a `.env` file accidentally left on a staging server). TruffleHog scans both.

**What to build:**
- Add `scan_worktree()` function in `scanner.py` that walks the filesystem of `repo_path`
  skipping `.git/` and applies the active rule set
- New `--include-worktree` CLI flag (off by default, since history scan is the core value)
- Deduplicate worktree findings against history findings by `(rule_id, secret)` key
- Tests: add a fixture file with a credential in the working tree but not in any commit

**Bug-bounty impact:** Catches the "remove from history, leave in working copy" pattern.
Researchers who manually inspect cloned repos catch these; now tombstone catches them too.

---

### 7. Suppression allowlist for known test credentials `[S]` — ✅ IMPLEMENTED (Phase 2, Rotation 7)

**Why:** The `generic-high-entropy-secret` rule produces false positives on test fixtures that
include realistic-looking but known-fake credentials (e.g., `AKIAIOSFODNN7EXAMPLE`, Stripe
test keys like `sk_test_xxxx`). Every professional secret-scanning tool supports an allowlist/
baseline. Without it, tombstone output on any repo that has tests is noisy.

**What to build:**
- `--allowlist <file>` flag: a TOML/YAML file specifying secrets or regexes to suppress
- Built-in default allowlist for well-known test values: AWS EXAMPLE key, Stripe test prefix
  `sk_test_`, common placeholder strings (`PLACEHOLDER`, `CHANGEME`, `DUMMY`)
- `tombstone baseline` subcommand: scan once, write all findings as suppressed, subsequent
  runs report only new findings
- Tests: verify that `AKIAIOSFODNN7EXAMPLE` is suppressed by default

**Bug-bounty impact:** Noise reduction makes tombstone output directly report-ready. Currently,
researchers must manually filter before filing. Every false positive erodes confidence in the tool.

---

### 8. Parallel blob processing for large repos `[M]` — ✅ IMPLEMENTED (Phase 2, Rotation 9)

**Why:** Betterleaks and Semgrep both emphasize parallel/multicore scanning. Large target repos
(monorepos, long-lived open-source projects) can have tens of thousands of commits. Current
tombstone uses a single-threaded `iter_commits()` loop. A thread-pool approach over blobs within
a commit batch would yield meaningful speedups with minimal complexity increase.

**What to build:**
- Thread pool (`concurrent.futures.ThreadPoolExecutor`) over batches of blobs within commits
- Default worker count: `min(4, os.cpu_count())`; configurable via `--workers N`
- Thread-safe `seen` set (use `threading.Lock` or process in batches and merge afterward)
- Benchmark: measure scan time on a large fixture (1000+ commits) before/after
- Tests: verify results are identical between single-threaded and parallel paths

**Bug-bounty impact:** Makes tombstone viable for the largest targets. A 4x speedup on a monorepo
turns a 20-minute wait into a 5-minute wait, which changes researcher workflow.

---

### 9. Severity rating per finding `[S]`

**Why:** H1 and Bugcrowd both use severity to triage. AWS access keys and GitHub org-admin PATs
are Critical/P1. Generic high-entropy matches are P3 until proven. tombstone should emit a
`severity` field based on the rule type so the researcher knows immediately what to prioritize.

**What to build:**
- Add `severity: "critical" | "high" | "medium" | "low"` to `Rule` in necromancer-patterns
- AWS access key → critical; Stripe live key → critical; GitHub PAT → critical;
  generic-high-entropy → medium (confidence can upgrade it)
- Emit `severity` in `Finding.to_dict()` and in h1md/bcmd report headers
- Tests: verify severity fields present in JSON output

---

### 10. Scan GitHub Actions workflow files for leaked secrets `[S]` — ✅ IMPLEMENTED (Phase 2, Rotation 10)

**Why:** `.github/workflows/*.yml` files are a high-yield target. The 2025 `tj-actions/
changed-files` supply chain attack showed that workflows can expose secrets via echoed env vars.
Researchers checking GitHub Actions logs for leaked CI/CD tokens has become a standard technique
in 2025. tombstone scans these files through its history scan already, but a targeted
`--workflow-scan` mode that specifically flags workflow files and known secret-printing patterns
(`echo ${{ secrets.` accidentally used outside `run:` context, `run: echo $SECRET`) adds
workflow-specific signal.

**What shipped:**
- New `src/tombstone/workflow.py` module: workflow-path classification
  (`is_workflow_file`) and an anti-pattern detector (`scan_workflow_text`) for
  three secret-exposure constructs — a `${{ secrets.X }}` interpolated into a
  `run:` shell command, an `echo` of a secret-derived env var, and a secret
  passed as a `--flag=${{ secrets.X }}` argument. These are *patterns*, not
  credential rules, so they live in tombstone (not necromancer-patterns) — this
  is the self-contained half of item 10 that needs no library changes.
- `--workflow-scan` CLI flag (off by default). When set, `scan_repo` flags
  workflow files in history (reusing the already-gathered blob jobs, so it
  honours `--since`/`--until`) and, with `--include-worktree`, in the working
  tree. Findings carry the `workflow-secret-exposure` rule at `confidence:
  medium` and flow through all formatters; `report.py` assigns them a High (P2)
  severity rationale for `bcmd`.
- Precision-tuned to skip the recommended safe `env:`-mapping pattern and
  `echo`s of non-secret variables, so report output stays trustworthy.
- 16 new tests (`tests/test_workflow.py`) covering path classification, each
  anti-pattern, safe-pattern non-flagging, gating on the flag, dedup, and report
  rendering. A workflow fixture with both dangerous and safe constructs was added
  to `tests/build_fixtures.py`.

**Note:** the *additional* half of item 10 — extending the shared
necromancer-patterns library with workflow-context credential rules — remains
open and is tracked there, as it requires a patterns-library bump.

---

## Shipped extensions (beyond the original ranking)

These were not in the original ranked list but emerged as high-value,
self-contained follow-ups to shipped work:

- **SARIF 2.1.0 output (`--format sarif`)** — ✅ IMPLEMENTED (Phase 2, Rotation 13).
  Emits OASIS-standard static-analysis results for GitHub code scanning, the VS
  Code SARIF viewer, and CI dashboards.
- **CI gating exit code (`--fail-on <severity>`)** — ✅ IMPLEMENTED (Phase 2,
  Rotation 14). Returns a dedicated exit code `3` when any reported finding is at
  or above the requested severity (`critical` > `high` > `medium` > `low`).
  Completes the CI story the SARIF formatter started: a single run can both emit
  SARIF and fail the build on a leaked credential. Self-contained — reads the
  existing per-finding `severity` field, no necromancer-patterns bump required.
  Allowlist-suppressed findings do not count toward the gate; default behaviour
  (no flag) is unchanged so existing pipelines keep exiting `0`.
- **Org-wide CI gating (`gh-org --fail-on <severity>`)** — ✅ IMPLEMENTED
  (Phase 2, Rotation 15). Extends the Rotation-14 single-repo CI gate to the
  `gh-org` org sweep: a single CI job can enumerate and scan an entire
  organization and exit `3` when *any* scanned repo leaks a credential at or
  above the requested severity. Self-contained — reuses the existing
  per-finding `severity` field and the `severity.meets_threshold` comparison, no
  necromancer-patterns bump required. Only findings on repos with
  `status == "scanned"` count: a repo skipped as out-of-scope or one that failed
  to clone is an operational outcome, not a credential leak, and never trips the
  gate. Per-repo allowlist suppression already applied upstream, so suppressed
  test credentials don't count. Default behaviour (no flag) unchanged — the
  sweep keeps exiting `0`.

- **Report archiving to a file (`--output-file` / `-o`)** — ✅ IMPLEMENTED
  (Phase 2, Rotation 16). Writes the formatted report (any `--format`) to a path
  instead of stdout, creating parent directories as needed, for both the
  single-repo scan and the `gh-org` sweep. Only the report payload lands in the
  file; the write confirmation, allowlist suppression counts, and `--fail-on`
  gate messages stay on stderr, so the artifact is clean to commit or pipe.
  Composes with `--fail-on` (the report is archived before the gate trips the
  exit code) and `--format sarif` (write a SARIF artifact for a later
  code-scanning upload). Self-contained — pure CLI/IO plumbing, no
  necromancer-patterns bump. Default behaviour (no flag → stdout) is unchanged.

- **Report formats for the org sweep (`gh-org --format h1md|bcmd|sarif`)** —
  ✅ IMPLEMENTED (Phase 2, Rotation 18). The single-repo scan already supported
  four output formats, but `gh-org` could emit only JSON — a researcher running
  an org-wide engagement (the hardest scope, and exactly what `gh-org` targets)
  had no path to a report-ready HackerOne/Bugcrowd markdown or a SARIF
  code-scanning artifact without hand-translating the JSON envelope. `gh-org`
  now accepts the same `--format {json,h1md,bcmd,sarif}` as the single-repo
  scan. The report formats flatten findings from every `status == "scanned"`
  repo (skipped/errored repos contribute nothing, mirroring the `--fail-on`
  gate) via a new `aggregate_findings()` helper and reuse the existing
  `report.format_findings` formatters unchanged. Because those formats have no
  per-repo dimension, each finding's file path is prefixed with its source repo
  as `owner/repo:path` so the aggregated report is unambiguous and reproduction
  commands point at the right clone — done with `dataclasses.replace`, leaving
  the frozen `Finding` schema untouched and the raw secret still never emitted.
  Self-contained — pure formatting/aggregation, no necromancer-patterns bump.
  Default behaviour (`--format json` → the per-repo envelope) is unchanged. 9
  new tests; composes with `--fail-on` (report archived/emitted before the gate)
  and `--output-file`.

- **Calendar-date scan scoping (`--since-date` / `--until-date`)** —
  ✅ IMPLEMENTED (Phase 2, Rotation 19). Completes the date half of item 3.
  The existing `--since`/`--until` scope a scan by *refspec* (commit SHA/ref),
  but the common bug-bounty trigger is a *date*: a breach-disclosure day, a
  risky-feature ship week, a credential-rotation cutoff. The two new flags map
  directly to gitpython's `iter_commits(after=..., before=...)` (which forward
  to `git log --since/--until`) and accept any git date expression
  (`2025-01-01`, `'2 weeks ago'`, `'2025-06-01 12:00'`). They compose with the
  refspec range — both narrowings apply, so a refspec range and a date window
  intersect. Self-contained — pure scanner/CLI plumbing reusing the existing
  commit walk, no necromancer-patterns bump. Default behaviour (no flag → full
  history) is unchanged. 11 new tests (`tests/test_date_range.py`) cover
  since/until/window narrowing on a dedicated fixed-date fixture, the
  refspec×date composition, empty-window and future-date edge cases, and CLI
  integration including `--help`.

## Not recommended

The following directions are **explicitly outside tombstone's niche** and should not be pursued:

- **Live credential verification (TruffleHog-style API calls):** This crosses from passive
  credential extraction into active use of discovered credentials. Unauthorized API calls with
  discovered secrets is legally and ethically out of scope for tombstone's design. If a researcher
  wants to verify, they do it manually after reviewing tombstone output.
- **ML / false-positive classification models:** tombstone is a fast, offline, deterministic
  tool. Embedding a model raises deployment complexity without proportional benefit for the
  bug-bounty workflow. Confidence scoring (item 4 above) achieves 80% of the UX benefit with
  none of the complexity.
- **Web UI:** Out of scope per v0.1 design. tombstone is a CLI tool. A web UI is a product
  decision requiring operator review.
- **Custom rule DSL:** Operators can write rules in necromancer-patterns (TOML/Python). A
  bespoke DSL adds learning curve without adding detection power.
- **Scanning non-git sources (S3, Docker, Slack):** These are TruffleHog's domain.
  tombstone's defensive moat is deep git-history scanning for bug-bounty operators, not
  infrastructure-wide secret sprawl management.

---

## Landscape context

| Tool | Status 2026 | Differentiator | tombstone gap filled |
|---|---|---|---|
| Gitleaks | Feature-frozen, security patches only | Fast regex + entropy | — |
| Betterleaks | Active (Feb 2026) | BPE tokenization, 98.6% recall, archive scanning | Items 4, 7 |
| TruffleHog | Active, $25M Series B (Nov 2025), 800+ detectors | Live verification, blast radius analysis | Items 1, 5, 6 |
| GitGuardian | Enterprise, 28M secrets tracked 2025 | Remediation workflows, NHI governance | Not tombstone's niche |

tombstone's position: **offensive, offline, scope-enforced, report-ready output**. No live
credential use. No cloud agent. Fast deterministic analysis.

AI service credential leaks grew 81% in 2025 (Hugging Face, Azure OpenAI, W&B). MCP config
files had 24 000 exposed secrets on public GitHub. GitHub added 24 new secret types in Nov 2025.
These make item 1 (pattern expansion) the highest-ROI next step.
