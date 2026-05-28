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

### 1. Expand credential patterns: GitHub PATs, GCP, Azure, AI keys `[M]`

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

### 3. Incremental scanning (`--since <commit-or-date>`) `[M]`

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

### 10. Scan GitHub Actions workflow files for leaked secrets `[S]`

**Why:** `.github/workflows/*.yml` files are a high-yield target. The 2025 `tj-actions/
changed-files` supply chain attack showed that workflows can expose secrets via echoed env vars.
Researchers checking GitHub Actions logs for leaked CI/CD tokens has become a standard technique
in 2025. tombstone scans these files through its history scan already, but a targeted
`--workflow-scan` mode that specifically flags workflow files and known secret-printing patterns
(`echo ${{ secrets.` accidentally used outside `run:` context, `run: echo $SECRET`) adds
workflow-specific signal.

---

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
