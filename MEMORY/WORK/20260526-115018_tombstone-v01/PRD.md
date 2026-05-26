---
task: Bring tombstone credential scanner to v0.1
slug: 20260526-115018_tombstone-v01
effort: advanced
phase: complete
progress: 26/26
mode: autonomous
started: 2026-05-26T11:50:18Z
updated: 2026-05-26T11:50:18Z
---

## Context

`tombstone` is project #7 in the necromancer offensive-security suite. It is a re-imagining of SAP's
abandoned Python `credential-digger` (locked to Python <=3.9). The defender-side credential-scanning
space is crowded (Gitleaks, TruffleHog, GitGuardian). tombstone defends a different niche:
**offensive-side credential extraction for bug-bounty engagements** — scanning in-scope target org
repos, leaked-source clones, and post-exploitation artifacts, with H1/Bugcrowd scope enforcement.

This Worker brings tombstone to v0.1 per the orchestrator's verbatim completion criteria. The tech
stack is Python 3.13+, a custom regex engine (patterns borrowed from gitleaks' Apache-2.0 ruleset
with attribution), gitpython for repo traversal, pytest for tests, JSON + HackerOne-markdown output.

### Plan

Package layout (src layout):
- `pyproject.toml` — setuptools, console_script entry point `tombstone`
- `src/tombstone/__init__.py`
- `src/tombstone/patterns.py` — regex rule definitions, pattern sets (minimal/aws/full)
- `src/tombstone/scanner.py` — gitpython history traversal + matching + entropy
- `src/tombstone/scope.py` — scope-file parsing + enforcement
- `src/tombstone/report.py` — JSON + h1md formatters, context redaction
- `src/tombstone/cli.py` — argparse CLI
- `tests/fixtures/leaky-repo/` — real git repo, 3+ commits, 3 planted creds, 5 innocuous
- `tests/fixtures/out-of-scope-repo/` — minimal git repo
- `tests/fixtures/scope.txt` — scope file listing only in-scope identifiers
- `tests/test_*.py` — unit + smoke (e2e) tests
- `README.md`, `NOTICE`, `vendor/gitleaks-LICENSE`

### Risks
- High-entropy generic detection causing false positives on the 5 innocuous patterns — mitigate with
  tuned entropy threshold + exclusion of common non-secret formats (UUIDs, git hashes, lorem text).
- gitpython traversing history must dedupe findings across commits to count exactly 3.
- Scope enforcement must trigger BEFORE any scanning and exit non-zero.

## Criteria

- [x] ISC-1: pyproject.toml defines package and `tombstone` console_script entry point
- [x] ISC-2: `pip install -e .` succeeds in fresh venv on Python 3.13+
- [x] ISC-3: `tombstone --help` exits zero and prints usage
- [x] ISC-4: `--help` lists `--repo-path` flag
- [x] ISC-5: `--help` lists `--scope-file` flag
- [x] ISC-6: `--help` lists `--format {json,h1md}` flag
- [x] ISC-7: `--help` lists `--pattern-set {minimal,aws,full}` flag
- [x] ISC-8: leaky-repo fixture is a real git repo with at least 3 commits
- [x] ISC-9: leaky-repo has AWS key planted in history
- [x] ISC-10: leaky-repo has Stripe key planted in history
- [x] ISC-11: leaky-repo has generic high-entropy secret planted in history
- [x] ISC-12: leaky-repo has 5 innocuous-looking patterns planted
- [x] ISC-13: scan of leaky-repo emits exactly 3 findings (no more)
- [x] ISC-14: scan of leaky-repo produces zero false positives on innocuous patterns
- [x] ISC-15: JSON output includes commit hash for each finding
- [x] ISC-16: JSON output includes file path and line number for each finding
- [x] ISC-17: JSON output redacts secret to non-secret characters (context)
- [x] ISC-18: h1md format produces HackerOne markdown output
- [x] ISC-19: scope-file parsing reads in-scope identifiers
- [x] ISC-20: out-of-scope repo scan prints clear "out of scope" message
- [x] ISC-21: out-of-scope repo scan exits non-zero
- [x] ISC-22: end-to-end smoke test passes
- [x] ISC-23: README has install snippet
- [x] ISC-24: README has scope-file format example and one usage example
- [x] ISC-25: NOTICE attributes gitleaks + includes upstream LICENSE at pinned commit
- [x] ISC-26: branch pushed to origin and PR titled "v0.1" opened

## Decisions

## Verification

All 26 criteria verified. Fresh-venv install on Python 3.14.5 succeeded; 28 pytest tests pass; CLI scan of leaky-repo emits exactly 3 findings (AWS/Stripe/generic) with zero false positives; out-of-scope scan exits 2 with clear message. Branch pushed; PR #1 "v0.1" open against main (https://github.com/bugsyhewitt/tombstone/pull/1).
