# Changelog

All notable changes to tombstone are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

First production-ready release of tombstone — an offensive-side credential
extraction tool for authorized bug-bounty engagements. Scans the full git
history of a target repository (not just the working tree) and emits structured
findings with reproducibility evidence (commit hash, file path, line number,
redacted context), with H1/Bugcrowd scope enforcement baked in.

### Added

- Calendar-date commit scoping (`--since-date` / `--until-date`) — PR #18.
- `still_present` (HEAD-liveness) signal on every finding — PR #19.
- New credential detection rules: Slack, Google API, GitLab PAT, SendGrid,
  npm token, private-key blocks — PR #20.
- `--committer` filter to scope findings by git committer identity — PR #21.
- New credential detection rules: Shopify access tokens, Twilio Account SIDs,
  Discord bot tokens — PR #22.
- GitHub-token family coverage (`gho_` / `ghu_` / `ghs_` / `ghr_`) — PR #23.
- AWS STS temporary access key id detection (`ASIA…`) — PR #24.
- Azure Storage SAS token detection — PR #25.
- Twilio API Key SID detection (`SK` + 32 hex) — PR #26.
- PyPI API upload token detection (macaroon-anchored, Critical) — PR #27.
- Docker Hub personal access token detection (`dckr_pat_…`, Critical) — PR #28.
- HashiCorp Vault token family detection (`hvs.` / `hvb.` / `hvr.`, Critical) — PR #29.
- Databricks personal access token detection (`dapi…`) — PR #30.
- Stripe restricted API key detection (`rk_live_` / `rk_test_`) — PR #31.
- Okta API token detection (`SSWS` + 40-char base64url, Critical) — PR #32.
- Datadog API / Application key detection — PR #33.
- Twilio Auth Token detection — PR #34.
- Linear API key detection (`lin_api_` + ≥36 base62) — PR #35.
- Grafana service-account token detection (`glsa_` + 22 base62 + `_` + 8 hex) — PR #36.

### Changed

- Version bumped from `0.1.0` to `1.0.0`. Wheel rebuild pins the new version
  in `pyproject.toml`, `src/tombstone/__init__.py`, and the ship-gate
  regression assertions.

### Fixed

- N/A (no fixes shipped in this release; the v0.2-WIP features are net-new
  additions on top of the v0.1 surface).

### Security

- The wheel-ship-gate contract (PR #37) is now locked into the test suite:
  every release-cut must pass `pytest -q -m ship_gate` to ship. The gate
  builds the wheel, installs it into a fresh venv, and proves the
  end-to-end surface (CLI entry-point, importable `__version__`, public
  API, leaky-repo scan, worktree scan, gh-org subcommand, scope refusal).

[1.0.0]: https://github.com/bugsyhewitt/tombstone/releases/tag/v1.0.0
