"""Tombstone-local credential rules layered on top of necromancer-patterns.

The shared :mod:`necromancer_patterns` library is the suite-wide source of truth
for credential detection and covers the cloud / AI provider keys (AWS, Stripe,
GitHub PAT, GCP, Azure DevOps, OpenAI, Hugging Face, Anthropic). It does **not**
yet cover several other high-value, structurally-distinct credential types that
turn up constantly in real bug-bounty git-history scans. Rather than fork the
pinned library, tombstone defines those extra rules here — exactly as
:mod:`tombstone.workflow` keeps its workflow secret-exposure detection local —
and merges them into the active rule set in :func:`tombstone.patterns.get_rules`.

Each rule is a plain :class:`necromancer_patterns.Rule`, so it plugs into the
existing scanner, confidence scoring and severity mapping unchanged: a
structurally-constrained match scores ``high`` confidence automatically, and the
finding's severity is read from the rule's :attr:`~necromancer_patterns.Rule.severity`.

The credential types added here:

* **Slack tokens** (``xoxb-`` / ``xoxp-`` / ``xoxa-`` / ``xoxr-`` / ``xoxs-``) —
  bot, user, app, refresh and legacy workspace tokens. A leaked bot token reads
  channels and posts as the integration; routinely P2–P1.
* **Google API key** (``AIza…``) — Maps / Cloud / Firebase API keys. Often
  billable and, when unrestricted, abusable for paid API quota.
* **GitLab personal access token** (``glpat-…``) — the GitLab analogue of a
  GitHub PAT; grants repo/registry/API access scoped to the user.
* **SendGrid API key** (``SG.<id>.<secret>``) — sends mail as the victim domain;
  a phishing / BEC primitive, consistently triaged High.
* **npm access token** (``npm_…``) — publishes packages as the owner; a supply
  chain compromise vector, Critical when the account owns popular packages.
* **Private key block** (``-----BEGIN … PRIVATE KEY-----``) — RSA/EC/DSA/OpenSSH
  /PGP private keys committed to history. Direct key material, always Critical.
* **Shopify access token** (``shpat_`` / ``shpss_`` / ``shpca_`` / ``shppa_`` +
  32 hex) — admin/storefront/custom/private app tokens. A leaked admin token
  reads/writes a store's orders, customers and products; routinely Critical.
* **Twilio Account SID** (``AC`` + 32 hex) — the account identifier paired with
  an auth token to send SMS / place calls as the victim. A toll-fraud and
  smishing primitive; the SID alongside a committed secret is consistently High.
* **Discord bot token** (``<base64 id>.<6-char>.<27-char>``) — authenticates as
  a bot: reads guild messages, manages members, posts as the integration. High.

All patterns are deliberately anchored (fixed prefixes, exact length windows, or
literal header lines) so the false-positive rate stays near zero — these are not
entropy heuristics.
"""

from __future__ import annotations

import re

from necromancer_patterns import SEVERITY_CRITICAL, SEVERITY_HIGH, Rule

# --------------------------------------------------------------------------- #
# Slack tokens                                                                 #
# --------------------------------------------------------------------------- #
# Slack tokens carry a ``xox<type>-`` prefix where <type> is one of
# b(ot) / p(user) / a(pp) / r(efresh) / s(legacy workspace). The body is a
# series of base62 segments separated by hyphens. We require at least two
# segments of >=10 chars so a short ``xoxb-`` lookalike doesn't match.
SLACK_TOKEN = Rule(
    rule_id="slack-token",
    description="Slack API token (bot / user / app / refresh / legacy)",
    regex=re.compile(r"\bxox[baprs]-(?:[0-9a-zA-Z]{10,48}-?){2,}"),
    severity=SEVERITY_HIGH,
)

# --------------------------------------------------------------------------- #
# Google API key                                                              #
# --------------------------------------------------------------------------- #
# Google API keys are the literal prefix ``AIza`` followed by exactly 35
# URL-safe base64 characters (39 total). Word boundaries keep us from matching
# inside a longer token.
GOOGLE_API_KEY = Rule(
    rule_id="google-api-key",
    description="Google API key (Maps / Cloud / Firebase)",
    regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    severity=SEVERITY_HIGH,
)

# --------------------------------------------------------------------------- #
# GitLab personal access token                                                #
# --------------------------------------------------------------------------- #
# GitLab PATs are ``glpat-`` followed by 20 URL-safe base64 characters.
GITLAB_PAT = Rule(
    rule_id="gitlab-pat",
    description="GitLab personal access token",
    regex=re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b"),
    severity=SEVERITY_CRITICAL,
)

# --------------------------------------------------------------------------- #
# SendGrid API key                                                            #
# --------------------------------------------------------------------------- #
# SendGrid keys are ``SG.`` + a 22-char id + ``.`` + a 43-char secret.
SENDGRID_API_KEY = Rule(
    rule_id="sendgrid-api-key",
    description="SendGrid API key",
    regex=re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    severity=SEVERITY_HIGH,
)

# --------------------------------------------------------------------------- #
# npm access token                                                            #
# --------------------------------------------------------------------------- #
# npm automation / publish tokens are ``npm_`` followed by 36 base62 chars.
NPM_TOKEN = Rule(
    rule_id="npm-token",
    description="npm access token (automation / publish)",
    regex=re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"),
    severity=SEVERITY_CRITICAL,
)

# --------------------------------------------------------------------------- #
# Private key blocks                                                          #
# --------------------------------------------------------------------------- #
# The PEM/OpenSSH/PGP "BEGIN ... PRIVATE KEY" header is the unambiguous marker
# that committed key material follows. We match the header line itself (the
# whole secret is the marker) and explicitly exclude PUBLIC KEY / CERTIFICATE
# headers by listing only the private-key variants.
PRIVATE_KEY = Rule(
    rule_id="private-key",
    description="Private key material (RSA / EC / DSA / OpenSSH / PGP)",
    regex=re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    ),
    severity=SEVERITY_CRITICAL,
)

# --------------------------------------------------------------------------- #
# Shopify access tokens                                                        #
# --------------------------------------------------------------------------- #
# Shopify tokens carry a fixed prefix selecting the token class — shpat_ (admin
# API), shpss_ (shared secret), shpca_ (custom app), shppa_ (private app) —
# followed by exactly 32 lowercase hex characters. The prefix + fixed-length hex
# body makes false positives effectively impossible.
SHOPIFY_TOKEN = Rule(
    rule_id="shopify-token",
    description="Shopify access token (admin / storefront / custom / private app)",
    regex=re.compile(r"\bshp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}\b"),
    severity=SEVERITY_CRITICAL,
)

# --------------------------------------------------------------------------- #
# Twilio Account SID                                                           #
# --------------------------------------------------------------------------- #
# A Twilio Account SID is the literal ``AC`` followed by exactly 32 hex
# characters (34 total). It's the account identifier that, paired with an auth
# token, authenticates to the Twilio API. We anchor on word boundaries and the
# exact length so a 34-char hex blob without the AC prefix doesn't match.
TWILIO_ACCOUNT_SID = Rule(
    rule_id="twilio-account-sid",
    description="Twilio Account SID (AC + 32 hex)",
    regex=re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    severity=SEVERITY_HIGH,
)

# --------------------------------------------------------------------------- #
# Discord bot token                                                           #
# --------------------------------------------------------------------------- #
# A Discord bot token is three base64url segments separated by dots:
#   <24-28 char id>.<6 char timestamp>.<27-38 char hmac>
# The first segment is the base64 of a numeric snowflake id, so it never starts
# with ``eyJ`` — the marker of a JWT, whose first segment is base64 JSON. We add
# a negative lookahead for ``eyJ`` so JWTs (a distinct, lower-value artifact) are
# not mis-flagged as Discord bot tokens.
DISCORD_BOT_TOKEN = Rule(
    rule_id="discord-bot-token",
    description="Discord bot token",
    regex=re.compile(
        r"\b(?!eyJ)[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"
    ),
    severity=SEVERITY_HIGH,
)


# Ordered list of the tombstone-local rules, appended to the library's rule set
# whenever a pattern set includes the generic/full credential coverage. Order is
# stable so finding output and tests are deterministic.
EXTRA_RULES: tuple[Rule, ...] = (
    SLACK_TOKEN,
    GOOGLE_API_KEY,
    GITLAB_PAT,
    SENDGRID_API_KEY,
    NPM_TOKEN,
    PRIVATE_KEY,
    SHOPIFY_TOKEN,
    TWILIO_ACCOUNT_SID,
    DISCORD_BOT_TOKEN,
)

# The rule ids contributed by this module, for tests and introspection.
EXTRA_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in EXTRA_RULES)

__all__ = [
    "SLACK_TOKEN",
    "GOOGLE_API_KEY",
    "GITLAB_PAT",
    "SENDGRID_API_KEY",
    "NPM_TOKEN",
    "PRIVATE_KEY",
    "SHOPIFY_TOKEN",
    "TWILIO_ACCOUNT_SID",
    "DISCORD_BOT_TOKEN",
    "EXTRA_RULES",
    "EXTRA_RULE_IDS",
]
