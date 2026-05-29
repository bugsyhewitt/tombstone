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
* **PyPI API token** (``pypi-AgEIcHlwaS5vcmc…``) — the Python-registry analogue
  of the npm token: a PyPI / Test-PyPI upload token that publishes packages as
  the owner. It is a `macaroon <https://pypi.org/help/#apitoken>`_ — the literal
  ``pypi-`` prefix followed by a base64url-encoded macaroon whose body *always*
  begins with the fixed string ``AgEIcHlwaS5vcmc`` (the base64 of the macaroon's
  location identifier ``pypi.org``). That fixed prefix-of-the-body is what makes
  the rule structurally rigid with a near-zero false-positive rate, distinguishing
  a real upload token from an arbitrary ``pypi-`` string. A leaked upload token
  lets an attacker publish or overwrite releases of the victim's packages — a
  direct software-supply-chain compromise, Critical when the account owns
  popular packages. The npm rule covers the JavaScript registry; this closes the
  same gap for the Python registry.
* **Docker Hub personal access token** (``dckr_pat_…``) — the
  container-registry analogue of the ``npm-token`` / ``pypi-token`` pair: a
  Docker Hub PAT authenticates as the owning user to ``docker login`` and the
  Hub API. With ``Read & Write`` (or ``Read, Write & Delete``) scope, a leaked
  token can pull private images and *push* arbitrary tags to the owner's
  repositories — a direct container-supply-chain compromise where every
  downstream ``docker pull`` then ships the attacker's image. Docker Hub PATs
  carry the fixed literal prefix ``dckr_pat_`` followed by a URL-safe base64
  body (Docker has issued both ~27-char and ~36-char body lengths over time);
  we anchor on that highly-distinctive prefix plus a 27–40-char base64url body
  with word-boundary guards so neither length variant is missed and an
  unrelated identifier starting with ``dckr_pat`` cannot match. Rated Critical
  exactly like ``npm-token`` / ``pypi-token``: a leaked PAT publishes images
  as the owner, exactly as a leaked npm or PyPI token publishes packages.
* **Private key block** (``-----BEGIN … PRIVATE KEY-----``) — RSA/EC/DSA/OpenSSH
  /PGP private keys committed to history. Direct key material, always Critical.
* **Shopify access token** (``shpat_`` / ``shpss_`` / ``shpca_`` / ``shppa_`` +
  32 hex) — admin/storefront/custom/private app tokens. A leaked admin token
  reads/writes a store's orders, customers and products; routinely Critical.
* **Twilio Account SID** (``AC`` + 32 hex) — the account identifier paired with
  an auth token to send SMS / place calls as the victim. A toll-fraud and
  smishing primitive; the SID alongside a committed secret is consistently High.
* **Twilio API Key SID** (``SK`` + 32 hex) — the *credential* half of Twilio's
  recommended auth scheme: an API Key SID is created via the console / API and is
  used as the HTTP basic-auth username (paired with its one-time-shown API Key
  Secret) to authenticate to the Twilio REST API. Unlike the Account SID
  (``AC…``), which is merely the account identifier, a leaked ``SK…`` key — being
  the thing you actually authenticate *with* and the thing Twilio's own docs tell
  you to rotate when leaked — is a direct credential exposure: sends SMS, places
  calls, and reads account resources billed to the target. It shares the Account
  SID's ``<2-letter prefix> + 32 hex`` shape but carries the ``SK`` prefix
  instead of ``AC``, so the existing ``twilio-account-sid`` rule does not catch
  it. We anchor on ``SK`` + exactly 32 hex with word boundaries; the two rules
  stay disjoint (``AC`` vs ``SK``) so a single SID is never double-reported.
* **Discord bot token** (``<base64 id>.<6-char>.<27-char>``) — authenticates as
  a bot: reads guild messages, manages members, posts as the integration. High.
* **GitHub token family** (``gho_`` / ``ghu_`` / ``ghs_`` / ``ghr_`` + 36 base62)
  — the GitHub token types the shared library's ``github-pat`` rule does *not*
  cover. ``ghs_`` is the server-to-server / GitHub App installation token — the
  same shape the ``GITHUB_TOKEN`` secret in GitHub Actions takes; ``gho_`` is an
  OAuth-app token, ``ghu_`` a user-to-server token, ``ghr_`` a refresh token. All
  grant repo / org / CI access per scope, exactly like a classic ``ghp_`` PAT, so
  a leaked one is routinely Critical/P1. The library only matches ``ghp_`` and
  the fine-grained ``github_pat_``; this rule closes the gap for the rest of the
  family without forking the pinned library.
* **AWS STS temporary access key id** (``ASIA`` + 16 base32) — the short-lived
  credential id minted by ``sts:AssumeRole`` / ``GetSessionToken`` / the EC2 &
  ECS instance-metadata service. It shares the long-lived access key's 20-char
  ``<4-letter-prefix> + 16 base32`` shape but carries the ``ASIA`` prefix instead
  of ``AKIA``. The shared library's ``aws-access-key-id`` rule anchors on
  ``AKIA`` only, so an ``ASIA`` id committed alongside its ``aws_session_token``
  is caught only by the low-confidence generic fallback. A leaked STS id +
  session token authenticates to AWS for the role's full permission set until the
  token expires — a real-world exposure (CI runners and Lambda layers routinely
  bake temporary credentials into logs and bundles). This rule closes the gap
  without forking the pinned library; ``AKIA`` stays owned by the library rule so
  the two never double-match.
* **HashiCorp Vault token** (``hvs.<base64url>`` / ``hvb.<base64url>`` /
  ``hvr.<base64url>``) — the modern Vault token family introduced in Vault 1.10
  (April 2022) and now the default issued by ``vault token create`` and every
  auth method (AppRole, JWT/OIDC, Kubernetes, AWS, userpass, LDAP). The three
  variants share the same dot-segmented shape but differ by token type:
  ``hvs.`` is a service token (the most common — full lifecycle, renewable,
  uses the token store), ``hvb.`` is a batch token (lightweight, non-renewable,
  not stored — issued at high volume by automated workflows), and ``hvr.`` is a
  recovery token (root-equivalent, minted during Vault rebuild / disaster
  recovery). All three authenticate to the Vault API as the bound entity and
  inherit that entity's policy set; a leaked token with any meaningful policy
  attached reads secrets, writes secrets, lists mounts, or — with a broad
  policy — escalates to full Vault compromise. Modern Vault tokens are the
  highest-yield secret-manager credential after cloud root keys: a Vault
  instance is, by definition, where the *other* secrets live, so one leaked
  ``hvs.`` token in CI logs or a committed env file is a single hop from the
  organization's entire secret estate. We anchor on the highly-distinctive
  ``hv[sbr]\\.`` prefix plus a ≥24-char base64url body with word-boundary
  guards: ``hvs``/``hvb``/``hvr`` followed by a literal dot is not a shape that
  collides with English words, identifiers, or other credential prefixes, and
  the 24-char minimum excludes any short ``hv?.`` lookalike. The library does
  not ship a Vault rule, so this closes the secret-manager-token gap without
  forking it. Rated Critical — a leaked Vault token is a direct path to the
  *other* secrets the organization stores in Vault.
* **Azure Storage SAS token** (``…sig=<url-encoded HMAC>…`` + a SAS companion
  query param) — a Shared Access Signature is the standalone, time-boxed
  credential Azure mints to delegate scoped access to Blob / Queue / Table / File
  storage. It is a URL query string whose defining field is ``sig=`` — a
  URL-encoded base64 HMAC-SHA256 signature — accompanied by the SAS parameter set
  (``sv=`` signed version, ``sp=`` permissions, ``se=`` / ``st=`` expiry / start,
  ``sr=`` / ``ss=`` / ``srt=`` resource scope). The shared library ships an Azure
  DevOps PAT rule but no Azure Storage SAS rule, so a SAS committed in a
  connection string, a download URL, or an SDK call is caught only by the
  low-confidence generic fallback (and often not at all — the signature sits
  inside a long URL, not assigned to a ``token``-like key). A leaked SAS grants
  its full permission set against the targeted container/blob until ``se``
  expiry, with no way to revoke short of rotating the storage account key — a
  routinely-High exposure on bug-bounty engagements. We anchor on ``sig=`` plus a
  required SAS companion param so an unrelated ``sig=`` (e.g. an app's own
  signature field) does not match; ``sv=``/``se=``/``sp=`` together with a
  base64 signature put the false-positive rate near zero without forking the
  pinned library.

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
# PyPI API token                                                              #
# --------------------------------------------------------------------------- #
# A PyPI (or Test-PyPI) upload token is a macaroon serialised as the literal
# ``pypi-`` prefix followed by a base64url-encoded body. The body is not free
# form: every PyPI token's macaroon encodes its location identifier ``pypi.org``
# first, which serialises to the fixed leading string ``AgEIcHlwaS5vcmc`` (the
# base64 of that identifier). Anchoring on ``pypi-AgEIcHlwaS5vcmc`` — prefix plus
# this fixed body-prefix — then requiring a realistic-length base64url tail keeps
# the false-positive rate near zero: an arbitrary string that merely starts with
# ``pypi-`` does not match. A leaked upload token publishes / overwrites releases
# of the owner's packages, so it is treated as Critical, mirroring the npm rule.
PYPI_TOKEN = Rule(
    rule_id="pypi-token",
    description="PyPI API token (upload / publish)",
    regex=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{60,}\b"),
    severity=SEVERITY_CRITICAL,
)

# --------------------------------------------------------------------------- #
# Docker Hub personal access token                                            #
# --------------------------------------------------------------------------- #
# A Docker Hub PAT carries the literal prefix ``dckr_pat_`` followed by a
# URL-safe base64 body. Docker has issued PATs with two observed body lengths
# over time — older tokens at ~27 chars, newer ones at ~36 chars — so we
# anchor on the fixed, highly-distinctive ``dckr_pat_`` prefix plus a body
# window of 27–40 base64url characters that covers both variants without
# letting a runaway-length string match. Word-boundary guards keep an embedded
# identifier from being partially matched. The prefix itself is unique enough
# (no English word, no common identifier shape) that this rule has no
# realistic collision with non-credential text. A leaked Docker Hub PAT with
# write scope publishes images as the owner — a direct container
# supply-chain compromise on par with leaking ``npm-token`` / ``pypi-token``
# for the JS / Python registries, so we rate it Critical.
DOCKER_HUB_PAT = Rule(
    rule_id="docker-hub-pat",
    description="Docker Hub personal access token (dckr_pat_…)",
    regex=re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{27,40}\b"),
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
# Twilio API Key SID                                                           #
# --------------------------------------------------------------------------- #
# A Twilio API Key SID is the literal ``SK`` followed by exactly 32 hex
# characters (34 total). It is the credential half of Twilio's recommended auth
# scheme — used as the HTTP basic-auth username, paired with the one-time API Key
# Secret, to authenticate to the REST API. It shares the Account SID's
# ``<2-letter prefix> + 32 hex`` shape but carries the ``SK`` prefix instead of
# ``AC``, so the ``twilio-account-sid`` rule does not match it. We anchor on
# ``SK`` + exactly 32 hex with word boundaries; ``AC`` stays owned by the
# account-sid rule so the two never double-match.
TWILIO_API_KEY_SID = Rule(
    rule_id="twilio-api-key-sid",
    description="Twilio API Key SID (SK + 32 hex)",
    regex=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
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

# --------------------------------------------------------------------------- #
# GitHub token family (gho_ / ghu_ / ghs_ / ghr_)                              #
# --------------------------------------------------------------------------- #
# GitHub issues several token types beyond the classic personal access token.
# The shared necromancer-patterns ``github-pat`` rule only matches ``ghp_`` and
# the fine-grained ``github_pat_`` token. The remaining members of the family
# share the ``gh<type>_`` + 36 base62 shape but carry a different second letter:
#
#   gho_  OAuth-app access token
#   ghu_  user-to-server token (GitHub App acting for a user)
#   ghs_  server-to-server token — GitHub App installation token; this is the
#         shape the ``GITHUB_TOKEN`` secret takes inside GitHub Actions runs
#   ghr_  refresh token
#
# Each grants repository / organization / CI access scoped to the installation
# or app, so a leaked one is the same Critical/P1 exposure as a classic PAT. We
# deliberately exclude ``ghp_`` here so we never double-match the library's
# ``github-pat`` rule (rule ids stay disjoint and a token matches exactly one).
# The fixed prefix + exact 36-char base62 body keeps the false-positive rate at
# zero — these are not entropy heuristics. We use the same boundary guards as the
# library's GitHub rule (a lookbehind/lookahead over the token charset) so a
# token embedded in a longer identifier is not partially matched.
GITHUB_TOKEN = Rule(
    rule_id="github-token",
    description="GitHub token (OAuth / user-to-server / Actions installation / refresh)",
    regex=re.compile(r"(?<![A-Za-z0-9_-])gh[ousr]_[0-9A-Za-z]{36}(?![A-Za-z0-9_-])"),
    severity=SEVERITY_CRITICAL,
)

# --------------------------------------------------------------------------- #
# AWS STS temporary access key id (ASIA…)                                      #
# --------------------------------------------------------------------------- #
# An AWS access key id is a 4-letter type prefix followed by exactly 16
# uppercase base32 characters (20 total). The long-lived id carries the ``AKIA``
# prefix — owned by the shared library's ``aws-access-key-id`` rule. The
# *temporary* id minted by STS (``AssumeRole`` / ``GetSessionToken`` / the
# instance-metadata service) carries the ``ASIA`` prefix instead and is NOT
# matched by the library rule. We anchor on ``ASIA`` + 16 base32 with the same
# word-boundary guards as the AWS key rule so an id embedded in a longer
# identifier is not partially matched, and we exclude ``AKIA`` here so the two
# rules stay disjoint and a single id is never double-reported. Paired with a
# leaked ``aws_session_token`` an ASIA id authenticates to AWS for the assumed
# role's full permission set until expiry — a real, high-value exposure.
AWS_STS_TEMP_KEY = Rule(
    rule_id="aws-sts-temp-key",
    description="AWS STS temporary access key id (ASIA…)",
    regex=re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    severity=SEVERITY_HIGH,
)

# --------------------------------------------------------------------------- #
# HashiCorp Vault token (hvs. / hvb. / hvr.)                                   #
# --------------------------------------------------------------------------- #
# The modern HashiCorp Vault token format introduced in Vault 1.10 (April 2022)
# uses a dot-segmented prefix selecting the token type — ``hvs.`` for service
# tokens (the default issued by every auth method and ``vault token create``),
# ``hvb.`` for batch tokens (lightweight, non-renewable, issued at high volume
# by automated workflows), and ``hvr.`` for recovery tokens (root-equivalent,
# minted during Vault rebuild / disaster recovery) — followed by a URL-safe
# base64 body. Body length varies materially across token types: service
# tokens are typically ~95 chars, batch tokens 138–212 chars, recovery tokens
# similar. Rather than ship three rules with three length windows, we anchor on
# the shared ``hv[sbr]\.`` prefix plus a single ≥24-char base64url body window
# that comfortably covers every variant. The 24-char minimum is well below any
# real Vault token length but high enough that a short ``hvs.`` lookalike
# (e.g. ``hvs.short``) cannot match. The prefix itself is structurally rigid —
# the literal ``hv`` plus one of three specific letters plus a literal dot is
# not a shape that collides with English words, identifiers, or other
# credential families — so the false-positive rate stays near zero without
# needing per-variant length tuning. Word-boundary guards keep an embedded
# identifier from being partially matched. A leaked Vault token authenticates
# to the Vault API as the bound entity and reads / writes secrets per the
# entity's policy set — a direct path to the *other* secrets the organization
# stores in Vault, so we rate it Critical exactly like a cloud root key.
HASHICORP_VAULT_TOKEN = Rule(
    rule_id="hashicorp-vault-token",
    description="HashiCorp Vault token (hvs. / hvb. / hvr.)",
    regex=re.compile(r"\bhv[sbr]\.[A-Za-z0-9_\-]{24,}\b"),
    severity=SEVERITY_CRITICAL,
)


# --------------------------------------------------------------------------- #
# Azure Storage SAS token (…sig=<url-encoded HMAC>… + SAS companion param)     #
# --------------------------------------------------------------------------- #
# A Shared Access Signature is a URL query string. Its defining field is
# ``sig=`` — a URL-encoded base64 HMAC-SHA256 signature (the ``+`` / ``/`` / ``=``
# base64 chars appear as ``%2B`` / ``%2F`` / ``%3D``, but a SAS is also commonly
# stored decoded, so we accept both raw base64 and percent-encoded forms). A bare
# ``sig=`` is too generic on its own (apps have their own ``sig`` fields), so we
# require a SAS *companion* parameter — one of ``sv`` (signed version), ``sp``
# (permissions), ``se`` / ``st`` (expiry / start), ``sr`` / ``ss`` / ``srt``
# (resource scope) — to appear in the same query string, on either side of
# ``sig=``. That anchor pair (a base64 signature of realistic length + a SAS
# companion key) drives the false-positive rate to near zero. We do not require a
# fixed parameter order — Azure SDKs and the portal emit them in differing orders.
AZURE_STORAGE_SAS = Rule(
    rule_id="azure-storage-sas",
    description="Azure Storage SAS token (sig= + SAS companion param)",
    regex=re.compile(
        r"(?<![A-Za-z0-9])"
        r"(?:"
        # companion param appears before sig=
        r"s(?:v|p|e|t|r|s|rt|ig|ip|po|dd|kt|ktid)=[^&\s\"']*"
        r"(?:&[A-Za-z]{2,4}=[^&\s\"']*)*?"
        r"&sig=[A-Za-z0-9%]{40,}"
        r"|"
        # sig= appears before any companion param
        r"sig=[A-Za-z0-9%]{40,}"
        r"(?:&[A-Za-z]{2,4}=[^&\s\"']*)*?"
        r"&s(?:v|p|e|t|r|s|rt|ip|po|dd|kt|ktid)=[^&\s\"']*"
        r")"
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
    PYPI_TOKEN,
    DOCKER_HUB_PAT,
    PRIVATE_KEY,
    SHOPIFY_TOKEN,
    TWILIO_ACCOUNT_SID,
    TWILIO_API_KEY_SID,
    DISCORD_BOT_TOKEN,
    GITHUB_TOKEN,
    AWS_STS_TEMP_KEY,
    HASHICORP_VAULT_TOKEN,
    AZURE_STORAGE_SAS,
)

# The rule ids contributed by this module, for tests and introspection.
EXTRA_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in EXTRA_RULES)

__all__ = [
    "SLACK_TOKEN",
    "GOOGLE_API_KEY",
    "GITLAB_PAT",
    "SENDGRID_API_KEY",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DOCKER_HUB_PAT",
    "PRIVATE_KEY",
    "SHOPIFY_TOKEN",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_API_KEY_SID",
    "DISCORD_BOT_TOKEN",
    "GITHUB_TOKEN",
    "AWS_STS_TEMP_KEY",
    "HASHICORP_VAULT_TOKEN",
    "AZURE_STORAGE_SAS",
    "EXTRA_RULES",
    "EXTRA_RULE_IDS",
]
