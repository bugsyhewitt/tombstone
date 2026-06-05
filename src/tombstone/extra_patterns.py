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
* **Databricks personal access token** (``dapi`` + 32 hex, optionally followed
  by ``-<digits>`` for a workspace-scoped variant) — the credential a researcher,
  data engineer, or job uses to authenticate to the Databricks REST API, the
  Workspace / Jobs / SQL / Unity Catalog APIs, and ``databricks`` CLI commands.
  A leaked Databricks PAT inherits the issuing user's full permission set on the
  workspace: it reads and writes notebooks (which routinely contain other
  embedded credentials — cloud keys, database URIs, model-registry tokens),
  starts / stops / configures clusters (a billed-compute primitive — runaway
  spend on the target's account), executes arbitrary code on those clusters via
  notebook / job runs (a code-execution primitive against the target's data
  plane), and reads Unity Catalog tables (a direct path to the target's data
  estate). The library ships no Databricks rule, so a Databricks PAT committed
  in a ``.databrickscfg``, an env file, or a CI workflow was previously caught
  only by the low-confidence generic fallback. The token shape is the literal
  prefix ``dapi`` followed by exactly 32 lowercase-hex characters (Databricks'
  documented PAT format), with an optional ``-<digits>`` workspace-scope suffix
  that some Azure-Databricks workspaces append. We anchor on the literal
  ``dapi`` prefix plus the exact 32-hex body with word-boundary guards: the
  prefix-plus-fixed-length-hex shape keeps the false-positive rate near zero
  (no English word, identifier, or common hex blob collides), and the optional
  workspace suffix matches both single-workspace and Azure variants without
  letting unrelated trailing text expand the secret. Rated Critical exactly
  like a cloud root key: a leaked PAT is a single hop from arbitrary code
  execution on the target's data-plane clusters and from the data those
  clusters can reach.
* **Stripe restricted API key** (``rk_live_…`` / ``rk_test_…``) — the
  *scoped* sibling of the unrestricted Stripe secret key (``sk_live_…`` /
  ``sk_test_…``). The shared library's ``stripe-secret-key`` rule anchors on
  ``sk_(live|test)_`` only, so an ``rk_live_…`` committed in a server-side
  ``.env``, a CI workflow or an SDK example was previously caught only by
  the low-confidence generic fallback. The rule body shape mirrors the
  library's Stripe rule (24+ base62) so both historical (24-char) and current
  (~99-char) lengths match; the ``rk_`` vs ``sk_`` prefix split keeps the two
  rules disjoint so a single key is never double-reported. Rated High (not
  Critical): a restricted key is permission-scoped, but the scopes commonly
  granted (read on ``customers`` / ``charges`` / ``payment_intents``) expose
  live-account PII and payment metadata — a P2-class data-disclosure on its
  own, escalating to Critical when the key carries write scope on payment
  resources. The ``rk_test_`` prefix is already in
  :data:`tombstone.confidence._TEST_MODE_MARKERS` so test-mode restricted
  keys auto-grade to LOW confidence exactly like ``sk_test_``.
* **Okta API token** (``SSWS <40-char base64url body>``) — the identity-platform
  credential that authenticates to the Okta admin / management API. Okta API
  tokens are issued from the Okta admin console and used by SDKs, terraform
  providers, CI jobs and one-off scripts to manage users, groups,
  applications, factors and sessions on the target's Okta org. The token
  itself is a 40-character URL-safe base64 string with no fixed body prefix,
  but Okta's API requires it to be transmitted in the ``Authorization`` header
  as ``Authorization: SSWS <token>`` (the literal ``SSWS`` scheme keyword is
  Okta's own — it stands for "Single Sign-On With Secret"). The same literal
  ``SSWS`` keyword appears in every place a leaked Okta API token shows up in
  source: ``okta.yaml`` and ``.okta/config`` config files write the token as
  ``token: SSWS …`` or under an ``apiToken: SSWS …`` key; Okta SDK
  initialisations and terraform provider blocks copy the literal header
  syntax; CI scripts and Postman collections set ``Authorization: SSWS …``
  directly. Anchoring on the ``SSWS`` literal followed by whitespace and a
  40-char base64url body makes the rule structurally rigid with a near-zero
  false-positive rate (no English word or common identifier collides with the
  ``SSWS`` scheme keyword). The library ships no Okta rule, so a leaked Okta
  API token was previously caught only by the low-confidence generic
  fallback. A leaked token authenticates as the issuing admin to Okta's
  management API and grants the issuer's full administrative scope — read
  and modify users (including password resets and factor enrollments), apps
  (including SAML / OIDC client secrets), groups, sessions, and audit logs —
  a complete identity-plane compromise. Rated Critical exactly like a cloud
  root key: from a single leaked Okta admin token an attacker pivots into
  every downstream application Okta federates to.
* **Twilio Auth Token** (``TWILIO_AUTH_TOKEN=<32 hex>``) — the *secret* half of
  Twilio's classic auth scheme: an Auth Token is a 32-character lowercase-hex
  string used as the HTTP basic-auth password (paired with the Account SID as
  the username) to authenticate to the Twilio REST API. Where the Account SID
  (``AC…``) and the API Key SID (``SK…``) are mere identifiers carrying a fixed
  2-letter prefix and matched structurally by ``twilio-account-sid`` /
  ``twilio-api-key-sid``, the Auth Token is the *thing you authenticate with* —
  it sends SMS, places calls, reads call/message logs, and reads account
  resources billed to the target. The token body itself has no fixed prefix
  (it is indistinguishable from any other 32-char lowercase-hex blob — a git
  blob SHA-1 is the same shape; an md5 hex string is the same shape), so the
  rule anchors on the Twilio-specific keyword that always accompanies the
  credential in source: a ``TWILIO_`` prefix on an ``AUTH_TOKEN`` /
  ``AUTHTOKEN`` suffix (case-insensitive on the keyword, ``-`` / ``_`` / ``.``
  separator), or a bare ``AUTH_TOKEN`` in close proximity to ``twilio`` (handled
  conservatively here via the ``TWILIO_…`` prefix family, which is the
  unambiguous shape). The library ships no Twilio Auth Token rule, so a leaked
  Auth Token committed in a ``.env``, a ``twilio.yaml``, a CI workflow, or a
  Twilio SDK init was previously caught only by the low-confidence generic
  fallback (and frequently missed entirely — ``AUTH_TOKEN`` without context is
  not a credential-name keyword the generic rule strongly prefers). This rule
  closes the gap; combined with ``twilio-account-sid`` it lets a scan recover
  the full ``(SID, secret)`` pair from a single repo. Rated High exactly like
  the Account SID / API Key SID: a leaked Auth Token is a direct toll-fraud
  and smishing primitive (the attacker authenticates as the target and bills
  SMS / calls to the target's account), escalating to Critical when paired
  with elevated privileges (subaccount creation, master account access).
* **Linear API key** (``lin_api_`` + ≥36 base62) — the personal API token a
  Linear user or service account uses to authenticate to Linear's GraphQL /
  REST API (``https://api.linear.app/graphql``). Linear is a widely-used
  engineering project-management and issue-tracking platform; a leaked Linear
  API key authenticates as the issuing user and grants that user's full
  permission set on every team and project they belong to: read/write issues,
  projects, cycles, roadmaps, team members, and labels. The token shape is the
  rigid literal prefix ``lin_api_`` followed by a ≥36-char base62 body
  (uppercase, lowercase, digits) with word-boundary guards, matching both the
  shorter legacy tokens (~40 chars) and the current longer format (~80 chars).
  The ``lin_api_`` prefix is Linear-specific and does not collide with any other
  credential family, so no keyword anchor is required — the prefix alone drives
  the false-positive rate to near zero. A leaked token is a direct read/write
  path to the target's entire Linear workspace, exposing project roadmaps, sprint
  contents, team structure, and inter-team communication; write scope enables
  comment injection, issue manipulation, and label/assignment changes across all
  teams the user belongs to. Rated High: not direct compute or customer payment
  data, but a routine P2-class exposure on bug-bounty programs for SaaS/startup
  targets that use Linear, and a structural discovery primitive for further
  privilege escalation (issue content frequently contains database URIs, API keys
  pasted as "context", and internal architecture notes).
* **Datadog API / Application key** (``DD_API_KEY=<32 hex>`` / ``DD_APP_KEY=<40
  hex>`` and their ``DATADOG_…`` / ``DD-…-KEY`` aliases) — the credential pair
  the Datadog agent, integrations, ``datadog`` Python / Go SDKs, terraform
  provider and CI jobs use to authenticate to the Datadog REST API and to
  submit metrics, logs, traces and events to a Datadog org. The *API key* is a
  32-character lowercase-hex string (``DD_API_KEY`` / ``DATADOG_API_KEY``
  /``dd-api-key``) used as the ``DD-API-KEY`` request header to write
  telemetry; the *Application key* is a 40-character lowercase-hex string
  (``DD_APP_KEY`` / ``DD_APPLICATION_KEY`` / ``DATADOG_APP_KEY`` /
  ``dd-application-key``) used as the ``DD-APPLICATION-KEY`` header for the
  read / management side of the API (dashboards, monitors, SLOs, users,
  service accounts). Like an Okta token, the secret body itself has *no*
  fixed prefix — a Datadog API key is indistinguishable from any other
  32-char lowercase-hex blob — so the rule anchors on the surrounding
  key-name keyword that always accompanies the credential in source: env
  files (``DD_API_KEY=…``), agent configs (``api_key: <hex>`` inside a
  ``datadog.yaml`` — covered conservatively here via the ``DD_`` /
  ``DATADOG_`` prefixed keys, which are the unambiguous shape), HTTP request
  examples (``DD-API-KEY: …``), terraform provider blocks
  (``datadog_api_key = "…"``) and CI workflows. The keyword family is
  Datadog-specific (``DD_`` / ``DATADOG_`` / ``DD-`` prefix on an
  ``API_KEY`` / ``APP_KEY`` / ``APPLICATION_KEY`` suffix) and does not
  collide with other vendors. The 32-hex (API) and 40-hex (Application) body
  lengths are Datadog's documented sizes; we enforce them exactly so a
  wrong-length lookalike does not match. A leaked API key writes arbitrary
  metrics, logs and events into the target's Datadog org (a log-poisoning
  and billed-ingestion primitive); a leaked Application key authenticates to
  the management API and reads or modifies dashboards, monitors, users and
  service accounts — observability-plane compromise that exposes the
  target's infrastructure topology and operational alerting and, with write
  access, lets an attacker silence alerts on a separate intrusion. Rated
  High: not a direct path to cloud compute or customer data on its own, but
  a routine P2 on bug-bounty engagements and a force multiplier (the
  observability data names every host, every service, and frequently every
  other credential the org has accidentally logged).
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
# Databricks personal access token (dapi + 32 hex, optional workspace suffix)  #
# --------------------------------------------------------------------------- #
# Databricks PATs are the credential used by ``databricks`` CLI commands, the
# REST API, Jobs/Workspace/SQL APIs and Unity Catalog. The documented shape is
# the literal prefix ``dapi`` followed by exactly 32 lowercase-hex chars. Some
# Azure-Databricks workspaces append a ``-<digits>`` workspace-scope suffix to
# the token; we accept that as an optional tail so both single-workspace and
# Azure-multiworkspace forms match. Word-boundary guards keep an embedded
# identifier from partial-matching. The library ships no Databricks rule, so
# this closes the data-platform-token gap; rated Critical because a leaked PAT
# is a single hop from arbitrary code execution on the target's data-plane
# clusters and from the data those clusters can reach.
DATABRICKS_PAT = Rule(
    rule_id="databricks-pat",
    description="Databricks personal access token (dapi…)",
    regex=re.compile(r"\bdapi[0-9a-f]{32}(?:-[0-9]+)?\b"),
    severity=SEVERITY_CRITICAL,
)


# --------------------------------------------------------------------------- #
# Stripe restricted API key (rk_live_ / rk_test_ + base62 body)                 #
# --------------------------------------------------------------------------- #
# Stripe issues two families of server-side API keys: an unrestricted *secret*
# key (``sk_live_`` / ``sk_test_``) and a *restricted* key (``rk_live_`` /
# ``rk_test_``) whose permissions are explicitly scoped per Stripe resource
# (read/write per ``customers`` / ``payment_intents`` / ``charges`` / etc.).
# The shared library's ``stripe-secret-key`` rule anchors on ``sk_(live|test)_``
# only, so an ``rk_live_…`` committed in a server-side ``.env``, a CI workflow,
# or an SDK example was previously caught by the low-confidence generic
# fallback (and frequently missed entirely — restricted keys carry the same
# 24+ base62 body as a secret key but a different prefix). The two rules stay
# disjoint by prefix (``sk_`` vs ``rk_``) so a single key is never
# double-reported. The body shape (``[0-9a-zA-Z]{24,}``) mirrors the library's
# Stripe rule exactly so length variation across Stripe's historical key
# lengths (older 24-char vs current ~99-char) is accepted without broadening
# the prefix anchor. The ``rk_test_`` variant is already listed in
# ``tombstone.confidence._TEST_MODE_MARKERS``, so a leaked test-mode
# restricted key auto-grades to LOW confidence exactly like ``sk_test_``.
#
# Severity is rated HIGH (not Critical): unlike a secret key, a restricted
# key is permission-scoped by design — its blast radius is bounded by the
# scopes the issuer granted. In practice the scopes commonly granted (read
# on ``customers`` / ``charges`` / ``payment_intents``) still expose PII and
# payment metadata for the live account, which is a P2-class exposure
# (data-disclosure of customer records). It escalates to Critical when the
# restricted key turns out to carry write scope on payment resources, but
# that requires Stripe-side scope inspection the scanner can't do offline,
# so the rule declares HIGH and the report rationale explains the escalation
# path.
STRIPE_RESTRICTED_KEY = Rule(
    rule_id="stripe-restricted-key",
    description="Stripe restricted API key (rk_live_… / rk_test_…)",
    regex=re.compile(r"\b(rk_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
    severity=SEVERITY_HIGH,
)


# --------------------------------------------------------------------------- #
# Okta API token (SSWS + 40-char base64url body)                               #
# --------------------------------------------------------------------------- #
# Okta API tokens are 40-character URL-safe base64 strings with no fixed body
# prefix, but Okta's REST API requires them to be transmitted as
# ``Authorization: SSWS <token>`` — the literal ``SSWS`` scheme keyword is
# Okta-specific (no other auth scheme uses it), and that same keyword shows up
# wherever a token leaks in source: SDK configs (``token: SSWS …``), the
# terraform provider's ``api_token`` field, Postman / curl examples, and
# ``okta.yaml`` files. Anchoring on the ``SSWS`` literal followed by
# whitespace and the 40-char body keeps the false-positive rate near zero
# without requiring a body-prefix anchor the credential itself does not have.
# A leaked Okta API token authenticates as the issuing admin and grants
# read/write access to the org's users, apps, groups, sessions and factors —
# a complete identity-plane compromise that pivots into every downstream
# application Okta federates to, so we rate it Critical.
OKTA_API_TOKEN = Rule(
    rule_id="okta-api-token",
    description="Okta API token (SSWS scheme + 40-char base64url body)",
    regex=re.compile(r"\bSSWS\s+([0-9A-Za-z_\-]{40})\b"),
    severity=SEVERITY_CRITICAL,
    secret_group=1,
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


# --------------------------------------------------------------------------- #
# Linear API key (lin_api_ + ≥36 base62)                                     #
# --------------------------------------------------------------------------- #
# Linear (https://linear.app) is a widely-used engineering project-management
# and issue-tracking platform. Its personal API tokens carry the rigid literal
# prefix ``lin_api_`` followed by a ≥36-character base62 body (uppercase,
# lowercase, digits). The ``lin_api_`` prefix is Linear-specific — no other
# SaaS platform or library uses it — so the prefix alone is a near-zero-false-
# positive anchor without a surrounding keyword requirement. The 36-char lower
# bound covers both the shorter legacy tokens (~40 chars total after the prefix)
# and the current longer format (~80 chars). Word-boundary guards prevent a
# partial match inside a longer identifier. The library ships no Linear rule,
# so a leaked token committed in a ``.env``, a CI workflow, a GraphQL client
# config, or an SDK init was previously caught only by the low-confidence
# generic fallback. A leaked Linear API key authenticates as the issuing user
# and grants that user's full permission set: read/write issues, projects,
# cycles, roadmaps, team members, and labels across every team they belong to.
# Rated High: a routine P2-class exposure on bug-bounty programs for SaaS/
# startup targets using Linear, and a structural discovery primitive (issue
# content frequently embeds database URIs, API keys, and internal architecture
# notes pasted as "context").
LINEAR_API_KEY = Rule(
    rule_id="linear-api-key",
    description="Linear API key (lin_api_ + ≥36 base62)",
    regex=re.compile(r"\blin_api_[A-Za-z0-9]{36,}\b"),
    severity=SEVERITY_HIGH,
)


# --------------------------------------------------------------------------- #
# Datadog API key / Application key                                           #
# --------------------------------------------------------------------------- #
# A Datadog API key is a 32-char lowercase-hex string; a Datadog Application
# key is a 40-char lowercase-hex string. Neither has a fixed body prefix, so
# the rule anchors on the surrounding Datadog-specific keyword that always
# accompanies the credential in source: a `DD_` / `DATADOG_` / `DD-` prefix on
# an `API_KEY` / `APP_KEY` / `APPLICATION_KEY` suffix (case-insensitive on the
# keyword, `-` or `_` separator). The keyword family is Datadog-specific and
# does not collide with other vendors. We capture the hex body as the secret
# (secret_group=1) and accept whitespace, `=`, `:`, or quoted-value assignment
# between keyword and value to cover env files, YAML configs, JSON, HTTP
# headers and SDK config. The library ships no Datadog rule, so a leaked
# Datadog credential was previously caught only by the low-confidence generic
# fallback. Rated High: a leaked API key writes telemetry into the target's
# org (log-poisoning, billed-ingestion); a leaked Application key reads /
# modifies dashboards, monitors and users — a force-multiplier on
# bug-bounty engagements.
DATADOG_API_KEY = Rule(
    rule_id="datadog-api-key",
    description="Datadog API key / Application key (DD_API_KEY / DD_APP_KEY + 32/40 hex)",
    regex=re.compile(
        r"(?i)\b(?:DD|DATADOG)[-_](?:API|APP(?:LICATION)?)[-_]KEY"
        r"\s*[:=]\s*[\"']?"
        r"([0-9a-f]{32}(?:[0-9a-f]{8})?)"
        r"[\"']?\b"
    ),
    severity=SEVERITY_HIGH,
    secret_group=1,
)


# --------------------------------------------------------------------------- #
# Twilio Auth Token                                                            #
# --------------------------------------------------------------------------- #
# A Twilio Auth Token is a 32-char lowercase-hex string used as the HTTP basic-
# auth password (paired with the Account SID as the username) to authenticate
# to the Twilio REST API. The body has no fixed prefix (a 32-char hex blob is
# also a git blob SHA-1, an md5 hex, etc.), so the rule anchors on the
# surrounding Twilio-specific keyword that always accompanies the credential
# in source: a `TWILIO_` (or `TWILIO-` / `TWILIO.`) prefix on an `AUTH_TOKEN`
# (or `AUTHTOKEN` / `AUTH-TOKEN`) suffix. The `twilio-account-sid` rule covers
# the `AC…` identifier and `twilio-api-key-sid` covers the `SK…` identifier;
# this closes the third Twilio credential gap by recovering the *secret* half
# of the classic auth pair, the thing Twilio's own docs tell you to rotate
# when leaked. Mixed-case is allowed on the keyword (env files SHOUT it,
# YAML/SDK configs use camelCase like `twilio.authToken`), the body is
# enforced as exactly 32 lowercase hex chars (Twilio's documented format),
# and word-boundary guards keep an embedded identifier from partial-matching.
TWILIO_AUTH_TOKEN = Rule(
    rule_id="twilio-auth-token",
    description="Twilio Auth Token (TWILIO_AUTH_TOKEN + 32 hex)",
    regex=re.compile(
        r"(?i)\bTWILIO[-_.]?(?:AUTH[-_.]?TOKEN|TOKEN)"
        r"\s*[:=]\s*[\"']?"
        r"([0-9a-f]{32})"
        r"[\"']?\b"
    ),
    severity=SEVERITY_HIGH,
    secret_group=1,
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
    DATABRICKS_PAT,
    STRIPE_RESTRICTED_KEY,
    OKTA_API_TOKEN,
    AZURE_STORAGE_SAS,
    DATADOG_API_KEY,
    TWILIO_AUTH_TOKEN,
    LINEAR_API_KEY,
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
    "DATABRICKS_PAT",
    "STRIPE_RESTRICTED_KEY",
    "OKTA_API_TOKEN",
    "AZURE_STORAGE_SAS",
    "DATADOG_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "LINEAR_API_KEY",
    "EXTRA_RULES",
    "EXTRA_RULE_IDS",
]
