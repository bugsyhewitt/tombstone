"""Unit tests for the regex rule engine and entropy heuristics."""

from tombstone.extra_patterns import (
    AWS_STS_TEMP_KEY,
    AZURE_STORAGE_SAS,
    DATABRICKS_PAT,
    DATADOG_API_KEY,
    DIGITALOCEAN_PAT,
    DISCORD_BOT_TOKEN,
    DOCKER_HUB_PAT,
    EXTRA_RULE_IDS,
    GITHUB_TOKEN,
    GITLAB_PAT,
    GOOGLE_API_KEY,
    GRAFANA_SERVICE_ACCOUNT_TOKEN,
    HASHICORP_VAULT_TOKEN,
    LINEAR_API_KEY,
    NPM_TOKEN,
    OKTA_API_TOKEN,
    PRIVATE_KEY,
    PYPI_TOKEN,
    SENDGRID_API_KEY,
    SHOPIFY_TOKEN,
    SLACK_TOKEN,
    STRIPE_RESTRICTED_KEY,
    TWILIO_ACCOUNT_SID,
    TWILIO_API_KEY_SID,
    TWILIO_AUTH_TOKEN,
)
from tombstone.patterns import (
    AWS_ACCESS_KEY,
    GENERIC_HIGH_ENTROPY,
    STRIPE_SECRET_KEY,
    available_pattern_sets,
    get_rules,
    shannon_entropy,
)


def _matches(rule, text):
    for m in rule.regex.finditer(text):
        secret = m.group(rule.secret_group)
        if rule.validator and not rule.validator(secret):
            continue
        return secret
    return None


def test_aws_rule_matches_real_key():
    assert _matches(AWS_ACCESS_KEY, "key=AKIAIOSFODNN7EXAMPLE") == "AKIAIOSFODNN7EXAMPLE"


def test_aws_rule_ignores_lowercase_lookalike():
    assert _matches(AWS_ACCESS_KEY, 'k = "akiaiosfodnn7example"') is None


def test_stripe_rule_matches_real_key():
    # Assemble the key from fragments so no `sk_live_<body>` literal lives in
    # committed source (avoids GitHub push protection). See build_fixtures.py.
    key = "sk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    secret = _matches(STRIPE_SECRET_KEY, f'K = "{key}"')
    assert secret == key


def test_generic_matches_high_entropy_secret():
    secret = _matches(GENERIC_HIGH_ENTROPY, 'api_key = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"')
    assert secret == "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"


def test_generic_ignores_uuid():
    assert _matches(GENERIC_HIGH_ENTROPY, 'secret = "550e8400-e29b-41d4-a716-446655440000"') is None


def test_generic_ignores_git_sha():
    assert _matches(GENERIC_HIGH_ENTROPY, 'token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"') is None


def test_generic_ignores_low_entropy_repetition():
    assert _matches(GENERIC_HIGH_ENTROPY, 'password = "passwordpasswordpassword"') is None
    assert _matches(GENERIC_HIGH_ENTROPY, 'token = "aaaabbbbccccddddeeeeffff"') is None


def test_entropy_increases_with_randomness():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("Zx9Kq2Lm")


def test_pattern_sets_exist():
    assert set(available_pattern_sets()) >= {"minimal", "aws", "cloud", "full"}


def test_full_set_includes_base_and_cloud_rules():
    # necromancer-patterns >=0.2 expands `full` with cloud/dev-platform tokens
    # (GitHub PAT, GCP SA key, Azure DevOps PAT, OpenAI, Hugging Face, Anthropic)
    # on top of the original AWS / Stripe / generic-high-entropy trio.
    rule_ids = {r.rule_id for r in get_rules("full")}
    assert {"aws-access-key-id", "stripe-secret-key", "generic-high-entropy-secret"} <= rule_ids
    assert {"github-pat", "openai-api-key", "anthropic-api-key"} <= rule_ids


# --------------------------------------------------------------------------- #
# Tombstone-local extra credential rules (Slack / Google / GitLab / SendGrid  #
# / npm / private key). Each gets a true-positive and a true-negative.        #
# Secrets are assembled from fragments or randomised so no real-looking        #
# literal lives in committed source (avoids GitHub push protection).           #
# --------------------------------------------------------------------------- #

# Reusable 48-char base62 body for assembling synthetic key bodies.
_BODY = "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5aB6cD7e"


def test_slack_token_matches_bot_token():
    token = "xox" + "b-2492837456-2384971234-" + _BODY[:24]
    assert _matches(SLACK_TOKEN, f'SLACK_TOKEN = "{token}"') == token


def test_slack_token_ignores_lookalike_prefix():
    # xoxo- is not a valid Slack token type and must not match.
    assert _matches(SLACK_TOKEN, "greeting = xoxo-hugs-and-kisses") is None


def test_google_api_key_matches_real_format():
    key = "AIza" + _BODY[:35]
    assert _matches(GOOGLE_API_KEY, f'GOOGLE_MAPS_KEY="{key}"') == key


def test_google_api_key_ignores_short_prefix():
    # Correct prefix but too short to be a real key.
    assert _matches(GOOGLE_API_KEY, "k = AIzaShortValue") is None


def test_gitlab_pat_matches_real_format():
    pat = "glpat-" + _BODY[:20]
    assert _matches(GITLAB_PAT, f"export GL_TOKEN={pat}") == pat


def test_gitlab_pat_ignores_short_token():
    assert _matches(GITLAB_PAT, "token = glpat-tooshort") is None


def test_sendgrid_key_matches_real_format():
    key = "SG." + _BODY[:22] + "." + (_BODY + _BODY)[:43]
    assert _matches(SENDGRID_API_KEY, f'SENDGRID_API_KEY="{key}"') == key


def test_sendgrid_key_ignores_truncated_value():
    assert _matches(SENDGRID_API_KEY, 'k = "SG.short.short"') is None


def test_npm_token_matches_real_format():
    token = "npm" + "_" + _BODY[:36]
    assert _matches(NPM_TOKEN, f"//registry.npmjs.org/:_authToken={token}") == token


def test_npm_token_ignores_short_token():
    assert _matches(NPM_TOKEN, "_authToken=npm_short") is None


# PyPI upload tokens are `pypi-` + a base64url macaroon whose body always begins
# with the fixed string `AgEIcHlwaS5vcmc` (base64 of the `pypi.org` location id),
# followed by a long base64url tail. We assemble a synthetic one from fragments so
# no real-looking credential literal lives in committed source.
_PYPI_BODY = "AgEIcHlwaS5vcmc" + (_BODY + _BODY)[:64]


def test_pypi_token_matches_real_format():
    token = "pypi" + "-" + _PYPI_BODY
    assert _matches(PYPI_TOKEN, f"export TWINE_PASSWORD={token}") == token


def test_pypi_token_ignores_arbitrary_pypi_prefixed_string():
    # A `pypi-` prefix without the fixed `AgEIcHlwaS5vcmc` macaroon body-prefix is
    # not an upload token (e.g. a package name or unrelated identifier).
    assert _matches(PYPI_TOKEN, "name = pypi-something-not-a-token") is None


def test_pypi_token_ignores_short_body():
    # Correct prefix + macaroon marker but the tail is too short to be a real
    # serialised macaroon.
    assert _matches(PYPI_TOKEN, "k = pypi-AgEIcHlwaS5vcmcshort") is None


# Docker Hub PATs carry a fixed `dckr_pat_` prefix followed by a URL-safe base64
# body. Docker has issued both ~27-char and ~36-char body lengths over time, so
# the rule accepts a 27-40 char body window. We assemble synthetic bodies from
# fragments so no real-looking credential literal lives in committed source.


def test_docker_hub_pat_matches_short_body_format():
    # The shorter-body form Docker Hub has historically issued (~27 base64url
    # chars after the prefix). Fixed-prefix + length window → matches.
    token = "dckr" + "_pat_" + _BODY[:27]
    assert _matches(DOCKER_HUB_PAT, f"docker_password={token}") == token


def test_docker_hub_pat_matches_long_body_format():
    # The longer-body form Docker Hub issues (~36 base64url chars after the
    # prefix). Same rule must cover both length variants without splitting.
    token = "dckr" + "_pat_" + _BODY[:36]
    assert _matches(DOCKER_HUB_PAT, f'DOCKERHUB_TOKEN = "{token}"') == token


def test_docker_hub_pat_ignores_short_body():
    # Correct prefix but the body is shorter than any real PAT — must not match.
    assert _matches(DOCKER_HUB_PAT, "k = dckr_pat_tooshort") is None


def test_docker_hub_pat_ignores_wrong_prefix():
    # A near-miss prefix (no underscore, different word) must not match — the
    # `dckr_pat_` prefix is the entire structural anchor.
    assert _matches(DOCKER_HUB_PAT, "k = docker_pat_" + _BODY[:36]) is None
    assert _matches(DOCKER_HUB_PAT, "k = dckrpat" + _BODY[:36]) is None


# HashiCorp Vault tokens are `hv[sbr].` + a base64url body. Service tokens
# (`hvs.`) are typically ~95 chars, batch tokens (`hvb.`) 138-212 chars,
# recovery tokens (`hvr.`) similar to service tokens. The rule uses a single
# ≥24-char body window that covers every variant; the prefix is the
# distinguishing structural anchor.


def test_hashicorp_vault_service_token_matches():
    # `hvs.` — service token, the default Vault issues. Body assembled from
    # fragments so no real-looking literal lives in committed source.
    token = "hv" + "s." + (_BODY + _BODY)[:95]
    assert _matches(HASHICORP_VAULT_TOKEN, f'VAULT_TOKEN = "{token}"') == token


def test_hashicorp_vault_batch_token_matches():
    # `hvb.` — batch token, longer-body variant.
    token = "hv" + "b." + (_BODY + _BODY + _BODY)[:140]
    assert _matches(HASHICORP_VAULT_TOKEN, f"export VAULT_TOKEN={token}") == token


def test_hashicorp_vault_recovery_token_matches():
    # `hvr.` — recovery token, root-equivalent.
    token = "hv" + "r." + (_BODY + _BODY)[:95]
    assert _matches(HASHICORP_VAULT_TOKEN, f"vault_token: {token}") == token


def test_hashicorp_vault_token_ignores_short_body():
    # Correct prefix but the body is shorter than the 24-char minimum — must
    # not match. `hvs.short` is a near-miss that real tokens never produce.
    assert _matches(HASHICORP_VAULT_TOKEN, "k = hvs.short") is None
    assert _matches(HASHICORP_VAULT_TOKEN, "k = hvs." + _BODY[:20]) is None


def test_hashicorp_vault_token_ignores_wrong_prefix():
    # `hv` followed by an unrelated letter, or `hvs` without the literal dot,
    # must not match — the `hv[sbr].` prefix is the entire structural anchor.
    assert _matches(HASHICORP_VAULT_TOKEN, "k = hvx." + _BODY[:95]) is None
    assert _matches(HASHICORP_VAULT_TOKEN, "k = hvs" + _BODY[:95]) is None
    assert _matches(HASHICORP_VAULT_TOKEN, "k = vs." + _BODY[:95]) is None


def test_private_key_matches_rsa_header():
    header = "-----BEGIN RSA PRIVATE KEY-----"
    assert _matches(PRIVATE_KEY, header) == header


def test_private_key_matches_openssh_header():
    header = "-----BEGIN OPENSSH PRIVATE KEY-----"
    assert _matches(PRIVATE_KEY, header) == header


def test_private_key_ignores_public_key_and_certificate():
    assert _matches(PRIVATE_KEY, "-----BEGIN PUBLIC KEY-----") is None
    assert _matches(PRIVATE_KEY, "-----BEGIN CERTIFICATE-----") is None


# A 32-char lowercase-hex body for Shopify / Twilio synthetic tokens. Random
# enough to look real, not a published example, and never a literal credential.
_HEX32 = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"


def test_shopify_admin_token_matches():
    token = "shp" + "at_" + _HEX32
    assert _matches(SHOPIFY_TOKEN, f'SHOPIFY_TOKEN = "{token}"') == token


def test_shopify_other_prefixes_match():
    for prefix in ("shpss_", "shpca_", "shppa_"):
        token = prefix + _HEX32
        assert _matches(SHOPIFY_TOKEN, f"token={token}") == token


def test_shopify_token_ignores_wrong_prefix_and_short_body():
    # Unknown prefix must not match, and a too-short hex body must not match.
    assert _matches(SHOPIFY_TOKEN, "k = shpzz_" + _HEX32) is None
    assert _matches(SHOPIFY_TOKEN, "k = shp" + "at_dead") is None


def test_twilio_account_sid_matches():
    sid = "AC" + _HEX32
    assert _matches(TWILIO_ACCOUNT_SID, f"TWILIO_ACCOUNT_SID={sid}") == sid


def test_twilio_sid_ignores_missing_prefix_and_short():
    # 32 hex without the AC prefix is not a SID; AC + short hex is not a SID.
    assert _matches(TWILIO_ACCOUNT_SID, "blob=" + _HEX32) is None
    assert _matches(TWILIO_ACCOUNT_SID, "sid=AC0a1b2c3d") is None


def test_twilio_api_key_sid_matches():
    key = "SK" + _HEX32
    assert _matches(TWILIO_API_KEY_SID, f"TWILIO_API_KEY_SID={key}") == key


def test_twilio_api_key_sid_ignores_missing_prefix_and_short():
    # 32 hex without the SK prefix is not an API key; SK + short hex is not one.
    assert _matches(TWILIO_API_KEY_SID, "blob=" + _HEX32) is None
    assert _matches(TWILIO_API_KEY_SID, "key=SK0a1b2c3d") is None


def test_twilio_account_and_api_key_sids_stay_disjoint():
    # The AC account-sid rule must not match an SK api-key sid, and vice versa,
    # so a single Twilio SID is never reported by both rules.
    account_sid = "AC" + _HEX32
    api_key_sid = "SK" + _HEX32
    assert _matches(TWILIO_API_KEY_SID, f"x={account_sid}") is None
    assert _matches(TWILIO_ACCOUNT_SID, f"x={api_key_sid}") is None


def test_discord_bot_token_matches():
    token = "MjI4N" + "Dg1OTE5NTI1NjY1NjEx" + ".Gx" + "h7Pq" + "." + (_BODY[:30])
    matched = _matches(DISCORD_BOT_TOKEN, f"DISCORD_TOKEN={token}")
    assert matched == token


def test_discord_token_ignores_jwt():
    # A JWT shares the dot-segmented shape but its first segment is the base64
    # of `{"…`, i.e. starts with `eyJ`. This first segment is 24 chars — a
    # length the Discord rule *would* otherwise accept — so the test exercises
    # the negative lookahead specifically, not the length window.
    jwt_header = "eyJhbGciOiJIUzI1NiJ9XYZA"  # 24 chars, starts with eyJ
    assert len(jwt_header) == 24
    jwt = jwt_header + ".Gxh7Pq." + (_BODY[:30])
    assert _matches(DISCORD_BOT_TOKEN, f"Authorization: Bearer {jwt}") is None


# --------------------------------------------------------------------------- #
# GitHub token family (gho_ / ghu_ / ghs_ / ghr_). The library's `github-pat`  #
# rule covers only ghp_ and github_pat_; this tombstone-local rule fills in the #
# rest of the family — including ghs_, the shape of the Actions GITHUB_TOKEN.   #
# A 36-char base62 body assembled from fragments keeps no real-looking literal  #
# in committed source (avoids GitHub push protection).                         #
# --------------------------------------------------------------------------- #

# 36-char base62 body for synthetic GitHub tokens.
_GH_BODY = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def test_github_token_matches_oauth_and_server_to_server_prefixes():
    # gho_ (OAuth), ghu_ (user-to-server), ghs_ (server-to-server / Actions
    # installation token), ghr_ (refresh) all match.
    assert len(_GH_BODY) == 36
    for prefix in ("gho_", "ghu_", "ghs_", "ghr_"):
        token = prefix + _GH_BODY
        assert _matches(GITHUB_TOKEN, f'GH_TOKEN = "{token}"') == token


def test_github_token_does_not_match_classic_pat():
    # ghp_ is the classic PAT, owned by the library's `github-pat` rule. This
    # rule must NOT match it, so the two rules stay disjoint and a single token
    # is never double-reported.
    classic_pat = "ghp_" + _GH_BODY
    assert _matches(GITHUB_TOKEN, f"token={classic_pat}") is None


def test_github_token_ignores_short_body():
    # Correct prefix but the body is too short to be a real token.
    assert _matches(GITHUB_TOKEN, "k = ghs_tooshort") is None


# --------------------------------------------------------------------------- #
# AWS STS temporary access key id (ASIA…). The library's `aws-access-key-id`    #
# rule anchors on the long-lived `AKIA` prefix only; this tombstone-local rule  #
# fills in the `ASIA` temporary-credential id minted by STS. A 16-char base32   #
# body keeps no real-looking literal in committed source.                       #
# --------------------------------------------------------------------------- #

# 16-char uppercase base32 body for synthetic AWS access key ids.
_ASIA_BODY = "QXAMPLE7K2L4M6N8"


def test_aws_sts_temp_key_matches_asia_id():
    assert len(_ASIA_BODY) == 16
    key = "ASIA" + _ASIA_BODY
    assert _matches(AWS_STS_TEMP_KEY, f"aws_access_key_id = {key}") == key


def test_aws_sts_temp_key_does_not_match_long_lived_akia():
    # AKIA is the long-lived id, owned by the library's `aws-access-key-id` rule.
    # This rule must NOT match it, so the two stay disjoint.
    akia = "AKIA" + _ASIA_BODY
    assert _matches(AWS_STS_TEMP_KEY, f"key={akia}") is None


def test_aws_sts_temp_key_ignores_short_and_lowercase():
    # Correct prefix but body too short, and a lowercase lookalike, must not match.
    assert _matches(AWS_STS_TEMP_KEY, "k = ASIASHORT") is None
    assert _matches(AWS_STS_TEMP_KEY, "k = asia" + _ASIA_BODY.lower()) is None


# --------------------------------------------------------------------------- #
# Azure Storage SAS token (sig=<url-encoded HMAC> + a SAS companion param). The #
# library ships an Azure DevOps PAT rule but no Storage SAS rule; this           #
# tombstone-local rule fills that gap. The anchor is `sig=` plus a SAS companion #
# query param (sv / sp / se / st / sr / ss / srt). A synthetic base64 signature  #
# assembled from fragments keeps no real-looking credential in committed source. #
# --------------------------------------------------------------------------- #

# A 50-char base64 body for synthetic SAS signatures — long enough to clear the
# rule's 40-char minimum without resembling a published credential.
_SAS_SIG = "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5aB6cD7eF8g"


def test_azure_sas_matches_companion_before_sig():
    # The canonical account-SAS query-string order: SAS params, then sig= last.
    sas = (
        "sv=2022-11-02&ss=b&srt=co&sp=rwdlac"
        "&se=2026-12-31T23:59:59Z&spr=https&sig=" + _SAS_SIG
    )
    url = "https://acct.blob.core.windows.net/c/blob.txt?" + sas
    assert _matches(AZURE_STORAGE_SAS, url) is not None


def test_azure_sas_matches_sig_before_companion():
    # Some SDKs / connection strings emit sig= before the other SAS params.
    blob = "sig=" + _SAS_SIG + "&sv=2021-08-06&sp=r&se=2026-05-01T00:00:00Z"
    conn = "SharedAccessSignature=" + blob
    assert _matches(AZURE_STORAGE_SAS, conn) is not None


def test_azure_sas_matches_url_encoded_signature():
    # The base64 signature is commonly percent-encoded (%2B %2F %3D) in URLs.
    sig = "Z%2F" + _SAS_SIG + "%3D"
    sas = "sp=r&sv=2022-11-02&sr=b&sig=" + sig
    assert _matches(AZURE_STORAGE_SAS, "?" + sas) is not None


def test_azure_sas_ignores_bare_sig_without_companion():
    # A long `sig=` value with no SAS companion param is some other app's
    # signature field, not a Storage SAS — must not match.
    assert _matches(AZURE_STORAGE_SAS, "callback?sig=" + _SAS_SIG + "&foo=bar") is None


def test_azure_sas_ignores_short_signature_and_lookalikes():
    # `sig=` too short to be an HMAC, even with a companion, must not match; and
    # near-miss keys (svg=, signature=) must not match.
    assert _matches(AZURE_STORAGE_SAS, "sv=2022-11-02&sig=deadbeef") is None
    assert _matches(AZURE_STORAGE_SAS, "svg=icon&signature=hello") is None


# --------------------------------------------------------------------------- #
# Databricks personal access token (`dapi` + 32 hex, optional `-<digits>`      #
# workspace-scope suffix). The library ships no Databricks rule; this           #
# tombstone-local rule closes the data-platform-token gap. The 32-hex body is   #
# assembled from fragments so no real-looking credential lives in committed     #
# source.                                                                       #
# --------------------------------------------------------------------------- #


def test_databricks_pat_matches_canonical_token():
    # `dapi` + 32 lowercase hex chars — the documented PAT shape.
    token = "da" + "pi" + _HEX32
    assert _matches(DATABRICKS_PAT, f'DATABRICKS_TOKEN = "{token}"') == token


def test_databricks_pat_matches_workspace_suffix_variant():
    # Some Azure-Databricks workspaces append a `-<digits>` workspace-scope
    # suffix to the token; both single-workspace and Azure forms must match.
    token = "da" + "pi" + _HEX32 + "-2"
    assert _matches(DATABRICKS_PAT, f"export DATABRICKS_TOKEN={token}") == token
    long_suffix = "da" + "pi" + _HEX32 + "-1234567"
    assert _matches(DATABRICKS_PAT, f"k={long_suffix}") == long_suffix


def test_databricks_pat_ignores_short_and_wrong_length():
    # Correct prefix but body shorter than 32 hex must not match — the exact
    # length is part of the structural anchor.
    assert _matches(DATABRICKS_PAT, "k = dapi" + _HEX32[:16]) is None
    assert _matches(DATABRICKS_PAT, "k = dapi" + _HEX32[:31]) is None
    # And a 33-hex body (one too long) must not match either; the boundary keeps
    # an unrelated trailing hex char from extending a real-looking token.
    assert _matches(DATABRICKS_PAT, "k = dapi" + _HEX32 + "a") is None


def test_databricks_pat_ignores_wrong_prefix_and_non_hex_body():
    # A near-miss prefix (`api` alone, or `dapix`) must not match.
    assert _matches(DATABRICKS_PAT, "k = api" + _HEX32) is None
    assert _matches(DATABRICKS_PAT, "k = dapix" + _HEX32) is None
    # Uppercase hex is not the Databricks PAT shape (the documented body is
    # lowercase hex); accepting it would broaden the false-positive surface to
    # any `dapi`-prefixed identifier whose tail happens to look hex-like.
    assert _matches(DATABRICKS_PAT, "k = dapi" + _HEX32.upper()) is None
    # A body that's 32 chars but contains a non-hex char must not match.
    assert _matches(DATABRICKS_PAT, "k = dapi" + "g" + _HEX32[1:]) is None


def test_databricks_pat_workspace_suffix_must_be_digits():
    # The optional workspace suffix is `-<digits>` only; letters after the dash
    # must not extend a match.
    base = "da" + "pi" + _HEX32
    # `-abc` is not a workspace suffix — the rule matches only the base token.
    assert _matches(DATABRICKS_PAT, f"k = {base}-abc") == base


# --------------------------------------------------------------------------- #
# Stripe restricted API key (`rk_live_` / `rk_test_` + 24+ base62). The shared #
# library's `stripe-secret-key` covers only the `sk_(live|test)_` prefix; this #
# tombstone-local rule closes the restricted-key gap. The body is assembled    #
# from fragments so no real-looking credential lives in committed source       #
# (avoids GitHub push protection on a known Stripe prefix).                    #
# --------------------------------------------------------------------------- #


def _rk_live(body: str) -> str:
    # Assemble the literal prefix at runtime to keep the committed source out
    # of GitHub's secret-scanning push-protection match window.
    return "rk" + "_" + "live" + "_" + body


def _rk_test(body: str) -> str:
    return "rk" + "_" + "test" + "_" + body


def test_stripe_restricted_key_matches_live_key():
    # Canonical shape: rk_live_ + 24+ base62 chars (mirroring the library's
    # Stripe secret-key body shape).
    key = _rk_live("9Hq2WkPmZ7tRb4Ld8Xn3Vc6q")
    assert _matches(STRIPE_RESTRICTED_KEY, f'STRIPE_KEY = "{key}"') == key


def test_stripe_restricted_key_matches_test_key():
    # The rk_test_ variant matches the same way; downstream confidence scoring
    # is what downgrades test-mode keys to LOW, not the regex.
    key = _rk_test("4eC39HqLyjWDarjtT1zdp7dc")
    assert _matches(STRIPE_RESTRICTED_KEY, f"export STRIPE_KEY={key}") == key


def test_stripe_restricted_key_matches_long_modern_body():
    # Stripe's current restricted keys carry a ~99-char body; the rule must
    # accept the long form without a fixed length cap.
    body = ("Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv" * 4)[:99]
    key = _rk_live(body)
    assert _matches(STRIPE_RESTRICTED_KEY, f"k={key}") == key


def test_stripe_restricted_key_ignores_short_body():
    # A body shorter than 24 chars is below the structural floor and must not
    # match — keeps an arbitrary `rk_live_x` style identifier from tripping the
    # rule.
    short = _rk_live("abc123")
    assert _matches(STRIPE_RESTRICTED_KEY, f"k = {short}") is None
    short_23 = _rk_live("a" * 23)
    assert _matches(STRIPE_RESTRICTED_KEY, f"k = {short_23}") is None


def test_stripe_restricted_key_ignores_wrong_mode_and_prefix():
    # `rk_prod_` is not a Stripe key mode; only `live` / `test` are valid.
    not_a_key = "rk" + "_" + "prod" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    assert _matches(STRIPE_RESTRICTED_KEY, f"k = {not_a_key}") is None
    # `pk_live_…` (publishable) and `sk_live_…` (secret) must not match the
    # restricted rule — those are owned by other rules / the library.
    pk = "pk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    sk = "sk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    assert _matches(STRIPE_RESTRICTED_KEY, f"k = {pk}") is None
    assert _matches(STRIPE_RESTRICTED_KEY, f"k = {sk}") is None


def test_stripe_restricted_key_disjoint_from_stripe_secret_key():
    # An `rk_live_…` must NOT match the library's `stripe-secret-key` rule,
    # and an `sk_live_…` must NOT match the restricted rule — the two are
    # disjoint by prefix so a single key is never double-reported.
    rk = _rk_live("9Hq2WkPmZ7tRb4Ld8Xn3Vc6q")
    sk = "sk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    assert _matches(STRIPE_SECRET_KEY, f"k = {rk}") is None
    assert _matches(STRIPE_RESTRICTED_KEY, f"k = {sk}") is None


# --------------------------------------------------------------------------- #
# Okta API token (`SSWS <40-char base64url>`). The library ships no Okta rule;  #
# this tombstone-local rule fills the identity-platform gap. The 40-char body   #
# is assembled from fragments so no real-looking credential lives in committed  #
# source.                                                                       #
# --------------------------------------------------------------------------- #

# 40-char base64url body for synthetic Okta API tokens (matches Okta's
# documented token length). Assembled from fragments — never a published value.
_OKTA_BODY = "00aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ"


def test_okta_api_token_matches_authorization_header():
    # The canonical place Okta tokens appear: an HTTP Authorization header
    # using the literal `SSWS` scheme. The rule must extract just the token
    # body (secret_group=1), not the leading `SSWS ` keyword.
    assert len(_OKTA_BODY) == 40
    header = "Authorization: SSWS " + _OKTA_BODY
    assert _matches(OKTA_API_TOKEN, header) == _OKTA_BODY


def test_okta_api_token_matches_config_file_style():
    # An `okta.yaml` / SDK config commonly writes the token with the SSWS
    # scheme inline as the value: `apiToken: SSWS <token>`.
    line = "apiToken: SSWS " + _OKTA_BODY
    assert _matches(OKTA_API_TOKEN, line) == _OKTA_BODY


def test_okta_api_token_matches_terraform_provider_style():
    # Some terraform examples / Postman collections quote the whole value
    # including the scheme; the rule should still match.
    line = 'api_token = "SSWS ' + _OKTA_BODY + '"'
    assert _matches(OKTA_API_TOKEN, line) == _OKTA_BODY


def test_okta_api_token_ignores_bare_token_without_ssws_scheme():
    # A bare 40-char base64url body without the `SSWS` scheme keyword is not
    # an identifiable Okta token — countless other 40-char base64url strings
    # exist (other API tokens, hashes, etc.). The `SSWS` literal IS the
    # anchor; without it the rule must not match.
    assert _matches(OKTA_API_TOKEN, "token = " + _OKTA_BODY) is None


def test_okta_api_token_ignores_short_body():
    # Correct scheme but body too short to be a real Okta API token.
    assert _matches(OKTA_API_TOKEN, "Authorization: SSWS " + _OKTA_BODY[:30]) is None


def test_okta_api_token_ignores_wrong_scheme():
    # `Bearer` / `Basic` / unrelated scheme keywords must not match — only
    # the Okta-specific `SSWS` scheme is the anchor.
    assert _matches(OKTA_API_TOKEN, "Authorization: Bearer " + _OKTA_BODY) is None
    assert _matches(OKTA_API_TOKEN, "Authorization: Basic " + _OKTA_BODY) is None


def test_okta_api_token_ignores_ssws_substring_without_token():
    # The literal `SSWS` appearing in unrelated text (e.g. a docstring
    # mentioning the scheme name) must not match without a 40-char base64url
    # body following it.
    assert _matches(OKTA_API_TOKEN, "The SSWS scheme is Okta-specific.") is None


# --------------------------------------------------------------------------- #
# Datadog API key / Application key (`DD_API_KEY=<32 hex>` /                  #
# `DD_APP_KEY=<40 hex>` and aliases). Like the Okta rule, the secret body has #
# no fixed prefix so the rule anchors on the surrounding Datadog-specific     #
# keyword; the rule captures the hex body as the secret. Hex bodies are       #
# assembled from fragments so no real-looking value lives in committed source.#
# --------------------------------------------------------------------------- #

# 32 lowercase-hex chars — the documented Datadog API-key body length.
_DD_API_BODY = _HEX32
# 40 lowercase-hex chars — the documented Datadog Application-key body length.
_DD_APP_BODY = _HEX32 + "aabbccdd"


def test_datadog_api_key_matches_env_assignment():
    assert len(_DD_API_BODY) == 32
    line = f"DD_API_KEY={_DD_API_BODY}"
    assert _matches(DATADOG_API_KEY, line) == _DD_API_BODY


def test_datadog_api_key_matches_datadog_prefix_alias():
    line = f"DATADOG_API_KEY={_DD_API_BODY}"
    assert _matches(DATADOG_API_KEY, line) == _DD_API_BODY


def test_datadog_api_key_matches_yaml_colon_assignment():
    line = f"dd_api_key: {_DD_API_BODY}"
    assert _matches(DATADOG_API_KEY, line) == _DD_API_BODY


def test_datadog_api_key_matches_quoted_value():
    line = f'DD_API_KEY = "{_DD_API_BODY}"'
    assert _matches(DATADOG_API_KEY, line) == _DD_API_BODY


def test_datadog_api_key_matches_hyphen_header_style():
    assert len(_DD_API_BODY) == 32
    line = f"DD-API-KEY: {_DD_API_BODY}"
    assert _matches(DATADOG_API_KEY, line) == _DD_API_BODY


def test_datadog_application_key_matches_40_hex_body():
    assert len(_DD_APP_BODY) == 40
    line = f"DD_APP_KEY={_DD_APP_BODY}"
    assert _matches(DATADOG_API_KEY, line) == _DD_APP_BODY


def test_datadog_application_key_matches_full_application_keyword():
    line = f"DD_APPLICATION_KEY={_DD_APP_BODY}"
    assert _matches(DATADOG_API_KEY, line) == _DD_APP_BODY


def test_datadog_api_key_ignores_bare_hex_without_keyword():
    # The hex body alone (a 32-char lowercase-hex blob is also a git SHA-256,
    # an md5 hex string, etc.) must not match — the Datadog keyword IS the
    # anchor, without which there is no signal it is a Datadog credential.
    assert _matches(DATADOG_API_KEY, f"checksum = {_DD_API_BODY}") is None


def test_datadog_api_key_ignores_wrong_length_body():
    # 31 hex chars (too short) and 33 hex chars (too long) must not match —
    # Datadog's documented sizes are exactly 32 (API) or 40 (Application).
    short = _DD_API_BODY[:31]
    too_long = _DD_API_BODY + "f"
    assert _matches(DATADOG_API_KEY, f"DD_API_KEY={short}") is None
    assert _matches(DATADOG_API_KEY, f"DD_API_KEY={too_long}") is None


def test_datadog_api_key_ignores_non_hex_body():
    # The body must be lowercase hex. Uppercase / base62 must not match —
    # Datadog keys are always lowercase hex per their docs.
    non_hex = "0a1b2c3d4e5f60718293a4b5c6d7e8XY"
    assert len(non_hex) == 32
    assert _matches(DATADOG_API_KEY, f"DD_API_KEY={non_hex}") is None


def test_datadog_api_key_ignores_unrelated_keyword():
    # `AWS_API_KEY` / `GCP_API_KEY` / arbitrary `MY_API_KEY` must not match —
    # only the `DD_` / `DATADOG_` keyword prefix anchors the rule.
    assert _matches(DATADOG_API_KEY, f"AWS_API_KEY={_DD_API_BODY}") is None
    assert _matches(DATADOG_API_KEY, f"MY_API_KEY={_DD_API_BODY}") is None


# 32 lowercase-hex chars — the documented Twilio Auth Token body length.
_TWILIO_AUTH_BODY = _HEX32


def test_twilio_auth_token_matches_env_assignment():
    assert len(_TWILIO_AUTH_BODY) == 32
    line = f"TWILIO_AUTH_TOKEN={_TWILIO_AUTH_BODY}"
    assert _matches(TWILIO_AUTH_TOKEN, line) == _TWILIO_AUTH_BODY


def test_twilio_auth_token_matches_yaml_colon_assignment():
    line = f"twilio_auth_token: {_TWILIO_AUTH_BODY}"
    assert _matches(TWILIO_AUTH_TOKEN, line) == _TWILIO_AUTH_BODY


def test_twilio_auth_token_matches_quoted_value():
    line = f'TWILIO_AUTH_TOKEN = "{_TWILIO_AUTH_BODY}"'
    assert _matches(TWILIO_AUTH_TOKEN, line) == _TWILIO_AUTH_BODY


def test_twilio_auth_token_matches_dotted_sdk_style():
    # SDK-config / dotted-key form (`twilio.authToken = "…"`) — the same
    # credential transcribed by a YAML/JSON config or a JS SDK init.
    line = f'twilio.authToken = "{_TWILIO_AUTH_BODY}"'
    assert _matches(TWILIO_AUTH_TOKEN, line) == _TWILIO_AUTH_BODY


def test_twilio_auth_token_matches_hyphen_header_style():
    line = f"TWILIO-AUTH-TOKEN: {_TWILIO_AUTH_BODY}"
    assert _matches(TWILIO_AUTH_TOKEN, line) == _TWILIO_AUTH_BODY


def test_twilio_auth_token_ignores_bare_hex_without_keyword():
    # 32-char lowercase-hex is also a git blob SHA-1, an md5 hex, etc. —
    # without the TWILIO keyword anchor there is no signal it is the Twilio
    # secret, so a bare hex assignment must not match.
    assert _matches(TWILIO_AUTH_TOKEN, f"checksum = {_TWILIO_AUTH_BODY}") is None
    assert _matches(TWILIO_AUTH_TOKEN, f"AUTH_TOKEN={_TWILIO_AUTH_BODY}") is None


def test_twilio_auth_token_ignores_wrong_length_body():
    # Twilio's documented body length is exactly 32 lowercase hex chars.
    short = _TWILIO_AUTH_BODY[:31]
    too_long = _TWILIO_AUTH_BODY + "f"
    assert _matches(TWILIO_AUTH_TOKEN, f"TWILIO_AUTH_TOKEN={short}") is None
    assert _matches(TWILIO_AUTH_TOKEN, f"TWILIO_AUTH_TOKEN={too_long}") is None


def test_twilio_auth_token_ignores_non_hex_body():
    # Uppercase / base62 must not match — Twilio Auth Tokens are lowercase hex.
    non_hex = "0a1b2c3d4e5f60718293a4b5c6d7e8XY"
    assert len(non_hex) == 32
    assert _matches(TWILIO_AUTH_TOKEN, f"TWILIO_AUTH_TOKEN={non_hex}") is None


def test_twilio_auth_token_ignores_unrelated_vendor_keyword():
    # `AWS_AUTH_TOKEN` / `STRIPE_AUTH_TOKEN` / `MY_AUTH_TOKEN` must not match —
    # the TWILIO keyword IS the anchor.
    assert _matches(TWILIO_AUTH_TOKEN, f"AWS_AUTH_TOKEN={_TWILIO_AUTH_BODY}") is None
    assert _matches(TWILIO_AUTH_TOKEN, f"MY_AUTH_TOKEN={_TWILIO_AUTH_BODY}") is None


def test_twilio_auth_token_disjoint_from_account_and_api_key_sids():
    # The Auth Token rule must not steal matches from the SID rules: an SID
    # assignment carries the SID's 2-letter `AC…` / `SK…` body, not a bare
    # 32-hex blob, so the Auth Token rule should ignore it.
    account_sid_line = "TWILIO_ACCOUNT_SID=AC" + _TWILIO_AUTH_BODY
    api_key_sid_line = "TWILIO_API_KEY_SID=SK" + _TWILIO_AUTH_BODY
    assert _matches(TWILIO_AUTH_TOKEN, account_sid_line) is None
    assert _matches(TWILIO_AUTH_TOKEN, api_key_sid_line) is None


def test_broad_sets_include_extra_rules():
    # cloud and full are the broad multi-provider sets and must pick up the
    # tombstone-local rules.
    for pattern_set in ("cloud", "full"):
        rule_ids = {r.rule_id for r in get_rules(pattern_set)}
        assert EXTRA_RULE_IDS <= rule_ids


# ---------------------------------------------------------------------------
# Linear API key (lin_api_ + ≥36 base62)
# ---------------------------------------------------------------------------
# A real Linear API key uses the rigid literal prefix ``lin_api_`` followed
# by a base62 body. The prefix alone is the anchor — no keyword required.

_LINEAR_BODY_SHORT = "A" * 36  # minimum-length base62 body (legacy format)
_LINEAR_BODY_LONG = "A" * 72   # current longer format


def test_linear_api_key_matches_env_assignment_short():
    """lin_api_ + 36-char base62 body must match (env-file assignment form)."""
    assert _matches(LINEAR_API_KEY, f"lin_api_{_LINEAR_BODY_SHORT}") == f"lin_api_{_LINEAR_BODY_SHORT}"
    # The rule carries no secret_group capture, so the full match is returned.
    assert LINEAR_API_KEY.secret_group == 0


def test_linear_api_key_matches_env_var_form():
    """lin_api_ prefix plus base62 body matches in a plain env-file line."""
    token = f"lin_api_{_LINEAR_BODY_SHORT}"
    assert _matches(LINEAR_API_KEY, f"LINEAR_API_KEY={token}") == token


def test_linear_api_key_matches_long_body():
    """lin_api_ + 72-char body (current format) must also match."""
    token = f"lin_api_{_LINEAR_BODY_LONG}"
    assert _matches(LINEAR_API_KEY, token) == token


def test_linear_api_key_matches_mixed_case_base62_body():
    """The base62 body may contain uppercase, lowercase, and digits."""
    body = "aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kK0lLx"
    assert len(body) == 36
    token = f"lin_api_{body}"
    assert _matches(LINEAR_API_KEY, token) == token


def test_linear_api_key_ignores_short_body():
    """A body shorter than 36 chars must not match."""
    short = "A" * 35
    assert _matches(LINEAR_API_KEY, f"lin_api_{short}") is None


def test_linear_api_key_ignores_wrong_prefix():
    """Any prefix other than lin_api_ must not match even with a valid body."""
    body = _LINEAR_BODY_SHORT
    assert _matches(LINEAR_API_KEY, f"api_{body}") is None
    assert _matches(LINEAR_API_KEY, f"linear_{body}") is None
    assert _matches(LINEAR_API_KEY, f"lin_{body}") is None


def test_linear_api_key_severity_is_high():
    """Rule must carry the HIGH severity rating — a leaked Linear API key is
    a P2-class finding on bug-bounty programs for SaaS/startup targets."""
    from necromancer_patterns import SEVERITY_HIGH

    assert LINEAR_API_KEY.severity == SEVERITY_HIGH


def test_linear_api_key_bcmd_impact_text_is_registered():
    """The ``linear-api-key`` rule id must have a severity rationale entry in
    tombstone.report._SEVERITY so ``--format bcmd`` findings render with
    platform-native Demonstrated Impact framing."""
    from tombstone.report import _SEVERITY

    assert "linear-api-key" in _SEVERITY
    rating, description = _SEVERITY["linear-api-key"]
    assert "Linear" in description
    assert "P2" in rating or "High" in rating


# --------------------------------------------------------------------------- #
# Grafana service-account token (glsa_ + 22 base62 + _ + 8 hex)              #
# --------------------------------------------------------------------------- #

_GRAFANA_BODY = "A" * 22  # exactly 22 base62 chars
_GRAFANA_CHECKSUM = "deadbeef"  # exactly 8 lowercase hex chars
_GRAFANA_VALID = f"glsa_{_GRAFANA_BODY}_{_GRAFANA_CHECKSUM}"


def test_grafana_service_account_token_matches_canonical_form():
    """The canonical glsa_<22base62>_<8hex> form must match."""
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, _GRAFANA_VALID) == _GRAFANA_VALID


def test_grafana_service_account_token_matches_in_env_assignment():
    """Token embedded in an env-style assignment must be detected."""
    line = f"GRAFANA_TOKEN={_GRAFANA_VALID}"
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, line) == _GRAFANA_VALID


def test_grafana_service_account_token_matches_yaml_colon_style():
    """Token as a YAML value (``token: glsa_…``) must be detected."""
    line = f"token: {_GRAFANA_VALID}"
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, line) == _GRAFANA_VALID


def test_grafana_service_account_token_matches_mixed_case_base62_body():
    """Body chars may be uppercase, lowercase, or digits — all valid base62."""
    body = "aB3dEf5gHi7jKl9mNo1pQr"  # exactly 22 mixed base62 chars
    token = f"glsa_{body}_{_GRAFANA_CHECKSUM}"
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, token) == token


def test_grafana_service_account_token_ignores_short_body():
    """A body shorter than 22 chars must not match."""
    short_body = "A" * 21
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, f"glsa_{short_body}_{_GRAFANA_CHECKSUM}") is None


def test_grafana_service_account_token_ignores_long_body():
    """A body longer than 22 chars must not match (exact length required)."""
    long_body = "A" * 23
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, f"glsa_{long_body}_{_GRAFANA_CHECKSUM}") is None


def test_grafana_service_account_token_ignores_wrong_checksum_length():
    """A checksum shorter or longer than 8 hex chars must not match."""
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, f"glsa_{_GRAFANA_BODY}_deadbee") is None   # 7
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, f"glsa_{_GRAFANA_BODY}_deadbeef0") is None  # 9


def test_grafana_service_account_token_ignores_wrong_prefix():
    """Any prefix other than glsa_ must not match."""
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, f"gfsa_{_GRAFANA_BODY}_{_GRAFANA_CHECKSUM}") is None
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, f"sa_{_GRAFANA_BODY}_{_GRAFANA_CHECKSUM}") is None


def test_grafana_service_account_token_ignores_uppercase_checksum():
    """The checksum field must be lowercase hex; uppercase must not match."""
    upper_checksum = "DEADBEEF"
    assert _matches(GRAFANA_SERVICE_ACCOUNT_TOKEN, f"glsa_{_GRAFANA_BODY}_{upper_checksum}") is None


def test_grafana_service_account_token_severity_is_high():
    """Rule must carry the HIGH severity rating."""
    from necromancer_patterns import SEVERITY_HIGH

    assert GRAFANA_SERVICE_ACCOUNT_TOKEN.severity == SEVERITY_HIGH


def test_grafana_service_account_token_bcmd_impact_text_is_registered():
    """The ``grafana-service-account-token`` rule id must have a severity
    rationale entry in tombstone.report._SEVERITY for bcmd output."""
    from tombstone.report import _SEVERITY

    assert "grafana-service-account-token" in _SEVERITY
    rating, description = _SEVERITY["grafana-service-account-token"]
    assert "Grafana" in description
    assert "P2" in rating or "High" in rating


def test_grafana_service_account_token_is_in_extra_rule_ids():
    """The rule id must appear in EXTRA_RULE_IDS."""
    assert "grafana-service-account-token" in EXTRA_RULE_IDS


# --------------------------------------------------------------------------- #
# DigitalOcean personal access token (dop_v1_ + 64 lowercase hex)             #
# --------------------------------------------------------------------------- #

_DO_PAT_BODY = "a" * 64  # exactly 64 lowercase hex chars (all 'a' is valid hex)
_DO_PAT_VALID = f"dop_v1_{_DO_PAT_BODY}"


def test_digitalocean_pat_matches_canonical_form():
    """The canonical dop_v1_<64hex> form must match."""
    assert _matches(DIGITALOCEAN_PAT, _DO_PAT_VALID) == _DO_PAT_VALID


def test_digitalocean_pat_matches_in_env_assignment():
    """Token embedded in an env-style assignment must be detected."""
    line = f"DO_TOKEN={_DO_PAT_VALID}"
    assert _matches(DIGITALOCEAN_PAT, line) == _DO_PAT_VALID


def test_digitalocean_pat_matches_yaml_colon_style():
    """Token as a YAML value (``token: dop_v1_…``) must be detected."""
    line = f"token: {_DO_PAT_VALID}"
    assert _matches(DIGITALOCEAN_PAT, line) == _DO_PAT_VALID


def test_digitalocean_pat_rejects_short_body():
    """A body shorter than 64 hex chars must not match."""
    short = "a" * 63
    assert _matches(DIGITALOCEAN_PAT, f"dop_v1_{short}") is None


def test_digitalocean_pat_rejects_wrong_prefix():
    """A 64-char hex body with a non-dop_v1_ prefix must not match."""
    assert _matches(DIGITALOCEAN_PAT, f"do_v1_{_DO_PAT_BODY}") is None
    assert _matches(DIGITALOCEAN_PAT, f"pat_v1_{_DO_PAT_BODY}") is None
    assert _matches(DIGITALOCEAN_PAT, f"dop_{_DO_PAT_BODY}") is None


def test_digitalocean_pat_severity_is_critical():
    """Rule must carry the CRITICAL severity rating."""
    from necromancer_patterns import SEVERITY_CRITICAL

    assert DIGITALOCEAN_PAT.severity == SEVERITY_CRITICAL


def test_digitalocean_pat_bcmd_impact_text_is_registered():
    """The ``digitalocean-pat`` rule id must have a severity rationale entry in
    tombstone.report._SEVERITY so ``--format bcmd`` findings render with
    platform-native Demonstrated Impact framing."""
    from tombstone.report import _SEVERITY

    assert "digitalocean-pat" in _SEVERITY
    rating, description = _SEVERITY["digitalocean-pat"]
    assert "DigitalOcean" in description
    assert "Critical" in rating or "P1" in rating


def test_digitalocean_pat_is_in_extra_rule_ids():
    """The rule id must appear in EXTRA_RULE_IDS."""
    assert "digitalocean-pat" in EXTRA_RULE_IDS


def test_narrow_aws_sets_exclude_extra_rules():
    # The AWS-only sets stay narrow — no extra rules leak in.
    for pattern_set in ("minimal", "aws"):
        rule_ids = {r.rule_id for r in get_rules(pattern_set)}
        assert not (EXTRA_RULE_IDS & rule_ids)


def test_no_duplicate_rule_ids_in_full_set():
    rule_ids = [r.rule_id for r in get_rules("full")]
    assert len(rule_ids) == len(set(rule_ids))
