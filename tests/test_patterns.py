"""Unit tests for the regex rule engine and entropy heuristics."""

from tombstone.extra_patterns import (
    AWS_STS_TEMP_KEY,
    AZURE_STORAGE_SAS,
    DISCORD_BOT_TOKEN,
    EXTRA_RULE_IDS,
    GITHUB_TOKEN,
    GITLAB_PAT,
    GOOGLE_API_KEY,
    NPM_TOKEN,
    PRIVATE_KEY,
    PYPI_TOKEN,
    SENDGRID_API_KEY,
    SHOPIFY_TOKEN,
    SLACK_TOKEN,
    TWILIO_ACCOUNT_SID,
    TWILIO_API_KEY_SID,
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


def test_broad_sets_include_extra_rules():
    # cloud and full are the broad multi-provider sets and must pick up the
    # tombstone-local rules.
    for pattern_set in ("cloud", "full"):
        rule_ids = {r.rule_id for r in get_rules(pattern_set)}
        assert EXTRA_RULE_IDS <= rule_ids


def test_narrow_aws_sets_exclude_extra_rules():
    # The AWS-only sets stay narrow — no extra rules leak in.
    for pattern_set in ("minimal", "aws"):
        rule_ids = {r.rule_id for r in get_rules(pattern_set)}
        assert not (EXTRA_RULE_IDS & rule_ids)


def test_no_duplicate_rule_ids_in_full_set():
    rule_ids = [r.rule_id for r in get_rules("full")]
    assert len(rule_ids) == len(set(rule_ids))
