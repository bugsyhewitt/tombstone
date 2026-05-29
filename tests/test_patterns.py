"""Unit tests for the regex rule engine and entropy heuristics."""

from tombstone.extra_patterns import (
    EXTRA_RULE_IDS,
    GITLAB_PAT,
    GOOGLE_API_KEY,
    NPM_TOKEN,
    PRIVATE_KEY,
    SENDGRID_API_KEY,
    SLACK_TOKEN,
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


def test_private_key_matches_rsa_header():
    header = "-----BEGIN RSA PRIVATE KEY-----"
    assert _matches(PRIVATE_KEY, header) == header


def test_private_key_matches_openssh_header():
    header = "-----BEGIN OPENSSH PRIVATE KEY-----"
    assert _matches(PRIVATE_KEY, header) == header


def test_private_key_ignores_public_key_and_certificate():
    assert _matches(PRIVATE_KEY, "-----BEGIN PUBLIC KEY-----") is None
    assert _matches(PRIVATE_KEY, "-----BEGIN CERTIFICATE-----") is None


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
