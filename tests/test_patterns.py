"""Unit tests for the regex rule engine and entropy heuristics."""

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
