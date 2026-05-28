"""Deterministically (re)build the git-repo test fixtures.

Run with: python tests/build_fixtures.py

Creates two real git repositories under tests/fixtures/:

  leaky-repo/         3 commits, 3 planted credentials spread across history,
                      plus 5 innocuous-looking strings that must NOT match.
  out-of-scope-repo/  minimal repo used to exercise scope refusal.

The credentials are planted across DIFFERENT commits (and one only exists in
history, not the final working tree) so the scanner's gitpython history
traversal is genuinely exercised.
"""

from __future__ import annotations

import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
LEAKY = os.path.join(FIXTURES, "leaky-repo")
OOS = os.path.join(FIXTURES, "out-of-scope-repo")

# [Worker decision: synthesize the planted Stripe key at runtime]
# The Stripe secret-key prefix joined with a 24-char body is assembled here
# from fragments rather than written as a single string literal. This keeps any
# `sk_live_<body>` literal out of committed source so GitHub push protection
# does not reject the fixtures, while the file actually WRITTEN to the leaky-repo
# on disk still contains a complete, rule-matching key. The body is a fixed
# pseudo-random base62 string with no resemblance to any real credential.
_STRIPE_PREFIX = "sk" + "_" + "live" + "_"
_STRIPE_BODY = "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"  # 24 chars, fixed, synthetic
PLANTED_STRIPE_KEY = _STRIPE_PREFIX + _STRIPE_BODY


def run(cmd: list[str], cwd: str) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)


def git_init(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    run(["git", "init", "-q"], cwd=path)
    run(["git", "config", "user.email", "fixture@tombstone.test"], cwd=path)
    run(["git", "config", "user.name", "tombstone fixture"], cwd=path)


def write(path: str, name: str, content: str) -> None:
    with open(os.path.join(path, name), "w", encoding="utf-8") as fh:
        fh.write(content)


def commit(path: str, message: str) -> None:
    run(["git", "add", "-A"], cwd=path)
    run(
        [
            "git",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            message,
        ],
        cwd=path,
    )


def build_leaky() -> None:
    if os.path.isdir(LEAKY):
        shutil.rmtree(LEAKY)
    git_init(LEAKY)

    # --- Commit 1: a benign config plus innocuous look-alikes ---------------
    # Innocuous #1: UUID (high-entropy shape, excluded by UUID rule)
    # Innocuous #2: git SHA (hex-sha shape, excluded)
    write(
        LEAKY,
        "config.yaml",
        (
            "service: payments\n"
            'request_id: "550e8400-e29b-41d4-a716-446655440000"\n'
            'last_commit: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"\n'
            "region: us-east-1\n"
        ),
    )
    commit(LEAKY, "Initial config")

    # --- Commit 2: a real AWS key + more innocuous look-alikes --------------
    # Real #1: AWS access key id (matches aws-access-key-id rule)
    # Innocuous #3: lowercase AWS look-alike (fails uppercase body)
    # Innocuous #4: low-entropy repetitive value under a secret-ish key
    write(
        LEAKY,
        "deploy.sh",
        (
            "#!/bin/sh\n"
            "# deployment script\n"
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "# placeholder, not a real key:\n"
            'example_key = "akiaiosfodnn7example"\n'
            'password = "passwordpasswordpassword"\n'
        ),
    )
    commit(LEAKY, "Add deploy script")

    # --- Commit 3: a real Stripe key + real generic secret + last innocuous -
    # Real #2: Stripe secret key (matches stripe-secret-key rule)
    # Real #3: generic high-entropy secret under api_key (matches generic rule)
    # Innocuous #5: low-entropy dictionary-ish token under a secret key
    write(
        LEAKY,
        "settings.py",
        (
            "# application settings\n"
            f'STRIPE_SECRET_KEY = "{PLANTED_STRIPE_KEY}"\n'
            'api_key = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"\n'
            'token = "aaaabbbbccccddddeeeeffff"\n'
        ),
    )
    commit(LEAKY, "Add application settings")

    # --- Commit 4: a GitHub Actions workflow with secret-exposure patterns --
    # Exercises --workflow-scan. Contains BOTH dangerous patterns (a secret
    # interpolated into a run: command, and an echo of a secret-derived env var)
    # AND the safe env:-mapping pattern that must NOT be flagged. None of these
    # are real credentials, so committing the literal ${{ secrets.X }} markers is
    # safe from GitHub push protection.
    os.makedirs(os.path.join(LEAKY, ".github", "workflows"), exist_ok=True)
    write(
        os.path.join(LEAKY, ".github", "workflows"),
        "deploy.yml",
        (
            "name: deploy\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            # SAFE: env mapping from a secret — recommended pattern, no flag.
            "      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
            "    steps:\n"
            # DANGEROUS #1: secret interpolated directly into a run: command.
            "      - run: curl -H \"Authorization: ${{ secrets.API_TOKEN }}\" "
            "https://api.example.com\n"
            # DANGEROUS #2: echo of a secret-derived environment variable.
            "      - run: echo \"$DEPLOY_TOKEN\"\n"
            # SAFE: echo of a non-secret variable must NOT be flagged.
            "      - run: echo \"$HOME building project\"\n"
        ),
    )
    commit(LEAKY, "Add deploy workflow")

    # --- Commit 5: remove deploy.sh so the AWS key lives ONLY in history ----
    os.remove(os.path.join(LEAKY, "deploy.sh"))
    commit(LEAKY, "Remove deploy script (key still in history)")

    # --- Working tree only: a credential that was NEVER committed -----------
    # This file exists only in the working copy (not in any commit), exercising
    # the --include-worktree scan path. The classic "removed from history but
    # left in the working copy / .env on a staging box" pattern.
    write(
        LEAKY,
        "local.env",
        (
            "# left behind in the working copy, never committed\n"
            'WORKTREE_API_KEY = "Qw8Er5Ty2Ui9Op3As6Df1Gh4Jk7Lz0Mn"\n'
        ),
    )


def build_out_of_scope() -> None:
    if os.path.isdir(OOS):
        shutil.rmtree(OOS)
    git_init(OOS)
    write(
        OOS,
        "README.md",
        "# unrelated-vendor repo\n\nThis repo is NOT in our bounty scope.\n",
    )
    commit(OOS, "Initial commit")


def main() -> None:
    os.makedirs(FIXTURES, exist_ok=True)
    build_leaky()
    build_out_of_scope()
    print("fixtures rebuilt:")
    print(f"  {LEAKY}")
    print(f"  {OOS}")


if __name__ == "__main__":
    main()
