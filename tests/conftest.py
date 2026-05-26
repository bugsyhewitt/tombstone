"""Pytest session setup: ensure the git-repo fixtures exist before tests run.

The leaky-repo and out-of-scope-repo fixtures are real, multi-commit git
repositories. A nested ``.git`` directory cannot be committed inside the parent
tombstone repository, so the fixtures are generated deterministically from
``tests/build_fixtures.py`` at the start of every test session. This guarantees
a fresh clone of tombstone can build identical fixtures and reproduce the v0.1
scan results.
"""

import os

import build_fixtures


def _needs_build() -> bool:
    leaky_git = os.path.join(build_fixtures.LEAKY, ".git")
    oos_git = os.path.join(build_fixtures.OOS, ".git")
    return not (os.path.isdir(leaky_git) and os.path.isdir(oos_git))


# Build at import time so module-scoped fixtures that scan the repos work.
if _needs_build():
    build_fixtures.main()
