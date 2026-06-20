"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v0.1 suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
LEAKY = FIXTURES / "leaky-repo"
OOS = FIXTURES / "out-of-scope-repo"
SCOPE = FIXTURES / "scope.txt"

# Runtime deps the wheel itself declares in pyproject.toml [project.dependencies].
_RUNTIME_DEPS = [
    "gitpython>=3.1",
    "necromancer-patterns @ git+https://github.com/bugsyhewitt/necromancer-patterns@0d93e7d",
]


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _ensure_build_available():
    """Install `build` into the test-runner's venv if it isn't already present."""
    try:
        _run([sys.executable, "-m", "build", "--version"])
    except subprocess.CalledProcessError:
        _run([sys.executable, "-m", "pip", "install", "--quiet", "build"])


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    _ensure_build_available()
    out = tmp_path / "build-out"
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=str(REPO_ROOT),
    )
    wheels = list(out.glob("tombstone-1.0.0-*.whl"))
    sdists = list(out.glob("tombstone-1.0.0.tar.gz"))
    assert wheels, f"wheel not built; got: {sorted(p.name for p in out.iterdir())}"
    assert sdists, f"sdist not built; got: {sorted(p.name for p in out.iterdir())}"
    test_wheel_builds_cleanly._wheel = wheels[0]


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(tmp_path):
    """`pip install <wheel>` into a brand-new venv resolves the entry-point."""
    wheel = getattr(test_wheel_builds_cleanly, "_wheel", None)
    if wheel is None:
        pytest.skip("preceding test did not produce a wheel")
    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"
    _run([str(pip), "install", "--quiet", str(wheel), "--no-deps"])
    _run([str(pip), "install", "--quiet", *_RUNTIME_DEPS])
    version = _run([str(venv_dir / "bin" / "tombstone"), "--version"]).stdout.strip()
    assert version == "tombstone 1.0.0", f"unexpected version output: {version!r}"
    test_wheel_installs_into_fresh_venv._venv_dir = venv_dir


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv():
    """`import tombstone; assert tombstone.__version__ == '1.0.0'` in fresh venv."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    py = venv_dir / "bin" / "python"
    _run([str(py), "-c", "import tombstone; assert tombstone.__version__ == '1.0.0'"])


@pytest.mark.ship_gate
def test_installed_wheel_public_api():
    """Every public module in the wheel install is importable."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    py = venv_dir / "bin" / "python"
    public_modules = [
        "tombstone.cli",
        "tombstone.scanner",
        "tombstone.report",
        "tombstone.patterns",
        "tombstone.extra_patterns",
        "tombstone.confidence",
        "tombstone.severity",
        "tombstone.scope",
        "tombstone.allowlist",
        "tombstone.workflow",
        "tombstone.github_org",
    ]
    code = "import importlib; mods = " + repr(public_modules) + (
        "; [importlib.import_module(m) for m in mods]; print('OK', len(mods))"
    )
    out = _run([str(py), "-c", code])
    assert "OK 11" in out.stdout, f"public-API import failed: {out.stderr}"


@pytest.mark.ship_gate
def test_installed_wheel_scans_leaky_repo():
    """The installed wheel finds the three planted credentials in leaky-repo's history."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    binary = venv_dir / "bin" / "tombstone"
    # --no-allowlist: AKIAIOSFODNN7EXAMPLE is suppressed by the default allowlist
    # (it's a known vendor example key); bypass suppression to prove the detector fires.
    out = _run(
        [str(binary), "--repo-path", str(LEAKY), "--format", "json", "--no-allowlist"]
    ).stdout
    result = json.loads(out)
    rule_ids = {f["rule_id"] for f in result.get("findings", [])}
    severities = {f["severity"] for f in result.get("findings", [])}
    assert "stripe-secret-key" in rule_ids, f"missing stripe finding: {rule_ids}"
    assert "generic-high-entropy-secret" in rule_ids, f"missing generic: {rule_ids}"
    assert "aws-access-key-id" in rule_ids, f"missing aws finding: {rule_ids}"
    assert "critical" in severities, f"no critical findings: {severities}"


@pytest.mark.ship_gate
def test_installed_wheel_worktree_and_gh_org():
    """The installed wheel sees the uncommitted local.env (--include-worktree)
    and exposes the gh-org subcommand."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    binary = venv_dir / "bin" / "tombstone"
    out = _run(
        [str(binary), "--repo-path", str(LEAKY),
         "--include-worktree", "--format", "json"]
    ).stdout
    result = json.loads(out)
    worktree_paths = {f["file_path"] for f in result.get("findings", [])
                     if f.get("commit") == "WORKTREE"}
    assert "local.env" in worktree_paths, f"worktree local.env missing: {worktree_paths}"
    help_out = _run([str(binary), "gh-org", "--help"]).stdout
    assert "org" in help_out.lower(), f"gh-org --help did not mention 'org': {help_out!r}"


@pytest.mark.ship_gate
def test_installed_wheel_scope_refuses_out_of_scope_repo():
    """Scope enforcement works in the installed wheel: out-of-scope scan
    exits non-zero with a refusal message."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    binary = venv_dir / "bin" / "tombstone"
    proc = subprocess.run(
        [str(binary), "--scope-file", str(SCOPE),
         "--repo-path", str(OOS), "--format", "json"],
        capture_output=True, text=True,
    )
    assert proc.returncode != 0, (
        f"scope enforcement did not fail; exit={proc.returncode}; "
        f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
    )
    combined = (proc.stdout + proc.stderr).lower()
    assert "scope" in combined, f"no scope-refusal message: {proc.stderr!r}"


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """CHANGELOG.md at repo root pins the v1.0.0 release entry."""
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.is_file(), f"CHANGELOG.md missing at {REPO_ROOT}"
    text = changelog.read_text(encoding="utf-8")
    assert "## [1.0.0] - 2026-06-20" in text, (
        f"CHANGELOG.md does not pin v1.0.0 entry; first 200 chars: {text[:200]!r}"
    )
