"""Tests for --output-file / -o report archiving."""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "tombstone.cli", *args],
        capture_output=True,
        text=True,
    )


def test_output_file_listed_in_help():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--output-file" in result.stdout
    # Short alias documented too.
    assert "-o" in result.stdout


def test_output_file_writes_report_and_keeps_stdout_clean(tmp_path):
    out = tmp_path / "report.json"
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist",
         "--output-file", str(out)]
    )
    assert result.returncode == 0
    # The report goes to the file, NOT to stdout.
    assert result.stdout.strip() == ""
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["finding_count"] == 3
    # A confirmation line is printed to stderr so the write is visible.
    assert "report written to" in result.stderr
    assert str(out) in result.stderr


def test_output_file_short_alias_works(tmp_path):
    out = tmp_path / "report.sarif"
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "sarif", "--no-allowlist",
         "-o", str(out)]
    )
    assert result.returncode == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 3


def test_output_file_creates_parent_directories(tmp_path):
    out = tmp_path / "nested" / "dir" / "report.json"
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist",
         "--output-file", str(out)]
    )
    assert result.returncode == 0
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["finding_count"] == 3


def test_output_file_ends_with_newline(tmp_path):
    out = tmp_path / "report.json"
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist",
         "--output-file", str(out)]
    )
    assert result.returncode == 0
    assert out.read_text(encoding="utf-8").endswith("\n")


def test_output_file_does_not_break_fail_on_gate(tmp_path):
    # --output-file and --fail-on compose: the report is archived to the file,
    # and the gate still trips with exit 3 on a critical finding.
    out = tmp_path / "report.json"
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist",
         "--output-file", str(out), "--fail-on", "critical"]
    )
    assert result.returncode == 3
    # The archived file still contains the full report despite the non-zero exit.
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["finding_count"] == 3
    assert "fail-on" in result.stderr.lower()


def test_without_output_file_still_prints_to_stdout():
    # Default behaviour is unchanged: no --output-file means the report goes to
    # stdout exactly as before.
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist"]
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 3
    assert "report written to" not in result.stderr


def test_output_file_unwritable_path_errors(tmp_path):
    # A path whose parent is a regular file (not a directory) cannot be created,
    # so the write fails and tombstone exits with EXIT_ERROR (1), not a crash.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory\n", encoding="utf-8")
    out = blocker / "report.json"
    result = _run_cli(
        ["--repo-path", LEAKY, "--format", "json", "--no-allowlist",
         "--output-file", str(out)]
    )
    assert result.returncode == 1
    assert "could not write output file" in result.stderr


def test_gh_org_output_file_listed_in_help():
    result = _run_cli(["gh-org", "--help"])
    assert result.returncode == 0
    assert "--output-file" in result.stdout
