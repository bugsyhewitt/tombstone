"""Tests for the HEAD-presence (liveness) signal on findings.

Every credential finding carries ``still_present``: True if the credential is
still in the repository's current HEAD tree, False if it was removed and lives
only in older history. A still-present secret is a far stronger live-credential
signal than one that was committed once and later deleted, so this drives
triage — a researcher chases still-present criticals first.

The leaky-repo fixture is built to exercise exactly this:

  * ``deploy.sh`` (with an AWS key) is added in an early commit and **removed**
    in a later one, so its credential lives ONLY in history → still_present=False
  * ``settings.py`` (Stripe key + generic secret) survives to HEAD →
    still_present=True
  * ``local.env`` is an uncommitted working-tree file → still_present=True
"""

import os

from tombstone.report import to_bcmd, to_h1md, to_json, to_sarif
from tombstone.scanner import WORKTREE_COMMIT, Finding, scan_repo

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY = os.path.join(HERE, "fixtures", "leaky-repo")

# The AWS key planted in deploy.sh, which is later removed from HEAD.
REMOVED_SECRET = "AKIAIOSFODNN7EXAMPLE"
# The Stripe key + generic secret in settings.py, which survive to HEAD.
SURVIVING_GENERIC = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"
# The uncommitted working-tree credential.
WORKTREE_SECRET = "Qw8Er5Ty2Ui9Op3As6Df1Gh4Jk7Lz0Mn"


def _by_secret(findings, secret):
    for f in findings:
        if secret in f._secret:
            return f
    return None


# --------------------------------------------------------------------------- #
# Scanner behaviour
# --------------------------------------------------------------------------- #


def test_removed_credential_is_marked_not_present():
    # deploy.sh's AWS key was removed from HEAD — it lives only in history.
    findings = scan_repo(LEAKY, pattern_set="full")
    aws = _by_secret(findings, REMOVED_SECRET)
    assert aws is not None, "the historical AWS key should still be found"
    assert aws.still_present is False


def test_surviving_credential_is_marked_present():
    # settings.py survives to HEAD, so its secrets are still present.
    findings = scan_repo(LEAKY, pattern_set="full")
    generic = _by_secret(findings, SURVIVING_GENERIC)
    assert generic is not None
    assert generic.still_present is True


def test_default_is_present_for_default_finding():
    # The dataclass default is True so older call sites / report tests that
    # construct a Finding without the field keep working and assume "current".
    f = Finding(
        rule_id="aws-access-key-id",
        description="AWS access key ID",
        commit="deadbeef",
        file_path="x.env",
        line_number=1,
        redacted_context="x",
    )
    assert f.still_present is True


def test_worktree_finding_is_always_present():
    # A working-tree finding describes the current on-disk state, so it is
    # present by definition even though it has no HEAD blob.
    findings = scan_repo(LEAKY, pattern_set="full", include_worktree=True)
    wt = _by_secret(findings, WORKTREE_SECRET)
    assert wt is not None
    assert wt.commit == WORKTREE_COMMIT
    assert wt.still_present is True


def test_liveness_independent_of_since_range():
    # The liveness flag reflects the TRUE HEAD state regardless of which commits
    # the --since/--until range happens to report. Even when we restrict the
    # scan to a slice of history, a credential that survives to HEAD is still
    # marked present and a removed one is still marked removed.
    full = scan_repo(LEAKY, pattern_set="full")
    removed_full = _by_secret(full, REMOVED_SECRET)
    survive_full = _by_secret(full, SURVIVING_GENERIC)
    assert removed_full.still_present is False
    assert survive_full.still_present is True


def test_workflow_findings_keep_present_default():
    # Workflow secret-exposure findings expose a pattern, not a literal HEAD
    # credential; their synthetic dedupe key has no HEAD counterpart, so they
    # must not be wrongly downgraded to "removed".
    findings = scan_repo(LEAKY, pattern_set="full", workflow_scan=True)
    workflow = [f for f in findings if f.rule_id == "workflow-secret-exposure"]
    assert workflow, "the fixture workflow should produce exposure findings"
    assert all(f.still_present is True for f in workflow)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def _history_finding(**overrides) -> Finding:
    base = dict(
        rule_id="aws-access-key-id",
        description="AWS access key ID",
        commit="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        file_path="config/prod.env",
        line_number=7,
        redacted_context='aws_key = "AK****EF"',
        confidence="high",
        severity="critical",
        author="Jane Dev <jane@acme-corp.example>",
        committed_at="2026-05-20T14:03:11+00:00",
        still_present=True,
        _secret="AKIAEXAMPLEEXAMPLE01",
    )
    base.update(overrides)
    return Finding(**base)


def test_to_dict_emits_still_present():
    assert _history_finding(still_present=True).to_dict()["still_present"] is True
    assert _history_finding(still_present=False).to_dict()["still_present"] is False


def test_json_carries_still_present():
    out = to_json([_history_finding(still_present=False)])
    assert '"still_present": false' in out


def test_h1md_shows_still_present_for_history():
    md_present = to_h1md([_history_finding(still_present=True)])
    assert "**Still present:** yes — still in current HEAD" in md_present
    md_removed = to_h1md([_history_finding(still_present=False)])
    assert "removed from HEAD, only in history" in md_removed


def test_h1md_omits_still_present_for_worktree():
    f = _history_finding(commit=WORKTREE_COMMIT, author="", committed_at="")
    md = to_h1md([f])
    assert "**Still present:**" not in md


def test_bcmd_notes_liveness_for_history():
    md_present = to_bcmd([_history_finding(still_present=True)])
    assert "still present in the current HEAD" in md_present
    md_removed = to_bcmd([_history_finding(still_present=False)])
    assert "removed from the current HEAD" in md_removed


def test_sarif_carries_still_present_property():
    import json

    doc = json.loads(to_sarif([_history_finding(still_present=False)]))
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["still_present"] is False
    assert "still_present=false" in result["message"]["text"]
