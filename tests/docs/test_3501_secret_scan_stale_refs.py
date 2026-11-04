#!/usr/bin/env python3
"""Regression test for #3501: the secret-scan gate must measure the history it
was told to scan, not whatever a reused self-hosted workspace was left holding.

What #3520's CI exposed, and what could quietly undo the fix:

* `check-git-secrets.py`'s allowlist probe answers "does this entry's file
  exist in history?" with `git log --all -1 -- <path>`, and gitleaks' own
  object walk likewise starts from every ref in the repository. Both read the
  ref set, not the commit under test.
* `actions/checkout` runs `git clean -ffdx`, which removes leftover FILES and
  never stale REFS. On the reused `honeypot-ci` workspace, refs from earlier
  PRs survived, so the scan answered from a history the job was not asked to
  scan. Two clones of one IDENTICAL tree, differing only in stale
  `refs/remotes/pull/*`, measured 120 findings (62 of them in the two
  allowlisted historical paths) against 23 findings and 0 for the same tree
  without them.
* That is what made the gate report load-bearing allowlist entries as rot, and
  why `main` failed on one entry while the PR failed on two -- same tree,
  different leftover state per runner. A gate whose verdict depends on which
  box ran it is not a gate.

The fix purges the remote-tracking refs before scanning, so the scan's view of
history is the commit it was told to scan. The tests below pin that the purge
is present, that it is scoped so it cannot delete the ref actually being
checked out, and that the leftover assertion is a hard failure rather than a
silent best-effort.
"""
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "quality.yml"


def _secret_scan_step() -> str:
    """The body of the secret-scan row, so assertions cannot match a comment
    somewhere else in a 2700-line workflow."""
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r'- name: "Full-history secret scan \(gitleaks, #3501\)"(.*?)(?=\n\s*- name: |\n\s{10}- name: )',
        text,
        re.S,
    )
    assert match, "secret-scan step not found in quality.yml"
    return match.group(1)


def test_secret_scan_purges_stale_remote_tracking_refs():
    """`git log --all` and gitleaks both read every ref, and checkout's clean
    never removes refs -- so without this the scan measures whatever the
    workspace was reused from."""
    step = _secret_scan_step()
    assert "refs/remotes" in step, (
        "the secret-scan step must purge stale remote-tracking refs; without it "
        "`git log --all` and gitleaks measure leftover history (#3501)"
    )
    assert "update-ref" in step, "the purge must delete refs via update-ref"


def test_purge_excludes_origin_head_symref():
    """update-ref refuses to delete through a symref, so `origin/HEAD` must be
    excluded or the purge aborts mid-stream on a real runner."""
    step = _secret_scan_step()
    assert re.search(r"grep -v -e 'origin/HEAD\$'", step) or \
        re.search(r"grep -v 'origin/HEAD\$'", step), (
        "the purge must exclude origin/HEAD: update-ref rejects deletes through "
        "a symref, and an aborting purge would leave the gate reading ambient refs"
    )


def test_purge_survives_a_clean_runner_under_pipefail(tmp_path):
    """A runner with no stale refs must not fail the purge.

    This bit the first cut of the fix: the refs were filtered through
    `git for-each-ref | grep -v ...`, and under `set -o pipefail` a `grep -v`
    that selects nothing exits 1. The job then died 17ms into the scan on a
    perfectly clean runner, printing no error at all -- the exact situation
    the fix exists to make work. Empty is a valid ref set, so the filter must
    not be able to fail the step.

    Runs the purge snippet verbatim under the same `set -euo pipefail` the
    workflow uses, against a clone holding nothing but origin/HEAD and the
    PR's own merge ref."""
    step = _secret_scan_step()
    snippet = re.search(r"(pr_merge_ref=.*?update-ref -d \"\$ref\".*?\n\s*done)",
                        step, re.S)
    assert snippet, "purge loop not found verbatim"
    # The workflow interpolates the PR number; pin it so the excerpt is
    # runnable bash.
    script = "PR_MERGE_REF=3528\nexport PR_MERGE_REF\n" + snippet.group(1)

    repo = tmp_path / "clean"
    repo.mkdir()
    run = lambda *a: subprocess.run(a, cwd=repo, check=True, capture_output=True, text=True)
    run("git", "init", "-q", "-b", "main")
    (repo / "f.txt").write_text("x\n", encoding="utf-8")
    run("git", "add", "-A")
    run("git", "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "one")
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                         capture_output=True, text=True, check=True).stdout.strip()
    run("git", "update-ref", "refs/remotes/origin/HEAD", sha)
    run("git", "update-ref", "refs/remotes/pull/3528/merge", sha)

    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + script],
        cwd=repo, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        "the purge must exit 0 on a clean runner with nothing to delete; under "
        f"`set -o pipefail` an unguarded `grep -v` that matches nothing exits 1 "
        f"and kills the scan:\n{result.stdout}\n{result.stderr}"
    )


def test_purge_cannot_delete_the_ref_being_checked_out():
    """The scan runs on a detached checkout of one commit; deleting all of
    refs/remotes must not remove the very ref the job resolved. This is a
    guard on the blast radius, not on the mechanism."""
    step = _secret_scan_step()
    # The purge must run BEFORE the scan and never touch refs/heads or HEAD.
    assert not re.search(r"delete \|delete \(HEAD\)", step), "must not delete HEAD"
    purge_at = step.find("update-ref")
    # Anchor on the EXECUTION, not a comment: this step mentions the script by
    # name in prose before it runs it.
    scan_at = step.find("python3 scripts/check-git-secrets.py")
    assert purge_at != -1 and scan_at != -1, "purge and scan both present"
    assert purge_at < scan_at, "refs must be purged BEFORE the scan runs"


def test_leftover_refs_after_purge_is_a_hard_failure():
    """A purge that silently fails leaves the gate measuring ambient state,
    which is the exact bug. The post-condition must be an error, not a warning
    and not `|| true`."""
    step = _secret_scan_step()
    assert "leftover" in step, "the purge must assert its own post-condition"
    assert re.search(r"::error::secret-scan:.*(leftover|stale)", step), (
        "surviving refs must be reported as ::error:: so a failed purge is never "
        "read as a clean scan"
    )
    # The purge itself may be best-effort (`|| true`), but the post-condition
    # must not be: an unchecked purge leaves the gate measuring ambient state.
    after = step[step.find("leftover"):]
    assert "exit 1" in after, "a failed purge must exit non-zero, not warn"


def test_purge_is_idempotent_and_safe_on_a_clean_clone(tmp_path):
    """Run the purge verbatim against a real clone with and without stale refs.

    This is the behavioural half: the snippet must actually remove a stale
    pull ref, must leave a clean clone's `origin/main` intact, and must be
    safe to run twice."""
    step = _secret_scan_step()
    snippet = re.search(r"(pr_merge_ref=.*?update-ref -d \"\$ref\".*?\n\s*done)",
                        step, re.S)
    assert snippet, "purge snippet not found verbatim"
    script = "PR_MERGE_REF=3528\nexport PR_MERGE_REF\n" + snippet.group(1)

    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(a, cwd=repo, check=True, capture_output=True, text=True)
    run("git", "init", "-q", "-b", "main")
    (repo / "f.txt").write_text("x\n", encoding="utf-8")
    run("git", "add", "-A")
    run("git", "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "one")
    main_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                              capture_output=True, text=True, check=True).stdout.strip()
    # Plant a stale remote-tracking ref, exactly what a reused workspace holds.
    run("git", "update-ref", "refs/remotes/pull/9999/head", main_sha)

    for _ in range(2):  # idempotent: running twice must be safe
        subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                       cwd=repo, check=True, capture_output=True, text=True)
        left = subprocess.run(
            ["git", "for-each-ref", "--format=%(refname)", "refs/remotes"],
            cwd=repo, capture_output=True, text=True, check=True,
        ).stdout.split()
        left = [r for r in left if not r.endswith("origin/HEAD")]
        assert left == [], f"stale refs survived the purge: {left}"

    # The branch the job checked out must still be there and unchanged.
    assert subprocess.run(["git", "rev-parse", "main"], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip() == main_sha