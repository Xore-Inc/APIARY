#!/usr/bin/env python3
"""Regression test for #3964: scripts/dispatch-main-ci-after-merge.sh.

The script waits for a pull request to merge and then dispatches Quality,
Containers and CodeQL on main. A fake `gh` on PATH records every call, so the
three outcomes are checked without touching GitHub:

- MERGED: the three workflows are dispatched on main, and nothing else;
- CLOSED without merge: nothing is dispatched;
- still open at the deadline: nothing is dispatched and the exit is 0.
"""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "dispatch-main-ci-after-merge.sh"

FAKE_GH = """#!/usr/bin/env bash
echo "$*" >> "$FAKE_GH_LOG"
case "$*" in
  "pr view"*"--json state"*) echo "$FAKE_PR_STATE" ;;
  "pr view"*"--json mergeCommit"*) echo "0123456789abcdef0123456789abcdef01234567" ;;
  "workflow run"*) ;;
  *) echo "unexpected gh call: $*" >&2; exit 9 ;;
esac
"""


def run(tmp_path: Path, state: str, timeout: str = "5") -> tuple[subprocess.CompletedProcess, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(FAKE_GH)
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "gh.log"
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_GH_LOG": str(log),
        "FAKE_PR_STATE": state,
        "GITHUB_REPOSITORY": "Xore-Inc/APIARY",
        "TIMEOUT_SECONDS": timeout,
        "POLL_SECONDS": "0",
    }
    proc = subprocess.run(["bash", str(SCRIPT), "3999"], env=env, capture_output=True, text=True, timeout=60)
    calls = log.read_text().splitlines() if log.exists() else []
    return proc, calls


def test_merged_pr_dispatches_the_three_workflows_on_main(tmp_path):
    proc, calls = run(tmp_path, "MERGED")
    assert proc.returncode == 0, proc.stderr
    dispatched = [c for c in calls if c.startswith("workflow run")]
    assert dispatched == [
        "workflow run quality.yml --repo Xore-Inc/APIARY --ref main",
        "workflow run containers.yml --repo Xore-Inc/APIARY --ref main",
        "workflow run security.yml --repo Xore-Inc/APIARY --ref main",
    ]


def test_closed_without_merge_dispatches_nothing(tmp_path):
    proc, calls = run(tmp_path, "CLOSED")
    assert proc.returncode == 0, proc.stderr
    assert not [c for c in calls if c.startswith("workflow run")]
    assert "closed without merging" in proc.stdout


def test_still_open_at_the_deadline_warns_and_dispatches_nothing(tmp_path):
    proc, calls = run(tmp_path, "OPEN", timeout="0")
    assert proc.returncode == 0, proc.stderr
    assert not [c for c in calls if c.startswith("workflow run")]
    assert "::warning title=Main CI not dispatched::" in proc.stdout


@pytest.mark.parametrize("workflow", ["quality.yml", "containers.yml", "security.yml"])
def test_each_dispatched_workflow_accepts_workflow_dispatch(workflow):
    import re

    text = (REPO / ".github" / "workflows" / workflow).read_text()
    assert re.search(r"^  workflow_dispatch:", text, re.MULTILINE), workflow


def test_dependabot_job_grants_actions_write_and_runs_the_base_script():
    text = (REPO / ".github" / "workflows" / "dependabot-auto-merge.yml").read_text()
    assert "actions: write" in text
    assert 'git show "$BASE_SHA:scripts/dispatch-main-ci-after-merge.sh"' in text
