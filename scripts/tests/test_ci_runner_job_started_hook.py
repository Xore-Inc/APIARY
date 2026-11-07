#!/usr/bin/env python3
"""Pin the honeypot-ci job-started hook's fork-PR refusal policy.

The workflow-level fork gate is editable by the pull request itself, so the
runner-side hook (scripts/github-ci-runner/job-started-hook.sh) is the
enforcement point that must refuse fork pull requests, and
install-ci-runner.sh must wire it through the systemd unit.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "scripts" / "github-ci-runner" / "job-started-hook.sh"
INSTALLER = ROOT / "scripts" / "github-ci-runner" / "install-ci-runner.sh"


def run_hook(tmp_path: Path, event: str, payload: dict | None) -> int:
    env = {"PATH": os.environ["PATH"], "GITHUB_EVENT_NAME": event}
    if payload is not None:
        event_file = tmp_path / "event.json"
        event_file.write_text(json.dumps(payload), encoding="utf-8")
        env["GITHUB_EVENT_PATH"] = str(event_file)
    return subprocess.run(["bash", str(HOOK)], env=env, capture_output=True).returncode


def pr_payload(base: str, head: str | None, fork: bool = False) -> dict:
    head_repo = None if head is None else {"full_name": head, "fork": fork}
    return {
        "pull_request": {
            "base": {"repo": {"full_name": base}},
            "head": {"repo": head_repo},
        }
    }


def test_fork_pull_request_is_refused(tmp_path):
    assert (
        run_hook(
            tmp_path, "pull_request", pr_payload("Xore/APIARY", "evil/APIARY", True)
        )
        != 0
    )


def test_deleted_fork_head_is_refused(tmp_path):
    assert run_hook(tmp_path, "pull_request", pr_payload("Xore/APIARY", None)) != 0


def test_missing_payload_is_refused(tmp_path):
    assert run_hook(tmp_path, "pull_request", None) != 0


def test_same_repo_pull_request_is_allowed(tmp_path):
    assert (
        run_hook(tmp_path, "pull_request", pr_payload("Xore/APIARY", "Xore/APIARY"))
        == 0
    )


def test_non_pull_request_events_are_allowed(tmp_path):
    for event in ("push", "workflow_dispatch", "schedule"):
        assert run_hook(tmp_path, event, None) == 0


def test_installer_wires_the_hook_through_the_unit():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "job-started-hook.sh" in text
    assert "ACTIONS_RUNNER_HOOK_JOB_STARTED=" in text
