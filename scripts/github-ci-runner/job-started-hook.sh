#!/usr/bin/env bash
# Runner-side job-started hook for the honeypot-ci self-hosted runners.
#
# Why this exists: the workflow-level fork gate (ci-router.yml's trust check
# plus the `runs-on` expressions in quality.yml, containers.yml, security.yml,
# pages.yml and image-security-scan.yml) lives in YAML that, for a
# `pull_request` event, is taken from the pull request's own revision. A fork
# can therefore edit the router, the downstream `if:`/`runs-on:` expressions,
# or add a direct `runs-on: [self-hosted, ...]` job, and none of those edits
# is subject to the gate they remove. This hook is the one enforcement point
# the pull request cannot edit: it is installed root-owned on the runner host
# and registered through the systemd unit (ACTIONS_RUNNER_HOOK_JOB_STARTED,
# see install-ci-runner.sh), and the runner executes it before any step of any
# job -- including checkout of pull-request content -- so a refusal here
# prevents attacker-controlled code from ever reaching this host.
#
# Policy: a job triggered by a pull-request-family event is permitted only
# when the pull request's head repository is the base repository. Anything
# that cannot be positively established as same-repo (missing or unreadable
# event payload, missing interpreter, null head repository as left by a
# deleted fork) is refused. Other events (push to main, workflow_dispatch,
# schedule) are not affected.
set -euo pipefail

event="${GITHUB_EVENT_NAME:-}"

case "$event" in
  pull_request|pull_request_target|pull_request_review|pull_request_review_comment)
    ;;
  *)
    exit 0 ;;
esac

deny() {
  echo "::error::honeypot-ci job-started hook: refusing '$event' job: $1" >&2
  echo "honeypot-ci job-started hook: refusing '$event' job: $1" >&2
  exit 1
}

payload="${GITHUB_EVENT_PATH:-}"
[[ -n "$payload" && -r "$payload" ]] || deny "event payload is not available, so the pull request origin cannot be verified"
command -v python3 >/dev/null 2>&1 || deny "python3 is not available to verify the pull request origin"

python3 - "$payload" <<'PY' || deny "pull request head repository is not the base repository (fork or unverifiable origin)"
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        pr = json.load(fh)["pull_request"]
    base = pr["base"]["repo"]["full_name"]
    head = pr["head"]["repo"]["full_name"]
    head_fork = pr["head"]["repo"].get("fork")
except (OSError, ValueError, KeyError, TypeError, AttributeError):
    sys.exit(1)

if not base or not head or base != head or head_fork is True:
    sys.exit(1)
PY
