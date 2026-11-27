#!/usr/bin/env bash
# #3964: dispatch main's CI once a pull request has actually merged.
#
# A merge made with the workflow token creates no push event, so Quality,
# Containers and CodeQL never run on the merge commit. Dependabot auto-merge
# is such a merge: `gh pr merge --auto` returns as soon as auto-merge is armed,
# and GitHub performs the merge later, when the required checks pass. Nothing
# in the arming run can see that merge, so this script waits for the PR to
# reach MERGED and then dispatches the three workflows on main.
#
# workflow_dispatch is the one event a workflow token may trigger, so no
# credential beyond the job's GITHUB_TOKEN (actions: write) is needed.
#
# Usage: dispatch-main-ci-after-merge.sh <pr-number>
# Environment:
#   GH_TOKEN             token for gh (the job's GITHUB_TOKEN)
#   GITHUB_REPOSITORY    owner/name (set by Actions; pass it when running by hand)
#   TIMEOUT_SECONDS      how long to wait for the merge (default 10800)
#   POLL_SECONDS         interval between state checks (default 30)
# Exit status: 0 when main was dispatched, or the PR closed unmerged, or the
# wait ran out (a warning: a later merge is a human's push and runs CI anyway);
# 1 when a dispatch failed.
set -euo pipefail

pr="${1:?usage: dispatch-main-ci-after-merge.sh <pr-number>}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
timeout="${TIMEOUT_SECONDS:-10800}"
poll="${POLL_SECONDS:-30}"
deadline=$(( $(date +%s) + timeout ))

while :; do
  state=$(gh pr view "$pr" --repo "$repo" --json state --jq .state)
  case "$state" in
    MERGED) break ;;
    CLOSED)
      echo "PR #$pr closed without merging; nothing to dispatch."
      exit 0
      ;;
  esac
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "::warning title=Main CI not dispatched::PR #$pr is still $state after ${timeout}s. If it merges later, the merge is a push to main and runs CI."
    exit 0
  fi
  sleep "$poll"
done

merge_sha=$(gh pr view "$pr" --repo "$repo" --json mergeCommit --jq .mergeCommit.oid)
echo "PR #$pr merged as $merge_sha; dispatching main CI."
for workflow in quality.yml containers.yml security.yml; do
  gh workflow run "$workflow" --repo "$repo" --ref main
  echo "dispatched $workflow on main"
done
