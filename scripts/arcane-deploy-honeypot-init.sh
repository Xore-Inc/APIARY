#!/usr/bin/env bash
# arcane-deploy-honeypot-init.sh -- #2714: `honeypot-init` is six one-shot
# bootstrap containers by construction (persona-apply, log-init,
# elasticsearch-setup, honeypot-kibana-setup, arkime-init, snare-clone). Every
# deploy through Arcane's redeploy endpoint ends
# `{"error":"failed to deploy project: container <name> exited (0)"}` even
# when every job did exactly what it was supposed to and exited clean.
#
# Traced to the actual library Arcane's ComposeUp/Start call into
# (github.com/docker/compose/v5 pkg/compose, the same code `docker compose up
# --wait` itself runs): `--wait` builds a synthetic "must be running or
# healthy" condition for every project service UNLESS some other service in
# the same compose file depends on it via `condition:
# service_completed_successfully` (pkg/compose/start.go's
# getDependencyCondition). A service nothing depends on that way -- exactly
# what a *terminal* one-shot job is, by definition -- hits
# pkg/compose/convergence.go's isServiceHealthy(), which treats ANY exited
# container (regardless of exit code) as the literal error this issue is
# about. This is not an Arcane bug to patch around at the compose-file level:
# of the six jobs here, log-init and elasticsearch-setup already have a
# same-file dependent (honeypot-kibana-setup depends_on
# elasticsearch-setup; log-init depends_on persona-apply) and correctly never
# trip this. honeypot-kibana-setup, arkime-init, and snare-clone are genuine
# DAG leaves -- nothing in this file runs after them -- so there is no
# same-file service that can legitimately depend on them without inventing an
# artificial ordering coupling that doesn't reflect reality (and would just
# relocate the problem: whatever new sentinel service absorbed that
# dependency would itself become an unwired leaf). Confirmed against
# docker/compose v5.5.0 source, not guessed; matches an open, unimplemented
# upstream feature request (getarcaneapp/arcane#3305, "Treat successful
# one-shot Compose services as completed").
#
# So per this issue's own item 2: treat the specific shape
# `container <name> exited (0)` as success in OUR tooling, but only after
# verifying against real container state that every one-shot job actually
# completed clean -- never by pattern-matching the error string alone, which
# would just as happily swallow a genuine crash. Any other error is a real
# failure and is never suppressed.
#
# Usage:
#   scripts/arcane-deploy-honeypot-init.sh [--apply]
#   Without --apply, only looks up the project and prints what a deploy
#   would do (no redeploy call, no docker calls).
#
# Environment:
#   ARCANE_URL       Arcane API base URL (default: http://10.8.0.2:3552)
#   ARCANE_API_KEY   Arcane API key -- sent as `X-API-Key`, not
#                    `Authorization: Bearer` (this is the API-key credential
#                    type, distinct from the Bearer/session token
#                    scripts/arcane-retry-failed-sync.sh and
#                    scripts/install-homeserver.sh's arcane_api() use).
#   STACKS_ROOT      Where compose-managed stacks live, for the post-deploy
#                    verification pass (default: /var/dockge/stacks). Must be
#                    run somewhere docker can see these containers directly --
#                    i.e. on the homeserver itself.
set -euo pipefail

ARCANE_URL="${ARCANE_URL:-http://10.8.0.2:3552}"
ARCANE_API_KEY="${ARCANE_API_KEY:-}"
STACKS_ROOT="${STACKS_ROOT:-/var/dockge/stacks}"
PROJECT_NAME="honeypot-init"

# Every one-shot job that must show Exited(0) for a real success. Order
# doesn't matter; this is a completeness check, not a sequencing one.
readonly ONE_SHOT_SERVICES=(
  persona-apply log-init elasticsearch-setup
  honeypot-kibana-setup arkime-init snare-clone
)

arcane_api() {
  local method="$1" path="$2"
  curl -sS -X "$method" "${ARCANE_URL%/}/api${path}" -H "X-API-Key: $ARCANE_API_KEY"
}

# find_project_id -- resolves honeypot-init's project id by name so this
# script survives a project being recreated (a fresh id) without editing.
find_project_id() {
  arcane_api GET "/agents/0/projects?limit=100" \
    | jq -r --arg n "$PROJECT_NAME" '(.data // .) | .[] | select(.name == $n) | .id' | head -1
}

# verify_one_shots_completed -- the actual safety check. Queries docker
# directly (not Arcane's HTTP status, which is exactly what's unreliable
# here) for every expected one-shot service's container state. Prints a
# PASS/FAIL line per service and returns non-zero if ANY service is not
# cleanly Exited(0) -- missing entirely, still running, or a non-zero exit
# code are all treated as a real failure, never suppressed.
#
# Arcane's HTTP call returns the false-failure the instant the FIRST
# one-shot's exit trips waitDependencies' errgroup (see the header comment)
# -- it does not wait for the *other* one-shots to finish, because Arcane's
# own process has already stopped watching by then. The underlying docker
# containers keep running to completion regardless (Arcane's error is a
# reporting failure, not something that touches the containers). Live-tested
# 2026-09-01: three of six jobs were still `running` the instant this
# function first ran, and all six were cleanly `exited 0` within 30 seconds.
# So this polls for every service to reach a terminal (non-running,
# non-created) state before judging pass/fail, instead of a single snapshot.
verify_one_shots_completed() {
  local project_dir="$STACKS_ROOT/$PROJECT_NAME"
  if [[ ! -f "$project_dir/compose.yml" ]]; then
    echo "FAIL  cannot verify: no compose.yml at $project_dir" >&2
    return 1
  fi

  local timeout_sec="${VERIFY_TIMEOUT_SEC:-120}"
  local waited=0
  local ps_json=""
  while (( waited < timeout_sec )); do
    ps_json=$(cd "$project_dir" && docker compose -f compose.yml ps -a --format json) || {
      echo "FAIL  cannot verify: docker compose ps failed in $project_dir" >&2
      return 1
    }
    local still_running=0
    for svc in "${ONE_SHOT_SERVICES[@]}"; do
      local st
      st=$(jq -r --arg s "$svc" 'select(.Service == $s) | .State' <<<"$ps_json" 2>/dev/null | head -1)
      [[ "$st" == "running" || "$st" == "created" || -z "$st" ]] && still_running=1
    done
    (( still_running == 0 )) && break
    sleep 3
    waited=$(( waited + 3 ))
  done
  if (( waited >= timeout_sec )); then
    echo "-- timed out after ${timeout_sec}s waiting for all one-shot jobs to reach a terminal state; judging on whatever's there now" >&2
  fi

  local overall=0
  for svc in "${ONE_SHOT_SERVICES[@]}"; do
    local entry state exit_code
    entry=$(jq -c --arg s "$svc" 'select(.Service == $s)' <<<"$ps_json" 2>/dev/null | head -1)
    if [[ -z "$entry" ]]; then
      echo "FAIL  $svc: no container at all" >&2
      overall=1
      continue
    fi
    state=$(jq -r '.State' <<<"$entry")
    exit_code=$(jq -r '.ExitCode // "?"' <<<"$entry")
    if [[ "$state" == "exited" && "$exit_code" == "0" ]]; then
      echo "PASS  $svc: exited 0"
    else
      echo "FAIL  $svc: state=$state exitCode=$exit_code (expected exited 0)" >&2
      overall=1
    fi
  done
  return "$overall"
}

main() {
  local apply=0
  for arg in "$@"; do
    case "$arg" in
      --apply) apply=1 ;;
      -h|--help)
        sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
      *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
  done

  if [[ -z "$ARCANE_API_KEY" ]]; then
    echo "ARCANE_API_KEY is required" >&2
    exit 2
  fi

  local project_id
  project_id=$(find_project_id)
  if [[ -z "$project_id" ]]; then
    echo "FAIL  no Arcane project named '$PROJECT_NAME' found"
    exit 1
  fi
  echo "-- $PROJECT_NAME is project $project_id"

  if [[ "$apply" -eq 0 ]]; then
    echo "WOULD REDEPLOY  $PROJECT_NAME (project $project_id); pass --apply to actually deploy"
    exit 0
  fi

  echo "-- redeploying $PROJECT_NAME (project $project_id); this streams and can take a few minutes"
  local redeploy_resp
  redeploy_resp=$(curl -sS -N -m 600 -X POST \
    "${ARCANE_URL%/}/api/agents/0/projects/$project_id/deploy?action=redeploy" \
    -H "X-API-Key: $ARCANE_API_KEY" -H "Content-Type: application/json") || {
    echo "FAIL  $PROJECT_NAME: redeploy request itself failed (network/HTTP-level)"
    exit 1
  }

  if grep -q '"done":[[:space:]]*true' <<<"$redeploy_resp"; then
    echo "PASS  $PROJECT_NAME: redeploy completed clean, no override needed"
    exit 0
  fi

  # Only the exact shape this issue is about gets the override path. Every
  # other error is a real failure and is reported as-is, unsuppressed.
  local exit0_error
  exit0_error=$(grep -oE '"error":"failed to deploy project: container [^"]+ exited \(0\)"' <<<"$redeploy_resp" || true)
  if [[ -z "$exit0_error" ]]; then
    echo "FAIL  $PROJECT_NAME: redeploy reported an error Arcane's stream did not end done:true, and it is not the known exited(0) shape:"
    echo "$redeploy_resp" >&2
    exit 1
  fi

  echo "-- Arcane reported the known false-failure ($exit0_error); verifying real container state before treating this as success"
  if verify_one_shots_completed; then
    echo "PASS  $PROJECT_NAME: init ran and completed (all one-shot jobs exited 0; Arcane's exited(0) report suppressed)"
    exit 0
  else
    echo "FAIL  $PROJECT_NAME: init crashed -- at least one one-shot job did not cleanly exit 0 (see FAIL lines above); NOT suppressing this one"
    exit 1
  fi
}

main "$@"
