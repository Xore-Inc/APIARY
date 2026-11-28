#!/usr/bin/env bash
# arcane-retry-failed-sync.sh — #2705: Arcane's gitops-sync endpoint has a
# ~5-minute hard deadline. When a sync's own redeploy step is still building
# an image past that deadline, the sync call itself 500s ("Internal Server
# Error", "Failed to perform GitOps sync") even though the directory sync
# (files on disk) already completed. The failure is not atomic: the stack
# directory ends up newer than the containers still running from it, and no
# status field reflects that drift.
#
# This script does not re-run the sync (that would just hit the same
# deadline again). It checks each named sync's lastSyncStatus and, for the
# ones that failed, calls the project redeploy endpoint directly -- that
# endpoint streams its own build/deploy progress over the HTTP response and
# is not bounded by the sync deadline, so it can actually finish.
#
# Read-only by default; pass --apply to actually redeploy. Safe to run
# repeatedly: a sync already reporting success is left alone.
set -euo pipefail

ARCANE_URL="${ARCANE_URL:-http://10.8.0.2:3552}"
ARCANE_BEARER="${ARCANE_BEARER:-}"
ARCANE_API_KEY="${ARCANE_API_KEY:-}"

usage() {
  cat <<'EOF'
usage: arcane-retry-failed-sync.sh [--apply] <sync-id-or-name> [more...]

Checks each named Arcane gitops sync's last sync status. Any sync whose
lastSyncStatus is "failed" gets its owning project redeployed directly
(POST /agents/0/projects/{id}/deploy?action=redeploy, Arcane v3), which is not
subject to the
sync endpoint's own ~5 minute deadline.

Environment:
  ARCANE_URL        Arcane API base URL (default: http://10.8.0.2:3552)
  ARCANE_API_KEY    Arcane API key, sent as X-API-Key (preferred)
  ARCANE_BEARER     Arcane session JWT, sent as Bearer (if no API key)

Options:
  --apply     Actually redeploy. Without it, only prints what would happen.
  --dry-run   Explicit no-op mode (the default).
EOF
}

# arcane_api <method> <path> [json-body] -- see scripts/install-homeserver.sh's
# arcane_api() for the same convention (Bearer token, JSON in/out).
# Arcane v3 takes an API key only as X-API-Key; Bearer is for session JWTs.
auth_header() {
  if [[ -n "$ARCANE_API_KEY" ]]; then
    printf 'X-API-Key: %s' "$ARCANE_API_KEY"
  else
    printf 'Authorization: Bearer %s' "$ARCANE_BEARER"
  fi
}

arcane_api() {
  local method="$1" path="$2" body="${3:-}"
  local -a curl_args=(-sS -X "$method" "${ARCANE_URL%/}/api${path}" \
    -H "$(auth_header)" -H "Content-Type: application/json")
  [[ -n "$body" ]] && curl_args+=(-d "$body")
  curl "${curl_args[@]}"
}

# needs_redeploy <lastSyncStatus> -- pure decision logic, kept separate from
# any network call so it can be unit-tested against fixture data. A sync
# that already reports "success" needs no action: re-redeploying a healthy
# project is wasted work, not just harmless, so this must stay narrow.
needs_redeploy() {
  local status="$1"
  [[ "$status" == "failed" ]]
}

# find_sync <target> <syncs-json> -- picks the matching gitops-sync object
# (by id or exact name) out of a GET /agents/0/gitops/syncs?limit=100
# response body. Prints nothing if there is no match.
find_sync() {
  local target="$1" syncs_json="$2"
  jq -c --arg t "$target" \
    '(.data // .) | .[] | select(.id == $t or .name == $t)' \
    <<<"$syncs_json" 2>/dev/null | head -1
}

# process_target <target> -- looks up one sync, decides, and (in --apply
# mode) redeploys. Prints one PASS/WOULD REDEPLOY/FAIL line and returns
# non-zero only on FAIL, so the caller can track an overall exit code.
process_target() {
  local target="$1" dry_run="$2"
  local syncs_json sync_obj status project_id

  syncs_json=$(arcane_api GET "/agents/0/gitops/syncs?limit=100")
  sync_obj=$(find_sync "$target" "$syncs_json")
  if [[ -z "$sync_obj" ]]; then
    echo "FAIL  $target: no matching gitops sync found"
    return 1
  fi

  status=$(jq -r '.lastSyncStatus // "unknown"' <<<"$sync_obj")
  project_id=$(jq -r '.projectId // empty' <<<"$sync_obj")

  if ! needs_redeploy "$status"; then
    echo "PASS  $target: lastSyncStatus=$status, no action needed"
    return 0
  fi

  if [[ -z "$project_id" ]]; then
    echo "FAIL  $target: lastSyncStatus=failed but sync has no projectId to redeploy"
    return 1
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    echo "WOULD REDEPLOY  $target (project $project_id): lastSyncStatus=$status"
    return 0
  fi

  echo "-- redeploying $target (project $project_id); this streams and can take several minutes"
  local redeploy_resp
  redeploy_resp=$(curl -sS -N -m 3600 -X POST \
    "${ARCANE_URL%/}/api/agents/0/projects/$project_id/deploy?action=redeploy" \
    -H "$(auth_header)" -H "Content-Type: application/json") || {
    echo "FAIL  $target: redeploy request failed"
    return 1
  }
  if grep -q '"done":[[:space:]]*true' <<<"$redeploy_resp"; then
    echo "PASS  $target: redeploy completed"
    return 0
  fi
  echo "FAIL  $target: redeploy stream ended without a done:true frame: $redeploy_resp"
  return 1
}

main() {
  local dry_run=1
  local -a targets=()
  for arg in "$@"; do
    case "$arg" in
      --apply) dry_run=0 ;;
      --dry-run) dry_run=1 ;;
      -h|--help) usage; exit 0 ;;
      *) targets+=("$arg") ;;
    esac
  done

  if [[ ${#targets[@]} -eq 0 ]]; then
    usage >&2
    exit 2
  fi
  if [[ -z "$ARCANE_API_KEY" && -z "$ARCANE_BEARER" ]]; then
    echo "ARCANE_API_KEY (or ARCANE_BEARER) is required" >&2
    exit 2
  fi

  local overall=0
  for target in "${targets[@]}"; do
    process_target "$target" "$dry_run" || overall=1
  done
  exit "$overall"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
