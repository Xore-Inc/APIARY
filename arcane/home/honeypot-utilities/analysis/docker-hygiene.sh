#!/bin/sh
set -eu

# #252: T-Pot's own daily cron does `docker container prune -f; docker image
# prune -f; docker volume prune -f` plus a full-stack stop/reboot -- not
# something to copy wholesale (this stack's own zero-downtime goals, #212,
# go the other direction). But the underlying problem -- dangling images
# from routine `docker compose build` rebuilds accumulating with nothing
# ever reclaiming them -- is real, and had no equivalent here at all.
#
# Deliberately narrower than T-Pot's version:
#   - container removal only ever touches already-STOPPED containers, never
#     anything running, never a compose-managed one (#3658), and never one
#     that opts out with the label apiary.hygiene=keep (#3841). A stopped
#     compose service is still part of its stack: it may be paused for a
#     benchmark (#3135), crashed, or kept stopped as a rollback path.
#     Deleting it means `docker start` can no longer bring it back, and
#     nothing recreates it. On 2026-09-29 one pass deleted five stopped
#     sensors this way, and they stayed gone for 17 days. A container that
#     is not compose-managed (for example the benchmark Ollama of #3706,
#     made with `docker create`) has no such label to hide behind: put
#     `--label apiary.hygiene=keep` on it when it is created. Labels cannot
#     be added to an existing container, so it has to be recreated.
#     This is a list-then-remove pass, not POST /containers/prune, because
#     prune cannot express "skip A or B": repeated label! values are ANDed,
#     so label!=[compose, keep] only spares a container carrying BOTH
#     labels (tested against the daemon, #3841).
#   - image prune is age-bounded (--filter until=<hours>h), not blanket --
#     an image built minutes ago for a redeploy in progress is never a
#     target, only ones old enough that nothing still building/deploying
#     could plausibly need them.
#   - volume prune is NOT run here, ever. Several named volumes in this
#     stack (es-data, dionaea-lib, dashboard-state, ...) are deliberately
#     long-lived state; an unattended blanket volume prune risks real data
#     loss if a volume is briefly unmounted/unreferenced during a redeploy
#     window. Volume hygiene, if wanted, needs its own separate, carefully
#     scoped pass -- not bundled into this one.
#
# Talks to docker-socket-proxy (arcane/home/honeypot-utilities/compose.yml), never the raw
# socket -- same trust boundary autoheal already uses, IMAGES=1 added
# alongside its existing CONTAINERS=1/POST=1 grant for this job specifically.

interval="${HYGIENE_INTERVAL:-604800}"   # weekly by default
start_delay="${HYGIENE_START_DELAY:-300}"
image_max_age_hours="${HYGIENE_IMAGE_MAX_AGE_HOURS:-168}"  # 1 week
keep_label="apiary.hygiene=keep"
compose_label="com.docker.compose.project"
# Optional extra label (key=value) every removal candidate must carry. Unset
# in the stack; it exists so the real code path can be exercised against
# throwaway containers without touching anything else (#3841).
scope_label="${HYGIENE_SCOPE_LABEL:-}"
docker_host="${DOCKER_PROXY_URL:-http://docker-socket-proxy:2375}"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() { echo "docker-hygiene: $*" >&2; }

# Docker's prune filters are a JSON map of string arrays, URL-encoded.
encode_filters() {
  printf '%s' "$1" | sed "s/{/%7B/g; s/}/%7D/g; s/\[/%5B/g; s/\]/%5D/g; s/\"/%22/g; s/:/%3A/g; s/,/%2C/g; s/=/%3D/g"
}

# Print the full ids of the containers (any state) matching a /containers/json
# filter, one per line. Non-zero if the request fails.
list_ids() {
  encoded="$(encode_filters "$1")"
  body="$(curl -fsS "$docker_host/containers/json?all=1&filters=$encoded" 2>/dev/null)" || return 1
  printf '%s' "$body" | grep -o '"Id":"[a-f0-9]\{64\}"' | sed 's/^"Id":"\(.*\)"$/\1/' || true
}

prune_containers() {
  # Candidates first, protected sets second. Labels never change, so a
  # container that is a candidate and protected is in the protected list no
  # matter when that second request runs (it lists every state, not just
  # stopped). Any failed request skips the pass: removing on a partial view
  # could delete something protected.
  stopped='{"status":["created","exited","dead"]'
  [ -z "$scope_label" ] || stopped="$stopped,\"label\":[\"$scope_label\"]"
  stopped="$stopped}"
  candidates="$(list_ids "$stopped")" || { log "container list request failed, skipping container pass"; return 0; }
  keep="$(list_ids "{\"label\":[\"$keep_label\"]}")" || { log "keep-label list request failed, skipping container pass"; return 0; }
  compose="$(list_ids "{\"label\":[\"$compose_label\"]}")" || { log "compose-label list request failed, skipping container pass"; return 0; }
  keep=" $(printf '%s ' $keep) "
  compose=" $(printf '%s ' $compose) "

  removed=0 kept=0 managed=0 failed=0
  for id in $candidates; do
    case "$keep" in *" $id "*) kept=$((kept + 1)); continue ;; esac
    case "$compose" in *" $id "*) managed=$((managed + 1)); continue ;; esac
    # Plain DELETE: no force (a container that started since the list is
    # refused with 409) and no volume removal, like prune.
    if curl -fsS -X DELETE "$docker_host/containers/$id" >/dev/null 2>&1; then
      removed=$((removed + 1))
      log "removed stopped container $(printf '%.12s' "$id")"
    else
      failed=$((failed + 1))
      log "could not remove $(printf '%.12s' "$id")"
    fi
  done
  log "containers: $removed removed, $kept kept ($keep_label), $managed kept (compose-managed), $failed failed"
}

prune_images() {
  # Docker's prune filter takes a JSON-encoded map of string arrays.
  # "dangling":["true"] is explicit, not relied on as an API default --
  # this must never remove a still-tagged, in-use-by-name image, only
  # untagged layers left behind by a rebuild.
  filters="$(printf '{"until":["%sh"],"dangling":["true"]}' "$image_max_age_hours")"
  encoded="$(encode_filters "$filters")"
  resp="$(curl -fsS -X POST "$docker_host/images/prune?filters=$encoded" 2>/dev/null)" || {
    log "image prune request failed"
    return 0
  }
  reclaimed="$(printf '%s' "$resp" | sed -n 's/.*"SpaceReclaimed":\([0-9]*\).*/\1/p')"
  removed="$(printf '%s' "$resp" | grep -o '"Deleted":"[a-f0-9:]*"' | wc -l | tr -d ' ')"
  log "images pruned (older than ${image_max_age_hours}h, dangling only): ${removed:-0} removed, ${reclaimed:-0} bytes reclaimed"
}

sleep "$start_delay"

while true; do
  log "starting pass ($(now))"
  prune_containers
  prune_images
  sleep "$interval"
done
