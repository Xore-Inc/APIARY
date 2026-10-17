#!/usr/bin/env bash
# sync-client-secrets.sh -- after a fresh `--import-realm` (apiary-realm.json
# pins no client "secret", so Keycloak generates a new random one for every
# confidential client on each import), fetches the 7 VPS oauth2-proxy gateway
# clients' fresh secrets from Keycloak on the homeserver and writes them into
# the matching `vps/secrets/oidc/<client>/client-secret` file on the VPS,
# then restarts each gateway. Replaces the fully-manual per-client procedure
# in docs/KEYCLOAK-OPERATIONS.md -- run this instead of copy-pasting kcadm
# commands seven times by hand.
#
# The realm has 11 confidential clients total (#2368, #3578); the other 4 are NOT
# handled here because none of them sit behind a VPS oauth2-proxy gateway.
# Each of those has its own idempotent provisioner script and must be run
# separately, alongside this one, as part of the same clean-rebuild pass --
# see docs/KEYCLOAK-OPERATIONS.md §7:
#   apiary-dashboard    native OIDC in the dashboard binary itself (no VPS
#                        gateway since #1026's follow-up retired
#                        oidc-dashboard) -- provision-dashboard-oidc-secret.sh
#   apiary-dashboard-rewrite  the rewrite dashboard's own client (#3578), same
#                        script with DASHBOARD_CLIENT_ID=apiary-dashboard-rewrite
#                        -- provision-dashboard-oidc-secret.sh
#   arcane               Arcane's own OIDC login; reads its secret from a
#                        homeserver .env file, not a VPS secrets file --
#                        provision-arcane-oidc-secret.sh
#   auth-events-poller   service-account-only client with a Keycloak role
#                        grant, never an interactive login --
#                        provision-events-poller.sh
#
# Run from the homeserver (needs docker exec access to hp-keycloak) with SSH
# access to the VPS. Secret values are piped directly over SSH, never
# written to a local file or passed as a command-line argument.
set -euo pipefail

REALM="${KEYCLOAK_REALM:-apiary}"
VPS_HOST="${VPS_HOST:-vps}"
VPS_SECRETS_DIR="${VPS_SECRETS_DIR:-/root/vps/secrets/oidc}"
KC_CONTAINER="${KC_CONTAINER:-hp-keycloak}"
KC_CONFIG="${KC_CONFIG:-/tmp/kcadm-sync-client-secrets.config}"
KC="/opt/keycloak/bin/kcadm.sh"

# client id -> vps/docker-compose.yml service/container name of its
# oauth2-proxy gateway sidecar (not always a plain "oidc-<client>" prefix --
# traefik-dashboard's is oidc-traefik, not oidc-traefik-dashboard). Two
# entries have rotted out from under this map before, each the same way: its
# gateway got decommissioned elsewhere in the repo and nothing here noticed.
# A different, now-retired gateway pair lived here until #1194
# decommissioned it (removed by #2195, two days after this script landed);
# apiary-dashboard/oidc-dashboard lived here until #1026's follow-up retired
# that compose service three weeks before anyone noticed this map still
# targeted it (#2368). Either kind turns the closing `docker compose up -d
# --force-recreate` into a guaranteed reject, since Compose validates every
# named service before recreating any of them -- so a single stale row
# silently blocks every *valid* gateway from ever picking up its rotated
# secret. The pre-flight check below guards against a repeat: a
# listed-but-decommissioned client aborts loudly before any writes instead
# of quietly wedging the whole run again.
declare -A CLIENT_CONTAINERS=(
  [kibana]=oidc-kibana                # Kibana's oauth2-proxy gateway
  [evebox]=oidc-evebox                # EveBox's oauth2-proxy gateway
  [arkime]=oidc-arkime                # Arkime's oauth2-proxy gateway
  [tanner]=oidc-tanner                # TANNER's oauth2-proxy gateway
  [revdeck]=oidc-revdeck              # RevDeck's oauth2-proxy gateway
  [unsloth]=oidc-unsloth              # Unsloth Studio's oauth2-proxy gateway (#3689)
  [traefik-dashboard]=oidc-traefik    # Traefik dashboard's oauth2-proxy gateway
)
CLIENTS=("${!CLIENT_CONTAINERS[@]}")

: "${KEYCLOAK_ADMIN_USERNAME:?set KEYCLOAK_ADMIN_USERNAME (master-realm admin -- the bootstrap account works fine right after a fresh --import-realm, before a named admin exists yet)}"
: "${KEYCLOAK_ADMIN_PASSWORD:?set KEYCLOAK_ADMIN_PASSWORD}"

docker exec "$KC_CONTAINER" "$KC" config credentials \
  --config "$KC_CONFIG" --server http://127.0.0.1:8080 --realm master \
  --user "$KEYCLOAK_ADMIN_USERNAME" --password "$KEYCLOAK_ADMIN_PASSWORD"

# #2194: from this point the config file holds the live admin access token
# -- remove it on every exit path, not just success (a mid-run failure under
# set -euo pipefail used to leave it in hp-keycloak:/tmp until restart).
# Deliberately ahead of the #2195 pre-flight below so even its abort path
# cleans up. Idiom per provision-account-console-scopes.sh.
cleanup() { docker exec "$KC_CONTAINER" rm -f "$KC_CONFIG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# #2195: validate the hand-maintained map against the realm's own client
# list BEFORE syncing anything. A listed-but-decommissioned client used to
# fail silently at both ends at once: every run printed "SKIP <client>",
# set fail=1, and exited 1 forever after (so a real missing-client SKIP
# could never stand out), while the dead gateway still rode along in the
# recreate step and made docker compose reject it outright -- even
# validly-synced gateways were then never restarted until someone stepped
# in by hand. One loud abort before any writes replaces both failure modes;
# when this fires the MAP above has drifted from the realm and needs
# editing, not a rerun.
realm_clients="$(docker exec "$KC_CONTAINER" "$KC" get clients -r "$REALM" \
  --fields clientId --format csv --noquotes --config "$KC_CONFIG")"
missing=()
for client in "${CLIENTS[@]}"; do
  grep -qxF "$client" <<<"$realm_clients" || missing+=("$client")
done
if ((${#missing[@]})); then
  printf 'ABORT: listed in CLIENT_CONTAINERS but absent from realm %s: %s\n' \
    "$REALM" "${missing[*]}" >&2
  exit 2
fi

fail=0
synced_containers=()
for client in "${CLIENTS[@]}"; do
  uuid="$(docker exec "$KC_CONTAINER" "$KC" get clients -r "$REALM" \
    -q "clientId=${client}" --fields id --format csv --noquotes --config "$KC_CONFIG")"
  if [[ -z "$uuid" ]]; then
    echo "SKIP $client: no such client in realm $REALM" >&2
    fail=1
    continue
  fi
  secret="$(docker exec "$KC_CONTAINER" "$KC" get \
    "clients/${uuid}/client-secret" -r "$REALM" --config "$KC_CONFIG" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')"

  # #787: <<<"$secret" (a herestring) always appends exactly one trailing
  # newline to whatever it feeds a command's stdin -- that's herestring
  # syntax, not something $secret itself carries (command substitution
  # already stripped any trailing newline off it). `cat` on the receiving
  # end writes that byte to the file verbatim, so every synced secret file
  # actually held the real secret plus a spurious trailing \n. Found live:
  # oauth2-proxy reads --client-secret-file raw and does not trim it, so
  # the client_secret it POSTed to Keycloak's token endpoint never matched
  # what Keycloak had, and every gateway login failed with
  # unauthorized_client/invalid_client_credentials after a rotation --
  # masked until now by secrets rarely actually being rotated post-setup.
  # printf '%s' (no \n) is exact-bytes; piping it in instead of using a
  # herestring is what actually avoids the injected newline.
  printf '%s' "$secret" | ssh "$VPS_HOST" "install -d -m 750 '${VPS_SECRETS_DIR}/${client}' && \
    umask 077 && cat > '${VPS_SECRETS_DIR}/${client}/client-secret' && \
    chown root:65532 '${VPS_SECRETS_DIR}/${client}/client-secret' && \
    chmod 440 '${VPS_SECRETS_DIR}/${client}/client-secret'"
  synced_containers+=("${CLIENT_CONTAINERS[$client]}")
  echo "synced $client"
done

# #2195: recreate ONLY gateways whose secret actually changed hands this
# run. The old always-full list is what let a stale entry turn "every sync
# ok, restart rejected by compose" into "nothing restarted". An empty set
# means every row skipped -- say so rather than calling compose with zero
# services.
if ((${#synced_containers[@]})); then
  ssh "$VPS_HOST" "cd /root/vps && docker compose up -d --force-recreate ${synced_containers[*]}"
else
  echo "no secrets synced; skipping gateway recreation" >&2
fi

exit "$fail"
