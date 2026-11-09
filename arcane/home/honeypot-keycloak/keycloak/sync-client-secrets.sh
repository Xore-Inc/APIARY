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
# Run from the homeserver as root (root's ~/.ssh/config carries the `vps`
# alias) with SSH access to the VPS. #3824: authenticates with the permanent
# admin client (secrets/admin-client-secret) through lib-admin.sh instead of a
# kcadm password on the command line. Each secret goes from a 0600 file in a
# private temp dir straight into ssh's stdin -- never a command-line argument,
# never printed.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=lib-admin.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-admin.sh"

REALM="${KEYCLOAK_REALM:-apiary}"
VPS_HOST="${VPS_HOST:-vps}"
VPS_SECRETS_DIR="${VPS_SECRETS_DIR:-/root/vps/secrets/oidc}"
ADMIN_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-apiary-ops-admin}"

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

kc_login "${ADMIN_ID}" "${KEYCLOAK_SECRETS_DIR}/admin-client-secret"

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
realm_clients="$(kc_api GET "/${REALM}/clients" | kc_json '"\n".join(c["clientId"] for c in d)')"
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
  uuid="$(kc_client_uuid "${REALM}" "${client}")"
  if [[ -z "$uuid" ]]; then
    echo "SKIP $client: no such client in realm $REALM" >&2
    fail=1
    continue
  fi
  kc_write_secret "${REALM}" "${uuid}" "${kc_tmp}/${client}.secret" root:root 600

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
  # #787's lesson holds: the file carries the exact secret bytes, no newline.
  ssh "$VPS_HOST" "install -d -m 750 '${VPS_SECRETS_DIR}/${client}' && \
    umask 077 && cat > '${VPS_SECRETS_DIR}/${client}/client-secret' && \
    chown root:65532 '${VPS_SECRETS_DIR}/${client}/client-secret' && \
    chmod 440 '${VPS_SECRETS_DIR}/${client}/client-secret'" < "${kc_tmp}/${client}.secret"
  rm -f "${kc_tmp}/${client}.secret"
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
