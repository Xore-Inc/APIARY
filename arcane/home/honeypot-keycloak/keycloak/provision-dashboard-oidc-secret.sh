#!/usr/bin/env bash
# provision-dashboard-oidc-secret.sh -- a fresh --import-realm generates a
# new random client secret for apiary-dashboard (same reasoning as
# provision-events-poller.sh's own comment: no realm-JSON concept for
# pinning a client secret). Nothing ever wrote that secret to where the
# dashboard binary itself expects it
# (arcane/home/honeypot-dashboard/compose.yml's OIDC_CLIENT_SECRET_FILE=
# /run/dashboard-secrets/oidc-client-secret) -- sync-client-secrets.sh
# covers the *gateway* sidecars' copies on the VPS, not this one. Found
# live during #787's homeserver reinstall (2026-08-09): both dashboard and
# dashboard-b crash-looped forever on "OIDC_CLIENT_SECRET(_FILE) must
# contain at least 32 characters" because secrets/ was simply empty.
#
# Idempotent: safe to re-run after a realm re-import (the secret file is
# simply overwritten with the current value). Both dashboard containers
# have restart: unless-stopped, so writing the file here is enough --
# no need to also restart them, their own crash-restart loop picks it up.
#
# #3578/#3749: DASHBOARD_CLIENT_ID selects the client. The default is the
# production dashboard's client, apiary-dashboard-rewrite, whose secret file
# lives in the apiary-dashboard Arcane project (DASHBOARD_SECRETS_DIR). The
# legacy apiary-dashboard client served dashboard-next, removed in #3749.
#
# Run on the homeserver (needs docker exec access to hp-keycloak).
set -euo pipefail

REALM="${KEYCLOAK_REALM:-apiary}"
KC_CONTAINER="${KC_CONTAINER:-hp-keycloak}"
KC_CONFIG="${KC_CONFIG:-/tmp/kcadm-provision-dashboard-oidc-secret.config}"
SECRETS_DIR="${DASHBOARD_SECRETS_DIR:-/var/dockge/stacks/apiary-dashboard/secrets}"
CLIENT_ID="${DASHBOARD_CLIENT_ID:-apiary-dashboard-rewrite}"
KC="/opt/keycloak/bin/kcadm.sh"

: "${KEYCLOAK_ADMIN_USERNAME:?set KEYCLOAK_ADMIN_USERNAME (master-realm admin -- the bootstrap account works fine right after a fresh --import-realm, before a named admin exists yet)}"
: "${KEYCLOAK_ADMIN_PASSWORD:?set KEYCLOAK_ADMIN_PASSWORD}"

docker exec "$KC_CONTAINER" "$KC" config credentials \
  --config "$KC_CONFIG" --server http://127.0.0.1:8080 --realm master \
  --user "$KEYCLOAK_ADMIN_USERNAME" --password "$KEYCLOAK_ADMIN_PASSWORD"

# #2194: from this point the config file holds the live admin access token
# -- remove it on every exit path, not just success (a mid-run failure under
# set -euo pipefail used to leave it in hp-keycloak:/tmp until restart).
cleanup() { docker exec "$KC_CONTAINER" rm -f "$KC_CONFIG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

client_uuid="$(docker exec "$KC_CONTAINER" "$KC" get clients -r "$REALM" \
  -q "clientId=${CLIENT_ID}" --fields id --format csv --noquotes --config "$KC_CONFIG")"
[[ -n "$client_uuid" ]] || { echo "${CLIENT_ID} client not found in realm $REALM -- import the realm first" >&2; exit 1; }

secret="$(docker exec "$KC_CONTAINER" "$KC" get \
  "clients/${client_uuid}/client-secret" -r "$REALM" --config "$KC_CONFIG" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')"

install -d -m 750 "$SECRETS_DIR"
umask 077
printf '%s' "$secret" > "$SECRETS_DIR/oidc-client-secret"

# Group-own the secret by the group apiary-dashboard's compose joins the
# container to (group_add DEPLOY_RUNNER_GID), so the unprivileged dashboard
# can read it. History below is from the legacy dashboard-next (#3749).
#
# The comment that used to sit here said these services "run as root:root" and
# matched ownership accordingly. That described the RETIRED Go dashboard, which
# had no USER in its Dockerfile and so bypassed file permissions entirely.
# dashboard-next runs as the frontend-next image's unprivileged `node` user
# (uid 1000), which is exactly why its compose carries a group_add -- and
# root:root 440 defeats that, because no group membership can grant read on a
# file whose group IS root. Live symptom, found after the 2026-09-03 rebuild:
#
#   [auth] /auth/login could not start sign-in:
#     Error: EACCES: permission denied, open '/run/dashboard-secrets/oidc-client-secret'
#
# which the dashboard surfaces to users as "Sign-in is temporarily unavailable
# -- the identity provider or session store did not answer", pointing at
# Keycloak for what is a local file-permission problem.
DASHBOARD_SECRETS_GROUP="${DASHBOARD_SECRETS_GROUP:-deploy-runner}"
if secret_gid="$(getent group "$DASHBOARD_SECRETS_GROUP" | cut -d: -f3)" && [[ -n "$secret_gid" ]]; then
  chown "root:$secret_gid" "$SECRETS_DIR" "$SECRETS_DIR/oidc-client-secret"
  echo "secret group-owned by $DASHBOARD_SECRETS_GROUP (gid $secret_gid)"
else
  chown root:root "$SECRETS_DIR/oidc-client-secret"
  echo "WARNING: group '$DASHBOARD_SECRETS_GROUP' does not exist -- left root:root." >&2
  echo "         the dashboard runs unprivileged and will fail with EACCES reading this." >&2
fi
chmod 750 "$SECRETS_DIR"
chmod 440 "$SECRETS_DIR/oidc-client-secret"
echo "wrote client secret to $SECRETS_DIR/oidc-client-secret"
