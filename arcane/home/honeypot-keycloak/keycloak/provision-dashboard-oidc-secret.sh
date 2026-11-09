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
# Run on the homeserver as root. #3824: authenticates with the permanent admin
# client (secrets/admin-client-secret) through lib-admin.sh.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib-admin.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-admin.sh"

REALM="${KEYCLOAK_REALM:-apiary}"
ADMIN_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-apiary-ops-admin}"
SECRETS_DIR="${DASHBOARD_SECRETS_DIR:-/var/dockge/stacks/apiary-dashboard/secrets}"
CLIENT_ID="${DASHBOARD_CLIENT_ID:-apiary-dashboard-rewrite}"

kc_login "${ADMIN_ID}" "${KEYCLOAK_SECRETS_DIR}/admin-client-secret"

client_uuid="$(kc_client_uuid "${REALM}" "${CLIENT_ID}")"
[[ -n "$client_uuid" ]] || { echo "${CLIENT_ID} client not found in realm $REALM -- import the realm first" >&2; exit 1; }

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
  owner="root:$secret_gid"
  echo "secret group-owned by $DASHBOARD_SECRETS_GROUP (gid $secret_gid)"
else
  owner="root:root"
  echo "WARNING: group '$DASHBOARD_SECRETS_GROUP' does not exist -- left root:root." >&2
  echo "         the dashboard runs unprivileged and will fail with EACCES reading this." >&2
fi
install -d -m 750 "$SECRETS_DIR"
chown "$owner" "$SECRETS_DIR"
chmod 750 "$SECRETS_DIR"
kc_write_secret "${REALM}" "${client_uuid}" "$SECRETS_DIR/oidc-client-secret" "$owner" 440
echo "wrote client secret to $SECRETS_DIR/oidc-client-secret"
