#!/usr/bin/env bash
# provision-events-poller.sh (#1066) -- auth-events-poller is a
# service-account-only client (see apiary-realm.json's own comment on it);
# a fresh --import-realm creates the client but Keycloak has no realm-JSON
# concept for granting a client's service-account user another client's
# roles (same reasoning docs/KEYCLOAK-OPERATIONS.md already gives for why
# secrets/users are never baked into the export). This script does that
# one-time grant -- realm-management's view-events role, the minimum needed
# for GET /admin/realms/{realm}/events -- and writes the client secret to
# where auth-events-worker's compose stack expects it.
#
# Idempotent: safe to re-run after a realm re-import (grants a role a
# second time is a no-op in Keycloak, and the secret file is simply
# overwritten with the current value).
#
# Run on the homeserver as root. #3824: authenticates with the permanent admin
# client (secrets/admin-client-secret) through lib-admin.sh.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib-admin.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-admin.sh"

REALM="${KEYCLOAK_REALM:-apiary}"
ADMIN_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-apiary-ops-admin}"
SECRETS_DIR="${EVENTS_POLLER_SECRETS_DIR:-/var/dockge/stacks/auth-events-worker-secrets}"

kc_login "${ADMIN_ID}" "${KEYCLOAK_SECRETS_DIR}/admin-client-secret"

client_uuid="$(kc_client_uuid "${REALM}" auth-events-poller)"
[[ -n "$client_uuid" ]] || { echo "auth-events-poller client not found in realm $REALM -- import the realm first" >&2; exit 1; }

sa_user_id="$(kc_api GET "/${REALM}/clients/${client_uuid}/service-account-user" | kc_json 'd["id"]')"
[[ -n "$sa_user_id" ]] || { echo "auth-events-poller has no service-account user -- is serviceAccountsEnabled true?" >&2; exit 1; }

rm_uuid="$(kc_client_uuid "${REALM}" realm-management)"
kc_api GET "/${REALM}/clients/${rm_uuid}/roles/view-events" \
  | python3 -c 'import json,sys; json.dump([json.load(sys.stdin)], sys.stdout)' > "${kc_tmp}/role.json"
kc_api POST "/${REALM}/users/${sa_user_id}/role-mappings/clients/${rm_uuid}" "${kc_tmp}/role.json" >/dev/null
echo "granted realm-management:view-events to auth-events-poller's service account"

# GID 10101 matches auth-events-worker/Dockerfile's fixed, non-root
# `authevents` user -- same reasoning as vps/secrets/oidc/*'s
# "chown root:65532" convention (docs/KEYCLOAK-OPERATIONS.md). The
# directory itself needs the same group, not just the file -- traversal
# (the executable bit) is checked on the directory, and a file-only chown
# left group-root's directory unreadable by GID 10101 (caught live).
install -d -m 750 -o root -g 10101 "$SECRETS_DIR"
kc_write_secret "${REALM}" "${client_uuid}" "$SECRETS_DIR/client-secret" root:10101 440
echo "wrote client secret to $SECRETS_DIR/client-secret"
