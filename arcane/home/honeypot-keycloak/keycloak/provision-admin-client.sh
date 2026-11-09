#!/usr/bin/env bash
# provision-admin-client.sh (#3824) -- turn the temporary bootstrap admin
# *client* that a fresh database starts with into a permanent master-realm admin
# client for tooling, then remove the bootstrap one.
#
# compose.yml exports KC_BOOTSTRAP_ADMIN_CLIENT_ID/_SECRET only while
# secrets/bootstrap-admin-client-secret exists. On an empty database Keycloak
# then creates a temporary admin service-account client in master instead of a
# bootstrap user, so a rebuilt realm holds no human account at all until an
# operator creates one.
#
# This script, run on the homeserver as root right after that first start:
#   1. logs in with the bootstrap client (client_credentials, secret read from
#      its file by curl -- never on a command line);
#   2. creates the confidential service-account client KEYCLOAK_ADMIN_CLIENT_ID
#      (default apiary-ops-admin) in master if absent, with no browser or
#      password flows, and grants its service account the master `admin` role;
#   3. writes that client's secret to secrets/admin-client-secret (root 0440);
#   4. proves the new credential works (token + GET /admin/realms);
#   5. deletes the bootstrap client -- only if Keycloak itself marked it
#      temporary (is_temporary_admin=true) -- and removes
#      secrets/bootstrap-admin-client-secret.
#
# Idempotent: with no bootstrap secret file left it only re-verifies the
# permanent client. Every other provisioner reads the same admin-client-secret.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib-admin.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-admin.sh"

ADMIN_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-apiary-ops-admin}"
ADMIN_SECRET="${KEYCLOAK_SECRETS_DIR}/admin-client-secret"
BOOT_ID="${KEYCLOAK_BOOTSTRAP_ADMIN_CLIENT_ID:-$(kc_env KEYCLOAK_BOOTSTRAP_ADMIN_CLIENT_ID)}"
BOOT_ID="${BOOT_ID:-bootstrap-admin-client}"
BOOT_SECRET="${KEYCLOAK_SECRETS_DIR}/bootstrap-admin-client-secret"

if [[ -f "${BOOT_SECRET}" ]]; then
  kc_login "${BOOT_ID}" "${BOOT_SECRET}"

  uuid="$(kc_client_uuid master "${ADMIN_ID}")"
  if [[ -z "${uuid}" ]]; then
    python3 - "${ADMIN_ID}" > "${kc_tmp}/client.json" <<'EOF'
import json, sys
json.dump({
    "clientId": sys.argv[1],
    "name": "APIARY operator tooling (master admin, client credentials)",
    "description": "#3824: permanent master-realm admin for scripts. Service account only; no browser, password or implicit flow.",
    "enabled": True, "protocol": "openid-connect", "publicClient": False,
    "clientAuthenticatorType": "client-secret",
    "standardFlowEnabled": False, "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
    "frontchannelLogout": False, "redirectUris": [], "webOrigins": [],
}, sys.stdout)
EOF
    kc_api POST /master/clients "${kc_tmp}/client.json" >/dev/null
    uuid="$(kc_client_uuid master "${ADMIN_ID}")"
    echo "created master client ${ADMIN_ID}"
  fi

  # Keycloak 26.8.2 only accepts admin REST calls from a token carrying the
  # admin-API audience, which its built-in `kc-admin-api` client scope adds.
  # Keycloak gives that scope to admin-cli, the console and its own bootstrap
  # client, but not to a client created over REST: without it the new
  # credential gets a token and then a 401 on every admin call (measured on a
  # scratch 26.8.2, #3824). Older releases have no such scope; skip it there.
  scope_id="$(kc_api GET /master/client-scopes | kc_json '([s["id"] for s in d if s["name"]=="kc-admin-api"] or [""])[0]')"
  if [[ -n "${scope_id}" ]]; then
    kc_api PUT "/master/clients/${uuid}/default-client-scopes/${scope_id}" >/dev/null
    echo "added default client scope kc-admin-api to ${ADMIN_ID}"
  fi

  sa_id="$(kc_api GET "/master/clients/${uuid}/service-account-user" | kc_json 'd["id"]')"
  kc_api GET /master/roles/admin | python3 -c 'import json,sys; json.dump([json.load(sys.stdin)], sys.stdout)' > "${kc_tmp}/role.json"
  kc_api POST "/master/users/${sa_id}/role-mappings/realm" "${kc_tmp}/role.json" >/dev/null
  echo "granted master realm role admin to service-account-${ADMIN_ID}"

  install -d -m 750 -o root -g root "${KEYCLOAK_SECRETS_DIR}"
  kc_write_secret master "${uuid}" "${ADMIN_SECRET}" root:root 440
  echo "wrote ${ADMIN_SECRET}"
fi

kc_login "${ADMIN_ID}" "${ADMIN_SECRET}"
realms="$(kc_api GET '' | kc_json '",".join(sorted(r["realm"] for r in d))')"
echo "permanent admin client ${ADMIN_ID} works; realms visible: ${realms}"

if [[ -f "${BOOT_SECRET}" ]]; then
  boot_uuid="$(kc_client_uuid master "${BOOT_ID}")"
  if [[ -n "${boot_uuid}" ]]; then
    temp="$(kc_api GET "/master/clients/${boot_uuid}" | kc_json 'd.get("attributes",{}).get("is_temporary_admin","")')"
    if [[ "${temp}" == "true" ]]; then
      kc_api DELETE "/master/clients/${boot_uuid}" >/dev/null
      echo "deleted temporary bootstrap client ${BOOT_ID}"
    else
      echo "REFUSING to delete ${BOOT_ID}: not marked is_temporary_admin=true" >&2
      exit 1
    fi
  fi
  rm -f "${BOOT_SECRET}"
  echo "removed ${BOOT_SECRET}"
fi

[[ -z "$(kc_client_uuid master "${BOOT_ID}")" ]] && echo "verified: no ${BOOT_ID} client in master"
