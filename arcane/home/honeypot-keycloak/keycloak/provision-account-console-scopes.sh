#!/usr/bin/env bash
# provision-account-console-scopes.sh -- #1697: give Keycloak's built-in
# `account-console` client the default client scopes it needs, after every
# realm import.
#
# Without them the account console loads and then fails with "Something went
# wrong", because its own REST call comes back 403 (#1690). The `roles` scope
# is the one that matters: it carries the `client roles` mapper (which emits
# `resource_access.account.roles`) and `audience resolve` (which adds
# `aud: account`) -- exactly the two things the Account API checks for, and
# exactly what the token lacks without it.
#
# Why this is a post-import step and not realm JSON:
#
#   1. `account-console` is a Keycloak *built-in*, created automatically
#      during --import-realm. It is deliberately not one of the 9 clients
#      keycloak/realm/apiary-realm.json declares, and adding it there fails
#      keycloak/realm/validate.sh's exact-client-list assertion -- which
#      gates the container's own startup batch update, so that is not a
#      check to loosen casually.
#   2. Setting `defaultDefaultClientScopes` on the realm -- the documented
#      knob for "what new clients get" -- does NOT reach it. Measured
#      directly (2026-08-23) by importing the realm both ways into a
#      disposable Keycloak 26.7.1 + Postgres, the same topology
#      scripts/test-keycloak-realm-import.sh builds:
#
#        realm as shipped              -> account-console scopes: <none>
#        realm + defaultDefaultClientScopes -> account-console scopes: <none>
#
#      Keycloak creates its built-in clients during realm creation without
#      consulting that list. So there is no declarative fix available, and
#      reconciling afterwards is the only thing that actually works.
#
# The scopes applied are stock Keycloak's own set for this client, and match
# every user-facing client already declared in this realm
# (apiary-dashboard, arcane, arkime, evebox, kibana, revdeck, tanner,
# traefik-dashboard, unsloth all carry exactly these five).
#
# Idempotent: re-running is a no-op, so it is safe on every install and safe
# to run by hand against a live realm to repair one.
#
# Run on the homeserver as root. #3824: authenticates with the permanent admin
# client (secrets/admin-client-secret, see provision-admin-client.sh) through
# lib-admin.sh instead of a kcadm password on the command line.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib-admin.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-admin.sh"

REALM="${KEYCLOAK_REALM:-apiary}"
ADMIN_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-apiary-ops-admin}"

# stock Keycloak's default set for account-console.
DEFAULT_SCOPES=(acr email profile roles web-origins)
# offline_access is optional rather than default on this client, matching
# stock -- a token for the account console should not carry an offline scope
# unless something explicitly asks for one.
OPTIONAL_SCOPES=(offline_access)

kc_login "${ADMIN_ID}" "${KEYCLOAK_SECRETS_DIR}/admin-client-secret"

client_uuid="$(kc_client_uuid "${REALM}" account-console)"
[[ -n "$client_uuid" ]] || { echo "account-console client not found in realm $REALM -- import the realm first" >&2; exit 1; }

# One listing, resolved by exact name (#1697: a per-name kcadm query did not
# filter and silently returned the first scope every time).
kc_api GET "/${REALM}/client-scopes" > "${kc_tmp}/scopes.json"
scope_id_for() {
  python3 -c 'import json,sys; m=[s["id"] for s in json.load(open(sys.argv[1])) if s["name"]==sys.argv[2]]; print(m[0] if m else "")' \
    "${kc_tmp}/scopes.json" "$1"
}

assign() {
  local kind="$1" name="$2" id
  id="$(scope_id_for "$name")"
  if [[ -z "$id" ]]; then
    echo "  ? scope '$name' does not exist in realm $REALM -- skipping" >&2
    return 0
  fi
  kc_api PUT "/${REALM}/clients/${client_uuid}/${kind}-client-scopes/${id}" >/dev/null
  echo "  + ${kind} scope: $name"
}

for scope in "${DEFAULT_SCOPES[@]}"; do assign default "$scope"; done
for scope in "${OPTIONAL_SCOPES[@]}"; do assign optional "$scope"; done

applied="$(kc_api GET "/${REALM}/clients/${client_uuid}/default-client-scopes" | kc_json '" ".join(sorted(s["name"] for s in d))')"
echo "account-console default scopes now: ${applied:-<none>}"

for scope in "${DEFAULT_SCOPES[@]}"; do
  case " $applied " in
    *" $scope "*) ;;
    *) echo "account-console is still missing the '$scope' scope -- the account console will 403 (#1690)" >&2; exit 1 ;;
  esac
done
