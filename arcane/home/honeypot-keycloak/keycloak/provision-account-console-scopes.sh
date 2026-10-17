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
# Run on the homeserver (needs docker exec access to hp-keycloak).
set -euo pipefail

REALM="${KEYCLOAK_REALM:-apiary}"
KC_CONTAINER="${KC_CONTAINER:-hp-keycloak}"
KC_CONFIG="${KC_CONFIG:-/tmp/kcadm-provision-account-console-scopes.config}"
KC="/opt/keycloak/bin/kcadm.sh"

# stock Keycloak's default set for account-console.
DEFAULT_SCOPES=(acr email profile roles web-origins)
# offline_access is optional rather than default on this client, matching
# stock -- a token for the account console should not carry an offline scope
# unless something explicitly asks for one.
OPTIONAL_SCOPES=(offline_access)

: "${KEYCLOAK_ADMIN_USERNAME:?set KEYCLOAK_ADMIN_USERNAME (master-realm admin -- the bootstrap account works fine right after a fresh --import-realm, before a named admin exists yet)}"
: "${KEYCLOAK_ADMIN_PASSWORD:?set KEYCLOAK_ADMIN_PASSWORD}"

docker exec "$KC_CONTAINER" "$KC" config credentials \
  --config "$KC_CONFIG" --server http://127.0.0.1:8080 --realm master \
  --user "$KEYCLOAK_ADMIN_USERNAME" --password "$KEYCLOAK_ADMIN_PASSWORD"

cleanup() { docker exec "$KC_CONTAINER" rm -f "$KC_CONFIG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

client_uuid="$(docker exec "$KC_CONTAINER" "$KC" get clients -r "$REALM" \
  -q "clientId=account-console" --fields id --format csv --noquotes --config "$KC_CONFIG" | tr -d '\r')"
[[ -n "$client_uuid" ]] || { echo "account-console client not found in realm $REALM -- import the realm first" >&2; exit 1; }

# Resolve scope name -> id from one listing rather than per-name lookups.
# `kcadm get client-scopes -q name=<x>` does NOT filter (confirmed live: it
# returns the whole list regardless), so a per-name query silently hands back
# the *first* scope every time -- which looks like it worked and assigns the
# wrong scope five times over.
scope_ids="$(docker exec "$KC_CONTAINER" "$KC" get client-scopes -r "$REALM" \
  --fields id,name --format csv --noquotes --config "$KC_CONFIG" | tr -d '\r')"

scope_id_for() {
  local want="$1"
  while IFS=, read -r id name; do
    [[ "$name" == "$want" ]] && { printf '%s' "$id"; return 0; }
  done <<< "$scope_ids"
  return 1
}

assign() {
  local kind="$1" name="$2" id
  if ! id="$(scope_id_for "$name")"; then
    echo "  ? scope '$name' does not exist in realm $REALM -- skipping" >&2
    return 0
  fi
  docker exec "$KC_CONTAINER" "$KC" update \
    "clients/${client_uuid}/${kind}-client-scopes/${id}" -r "$REALM" --config "$KC_CONFIG"
  echo "  + ${kind%%-*} scope: $name"
}

for scope in "${DEFAULT_SCOPES[@]}"; do assign default "$scope"; done
for scope in "${OPTIONAL_SCOPES[@]}"; do assign optional "$scope"; done

applied="$(docker exec "$KC_CONTAINER" "$KC" get "clients/${client_uuid}/default-client-scopes" \
  -r "$REALM" --config "$KC_CONFIG" | grep '"name"' | sed 's/.*: "//;s/".*//' | sort | tr '\n' ' ' || true)"
echo "account-console default scopes now: ${applied:-<none>}"

for scope in "${DEFAULT_SCOPES[@]}"; do
  case " $applied " in
    *" $scope "*) ;;
    *) echo "account-console is still missing the '$scope' scope -- the account console will 403 (#1690)" >&2; exit 1 ;;
  esac
done
