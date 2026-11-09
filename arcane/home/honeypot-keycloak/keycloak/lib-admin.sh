# shellcheck shell=bash
# lib-admin.sh (#3824) -- shared helpers for the provisioners that talk to the
# Keycloak admin REST API with a client-credentials token instead of a
# username/password on a kcadm command line. Sourced, never executed.
#
# Secrets never appear on a command line or in output: client secrets are read
# by curl itself from their files (--data-urlencode name@file), and the access
# token only ever lives in a 0600 header file (curl -H @file) that is removed on
# exit.
#
# Inputs (environment, all optional):
#   KEYCLOAK_STACK_DIR   stack dir holding .env      (default: this dir's parent, else
#                        /var/dockge/stacks/honeypot-keycloak)
#   KEYCLOAK_ADMIN_URL   base URL of Keycloak        (default: http://$HP_BIND:$KEYCLOAK_PORT from .env)
#   KEYCLOAK_SECRETS_DIR secrets dir                 (default: from .env, else $stack/secrets)

kc_lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
kc_stack_dir="${KEYCLOAK_STACK_DIR:-$(cd -- "${kc_lib_dir}/.." && pwd)}"
# Run from a repo checkout (install-homeserver.sh), the parent has no .env:
# fall back to the deployed stack directory.
[[ -f "${kc_stack_dir}/.env" || -n "${KEYCLOAK_STACK_DIR:-}" ]] || kc_stack_dir=/var/dockge/stacks/honeypot-keycloak
if [[ -f "${kc_stack_dir}/.env" ]]; then
  # Only the few non-secret keys this library needs, not a blanket `source`.
  kc_env() { sed -n "s/^$1=//p" "${kc_stack_dir}/.env" | tail -n1; }
else
  kc_env() { :; }
fi
KEYCLOAK_ADMIN_URL="${KEYCLOAK_ADMIN_URL:-http://$(kc_env HP_BIND):$(kc_env KEYCLOAK_PORT)}"
KEYCLOAK_SECRETS_DIR="${KEYCLOAK_SECRETS_DIR:-$(kc_env KEYCLOAK_SECRETS_DIR)}"
KEYCLOAK_SECRETS_DIR="${KEYCLOAK_SECRETS_DIR:-${kc_stack_dir}/secrets}"
KEYCLOAK_PUBLIC_DOMAIN="${KEYCLOAK_PUBLIC_DOMAIN:-$(kc_env KEYCLOAK_PUBLIC_DOMAIN)}"

kc_tmp="$(mktemp -d)"
chmod 700 "${kc_tmp}"
trap 'rm -rf "${kc_tmp}"' EXIT

# kc_login <client-id> <secret-file>: fetch a master-realm token for a
# confidential service-account client into ${kc_tmp}/auth (a curl header file).
kc_login() {
  local client_id="$1" secret_file="$2"
  [[ -r "${secret_file}" ]] || { echo "cannot read ${secret_file}" >&2; return 1; }
  curl -fsS -X POST "${KEYCLOAK_ADMIN_URL}/realms/master/protocol/openid-connect/token" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_id=${client_id}" \
    --data-urlencode "client_secret@${secret_file}" \
    -o "${kc_tmp}/token.json"
  python3 -c 'import json,sys; print("Authorization: Bearer " + json.load(open(sys.argv[1]))["access_token"])' \
    "${kc_tmp}/token.json" > "${kc_tmp}/auth"
  rm -f "${kc_tmp}/token.json"
}

# kc_api <METHOD> <path under /admin/realms> [json-body-file]: prints the body.
kc_api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-fsS -X "${method}" -H "@${kc_tmp}/auth" "${KEYCLOAK_ADMIN_URL}/admin/realms${path}")
  [[ -n "${body}" ]] && args+=(-H 'Content-Type: application/json' --data-binary "@${body}")
  curl "${args[@]}"
}

# kc_json <python-expr over `d`>: evaluate against JSON on stdin.
kc_json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

# kc_client_uuid <realm> <clientId>: empty when absent.
kc_client_uuid() {
  kc_api GET "/$1/clients?clientId=$2" | kc_json '(d[0]["id"] if d else "")'
}

# kc_write_secret <realm> <client-uuid> <dest-file> <owner:group> <mode>:
# writes the client's current secret to dest with exact bytes (no newline).
kc_write_secret() {
  local realm="$1" uuid="$2" dest="$3" own="$4" mode="$5"
  local tmp
  tmp="$(mktemp "$(dirname -- "${dest}")/.secret.XXXXXX")"
  kc_api GET "/${realm}/clients/${uuid}/client-secret" \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["value"])' > "${tmp}"
  [[ -s "${tmp}" ]] || { rm -f "${tmp}"; echo "empty secret for ${uuid}" >&2; return 1; }
  chown "${own}" "${tmp}"
  chmod "${mode}" "${tmp}"
  mv -f "${tmp}" "${dest}"
}
