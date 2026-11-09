#!/usr/bin/env bash
# provision-arcane-oidc-secret.sh (#1504) -- a fresh --import-realm generates
# a new random client secret for the `arcane` OIDC client (same reasoning as
# provision-dashboard-oidc-secret.sh's own comment: the realm JSON has no
# concept for pinning a client secret, so it can't be baked into the export).
# install-homeserver.sh's step_arcane_install stands Arcane up with a
# throwaway placeholder ARCANE_OIDC_CLIENT_SECRET just to satisfy
# docker-compose.arcane.yml's `:?` guard; this script replaces it with the
# real value once Keycloak is up, so interactive OIDC login actually works.
#
# Unlike the dashboard (which reads OIDC_CLIENT_SECRET_FILE from a mounted
# secrets file this can just overwrite in place), Arcane has NO *_FILE
# variant for this secret -- it reads OIDC_CLIENT_SECRET straight from the
# stack's own .env (confirmed against Arcane's env-var reference, see
# docker-compose.arcane.yml). So this script rewrites the .env line and then
# re-ups the stack to pick it up, rather than just dropping a file a running
# container's restart loop would notice.
#
# Idempotent: safe to re-run after a realm re-import (the .env line is simply
# rewritten with the current value and the stack re-upped).
#
# Run on the homeserver as root. #3824: authenticates with the permanent admin
# client (secrets/admin-client-secret) through lib-admin.sh, and the new value
# is spliced into .env by python reading it from a 0600 temp file -- it used to
# be a sed expression, i.e. on a command line.
#
# ARCANE_REUP=0 skips the closing `docker compose up -d` (Arcane is the deploy
# control plane; an operator may want to recreate it at a moment of their own).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib-admin.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-admin.sh"

REALM="${KEYCLOAK_REALM:-apiary}"
ADMIN_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-apiary-ops-admin}"
ARCANE_DIR="${ARCANE_STACK_DIR:-/var/dockge/stacks/honeypot-arcane}"
ENV_FILE="$ARCANE_DIR/.env"

[[ -f "$ENV_FILE" ]] || { echo "no $ENV_FILE -- was step_arcane_install run first?" >&2; exit 1; }

kc_login "${ADMIN_ID}" "${KEYCLOAK_SECRETS_DIR}/admin-client-secret"

client_uuid="$(kc_client_uuid "${REALM}" arcane)"
[[ -n "$client_uuid" ]] || { echo "arcane client not found in realm $REALM -- import the realm first" >&2; exit 1; }

kc_write_secret "${REALM}" "${client_uuid}" "${kc_tmp}/arcane-secret" "root:root" 600

# Rewrite the single ARCANE_OIDC_CLIENT_SECRET line in place, preserving the
# rest of the .env (ENCRYPTION_KEY/JWT_SECRET must NOT change).
python3 - "$ENV_FILE" "${kc_tmp}/arcane-secret" <<'PY'
import os, sys
env, secret = sys.argv[1], open(sys.argv[2]).read()
lines = open(env).read().splitlines()
out, done = [], False
for l in lines:
    if l.startswith("ARCANE_OIDC_CLIENT_SECRET="):
        out.append("ARCANE_OIDC_CLIENT_SECRET=" + secret); done = True
    else:
        out.append(l)
if not done:
    out.append("ARCANE_OIDC_CLIENT_SECRET=" + secret)
st = os.stat(env)
tmp = env + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("\n".join(out) + "\n")
os.chown(tmp, st.st_uid, st.st_gid)
os.replace(tmp, env)
PY
chmod 600 "$ENV_FILE"
echo "wrote real arcane OIDC client secret to $ENV_FILE"

# Re-up so Arcane's container picks up the new secret (env changes only take
# effect on recreate, not on a bare restart).
if [[ "${ARCANE_REUP:-1}" != "0" ]]; then
  (cd "$ARCANE_DIR" && docker compose -f compose.yml up -d)
fi
