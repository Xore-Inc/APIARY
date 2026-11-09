#!/usr/bin/env bash
# provision-master-realm.sh (#3824) -- apply the repo's master-realm settings
# (realm/master-realm-settings.json) after a fresh database.
#
# --import-realm cannot carry master: Keycloak creates master before the import
# runs, and the import skips any realm that already exists. So the few master
# settings that are not Keycloak defaults (the APIARY login/account theme and
# the WebAuthn/passkey policy) live in that file and are applied here as a
# partial realm update, plus one flow change: webauthn-authenticator in
# "Browser - Conditional 2FA" goes from DISABLED to ALTERNATIVE, the same as
# the apiary realm.
#
# Authenticates with the permanent admin client from provision-admin-client.sh
# (secrets/admin-client-secret). Idempotent. Run on the homeserver as root.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib-admin.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-admin.sh"

ADMIN_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-apiary-ops-admin}"
SETTINGS="${kc_lib_dir}/realm/master-realm-settings.json"

case "${KEYCLOAK_PUBLIC_DOMAIN}" in
  ""|*[!A-Za-z0-9.-]*) echo "invalid KEYCLOAK_PUBLIC_DOMAIN" >&2; exit 1 ;;
esac

kc_login "${ADMIN_ID}" "${KEYCLOAK_SECRETS_DIR}/admin-client-secret"

python3 - "${SETTINGS}" "${KEYCLOAK_PUBLIC_DOMAIN}" > "${kc_tmp}/master.json" <<'EOF'
import json, sys
rep = {k: v for k, v in json.load(open(sys.argv[1])).items() if not k.startswith("_")}
print(json.dumps(rep).replace("example.invalid", sys.argv[2]))
EOF
kc_api PUT /master "${kc_tmp}/master.json" >/dev/null
echo "applied $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "${kc_tmp}/master.json") master realm settings"

flow_path="/master/authentication/flows/browser/executions"
kc_api GET "${flow_path}" > "${kc_tmp}/execs.json"
python3 - "${kc_tmp}/execs.json" > "${kc_tmp}/exec.json" <<'EOF'
import json, sys
execs = json.load(open(sys.argv[1]))
hit = [e for e in execs if e.get("providerId") == "webauthn-authenticator"]
if len(hit) != 1:
    sys.exit(f"expected one webauthn-authenticator execution in the browser flow, found {len(hit)}")
e = hit[0]
e["requirement"] = "ALTERNATIVE"
print(json.dumps(e))
EOF
kc_api PUT "${flow_path}" "${kc_tmp}/exec.json" >/dev/null

kc_api GET /master | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("master: loginTheme=%s accountTheme=%s webAuthnPolicyRpId=%s passkeys=%s" % (
    d.get("loginTheme"), d.get("accountTheme"), d.get("webAuthnPolicyRpId"),
    d.get("webAuthnPolicyPasswordlessPasskeysEnabled")))'
kc_api GET "${flow_path}" | kc_json '"webauthn-authenticator requirement: " + [e["requirement"] for e in d if e.get("providerId")=="webauthn-authenticator"][0]'
