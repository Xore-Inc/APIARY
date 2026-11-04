#!/usr/bin/env bash
# test-oauth2-proxy-gateway-resilience.sh — #977: proves the isolated
# oauth2-proxy gateway pattern this repo uses for Kibana/EveBox/Arkime/
# TANNER/RevDeck/Dockge/Traefik actually holds, against a real disposable
# Keycloak + real oauth2-proxy (the exact same pinned image and PKCE/cookie
# settings vps/docker-compose.yml's x-oidc-gateway anchor uses), not a
# reimplementation or a mock. Six of #977's acceptance criteria in one pass:
#
#   - unauthenticated requests redirect only to the real, configured
#     Keycloak authorize endpoint, with PKCE S256 and the registered client
#   - a forged callback (code/state neither side ever issued) is rejected,
#     not granted a session
#   - a real login for a user WITH the required client role is granted
#     access, end to end
#   - a real login for a user WITHOUT the required client role is denied
#     (403) even though the login itself succeeded -- proves
#     OAUTH2_PROXY_ALLOWED_ROLES is actually enforced, not just configured
#   - the protected upstream has no published port of its own -- the
#     gateway is the *only* network path to it (mirrors every real
#     socat-hp-<app> backend's isolated oidc-<app> network in
#     vps/docker-compose.yml)
#   - stopping the gateway denies access outright (connection refused),
#     it never falls through to the upstream
#   - a tampered session cookie (the credential this deployment actually
#     relies on -- see below) is rejected outright, not silently accepted
#   - a session past OAUTH2_PROXY_COOKIE_EXPIRE is rejected, not honored
#
# On "wrong-issuer/audience/expired/bad-signature token thrown at the
# gateway": this deployment sets OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER
# and OAUTH2_PROXY_PASS_ACCESS_TOKEN both to "false" (see
# vps/docker-compose.yml's x-oidc-gateway anchor) -- there is no bearer-
# token code path in production for an attacker to target at all. The
# actual credential this gateway relies on is its own encrypted, signed
# session cookie; wrong-issuer/audience checks happen inside oauth2-proxy's
# own server-to-server token exchange with Keycloak's token endpoint,
# which an external attacker has no way to inject a forged response into
# without already controlling Keycloak or the network path to it. What IS
# on this gateway's real attack surface, and what the two new checks below
# cover: can a tampered or expired session cookie still grant access.
#
# Also covered, added for #1094: a live Keycloak outage mid-session (test
# #9 below) and /oauth2/sign_out actually revoking the session server-side,
# not just clearing the browser's own cookie (test #8 below).
#
# Still not covered here (out of scope for this script, tracked as
# still-open #977 work): JWKS/discovery failures and key/client-secret
# rotation drills.
set -euo pipefail

# #2915: the `trap ... EXIT` below does not fire on SIGKILL (a runner OOM-kill,
# a cancelled CI job escalating past SIGTERM, a hard timeout). A killed run
# leaves its containers -- still *running*, so `--rm` would never fire --
# together with their anonymous volumes and their network, for the life of the
# runner. That accumulation is the harm #2915 reports; it is not a port
# collision, since every port this script binds is picked ephemerally by
# `bind(("127.0.0.1", 0))`.
#
# So reap survivors of an earlier killed run before creating this run's own,
# skipping anything younger than ${reap_min_age_s}. The fleet runs several
# self-hosted runners against one Docker daemon and the names below carry `$$`
# precisely so runs may overlap -- an unguarded sweep would delete a concurrent
# run's containers out from under it. The threshold is deliberately far longer
# than any full run of this script takes.
reap_min_age_s="${APIARY_TEST_REAP_MIN_AGE_S:-3600}"
# `docker inspect` renders a container's .Created as RFC3339, but a network's as
# Go's default layout ("2026-09-04 23:32:36.321 +0200 CEST"), which GNU date
# rejects until the trailing zone abbreviation is dropped. Normalise both.
fixture_created_epoch() {
  local ts
  ts="$(printf '%s' "$1" | sed -E 's/ [A-Z]{2,5}$//')"
  [ -n "${ts}" ] || return 1
  date -u -d "${ts}" +%s 2>/dev/null
}
reap_stale_fixtures() {
  local prefix="$1" now id epoch
  now="$(date -u +%s)"
  for id in $(docker ps -aq --filter "name=^/${prefix}" 2>/dev/null); do
    epoch="$(fixture_created_epoch "$(docker inspect -f '{{.Created}}' "${id}" 2>/dev/null)")" || continue
    [ "$(( now - epoch ))" -ge "${reap_min_age_s}" ] || continue
    docker rm -fv "${id}" >/dev/null 2>&1 || true
  done
  for id in $(docker network ls -q --filter "name=^${prefix}" 2>/dev/null); do
    epoch="$(fixture_created_epoch "$(docker network inspect -f '{{.Created}}' "${id}" 2>/dev/null)")" || continue
    [ "$(( now - epoch ))" -ge "${reap_min_age_s}" ] || continue
    docker network rm "${id}" >/dev/null 2>&1 || true
  done
}
reap_stale_fixtures 'gwtest-'

network="gwtest-$$"
# #3520: every fixture name carries a dotted suffix, and the `$$` is kept as a
# label rather than being the only distinctive part. The whole OIDC login flow
# below is driven through a curl cookie jar, and that is version-sensitive in
# a way the rest of this suite is not: curl 8.22.0 refuses to send a cookie
# whose Netscape-jar domain is a DOTLESS hostname, with its own trace saying
# `cookie 'KC_AUTH_SESSION_HASH' dropped, domain '[file]' must not set cookies
# for 'gwtest-kc-<pid>'`. With a dotless name the jar is populated but never
# replayed, Keycloak's POST /login-actions/authenticate gets no session cookie
# and answers 400, and test #3 fails with the empty `callback=` the run log
# showed -- an auth-path failure that has nothing to do with the assertion.
# Docker's embedded DNS resolves a dotted container name fine (verified), so
# the fix is to name the fixtures with a dot rather than to pin curl back or
# to loosen the assertion.
suffix=".gwtest.local"
pg="gwtest-pg-$$${suffix}"
kc="gwtest-kc-$$${suffix}"
proxy="gwtest-proxy-$$${suffix}"
upstream="gwtest-upstream-$$${suffix}"
proxy_short="gwtest-proxy-short-$$${suffix}"
proxy_logout="gwtest-proxy-logout-$$${suffix}"
proxy_outage="gwtest-proxy-outage-$$${suffix}"
proxy_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
fail=0

cleanup() {
  # -v matters: postgres:18.4-bookworm declares an anonymous VOLUME for
  # /var/lib/postgresql and redis:7-alpine one for /data. Without -v,
  # `docker rm -f` deletes the container but leaves that volume behind,
  # dangling and unnamed, on every run.
  #
  # Four scripts in the quality.yml matrix share this trap and leak six
  # anonymous volumes per full run between them: test-keycloak-realm-import.sh
  # (1 postgres), test-oauth2-proxy-gateway-resilience.sh (1 postgres),
  # test-dashboard-oidc-pkce-totp-login.sh (1 postgres + 1 redis) and
  # test-dashboard-oidc-chaos.sh (1 postgres + 1 redis). All four are fixed
  # together; the 913 dangling volumes (52+ GB) that #2859's disk audit
  # found already on the homeserver came from all four, not from any one of
  # them, and are filed as #2904 for removal.
  docker rm -fv "${proxy}" "${proxy_short}" "${proxy_logout}" "${proxy_outage}" "${upstream}" "${kc}" "${pg}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }

# #982: every other service booted below (Postgres, Keycloak, the dashboard
# binary in the companion scripts) is confirmed ready with a real bounded
# poll before anything depends on it -- this one relied on a bare `sleep 3`
# instead, unlike the rest of this file. A loaded/slow CI runner taking
# longer than 3s to get oauth2-proxy's own HTTP server listening (its own
# OIDC-provider-discovery round trip against Keycloak, not just process
# start) would make test #1 below race a container that isn't actually
# serving yet -- a real, not hypothetical, source of flakiness given how
# CI resource contention actually behaves. /ping is oauth2-proxy's own
# unauthenticated healthcheck path, live as soon as its HTTP server is up.
# $1=container name to poll.
wait_for_proxy_ready() {
  local name="$1"
  for _ in $(seq 1 30); do
    code=$(docker run --rm --network "${network}" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 -s -o /dev/null -w '%{http_code}' "http://${name}:4180/ping" 2>/dev/null || true)
    [ "${code}" = "200" ] && return 0
    sleep 1
  done
  printf 'FAIL: %s never became ready (no 200 from /ping after 30s)\n' "${name}" >&2
  exit 1
}

docker network create "${network}" >/dev/null

docker run -d --name "${pg}" --network "${network}" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=test-only-not-real \
  postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382 >/dev/null
for _ in $(seq 1 30); do docker exec "${pg}" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break; sleep 1; done

docker run -d --name "${kc}" --network "${network}" \
  -e KC_DB=postgres -e KC_DB_URL_HOST="${pg}" -e KC_DB_URL_PORT=5432 -e KC_DB_URL_DATABASE=keycloak \
  -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=test-only-not-real \
  -e "KC_HOSTNAME=http://${kc}:8080" -e KC_HTTP_ENABLED=true -e KC_HEALTH_ENABLED=true \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=test-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=test-only-not-real \
  quay.io/keycloak/keycloak:26.7.1@sha256:f1f1f01e472c8a78df40d8f2a49a925274eda4d3d80d5f6edbb5c880ee3c01c6 \
  start --http-port=8080 >/dev/null

printf 'Waiting for the disposable Keycloak...\n'
for _ in $(seq 1 60); do
  code=$(docker run --rm --network "${network}" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 -s -o /dev/null -w '%{http_code}' "http://${kc}:8080/realms/master" 2>/dev/null || true)
  [ "${code}" = "200" ] && break
  sleep 2
done

admin_token() {
  docker run --rm --network "${network}" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 -s -X POST "http://${kc}:8080/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username=test-admin -d password=test-only-not-real \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"
}
TOKEN="$(admin_token)"

realm_json=$(cat <<EOF
{
  "realm": "gwtest", "enabled": true, "sslRequired": "none",
  "roles": {"client": {"gwtest-client": [{"name": "access"}]}},
  "clients": [{
    "clientId": "gwtest-client", "enabled": true, "publicClient": false,
    "secret": "test-gateway-secret-not-a-real-credential",
    "standardFlowEnabled": true, "implicitFlowEnabled": false,
    "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false,
    "redirectUris": ["http://${proxy}:4180/oauth2/callback", "http://${proxy_short}:4180/oauth2/callback", "http://${proxy_logout}:4180/oauth2/callback", "http://${proxy_outage}:4180/oauth2/callback"], "webOrigins": [],
    "attributes": {"pkce.code.challenge.method": "S256"}
  }],
  "users": [
    {"username": "authorized-user", "enabled": true, "emailVerified": true,
     "firstName": "Authorized", "lastName": "User", "email": "authorized@example.invalid",
     "credentials": [{"type": "password", "value": "TestPass123!", "temporary": false}],
     "clientRoles": {"gwtest-client": ["access"]}},
    {"username": "no-role-user", "enabled": true, "emailVerified": true,
     "firstName": "No", "lastName": "Role", "email": "norole@example.invalid",
     "credentials": [{"type": "password", "value": "TestPass123!", "temporary": false}]}
  ]
}
EOF
)
import_status=$(docker run --rm --network "${network}" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 -s -o /dev/null -w '%{http_code}' \
  -X POST "http://${kc}:8080/admin/realms" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  --data-binary "${realm_json}")
[ "${import_status}" = "201" ] || { printf 'realm import failed: HTTP %s\n' "${import_status}" >&2; exit 1; }

docker run -d --name "${upstream}" --network "${network}" python:3.12-alpine \
  sh -c "echo 'protected content' > /tmp/index.html && cd /tmp && python3 -m http.server 8000" >/dev/null

docker run -d --name "${proxy}" --network "${network}" -p "127.0.0.1:${proxy_port}:4180" \
  -e OAUTH2_PROXY_PROVIDER=keycloak-oidc \
  -e OAUTH2_PROXY_OIDC_ISSUER_URL="http://${kc}:8080/realms/gwtest" \
  -e OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 \
  -e OAUTH2_PROXY_EMAIL_DOMAINS="*" \
  -e OAUTH2_PROXY_CLIENT_ID=gwtest-client \
  -e OAUTH2_PROXY_CLIENT_SECRET=test-gateway-secret-not-a-real-credential \
  -e OAUTH2_PROXY_COOKIE_SECRET="$(openssl rand -base64 32 | tr -- '+/' '-_')" \
  -e OAUTH2_PROXY_REDIRECT_URL="http://${proxy}:4180/oauth2/callback" \
  -e OAUTH2_PROXY_UPSTREAMS="http://${upstream}:8000" \
  -e OAUTH2_PROXY_ALLOWED_ROLES=gwtest-client:access \
  -e OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256 \
  -e OAUTH2_PROXY_COOKIE_SECURE=false \
  -e OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username \
  -e OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true \
  quay.io/oauth2-proxy/oauth2-proxy:v7.15.3@sha256:10a1165743a192e1940b4708fb9647027185ce11a681a1c5519b442ff7f1f561 >/dev/null
wait_for_proxy_ready "${proxy}"

flow_dir="$(mktemp -d)"
# mktemp -d defaults to 0700, owned by the host user. curlimages/curl runs
# as a non-root in-container user that can't otherwise read/write here --
# same root cause as #1040's realm-import fixture. No secrets in this
# directory, only throwaway cookie jars and a driver script.
chmod 777 "${flow_dir}"
trap 'cleanup; rm -rf "${flow_dir}"' EXIT

# --- 1: unauthenticated redirects only to the real Keycloak authorize endpoint ---
auth_location=$(docker run --rm --network "${network}" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 -s -c /tmp/j1 -D - -o /dev/null "http://${proxy}:4180/oauth2/start?rd=/" \
  | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
case "${auth_location}" in
  "http://${kc}:8080/realms/gwtest/protocol/openid-connect/auth?"*"client_id=gwtest-client"*"code_challenge_method=S256"*)
    ok "unauthenticated request redirects to the real Keycloak authorize endpoint with PKCE S256" ;;
  *) bad "unexpected redirect target: ${auth_location}" ;;
esac

# --- 2: forged callback (code/state neither side issued) is rejected ---
forged_status=$(docker run --rm --network "${network}" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 -s -o /dev/null -w '%{http_code}' \
  "http://${proxy}:4180/oauth2/callback?code=totally-fake&state=attacker-forged-state")
if [ "${forged_status}" -ge 400 ]; then
  ok "forged callback (unknown code+state) rejected with HTTP ${forged_status}"
else
  bad "forged callback was NOT rejected: HTTP ${forged_status}"
fi

drive_login() {
  # $1=username $2=password $3=cookie-jar-name -> prints final protected-page status
  local user="$1" pass="$2" jar="$3"
  cat > "${flow_dir}/login.sh" <<SCRIPT
set -e
JAR=/w/${jar}
AUTH_URL=\$(curl -s -c "\${JAR}" -D - -o /dev/null "http://${proxy}:4180/oauth2/start?rd=/" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
LOGIN_PAGE=\$(curl -s -c "\${JAR}" -b "\${JAR}" "\${AUTH_URL}")
FORM_ACTION=\$(echo "\${LOGIN_PAGE}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"\$//' | sed 's/&amp;/\&/g')
CALLBACK=\$(curl -s -c "\${JAR}" -b "\${JAR}" -D - -o /dev/null --data-urlencode "username=${user}" --data-urlencode "password=${pass}" --data-urlencode "credentialId=" "\${FORM_ACTION}" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
curl -s -c "\${JAR}" -b "\${JAR}" -o /dev/null -w '%{http_code} ' "\${CALLBACK}"
curl -s -b "\${JAR}" -o /dev/null -w '%{http_code}' "http://${proxy}:4180/"
SCRIPT
  docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 sh /w/login.sh
}

# --- 3: real login, correct role -> granted ---
read -r callback_status protected_status <<< "$(drive_login authorized-user 'TestPass123!' jar-authorized.txt)"
if [ "${callback_status}" = "302" ] && [ "${protected_status}" = "200" ]; then
  ok "authorized real login: callback 302, protected page 200"
else
  bad "authorized login did not reach the protected page: callback=${callback_status} protected=${protected_status}"
fi

# --- 3b: tampering with the session cookie after a successful login is
# rejected outright, not silently honored -- this is the actual credential
# this gateway relies on (see header comment on why a bearer-token forgery
# test isn't meaningful for this deployment). Target oauth2-proxy's own
# session cookie by name (_oauth2_proxy), not "the first long value found"
# -- curl's Netscape jar format prefixes HttpOnly cookies' domain field
# with "#HttpOnly_", which looks like a comment line but isn't one; a naive
# `startswith("#")` skip silently walks past the real session cookie and
# tampers an unrelated Keycloak-side cookie instead, which of course still
# "passes" since nothing about the actual gateway session changed. ---
tampered_jar="${flow_dir}/jar-tampered.txt"
cp "${flow_dir}/jar-authorized.txt" "${tampered_jar}"
python3 - "${tampered_jar}" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()
out = []
tampered = False
for line in lines:
    raw = line.rstrip("\n")
    unprefixed = raw[len("#HttpOnly_"):] if raw.startswith("#HttpOnly_") else raw
    if not tampered and "\t" in unprefixed:
        parts = unprefixed.split("\t")
        if len(parts) == 7 and parts[5] == "_oauth2_proxy":
            mid = len(parts[6]) // 2
            ch = parts[6][mid]
            flipped = "A" if ch != "A" else "B"
            parts[6] = parts[6][:mid] + flipped + parts[6][mid + 1:]
            prefix = "#HttpOnly_" if raw.startswith("#HttpOnly_") else ""
            line = prefix + "\t".join(parts) + "\n"
            tampered = True
    out.append(line)
if not tampered:
    raise SystemExit("did not find the _oauth2_proxy session cookie to tamper with")
with open(path, "w") as f:
    f.writelines(out)
PYEOF
tampered_status=$(docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 \
  curl -s -o /dev/null -w '%{http_code}' -b "/w/jar-tampered.txt" "http://${proxy}:4180/")
if [ "${tampered_status}" != "200" ]; then
  ok "tampered session cookie rejected (HTTP ${tampered_status}, not 200)"
else
  bad "tampered session cookie was still accepted -- cookie integrity is not actually enforced"
fi

# --- 4: real login, correct password but missing client role -> denied ---
read -r norole_callback_status norole_protected_status <<< "$(drive_login no-role-user 'TestPass123!' jar-norole.txt)"
if [ "${norole_callback_status}" = "403" ] && [ "${norole_protected_status}" = "403" ]; then
  ok "login without the required client role denied (403) despite valid credentials"
else
  bad "role enforcement did not deny: callback=${norole_callback_status} protected=${norole_protected_status}"
fi

# --- 5: the upstream has no network path except through the gateway ---
upstream_ports=$(docker inspect "${upstream}" --format '{{.NetworkSettings.Ports}}')
if [ "${upstream_ports}" = "map[]" ]; then
  ok "protected upstream publishes no host port -- the gateway is the only path to it"
else
  bad "protected upstream has a published port, bypassing the gateway: ${upstream_ports}"
fi

# --- 6: stopping the gateway denies access outright, never falls through ---
docker stop "${proxy}" >/dev/null
outage_curl_exit=0
curl -s -o /dev/null --max-time 3 "http://127.0.0.1:${proxy_port}/" || outage_curl_exit=$?
docker start "${proxy}" >/dev/null
if [ "${outage_curl_exit}" -ne 0 ]; then
  ok "gateway outage: the public port refuses connections outright (curl exit ${outage_curl_exit}), no fallback to the upstream"
else
  bad "request succeeded while the gateway was stopped -- something else is answering"
fi

# --- 7: a session past its own cookie expiry is rejected, not honored.
# Uses a second, dedicated proxy instance with a deliberately short
# OAUTH2_PROXY_COOKIE_EXPIRE (production uses 30m as of #1178 -- see
# vps/docker-compose.yml's x-oidc-gateway anchor) so this check takes
# seconds, not minutes, without touching the main proxy instance's other
# tests above. ---
proxy_short_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
docker run -d --name "${proxy_short}" --network "${network}" -p "127.0.0.1:${proxy_short_port}:4180" \
  -e OAUTH2_PROXY_PROVIDER=keycloak-oidc \
  -e OAUTH2_PROXY_OIDC_ISSUER_URL="http://${kc}:8080/realms/gwtest" \
  -e OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 \
  -e OAUTH2_PROXY_EMAIL_DOMAINS="*" \
  -e OAUTH2_PROXY_CLIENT_ID=gwtest-client \
  -e OAUTH2_PROXY_CLIENT_SECRET=test-gateway-secret-not-a-real-credential \
  -e OAUTH2_PROXY_COOKIE_SECRET="$(openssl rand -base64 32 | tr -- '+/' '-_')" \
  -e OAUTH2_PROXY_REDIRECT_URL="http://${proxy_short}:4180/oauth2/callback" \
  -e OAUTH2_PROXY_UPSTREAMS="http://${upstream}:8000" \
  -e OAUTH2_PROXY_ALLOWED_ROLES=gwtest-client:access \
  -e OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256 \
  -e OAUTH2_PROXY_COOKIE_SECURE=false \
  -e OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username \
  -e OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true \
  -e OAUTH2_PROXY_COOKIE_EXPIRE=3s \
  -e OAUTH2_PROXY_COOKIE_REFRESH=0 \
  quay.io/oauth2-proxy/oauth2-proxy:v7.15.3@sha256:10a1165743a192e1940b4708fb9647027185ce11a681a1c5519b442ff7f1f561 >/dev/null
wait_for_proxy_ready "${proxy_short}"

drive_login_against() {
  # same as drive_login above but targets an arbitrary proxy container name
  local proxy_target="$1" user="$2" pass="$3" jar="$4"
  cat > "${flow_dir}/login-short.sh" <<SCRIPT
set -e
JAR=/w/${jar}
AUTH_URL=\$(curl -s -c "\${JAR}" -D - -o /dev/null "http://${proxy_target}:4180/oauth2/start?rd=/" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
LOGIN_PAGE=\$(curl -s -c "\${JAR}" -b "\${JAR}" "\${AUTH_URL}")
FORM_ACTION=\$(echo "\${LOGIN_PAGE}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"\$//' | sed 's/&amp;/\&/g')
CALLBACK=\$(curl -s -c "\${JAR}" -b "\${JAR}" -D - -o /dev/null --data-urlencode "username=${user}" --data-urlencode "password=${pass}" --data-urlencode "credentialId=" "\${FORM_ACTION}" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
curl -s -c "\${JAR}" -b "\${JAR}" -o /dev/null -w '%{http_code} ' "\${CALLBACK}"
curl -s -b "\${JAR}" -o /dev/null -w '%{http_code}' "http://${proxy_target}:4180/"
SCRIPT
  docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 sh /w/login-short.sh
}
read -r short_callback_status short_protected_status <<< "$(drive_login_against "${proxy_short}" authorized-user 'TestPass123!' jar-shortlived.txt)"
if [ "${short_callback_status}" = "302" ] && [ "${short_protected_status}" = "200" ]; then
  ok "short-lived-session login succeeded before expiry: callback 302, protected page 200"
else
  bad "short-lived-session login did not even succeed before expiry: callback=${short_callback_status} protected=${short_protected_status}"
fi

sleep 5
expired_status=$(docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 \
  curl -s -o /dev/null -w '%{http_code}' -b "/w/jar-shortlived.txt" "http://${proxy_short}:4180/")
docker rm -f "${proxy_short}" >/dev/null 2>&1 || true
if [ "${expired_status}" != "200" ]; then
  ok "session past its own cookie expiry rejected (HTTP ${expired_status}, not 200)"
else
  bad "session past its own cookie expiry was still honored -- expiry is not actually enforced"
fi

# --- 8: #1094 -- /oauth2/sign_out actually revokes the session, not just
# the browser's own cookie. This deployment's real config
# (vps/docker-compose.yml's x-oidc-gateway anchor) sets
# OAUTH2_PROXY_BACKEND_LOGOUT_URL (so sign_out also ends the user's
# Keycloak SSO session, not only this one gateway's cookie) and
# OAUTH2_PROXY_COOKIE_REFRESH=2m (so a revoked/ended session stops working
# again within that window even if a copy of the old cookie is replayed).
# Both settings are reproduced here -- a dedicated short-refresh proxy
# instance, same shape as test #7's short-cookie-expire instance, so this
# runs in seconds instead of the real 2m. The actual assertion that
# matters (see this issue's own wording): a SAVED COPY of the pre-logout
# cookie, replayed after logout + one refresh interval, must NOT still
# grant access -- proving real server-side revocation propagated back to
# the gateway, not merely that the browser's own cookie got cleared (which
# a stolen/replayed cookie would sail straight past).
proxy_logout_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
docker run -d --name "${proxy_logout}" --network "${network}" -p "127.0.0.1:${proxy_logout_port}:4180" \
  -e OAUTH2_PROXY_PROVIDER=keycloak-oidc \
  -e OAUTH2_PROXY_OIDC_ISSUER_URL="http://${kc}:8080/realms/gwtest" \
  -e OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 \
  -e OAUTH2_PROXY_EMAIL_DOMAINS="*" \
  -e OAUTH2_PROXY_CLIENT_ID=gwtest-client \
  -e OAUTH2_PROXY_CLIENT_SECRET=test-gateway-secret-not-a-real-credential \
  -e OAUTH2_PROXY_COOKIE_SECRET="$(openssl rand -base64 32 | tr -- '+/' '-_')" \
  -e OAUTH2_PROXY_REDIRECT_URL="http://${proxy_logout}:4180/oauth2/callback" \
  -e OAUTH2_PROXY_UPSTREAMS="http://${upstream}:8000" \
  -e OAUTH2_PROXY_ALLOWED_ROLES=gwtest-client:access \
  -e OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256 \
  -e OAUTH2_PROXY_COOKIE_SECURE=false \
  -e OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username \
  -e OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true \
  -e OAUTH2_PROXY_COOKIE_REFRESH=5s \
  -e OAUTH2_PROXY_BACKEND_LOGOUT_URL="http://${kc}:8080/realms/gwtest/protocol/openid-connect/logout?id_token_hint={id_token}" \
  quay.io/oauth2-proxy/oauth2-proxy:v7.15.3@sha256:10a1165743a192e1940b4708fb9647027185ce11a681a1c5519b442ff7f1f561 >/dev/null
wait_for_proxy_ready "${proxy_logout}"

read -r logout_callback_status logout_protected_status <<< "$(drive_login_against "${proxy_logout}" authorized-user 'TestPass123!' jar-logout.txt)"
if [ "${logout_callback_status}" != "302" ] || [ "${logout_protected_status}" != "200" ]; then
  bad "logout-scenario login did not even succeed: callback=${logout_callback_status} protected=${logout_protected_status}"
else
  # Copy the still-valid cookie BEFORE sign_out clears it client-side --
  # this copy is what proves (or disproves) real server-side revocation
  # below, independent of whatever the live jar's own cookie does.
  cp "${flow_dir}/jar-logout.txt" "${flow_dir}/jar-logout-presignout.txt"

  # oauth2-proxy v7.15.3 does NOT redirect the browser through the
  # configured OAUTH2_PROXY_BACKEND_LOGOUT_URL -- confirmed live: sign_out's
  # own Location header is just "rd"'s value ("/"), never the Keycloak
  # end-session URL. It calls that URL itself, server-to-server, before
  # responding. That means there's no redirect chain to follow or assert
  # on here -- the only real, non-implementation-specific way to prove the
  # backend logout call actually happened is functionally, below: if it
  # didn't fire, the saved pre-logout cookie's next refresh would still
  # succeed against a live Keycloak session.
  docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 \
    curl -s -o /dev/null -c "/w/jar-logout.txt" -b "/w/jar-logout.txt" "http://${proxy_logout}:4180/oauth2/sign_out?rd=/"

  # Past the 5s refresh interval: oauth2-proxy's next request against the
  # OLD, never-cleared cookie must attempt a refresh, find the underlying
  # Keycloak session/refresh token already ended, and deny access --
  # proving revocation is real, not merely that the browser lost its
  # cookie.
  sleep 8
  old_cookie_status=$(docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 \
    curl -s -o /dev/null -w '%{http_code}' -b "/w/jar-logout-presignout.txt" "http://${proxy_logout}:4180/")
  if [ "${old_cookie_status}" != "200" ]; then
    ok "a saved copy of the pre-logout session cookie no longer grants access after sign_out + one refresh interval (HTTP ${old_cookie_status}) -- real server-side revocation, not just a client-side cookie clear"
  else
    bad "a saved copy of the pre-logout session cookie STILL granted access after sign_out + a refresh interval -- logout is not actually revoking the session server-side"
  fi
fi
docker rm -f "${proxy_logout}" >/dev/null 2>&1 || true

# --- 9: #1094/#1178 -- what actually happens to an active gateway session
# during a live Keycloak network outage. Same short-refresh shape as
# scenario 8, but this time the outage is a real network partition (docker
# network disconnect), not a revoked token.
#
# Investigated, not assumed -- and the real answer is NOT what scenario 8
# might suggest. oauth2-proxy fails CLOSED when Keycloak explicitly
# rejects a refresh (invalid/revoked token: a clear answer it can act on).
# It does NOT fail closed when Keycloak is simply unreachable: a refresh
# attempt that errors at the network level (confirmed live: connection
# refused/timeout, not an OAuth error) is logged and the request proceeds
# on the session's existing cookie-encoded state regardless -- refresh
# failing to reach Keycloak doesn't shorten the cookie's own absolute
# expiry. This is a real, asymmetric gap against the dashboard's own
# native OIDC path (test-dashboard-oidc-chaos.sh scenario 1a), which
# deliberately fails closed with 503 once its 30s re-validation window
# lapses during the exact same kind of outage.
#
# #1178 accepted fail-open as a deliberate tradeoff (oauth2-proxy has no
# confirmed fail-closed-on-network-error knob in v7.15.3) but bounded its
# blast radius: OAUTH2_PROXY_COOKIE_EXPIRE went from 12h to 30m
# (vps/docker-compose.yml's x-oidc-gateway anchor) -- a session established
# right before an outage now rides out at most 30m of it, not up to 12h,
# regardless of whether Keycloak ever comes back. COOKIE_REFRESH (2m)
# silently renews the cookie for any actively-used session while Keycloak
# stays reachable, so this bound never touches normal usage, only the
# outage worst case. Scenario 9a below proves the fail-open window still
# holds (unchanged); 9b proves the new bound actually caps it, using its
# own short-EXPIRE proxy instance so this runs in seconds instead of 30m. ---
proxy_outage_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
docker run -d --name "${proxy_outage}" --network "${network}" -p "127.0.0.1:${proxy_outage_port}:4180" \
  -e OAUTH2_PROXY_PROVIDER=keycloak-oidc \
  -e OAUTH2_PROXY_OIDC_ISSUER_URL="http://${kc}:8080/realms/gwtest" \
  -e OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 \
  -e OAUTH2_PROXY_EMAIL_DOMAINS="*" \
  -e OAUTH2_PROXY_CLIENT_ID=gwtest-client \
  -e OAUTH2_PROXY_CLIENT_SECRET=test-gateway-secret-not-a-real-credential \
  -e OAUTH2_PROXY_COOKIE_SECRET="$(openssl rand -base64 32 | tr -- '+/' '-_')" \
  -e OAUTH2_PROXY_REDIRECT_URL="http://${proxy_outage}:4180/oauth2/callback" \
  -e OAUTH2_PROXY_UPSTREAMS="http://${upstream}:8000" \
  -e OAUTH2_PROXY_ALLOWED_ROLES=gwtest-client:access \
  -e OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256 \
  -e OAUTH2_PROXY_COOKIE_SECURE=false \
  -e OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username \
  -e OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true \
  -e OAUTH2_PROXY_COOKIE_REFRESH=5s \
  -e OAUTH2_PROXY_COOKIE_EXPIRE=45s \
  quay.io/oauth2-proxy/oauth2-proxy:v7.15.3@sha256:10a1165743a192e1940b4708fb9647027185ce11a681a1c5519b442ff7f1f561 >/dev/null
wait_for_proxy_ready "${proxy_outage}"

read -r outage_login_callback outage_login_protected <<< "$(drive_login_against "${proxy_outage}" authorized-user 'TestPass123!' jar-outage.txt)"
outage_login_epoch=$(date +%s)
if [ "${outage_login_callback}" != "302" ] || [ "${outage_login_protected}" != "200" ]; then
  bad "outage-scenario login did not even succeed: callback=${outage_login_callback} protected=${outage_login_protected}"
else
  # 9a: immediately after the outage starts, well inside the 5s refresh
  # interval: the session should still be served from the still-valid
  # local cookie state, no Keycloak round trip needed yet.
  docker network disconnect "${network}" "${kc}" >/dev/null
  immediate_outage_status=$(docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 \
    curl -s -o /dev/null -w '%{http_code}' -b "/w/jar-outage.txt" "http://${proxy_outage}:4180/")
  if [ "${immediate_outage_status}" = "200" ]; then
    ok "protected page still served immediately after Keycloak becomes unreachable (within the refresh grace window)"
  else
    bad "protected page failed immediately after Keycloak became unreachable, expected the refresh grace window to hold: got ${immediate_outage_status}"
  fi

  # 9a continued: past the 5s refresh interval (but still well inside the
  # 45s COOKIE_EXPIRE this proxy instance uses), the next request must
  # attempt a refresh against the now-unreachable Keycloak, fail, and
  # STILL be granted -- the fail-open behavior #1178 accepted as a
  # tradeoff, confirmed still holding within the cookie's own lifetime.
  # Sleep to an absolute deadline measured from login, not a flat
  # duration stacked on top of whatever the login/disconnect/curl round
  # trips above already cost -- on a loaded runner those alone can eat
  # several seconds, and a flat "sleep 8" here previously let that drift
  # push the check past a too-tight COOKIE_EXPIRE and fail spuriously.
  past_refresh_target=$((outage_login_epoch + 15))
  past_refresh_remaining=$((past_refresh_target - $(date +%s)))
  [ "${past_refresh_remaining}" -gt 0 ] && sleep "${past_refresh_remaining}"
  past_refresh_status=$(docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 \
    curl -s -o /dev/null -w '%{http_code}' -b "/w/jar-outage.txt" "http://${proxy_outage}:4180/")
  if [ "${past_refresh_status}" = "200" ]; then
    ok "confirmed: the gateway pattern still fails OPEN through a Keycloak network outage past its refresh interval, within the cookie's own lifetime (HTTP 200) -- a failed refresh attempt does not invalidate the still-cookie-valid session (see comment above; #1178 accepted this as a tradeoff and bounded it instead, proven in 9b below)"
  else
    bad "expected the gateway to fail open (200) during a network-level Keycloak outage while still within COOKIE_EXPIRE -- got ${past_refresh_status} instead; if this gateway's behavior genuinely changed, update #1178 and this comment together"
  fi

  # 9b: #1178's actual fix -- past this instance's 45s COOKIE_EXPIRE (still
  # mid-outage, kc still disconnected), the cookie's own absolute lifetime
  # has now lapsed regardless of the refresh cadence. This is the bound
  # that replaced production's old 12h exposure with 30m: the session must
  # now be denied, proving the new OAUTH2_PROXY_COOKIE_EXPIRE setting
  # actually caps the fail-open window rather than just being configured
  # and never verified. Same absolute-deadline approach as 9a above.
  past_expire_target=$((outage_login_epoch + 50))
  past_expire_remaining=$((past_expire_target - $(date +%s)))
  [ "${past_expire_remaining}" -gt 0 ] && sleep "${past_expire_remaining}"
  past_expire_status=$(docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 \
    curl -s -o /dev/null -w '%{http_code}' -b "/w/jar-outage.txt" "http://${proxy_outage}:4180/")
  docker network connect "${network}" "${kc}" >/dev/null
  if [ "${past_expire_status}" != "200" ]; then
    ok "confirmed: once COOKIE_EXPIRE itself lapses, the session is denied (HTTP ${past_expire_status}) even mid-outage -- #1178's bound actually caps the fail-open window, not just configured on paper"
  else
    bad "session STILL granted access past its own COOKIE_EXPIRE during a Keycloak outage -- #1178's fix is not actually bounding the fail-open window"
  fi
fi
docker rm -f "${proxy_outage}" >/dev/null 2>&1 || true

if [ "${fail}" -ne 0 ]; then
  printf '\nFAIL: one or more gateway-resilience assertions failed\n' >&2
  exit 1
fi
printf '\nPASS: all gateway-resilience assertions held\n'
