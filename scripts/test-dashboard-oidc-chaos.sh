#!/usr/bin/env bash
# test-dashboard-oidc-chaos.sh — #1661: the dashboard-next port of the retired
# Go-tier Keycloak-outage / key-rotation chaos suite (#982/#1502/#1659).
#
# Shared infrastructure and login driver live duplicated in
# scripts/test-dashboard-oidc-pkce-totp-login.sh rather than sourced: each
# script stands alone so CI failures are attributable, exactly like the two
# retired suites were separate files.
#
# Scenarios (the retirement of the Go tier left these gaps; see #1661):
#   A   Keycloak outage never invalidates an established BFF session:
#       sessions resolve from redis alone -- there is deliberately NO
#       per-request introspection or token refresh against the IdP (the
#       documented divergence in "Claims and sessions",
#       docs/KEYCLOAK-CUTOVER.md), so the working browser must keep serving
#       while the realm is dark.
#   A'  Logging out DURING an outage still tears down the local session --
#       #1094's property cannot become unavailable just because the provider
#       is unreachable: redis deletion happens locally, and the response
#       falls back to /auth/login instead of hanging or erroring out.
#   B   Graceful Keycloak restart: existing infrastructure comes back and a
#       brand-new password+TOTP login succeeds -- no stale state anywhere in
#       the BFF pins the recovered provider.
#   C   Realm signing-key rotation: a new higher-priority RSA provider makes
#       Keycloak sign fresh tokens with a key the BFF has never seen; the next
#       login MUST succeed, proving the JWKS machinery re-fetches keys instead
#       of trusting a startup-time cache.
#   D   (documented divergence, asserted nowhere here): the Go tier expected
#       tokens to be force-invalidated via remote introspection revocation and
#       users force-relogged during outages. This stack intentionally inverts
#       that -- availability over immediacy -- so scenario A asserts the
#       INVERSE of the old suite. See docs/KEYCLOAK-CUTOVER.md, and #1661 for
#       the mapping table.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
realm_file="${repo_root}/arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json"

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
reap_stale_fixtures 'dashkcchaos-'

network="dashkcchaos-$$"
pg="dashkcchaos-pg-$$"
kc="dashkcchaos-kc-$$"
redis="dashkcchaos-redis-$$"
kc_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
dash_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
redis_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
app_base="http://localhost:${dash_port}"
fail=0
bff_pid=""
sid=""
jar="$(mktemp)"

# Enrolled at prereq, reused by restart/key-rotation replays; see
# complete_totp_enrollment for how it crosses the $() boundary.
totp_secret=""
ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }

cleanup() {
  # Same post-mortem aids as the login suite: bff.log speaks for /auth/login
  # failures, DEBUG_KEEP=1 preserves the flow captures for page forensics.
  if [ "${DEBUG_BFF_LOG:-0}" = "1" ] && [ -n "${state_dir:-}" ] && [ -f "${state_dir}/bff.log" ]; then
    printf -- '-- bff.log --\n' >&2
    cat "${state_dir}/bff.log" >&2
  fi
  [ -n "${bff_pid}" ] && kill "${bff_pid}" >/dev/null 2>&1 || true
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
  docker rm -fv "${redis}" "${kc}" "${pg}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  if [ "${DEBUG_KEEP:-0}" = "1" ]; then
    printf '(DEBUG_KEEP=1: kept %s and %s)\n' "${flow_dir:-}" "${state_dir:-}" >&2
    return 0
  fi
  rm -rf "${flow_dir:-}" "${rendered_realm:-}" "${state_dir:-}" "${jar}"
}
trap cleanup EXIT

command -v docker >/dev/null || { printf 'docker is required\n' >&2; exit 1; }
command -v node >/dev/null || { printf 'node >= 20 is required to build frontend-next\n' >&2; exit 1; }
node_major=$(node -p 'process.versions.node.split(".")[0]')
[ "${node_major}" -ge 20 ] || { printf 'node >= 20 required, got %s (vite/nitro need util.styleText)\n' "$(node --version)" >&2; exit 1; }
curl_ver=$(curl --version | head -1 | awk '{print $4}')
if [ "$(printf '%s\n7.87.0\n' "${curl_ver}" | sort -V | head -1)" != "7.87.0" ]; then
  printf 'curl >= 7.87 required (%s found): Secure cookies are only sent over http://localhost since 7.87\n' "${curl_ver}" >&2
  exit 1
fi

docker network create "${network}" >/dev/null

docker run -d --name "${pg}" --network "${network}" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=test-only-not-real \
  postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382 >/dev/null
for _ in $(seq 1 30); do docker exec "${pg}" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break; sleep 1; done

rendered_realm="$(mktemp)"
sed -E "s|https://honeypot\\.example\\.invalid|http://localhost:${dash_port}|g" \
  "${realm_file}" > "${rendered_realm}"
chmod 644 "${rendered_realm}"

docker run -d --name "${kc}" --network "${network}" -p "127.0.0.1:${kc_port}:8080" \
  -e KC_DB=postgres -e KC_DB_URL_HOST="${pg}" -e KC_DB_URL_PORT=5432 -e KC_DB_URL_DATABASE=keycloak \
  -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=test-only-not-real \
  -e "KC_HOSTNAME=http://127.0.0.1:${kc_port}" -e KC_HTTP_ENABLED=true -e KC_HEALTH_ENABLED=true \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=test-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=test-only-not-real \
  -v "${rendered_realm}:/opt/keycloak/data/import/apiary-realm.json:ro" \
  quay.io/keycloak/keycloak:26.7.1@sha256:f1f1f01e472c8a78df40d8f2a49a925274eda4d3d80d5f6edbb5c880ee3c01c6 \
  start --http-port=8080 --import-realm >/dev/null

printf 'Waiting for the disposable Keycloak + realm import (up to 240s)...\n'
for i in $(seq 1 240); do
  docker logs "${kc}" 2>&1 | grep -q "KC-SERVICES0032: Import finished successfully" && break
  if docker logs "${kc}" 2>&1 | grep -q "ERROR: Failed to start server"; then
    printf 'FAIL: realm import crashed the server\n' >&2
    docker logs "${kc}" 2>&1 | tail -60 >&2
    exit 1
  fi
  [ "$i" -eq 240 ] && { printf 'FAIL: timed out waiting for import\n' >&2; exit 1; }
  sleep 1
done

docker run -d --name "${redis}" --network "${network}" -p "127.0.0.1:${redis_port}:6379" \
  redis:7-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499 >/dev/null
for _ in $(seq 1 30); do docker exec "${redis}" redis-cli ping >/dev/null 2>&1 && break; sleep 1; done

kcadm() { docker exec "${kc}" /opt/keycloak/bin/kcadm.sh "$@"; }
kcadm config credentials --server http://localhost:8080 --realm master \
  --user test-admin --password test-only-not-real >/dev/null

client_id=$(kcadm get clients -r apiary -q clientId=apiary-dashboard --fields id --format csv --noquotes | tail -1)
client_secret=$(kcadm get "clients/${client_id}/client-secret" -r apiary --fields value --format csv --noquotes | tail -1)

kcadm create users -r apiary -s username=chaos-totp-test -s enabled=true -s emailVerified=true >/dev/null
kcadm set-password -r apiary --username chaos-totp-test --new-password 'ChaosTotpTest9!Extra' >/dev/null
kcadm add-roles -r apiary --uusername chaos-totp-test --cclientid apiary-dashboard --rolename access >/dev/null

flow_dir="$(mktemp -d)"
chmod 777 "${flow_dir}"

cat > "${flow_dir}/totp.py" <<'PY'
import base64, hashlib, hmac, struct, sys, time
def totp(secret_b32, digest=hashlib.sha256, digits=6, period=30, t=None):
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int((t if t is not None else time.time()) // period)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, digest).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)
if __name__ == "__main__":
    print(totp(sys.argv[1]))
PY

# ── login driver (kept byte-compatible with the login suite) ──────────────
submit_totp_with_retry() {
  local jar="$1" action="$2" field="$3" success_substr="$4"
  shift 4
  local result="" attempt code into_period hdr_file body_file new_action accepted
  hdr_file="$(mktemp)"
  body_file="$(mktemp)"
  rm -f "${flow_dir}/totp-next-body.html"
  for attempt in 1 2 3 4 5; do
    into_period=$(python3 -c 'import time; print(int(time.time()) % 30)')
    [ "${into_period}" -gt 10 ] && sleep "$((30 - into_period + 1))"
    code=$(python3 "${flow_dir}/totp.py" "${totp_secret}")
    curl -s -c "${jar}" -b "${jar}" -D "${hdr_file}" -o "${body_file}" --data-urlencode "${field}=${code}" "$@" "${action}"
    result=$(grep -i '^location:' "${hdr_file}" | tail -1 | sed 's/^[Ll]ocation: //' | tr -d '\r' || true)
    accepted=false
    case "${result}" in *"${success_substr}"*) accepted=true ;; esac
    if [ "${accepted}" != true ] && [ -z "${result}" ] && ! grep -q "name=\"${field}\"" "${body_file}"; then
      accepted=true
      cp "${body_file}" "${flow_dir}/totp-next-body.html"
    fi
    [ "${accepted}" = true ] && break
    printf '    (TOTP submit attempt %d rejected, retrying after brute-force cooldown)\n' "${attempt}" >&2
    result=""
    new_action=$(grep -o 'action="[^"]*"' "${body_file}" | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
    [ -n "${new_action}" ] && action="${new_action}"
    sleep 65
  done
  rm -f "${hdr_file}" "${body_file}"
  echo "${result}"
}

complete_totp_enrollment() {
  local jar="$1" totp_page="$2" success_substr="$3"
  local manual_link manual_page form_action secret_field
  manual_link=$(echo "${totp_page}" | grep -o 'href="[^"]*mode=manual[^"]*"' | head -1 | sed 's/^href="//;s/"$//' | sed 's/&amp;/\&/g')
  if [ -z "${manual_link}" ]; then
    printf 'FAIL: no "Unable to scan?" manual-mode link on the CONFIGURE_TOTP page\n' >&2
    echo "${totp_page}" >&2
    exit 1
  fi
  manual_page=$(curl -s -c "${jar}" -b "${jar}" "${manual_link}")
  totp_secret=$(echo "${manual_page}" | grep -oE '[A-Z2-7]{4}( [A-Z2-7]{4}){7}' | head -1 | tr -d ' ')
  if [ -z "${totp_secret}" ]; then
    printf 'FAIL: no TOTP secret on the manual-mode CONFIGURE_TOTP page\n' >&2
    echo "${manual_page}" >&2
    exit 1
  fi
  # This function runs inside a $(dashboard_login_flow ...) command
  # substitution -- assignments do NOT survive back into the parent shell.
  # The restart/key-rotation replays log this account back in from THEIR OWN
  # subshells afterwards, so hand the secret over through flow_dir.
  printf '%s' "${totp_secret}" > "${flow_dir}/totp-secret-current.txt"
  form_action=$(echo "${manual_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
  secret_field=$(echo "${manual_page}" | grep -o 'id="totpSecret"[^>]*value="[^"]*"' | head -1 | grep -o 'value="[^"]*"' | sed 's/value="//;s/"$//')
  _totp_enroll_callback=$(submit_totp_with_retry "${jar}" "${form_action}" totp "${success_substr}" --data-urlencode "totpSecret=${secret_field}" --data-urlencode "userLabel=")
  _totp_enroll_next_body=""
  if [ -f "${flow_dir}/totp-next-body.html" ]; then
    _totp_enroll_next_body="$(cat "${flow_dir}/totp-next-body.html")"
    rm -f "${flow_dir}/totp-next-body.html"
  fi
  _totp_enroll_ok=""
  { [ -n "${_totp_enroll_callback}" ] || [ -n "${_totp_enroll_next_body}" ]; } && _totp_enroll_ok=true
}

# Terminal-callback-aware chain follower (login-suite twin has the long
# story): no blind -L, so a login-completing /auth/callback redirect is
# detected instead of dissolved into app-shell HTML. Sets _chain_cb to that
# location when authentication finished -- via global, never stdout, because
# $() callers would read a page body as the callback. Bodies land in
# chain-last.html, NUL-stripped on load by callers.
follow_auth_chain() {
  local __jar="$1" __url="$2"; shift 2
  local __hdr __hop __loc
  # Payload flags ride here as an array: visible size keeps them on
  # hop 1 only (cleared right below), and expansion stays word-safe.
  local __args=("$@")
  __hdr=$(mktemp)
  rm -f "${flow_dir}/chain-last.html"
  _chain_cb=""
  for __hop in 1 2 3 4 5 6 7 8; do
    # $@ rides hop 1 ONLY -- replaying payloads onto redirect GETs would
    # corrupt Keycloak's required-action endpoints.
    if [ "${#__args[@]}" -gt 0 ]; then
      # DEBUG_TRACE captures the wire-level bytes of payload-bearing hops
      # (test-only literal credentials; files stay inside flow_dir).
      if [ "${DEBUG_TRACE:-0}" = "1" ]; then
        curl -s --trace-ascii "${flow_dir}/post-trace-${__hop}.txt" \
          -c "${__jar}" -b "${__jar}" -D "${__hdr}" -o "${flow_dir}/chain-body.raw" "${__args[@]}" "${__url}"
      else
        curl -s -c "${__jar}" -b "${__jar}" -D "${__hdr}" -o "${flow_dir}/chain-body.raw" "${__args[@]}" "${__url}"
      fi
      __args=()
    else
      curl -s -c "${__jar}" -b "${__jar}" -D "${__hdr}" -o "${flow_dir}/chain-body.raw" "${__url}"
    fi
    if [ "${DEBUG_TRACE:-0}" = "1" ]; then
      # Post-mortem hop log: request target (origin only), payload KEYS
      # never values, and the response status/location of this hop.
      {
        printf 'hop %s %s\n' "${__hop}" "${__url}"
        for __a in "${__args[@]}"; do
          case "${__a}" in --data-urlencode*=*) printf 'payload key: %s\n' "${__a#--data-urlencode}" ;; esac
        done
        grep -iE "^(HTTP/|location:)" "${__hdr}" | tr -d '\r'
      } >> "${flow_dir}/chain-trace.log"
    fi
    __loc=$(grep -i '^location:' "${__hdr}" | tail -1 | sed 's/^[Ll]ocation: //' | tr -d '\r')
    # Snapshot every hop's body (NUL-stripped): callers read
    # chain-last.html for form scraping, however the loop ends --
    # including the plain 200-page exit via break below.
    tr -d '\000' < "${flow_dir}/chain-body.raw" > "${flow_dir}/chain-last.html"
    case "${__loc}" in
      "") break ;;
      "${app_base}/auth/callback"?*)
        rm -f "${__hdr}"
        # Reported through this global -- never stdout: callers would read a
        # login-page body here otherwise and mistake it for the callback.
        _chain_cb="${__loc}"
        return 0 ;;
      *) __url="${__loc}" ;;
    esac
  done
  rm -f "${__hdr}"
  return 0
}

dashboard_login_flow() {
  local jar="$1" username="$2" password="$3" step page form_action otp_action sel_cred
  local cb_url="#none"
  local auth_location
  auth_location=$(curl -s -c "${jar}" -D - -o /dev/null "${app_base}/auth/login" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
  follow_auth_chain "${jar}" "${auth_location}"
  [ -n "${_chain_cb}" ] && { echo "${_chain_cb}"; return 0; }
  page=$(tr -d '\000' < "${flow_dir}/chain-last.html")
  form_action=$(echo "${page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
  follow_auth_chain "${jar}" "${form_action}" \
    --data-urlencode "username=${username}" \
    --data-urlencode "password=${password}" \
    --data-urlencode "credentialId="
  [ -n "${_chain_cb}" ] && { echo "${_chain_cb}"; return 0; }
  page=$(tr -d '\000' < "${flow_dir}/chain-last.html")

  for step in 1 2 3 4 5 6; do
    otp_action=$(echo "${page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
    if grep -q 'name="otp"' <<<"${page}" && [ -n "${otp_action}" ]; then
      sel_cred=$(echo "${page}" | grep -o 'id="selectedCredentialId"[^>]*value="[^"]*"' | head -1 | grep -o 'value="[^"]*"' | sed 's/value="//;s/"$//')
      cb_url=$(submit_totp_with_retry "${jar}" "${otp_action}" otp "${app_base}/auth/callback" --data-urlencode "selectedCredentialId=${sel_cred}")
      echo "${cb_url}"
      return 0
    fi
    if grep -qi 'mode=manual' <<<"${page}"; then
      complete_totp_enrollment "${jar}" "${page}" "${app_base}/auth/callback"
      if [ -z "${_totp_enroll_ok}" ]; then
        printf '    (CONFIGURE_TOTP rejected across all retries for %s)\n' "${username}" >&2
        echo ""
        return 1
      fi
      if [ -n "${_totp_enroll_callback}" ]; then
        case "${_totp_enroll_callback}" in
          # Acceptance can close the whole SSO login (see login-suite twin):
          # the finished /auth/callback?code=... redirect means the BFF
          # already exchanged it -- echo it as this flow's result.
          "${app_base}/auth/callback"?*)
            echo "${_totp_enroll_callback}"
            return 0 ;;
          *)
            page=$(curl -sL -c "${jar}" -b "${jar}" "${_totp_enroll_callback}") ;;
        esac
      else
        page="${_totp_enroll_next_body}"
      fi
      continue
    fi
    printf '    (unexpected required-action page at step %d for %s: %s)\n' "${step}" "${username}" "$(echo "${page}" | head -c 160)" >&2
    echo ""
    return 1
  done
  echo ""
  return 1
}

# Same #HttpOnly_ handling as the login-suite twin: the session cookie is
# Secure+HttpOnly and curl writes it behind that prefix.
jar_cookie_value() {
  sed 's/^#HttpOnly_//' "$2" | awk '!/^#/ && $6 == "'"$1"'" {print $7}' | tail -1
}

# Readiness probe: the realm's OIDC discovery document, not /health/ready --
# Keycloak 26 serves health on a separate management port we do not publish,
# while discovery exercises exactly what this suite needs back after a
# restart: HTTP listener up, database session live, apiary realm loadable.
wait_kc_ready() {
  local i code
  for i in $(seq 1 120); do
    code=$(curl -s -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:${kc_port}/realms/apiary/.well-known/openid-configuration" 2>/dev/null || true)
    [ "${code}" = "200" ] && return 0
    sleep 1
  done
  return 1
}

session_doc_exists() {
  local exists
  exists=$(docker exec "${redis}" redis-cli EXISTS "bff:session:${sid}")
  [ "${exists}" = "1" ]
}

# ═══ Build + boot ══════════════════════════════════════════════════════════
dist_js="${repo_root}/arcane/home/honeypot-dashboard/frontend-next/.output/server/index.mjs"
if [ "${DASHBOARD_BFF_SKIP_BUILD:-0}" = "1" ] && [ -f "${dist_js}" ]; then
  printf 'Reusing prebuilt .output/server/index.mjs (DASHBOARD_BFF_SKIP_BUILD=1)\n'
else
  build_log="${flow_dir}/build.log"
  printf 'Building frontend-next (npm ci + npm run build)...\\n'
  (
    cd "${repo_root}/arcane/home/honeypot-dashboard/frontend-next"
    npm ci --no-audit --no-fund
    npm run build
  ) > "${build_log}" 2>&1 || { printf 'FAIL: BFF build failed -- tail of log follows\n' >&2; tail -40 "${build_log}" >&2; exit 1; }
fi
[ -f "${dist_js}" ] || { printf 'FAIL: build produced no .output/server/index.mjs\n' >&2; exit 1; }

state_dir="$(mktemp -d)"
# Throwaway token so the #2183 boot gate lets the server up with enforcement
# ON -- the chaos scenarios rotate what Keycloak knows, never this tier.
service_token='chaos-suite-local-token-not-a-secret'
# Plain-http Keycloak issuer: openid-client needs the explicit opt-in the
# OIDC_ALLOW_INSECURE seam provides (see src/lib/oidc.server.ts).
oidc_allow_insecure='1'
(
  cd "${repo_root}/arcane/home/honeypot-dashboard/frontend-next"
  PORT="${dash_port}" HOST=127.0.0.1 \
  SERVICE_TOKEN=${service_token} \
  OIDC_ALLOW_INSECURE=${oidc_allow_insecure} \
  OIDC_ISSUER_URL="http://127.0.0.1:${kc_port}/realms/apiary" \
  OIDC_EXTERNAL_URL="${app_base}" \
  OIDC_CLIENT_ID="apiary-dashboard" \
  OIDC_CLIENT_SECRET=${client_secret} \
  OIDC_SESSION_REDIS_URL="redis://127.0.0.1:${redis_port}/0" \
  node .output/server/index.mjs > "${state_dir}/bff.log" 2>&1 &
  echo $! > "${state_dir}/bff.pid"
)
sleep 2
bff_pid=$(cat "${state_dir}/bff.pid")
bff_up=0
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${dash_port}/healthz" 2>/dev/null || true)
  [ "${code}" = "200" ] && { bff_up=1; break; }
  sleep 1
done
[ "${bff_up}" = 1 ] || { printf 'FAIL: BFF never came up\n' >&2; cat "${state_dir}/bff.log" >&2; exit 1; }

# ═══ Prerequisite: establish ONE real enrolled+authenticated session ═══════
cb_url=$(dashboard_login_flow "${jar}" chaos-totp-test 'ChaosTotpTest9!Extra') || true
case "${cb_url}" in
  "${app_base}/auth/callback"?*) ok "prerequisite real PKCE+TOTP login succeeded" ;;
  *) bad "prerequisite login failed -- cannot run chaos scenarios"; printf '\nFAIL\n' >&2; exit 1 ;;
esac
curl -s -o /dev/null -w '' -c "${jar}" -b "${jar}" "${cb_url}"
prot=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar}" "${app_base}/")
[ "${prot}" = "200" ] || { bad "prerequisite session not granted (HTTP ${prot})"; printf '\nFAIL\n' >&2; exit 1; }
sid=$(jar_cookie_value '__Host-apiary_bff' "${jar}")
cp "${jar}" "${flow_dir}/jar-prereq.txt"

# dashboard_login_flow ran in a $() subshell above: its globals died there.
# The enrollment left the secret in flow_dir though -- reload it so later
# replays can compute valid codes for the already-enrolled account again.
if [ -f "${flow_dir}/totp-secret-current.txt" ]; then
  totp_secret="$(cat "${flow_dir}/totp-secret-current.txt")"
fi

# ═══ Scenario A: realm outage must NOT invalidate local sessions ═══════════
docker stop -t 10 "${kc}" >/dev/null
printf 'Keycloak stopped.\n'
sleep 2
prot=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar}" "${app_base}/")
health=$(curl -s -o /dev/null -w '%{http_code}' "${app_base}/healthz")
if [ "${prot}" = "200" ] && [ "${health}" = "200" ]; then
  ok "scenario A: with the realm completely dark, the established session still serves (HTTP ${prot}) and the BFF stays healthy -- availability-over-introspection divergence holds"
else
  bad "scenario A: protected=${prot} healthz=${health} while realm down (old Go tier would demand relogin; this stack must keep serving)"
fi
if session_doc_exists; then
  ok "scenario A: redis session document untouched by the outage"
else
  bad "scenario A: session document vanished while the realm was merely down"
fi

# ═══ Scenario A': logout works even with the provider unreachable ══════════
# #3153: cross-origin logout must still 403 (and leave the session alone)
# even with the realm down -- the same-origin gate is a local check, not an
# IdP round-trip, so provider outage is no excuse for it to fail open.
forged_logout_status=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar}" -H "Origin: http://evil.example" "${app_base}/auth/logout" || true)
forged_still_in_redis=$(docker exec "${redis}" redis-cli EXISTS "bff:session:${sid}")
if [ "${forged_logout_status}" = "403" ] && [ "${forged_still_in_redis}" = "1" ]; then
  ok "scenario A': cross-origin /auth/logout (Origin: evil.example) is rejected with 403 and leaves the session in redis, realm still down (#3153)"
else
  bad "scenario A': cross-origin logout was not blocked as expected: status=${forged_logout_status} redis EXISTS=${forged_still_in_redis}"
fi

logout_headers=$(curl -s -D - -o /dev/null -c "${jar}" -b "${jar}" -H "Origin: ${app_base}" "${app_base}/auth/logout" || true)
logout_status=$(echo "${logout_headers}" | head -1 | awk '{print $2}')
logout_location=$(echo "${logout_headers}" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
case "${logout_location}" in
  *"openid-connect/logout"*|*/auth/login*)
    ok "scenario A': logout responded (${logout_status}) with a sane redirect even though the IdP is unreachable (end_session attempted, /auth/login fallback)" ;;
  *)
    bad "scenario A': unexpected logout behavior with realm down: status='${logout_status}' location='${logout_location}'" ;;
esac
saved_status=$(curl -s -o /dev/null -w '%{http_code}' -b "${flow_dir}/jar-prereq.txt" "${app_base}/")
gone=$(docker exec "${redis}" redis-cli EXISTS "bff:session:${sid}")
if [ "${saved_status}" != "200" ] && [ "${gone}" = "0" ]; then
  ok "scenario A': local revocation really happened while dark -- saved-cookie copy now fails and the redis document is gone (#1094 property survives provider outage)"
else
  bad "scenario A': logout did not tear down the local session: saved-cookie GET=${saved_status}, redis EXISTS=${gone}"
fi

# ═══ Scenario B: graceful Keycloak restart, then a fresh login ═════════════
docker start "${kc}" >/dev/null
printf 'Keycloak restarting...\n'
if wait_kc_ready; then
  ok "scenario B: Keycloak came back healthy against its persistent store"
else
  bad "scenario B: Keycloak failed to become ready within 120s after restart"
fi
jar_b="${flow_dir}/jar-b.txt"
cb_b=$(dashboard_login_flow "${jar_b}" chaos-totp-test 'ChaosTotpTest9!Extra') || true
case "${cb_b}" in
  "${app_base}/auth/callback"?*)
    curl -s -o /dev/null -c "${jar_b}" -b "${jar_b}" "${cb_b}"
    prot=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar_b}" "${app_base}/")
    [ "${prot}" = "200" ] && ok "scenario B: brand-new PKCE+TOTP login through the restarted realm grants a session" \
      || bad "scenario B: login callback exchanged but protected page returned HTTP ${prot}"
    ;;
  *) bad "scenario B: fresh login after graceful restart failed: $(printf '%s' "${cb_b}" | sed -E 's/([?&]code=)[^&]*/\1REDACTED/')" ;;
esac

# ═══ Scenario C: realm signing-key rotation ════════════════════════════════
# Add a NEW RS256 provider with priority above everything built-in: Keycloak
# starts signing fresh tokens with a key this BFF instance has never seen.
# Startup-time-JWKS-cached implementations mint invalid-token rejections here;
# a correct jwksUri fetch-on-unknown-kid implementation sails through.
kcadmin_err=""
# providerId=rsa-generated: Keycloak mints its own keypair, so nothing key-
# shaped needs posting (the bare 'rsa' provider would demand an imported
# 'Private RSA Key'). Priority 200 out-prioritizes every built-in/imported
# key, making it the active signer -- i.e. a brand-new kid nobody cached.
if ! kcadm create components -r apiary \
    -s name=chaos-rotation-rsa \
    -s providerId=rsa-generated \
    -s providerType=org.keycloak.keys.KeyProvider \
    -s 'config.priority=["200"]' \
    -s 'config.enabled=["true"]' >/dev/null 2>"${flow_dir}/kcadm.err"; then
  kcadmin_err=$(cat "${flow_dir}/kcadm.err")
fi
if [ -n "${kcadmin_err}" ]; then
  bad "scenario C: could not add rotation RSA provider: $(echo "${kcadmin_err}" | head -2)"
else
  jar_c="${flow_dir}/jar-c.txt"
  cb_c=$(dashboard_login_flow "${jar_c}" chaos-totp-test 'ChaosTotpTest9!Extra') || true
  case "${cb_c}" in
    "${app_base}/auth/callback"?*)
      curl -s -o /dev/null -c "${jar_c}" -b "${jar_c}" "${cb_c}"
      prot=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar_c}" "${app_base}/")
      sid_c=$(jar_cookie_value '__Host-apiary_bff' "${jar_c}")
      doc_role=$(docker exec "${redis}" redis-cli --raw GET "bff:session:${sid_c}" 2>/dev/null | python3 -c 'import json,sys
try: print(json.loads(sys.stdin.read()).get("role",""))
except Exception: print("")' || true)
      if [ "${prot}" = "200" ] && [ "${doc_role}" = "user" ]; then
        ok "scenario C: fresh login under ROTATED signing keys validated and persisted a correct 'user' session -- JWKS cache refreshed on unknown kid"
      else
        bad "scenario C: rotated-key login broken: protected=${prot} role='${doc_role}'"
      fi
      ;;
    *) bad "scenario C: fresh login under rotated signing keys failed: $(printf '%s' "${cb_c}" | sed -E 's/([?&]code=)[^&]*/\1REDACTED/')" ;;
  esac
fi

if [ "${fail}" -ne 0 ]; then
  printf '\nFAIL: one or more Keycloak chaos-scenario assertions failed\n' >&2
  exit 1
fi
printf '\nPASS: BFF held its sessions, logout, restart recovery, and key rotation across a real Keycloak outage/restart/rotation cycle\n'
