#!/usr/bin/env bash
# test-dashboard-oidc-pkce-totp-login.sh — #1661: the dashboard-next port of
# the retired Go-tier suite (#982/#1502/#1659). Drives real authorization-code
# +PKCE logins, including the realm's mandatory TOTP second factor, against
# the REAL built BFF artifact (frontend-next's `npm run build` output run
# exactly as production runs it -- `node .output/server/index.mjs`) and a REAL
# disposable Keycloak importing the actual keycloak/realm/apiary-realm.json,
# same import path scripts/test-keycloak-realm-import.sh proves works. Not a
# mock issuer and not a unit test of claim parsing in isolation: this is the
# protocol path a browser takes, which the e2e matrix deliberately fakes away
# (see frontend-next/e2e/fixture-session.mjs's own comment).
#
# Assertions nothing else covers:
#   - /auth/login redirects to the real Keycloak authorize endpoint carrying
#     client_id, S256 PKCE, and a state parameter;
#   - a real password+TOTP login exchanges into a real __Host-apiary_bff
#     session cookie via /auth/callback, and a protected page serves;
#   - #1656 end-to-end: the persisted session's role derives from the token's
#     resource_access.apiary-dashboard.roles -- 'admin' for the admin-granted
#     account, plain 'user' without it. This stack holds no introspection
#     dependency, so the redis session document IS the authoritative artifact
#     of completeLogin()'s claim parsing;
#   - authorization codes are single-use; forged/expired states reject cleanly;
#   - #1094's property survives the port: /auth/logout deletes the Redis-backed
#     session server-side -- proven with a saved copy of the pre-logout cookie
#     (a live-jar-only check would only prove the browser lost its cookie) plus
#     a direct redis existence check -- and ends Keycloak's own SSO session via
#     RP-initiated logout with id_token_hint;
#   - #1036: an admin-set TEMPORARY credential forces UPDATE_PASSWORD ahead of
#     anything else, before granting access.
#
# Deliberate divergences from the retired Go suite:
#   - `go run .` became npm ci + npm run build + node .output/server/index.mjs:
#     the harness exercises production server output ("what ships", matching
#     e2e/start-dashboard.mjs's own stated policy).
#   - No backend-service instance runs: this issue's scope stops at the auth
#     path. Role-gated data calls collapse to null via serviceJSON without it,
#     and every assertion here lives inside the BFF itself.
#   - The app-facing base URL is http://localhost:$PORT (not 127.0.0.1):
#     __Host-apiary_bff is a Secure cookie, and curl sends Secure cookies over
#     plain HTTP only to trustworthy-origin hosts -- localhost qualifies since
#     curl 7.87, numeric IPs never. Fail-fast below explains exactly that.
#   - node >= 20 required to build (vite/nitro use node:util.styleText);
#     CI's setup-node pins 22.
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
reap_stale_fixtures 'dashkcnext-'

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
realm_file="${repo_root}/arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json"

network="dashkcnext-$$"
pg="dashkcnext-pg-$$"
kc="dashkcnext-kc-$$"
redis="dashkcnext-redis-$$"
kc_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
dash_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
redis_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
app_base="http://localhost:${dash_port}"
fail=0
bff_pid=""

ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }
# Public repo, public CI log: every callback URL printed below carries a real
# live single-use authorization code as ?code=. Redact like any secret.
redact_code() { printf '%s' "$1" | sed -E 's/([?&]code=)[^&]*/\1REDACTED/'; }

cleanup() {
  # Post-mortem aid: the BFF log is where /auth/login failures actually speak;
  # keep it visible when DEBUG_BFF_LOG=1 before the temp dirs vanish.
  if [ "${DEBUG_BFF_LOG:-0}" = "1" ] && [ -n "${state_dir:-}" ] && [ -f "${state_dir}/bff.log" ]; then
    printf '── bff.log ──\n' >&2
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
  rm -rf "${flow_dir:-}" "${rendered_realm:-}" "${state_dir:-}"
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

# Only the dashboard's own domain becomes this test's listen address; Keycloak
# itself is reached by published port, never through domain substitution.
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

# Redis BEFORE the BFF starts -- same ordering rule the Go suite recorded:
# startup-time pending-state/session writes must not race container boot.
docker run -d --name "${redis}" --network "${network}" -p "127.0.0.1:${redis_port}:6379" \
  redis:7-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499 >/dev/null
for _ in $(seq 1 30); do docker exec "${redis}" redis-cli ping >/dev/null 2>&1 && break; sleep 1; done

kcadm() { docker exec "${kc}" /opt/keycloak/bin/kcadm.sh "$@"; }
kcadm config credentials --server http://localhost:8080 --realm master \
  --user test-admin --password test-only-not-real >/dev/null

client_id=$(kcadm get clients -r apiary -q clientId=apiary-dashboard --fields id --format csv --noquotes | tail -1)
client_secret=$(kcadm get "clients/${client_id}/client-secret" -r apiary --fields value --format csv --noquotes | tail -1)

# Three accounts, three paths:
#   pkce-totp-test   permanent credential, client roles [access]      -> role 'user'
#   pkce-admin-test  permanent credential, client roles [access,admin]-> role 'admin'
#   first-login-test admin-set TEMPORARY password -> forced UPDATE_PASSWORD
# The realm defines exactly access/admin on apiary-dashboard; there is no
# literal 'user' client role -- non-admin resolves to 'user' by absence,
# which is precisely the #1656 mapping under test.
kcadm create users -r apiary -s username=pkce-totp-test -s enabled=true -s emailVerified=true >/dev/null
kcadm set-password -r apiary --username pkce-totp-test --new-password 'PkceTotpTest9!Extra' >/dev/null
kcadm add-roles -r apiary --uusername pkce-totp-test --cclientid apiary-dashboard --rolename access >/dev/null
pkce_user_kc_id=$(kcadm get users -r apiary -q username=pkce-totp-test --fields id --format csv --noquotes | tail -1)
kcadm create users -r apiary -s username=pkce-admin-test -s enabled=true -s emailVerified=true >/dev/null
kcadm set-password -r apiary --username pkce-admin-test --new-password 'PkceAdminTest9!Extra' >/dev/null
kcadm add-roles -r apiary --uusername pkce-admin-test --cclientid apiary-dashboard --rolename access --rolename admin >/dev/null
kcadm create users -r apiary -s username=first-login-test -s enabled=true -s emailVerified=true >/dev/null
# set-password -t makes Keycloak insert its own UPDATE_PASSWORD required
# action (see retired suite's note: kcadm's generic update 404s on
# reset-password -- a write-only endpoint with no GET for GET-then-PUT).
kcadm set-password -r apiary --username first-login-test --new-password 'TempOneTime1!Extra' --temporary >/dev/null
kcadm add-roles -r apiary --uusername first-login-test --cclientid apiary-dashboard --rolename access >/dev/null

flow_dir="$(mktemp -d)"
chmod 777 "${flow_dir}"

# Raw stdlib TOTP, no pyotp dependency, for CI portability. HmacSHA256 per
# the realm's otpPolicyAlgorithm.
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

# Submits a TOTP code aligned early in a fresh 30s window; retries across
# bruteForceProtected's minimumQuickLoginWaitSeconds (60s + margin). Every fix
# folded into the retired original transfers verbatim in behavior:
#   - enrollment form field is "totp", login-challenge form field is "otp";
#     conflating them submits empty/wrong fields forever ($3).
#   - Keycloak rotates session_code on every re-render; retries re-scrape the
#     fresh form action from each rejection's own body rather than reusing $2.
#   - #1096: rejection usually 200-renders the SAME form (empty Location),
#     but sometimes redirects to another required-action URL; acceptance can
#     arrive WITHOUT a redirect too -- distinguished by the code field being
#     absent from an inline-rendered response, whose winning body is written
#     to ${flow_dir}/totp-next-body.html (this function always runs inside a
#     command-substitution subshell: files survive, variables don't).
# $1=jar $2=action $3=code-field-name $4=Location success substring,
# remaining args extra --data-urlencode fields.
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

# Drives a CONFIGURE_TOTP required-action page ("Unable to scan?" manual link
# -> secret capture -> submit) to completion. Sets _totp_enroll_* globals:
#   ok        "true" iff genuinely accepted (the flag to branch on)
#   secret    the enrolled secret (also mirrored to global ${totp_secret},
#             what submit_totp_with_retry reads codes from)
#   callback  redirect target when Keycloak issued one (empty on inline next)
#   next_body next page HTML when acceptance rendered it inline instead
complete_totp_enrollment() {
  local jar="$1" totp_page="$2" success_substr="$3"
  local manual_link manual_page form_action secret_field saved_secret
  manual_link=$(echo "${totp_page}" | grep -o 'href="[^"]*mode=manual[^"]*"' | head -1 | sed 's/^href="//;s/"$//' | sed 's/&amp;/\&/g')
  if [ -z "${manual_link}" ]; then
    printf 'FAIL: no "Unable to scan?" manual-mode link on the CONFIGURE_TOTP page -- response follows\n' >&2
    echo "${totp_page}" >&2
    exit 1
  fi
  manual_page=$(curl -s -c "${jar}" -b "${jar}" "${manual_link}")
  # Each successive enrollment in one run overwrites the shared secret the
  # retry helper reads -- callers below sequence whole enrollments + their
  # login legs so each leg consumes its own secret before the next begins.
  saved_secret="${_totp_enroll_secret:-}"
  totp_secret=$(echo "${manual_page}" | grep -oE '[A-Z2-7]{4}( [A-Z2-7]{4}){7}' | head -1 | tr -d ' ')
  if [ -z "${totp_secret}" ]; then
    printf 'FAIL: no TOTP secret on the manual-mode CONFIGURE_TOTP page -- response follows\n' >&2
    echo "${manual_page}" >&2
    exit 1
  fi
  form_action=$(echo "${manual_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
  secret_field=$(echo "${manual_page}" | grep -o 'id="totpSecret"[^>]*value="[^"]*"' | head -1 | grep -o 'value="[^"]*"' | sed 's/value="//;s/"$//')
  _totp_enroll_secret="${totp_secret}"
  [ -n "${saved_secret}" ] && _totp_enroll_secret="${_totp_enroll_secret}|${saved_secret}"
  _totp_enroll_callback=$(submit_totp_with_retry "${jar}" "${form_action}" totp "${success_substr}" --data-urlencode "totpSecret=${secret_field}" --data-urlencode "userLabel=")
  _totp_enroll_next_body=""
  if [ -f "${flow_dir}/totp-next-body.html" ]; then
    _totp_enroll_next_body="$(cat "${flow_dir}/totp-next-body.html")"
    rm -f "${flow_dir}/totp-next-body.html"
  fi
  _totp_enroll_ok=""
  { [ -n "${_totp_enroll_callback}" ] || [ -n "${_totp_enroll_next_body}" ]; } && _totp_enroll_ok=true
}

# One complete dashboard-initiated OIDC login for any account, whatever
# required-action chain the realm owes it (CONFIGURE_TOTP first-timer, or
# already-enrolled straight to the OTP challenge, or temporary-password
# accounts sent through UPDATE_PASSWORD). Loops because a completed required
# action lands on whichever page comes next, not always the same one.
# Echos the resulting ${app_base}/auth/callback... location; empty on failure.
# Leaves session cookies in $1's jar on success (caller exchanges the code).
# NOTE for temporary-password accounts: they reach HERE having replaced the
# temp credential (drive step 2 below passes the password they were given;
# the chain calls them back out to replace it -- handled inside the loop).
# Advance one auth chain without blind-following (-L) so a login-completing
# /auth/callback?code=... redirect is DETECTED rather than dissolved into the
# app shell's HTML. Sets _chain_cb to the callback location exactly when
# authentication finished (empty otherwise) -- via global, never stdout: this
# runs inside $() callers, where echoing the final page body would be
# indistinguishable from the callback it replaces. Last body lands in
# chain-last.html, NUL-stripped on load by callers (some KC/nitro hops smuggle
# stray \0 into otherwise-plain HTML).
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
    # $@ rides hop 1 ONLY: replaying --data-urlencode payloads onto subsequent
    # redirect targets would turn their GETs into spurious POSTs.
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
  # Dashboard-initiated authorize: /auth/login issues the CSRF-bound PKCE
  # state. Everything downstream just fills Keycloak's forms.
  local auth_location
  auth_location=$(curl -s -c "${jar}" -D - -o /dev/null "${app_base}/auth/login" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
  follow_auth_chain "${jar}" "${auth_location}"
  [ -n "${_chain_cb}" ] && { echo "${_chain_cb}"; return 0; }
  page=$(tr -d '\000' < "${flow_dir}/chain-last.html")
  form_action=$(echo "${page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
  if [ -z "${form_action}" ]; then
    printf '    (no login form rendered where the authorize chain ended -- %s, see DEBUG_KEEP captures)\n' "${username}" >&2
    return 1
  fi
  follow_auth_chain "${jar}" "${form_action}" \
    --data-urlencode "username=${username}" \
    --data-urlencode "password=${password}" \
    --data-urlencode "credentialId="
  [ -n "${_chain_cb}" ] && { echo "${_chain_cb}"; return 0; }
  page=$(tr -d '\000' < "${flow_dir}/chain-last.html")

  for step in 1 2 3 4 5 6; do
    if [ "${DEBUG_KEEP:-0}" = "1" ]; then
      printf '%s' "${page}" > "${flow_dir}/step-${username}-${step}.html"
    fi
    # OTP challenge present? (login-otp.ftl names its field "otp" and carries
    # hidden selectedCredentialId -- omit it and every correct code fails.)
    otp_action=$(echo "${page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
    if grep -q 'name="otp"' <<<"${page}" && [ -n "${otp_action}" ]; then
      sel_cred=$(echo "${page}" | grep -o 'id="selectedCredentialId"[^>]*value="[^"]*"' | head -1 | grep -o 'value="[^"]*"' | sed 's/value="//;s/"$//')
      cb_url=$(submit_totp_with_retry "${jar}" "${otp_action}" otp "${app_base}/auth/callback" --data-urlencode "selectedCredentialId=${sel_cred}")
      echo "${cb_url}"
      return 0
    fi
    # A pending CONFIGURE_TOTP renders its QR page -- complete it (the loop
    # then sees whichever page acceptance yielded: another action inline, or
    # the OTP challenge on a followed redirect).
    if grep -qi 'mode=manual' <<<"${page}"; then
      printf 'configure-totp\n' >>"${flow_dir}/chain-${username}.log"
      complete_totp_enrollment "${jar}" "${page}" "${app_base}/auth/callback"
      if [ -z "${_totp_enroll_ok}" ]; then
        printf '    (CONFIGURE_TOTP rejected across all retries for %s)\n' "${username}" >&2
        echo ""
        return 1
      fi
      if [ -n "${_totp_enroll_callback}" ]; then
        case "${_totp_enroll_callback}" in
          # With TOTP newly configured the SSO session is complete: Keycloak
          # sends acceptance as the finished /auth/callback?code=... redirect.
          # The BFF has already exchanged that code by the time this fetch
          # follows it home -- so this IS the flow's success location, not a
          # page to scrape for further required actions.
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
    # Temporary-credential accounts land on UPDATE_PASSWORD first; replace
    # the handed-out one-time password so the account becomes usable.
    if grep -q 'name="password-new"' <<<"${page}"; then
      printf 'update-password\n' >>"${flow_dir}/chain-${username}.log"
      form_action=$(echo "${page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
      # A completed password update usually ends the whole auth session
      # (callback redirect) -- never blind-follow that into the app shell.
      follow_auth_chain "${jar}" "${form_action}" \
        --data-urlencode "password-new=${new_perm_password}" \
        --data-urlencode "password-confirm=${new_perm_password}"
      [ -n "${_chain_cb}" ] && { echo "${_chain_cb}"; return 0; }
      page=$(tr -d '\000' < "${flow_dir}/chain-last.html")
      continue
    fi
    # Anything else means we're stuck off the expected execution graph.
    printf '    (unexpected required-action page at step %d for %s: %s)\n' "${step}" "${username}" "$(echo "${page}" | head -c 160)" >&2
    echo ""
    return 1
  done
  echo ""
  return 1
}

# Read a cookie value out of a Netscape-format curl jar. Comment lines are
# skipped -- except #HttpOnly_-prefixed ones, which is how curl stores
# Secure+HttpOnly cookies (the __Host-apiary_bff session cookie is both):
# stripping that exact prefix turns them back into ordinary 7-field lines.
jar_cookie_value() {
  sed 's/^#HttpOnly_//' "$2" | awk '!/^#/ && $6 == "'"$1"'" {print $7}' | tail -1
}

session_doc() {
  local sid="$1"
  docker exec "${redis}" redis-cli --raw GET "bff:session:${sid}"
}

# ═══ Build + boot the real production server ══════════════════════════════
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
# The #2183 boot gate refuses to start without SERVICE_TOKEN (or the explicit
# dev override, which would muzzle the very tier this suite exercises) -- hand
# the server a throwaway test token so it boots with enforcement ON.
service_token='pkce-suite-local-token-not-a-secret'
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
if [ "${bff_up}" -ne 1 ]; then
  printf 'FAIL: BFF never came up -- log follows\n' >&2
  cat "${state_dir}/bff.log" >&2
  exit 1
fi
# Test-only permanent password handed to temporary-credential accounts by
# dashboard_login_flow (not exported: nothing downstream reads it via env).
new_perm_password='FirstLoginPerm2!Extra'

# ═══ Golden path: pkce-totp-test (role 'user') ═════════════════════════════
# First-ever login owes CONFIGURE_TOTP; the flow completes enrollment and the
# OTP challenge inside one dashboard-initiated round trip.
jar="${flow_dir}/jar-golden.txt"
login_start_headers=$(curl -s -c "${jar}" -D - -o "${flow_dir}/login-start-body.html" "${app_base}/auth/login" || true)
auth_location=$(grep -i '^location:' <<<"${login_start_headers}" | sed 's/^[Ll]ocation: //' | tr -d '\r' || true)
if [ -z "${auth_location}" ]; then
  printf 'DIAG /auth/login did not redirect -- status line + headers:\n%s\nbody (first 400B):\n' "${login_start_headers}" >&2
  head -c 400 "${flow_dir}/login-start-body.html" >&2
fi
case "${auth_location}" in
  "http://127.0.0.1:${kc_port}/realms/apiary/protocol/openid-connect/auth?"*)
    # Order-insensitive component check: Keycloak does not promise any query
    # parameter order, and the assertion only cares that the pieces exist.
    if grep -q 'client_id=apiary-dashboard' <<<"${auth_location}" \
      && grep -q 'code_challenge_method=S256' <<<"${auth_location}" \
      && grep -q '[?&]state=' <<<"${auth_location}"; then
      ok "/auth/login redirects to the real Keycloak authorize endpoint with PKCE S256 + state"
    else
      bad "authorize redirect is missing a required piece: $(redact_code "${auth_location}")"
    fi ;;
  *) bad "unexpected /auth/login redirect target: $(redact_code "${auth_location}")" ;;
esac

cb_url=$(dashboard_login_flow "${jar}" pkce-totp-test 'PkceTotpTest9!Extra') || true
case "${cb_url}" in
  "${app_base}/auth/callback"?*) ok "real password+TOTP login succeeded through the mandatory-TOTP enrollment chain" ;;
  *) bad "golden-path login failed for pkce-totp-test: $(redact_code "${cb_url:-<empty>}")" ;;
esac

if [ -n "${cb_url}" ]; then
  ex_status=$(curl -s -o /dev/null -w '%{http_code}' -c "${jar}" -b "${jar}" "${cb_url}")
  prot_status=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar}" "${app_base}/")
  case "${ex_status}" in
    302|303|307) exchange_shape="ok" ;;
    *) exchange_shape="bad" ;;
  esac
  if [ "${exchange_shape}" = "ok" ] && [ "${prot_status}" = "200" ]; then
    ok "real PKCE authorization-code exchange succeeded end to end; session cookie grants the protected page"
  else
    bad "callback/protected page did not grant a session: callback=${ex_status} protected=${prot_status}"
  fi

  # ── #1656 end-to-end: inspect what the exchange actually persisted ──
  sid=$(jar_cookie_value '__Host-apiary_bff' "${jar}")
  doc=$(session_doc "${sid}" || true)
  parsed_role=$(python3 -c 'import json,sys
try:
  d=json.loads(sys.argv[1]); print(d.get("role","")); print(d.get("sub",""), file=sys.stderr)
except Exception: print("")' "${doc}" 2>"${flow_dir}/sub.txt")
  stored_sub=$(cat "${flow_dir}/sub.txt")
  if [ "${parsed_role}" = "user" ]; then
    ok "persisted session role is 'user' for the access-only account (resource_access.apiary-dashboard.roles parsed correctly, #1656)"
  else
    bad "expected stored role 'user', got '${parsed_role}' (session doc: $(echo "${doc}" | head -c 120))"
  fi
  if [ -n "${stored_sub}" ] && [ "${stored_sub}" = "${pkce_user_kc_id}" ]; then
    ok "session identity key is Keycloak's immutable sub (${stored_sub})"
  else
    bad "stored sub does not match Keycloak's user id: '${stored_sub}' vs '${pkce_user_kc_id}'"
  fi
  stored_user=$(python3 -c 'import json,sys
try: print(json.loads(sys.argv[1]).get("username",""))
except Exception: print("")' "${doc}")
  [ "${stored_user}" = "pkce-totp-test" ] || bad "unexpected stored username '${stored_user}'"
fi

# ═══ pkce-admin-test (role 'admin') ════════════════════════════════════════
jar_admin="${flow_dir}/jar-admin.txt"
cb_admin=$(dashboard_login_flow "${jar_admin}" pkce-admin-test 'PkceAdminTest9!Extra')
case "${cb_admin}" in
  "${app_base}/auth/callback"?*)
    curl -s -o /dev/null -c "${jar_admin}" -b "${jar_admin}" "${cb_admin}"
    sid_admin=$(jar_cookie_value '__Host-apiary_bff' "${jar_admin}")
    doc_admin=$(session_doc "${sid_admin}" || true)
    role_admin=$(python3 -c 'import json,sys
try: print(json.loads(sys.argv[1]).get("role",""))
except Exception: print("")' "${doc_admin}")
    if [ "${role_admin}" = "admin" ]; then
      ok "persisted session role is 'admin' for the access+admin account (#1656 resource_access mapping, both directions)"
    else
      bad "expected stored role 'admin', got '${role_admin}' (session doc: $(echo "${doc_admin}" | head -c 120))"
    fi
    ;;
  *) bad "login flow failed for pkce-admin-test: $(redact_code "${cb_admin:-<empty>}")" ;;
esac

# ═══ Authorization codes are single-use ════════════════════════════════════
# Replaying the exact consumed callback must not mint a second session --
# neither via a reused redis pending-entry (getdel) nor via Keycloak's own
# code-consumption rejection.
if [ -n "${cb_url}" ]; then
  jar_replay="${flow_dir}/jar-replay.txt"
  replay_ex=$(curl -s -o /dev/null -w '%{http_code}' -c "${jar_replay}" -b "${jar_replay}" "${cb_url}")
  replay_prot=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar_replay}" "${app_base}/")
  if { [ "${replay_prot}" != "200" ]; } && ! { [ "${replay_ex}" = "302" ] || [ "${replay_ex}" = "303" ] || [ "${replay_ex}" = "307" ]; }; then
    ok "replaying the same authorization code does not grant a session (single-use enforced; exchange answered HTTP ${replay_ex})"
  else
    bad "authorization code was accepted twice: exchange=${replay_ex} protected=${replay_prot}"
  fi

  # A forged state has no pending redis entry -- completeLogin() must answer
  # a clean 400 ('login expired'), not crash or worse, proceed.
  forged=$(curl -s -o /dev/null -w '%{http_code}' "${app_base}/auth/callback?state=forged&code=x&session_state=y")
  [ "${forged}" = "400" ] || bad "forged-state callback returned ${forged}, expected 400"
  [ "${forged}" = "400" ] && ok "forged-state callback rejects with 400 login-expired"
fi

# ═══ Logout really revokes server-side (#1094 port) ════════════════════════
# Prove deletion of the redis-backed session itself, not just cookie
# clearing: test with a SAVED COPY of the pre-logout cookie plus a direct
# redis existence check -- a stolen-cookie scenario must fail after logout.
if [ -n "${sid:-}" ]; then
  cp "${jar}" "${flow_dir}/jar-prelogout.txt"

  # #3153: a cross-origin logout call must 403 and leave the session in
  # redis untouched -- run this before the real logout below, while the
  # session is still live, so a false "still in redis" pass can't hide
  # behind the real logout having already torn it down.
  forged_logout_status=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar}" -H "Origin: http://evil.example" "${app_base}/auth/logout")
  forged_still_in_redis=$(docker exec "${redis}" redis-cli EXISTS "bff:session:${sid}")
  if [ "${forged_logout_status}" = "403" ] && [ "${forged_still_in_redis}" = "1" ]; then
    ok "cross-origin /auth/logout (Origin: evil.example) is rejected with 403 and leaves the session in redis (#3153)"
  else
    bad "cross-origin logout was not blocked as expected: status=${forged_logout_status} redis EXISTS=${forged_still_in_redis}"
  fi

  logout_headers=$(curl -s -D - -o /dev/null -c "${jar}" -b "${jar}" -H "Origin: ${app_base}" "${app_base}/auth/logout")
  logout_status=$(echo "${logout_headers}" | head -1 | awk '{print $2}')
  logout_location=$(echo "${logout_headers}" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
  case "${logout_location}" in
    "http://127.0.0.1:${kc_port}"*/protocol/openid-connect/logout*"id_token_hint"*)
      ok "/auth/logout redirects (303) to Keycloak's real end-session endpoint with id_token_hint (ends the SSO session too)" ;;
    *) bad "/auth/logout did not redirect to end-session as expected: status=${logout_status} location=$(redact_code "${logout_location}")" ;;
  esac

  old_cookie_status=$(curl -s -o /dev/null -w '%{http_code}' -b "${flow_dir}/jar-prelogout.txt" "${app_base}/")
  still_in_redis=$(docker exec "${redis}" redis-cli EXISTS "bff:session:${sid}")
  if [ "${old_cookie_status}" != "200" ] && [ "${still_in_redis}" = "0" ]; then
    ok "pre-logout cookie copy no longer grants access AND the session document is gone from redis -- revocation is server-side, not cosmetic"
  else
    bad "logout left residue: saved-cookie GET=${old_cookie_status}, redis EXISTS=${still_in_redis}"
  fi
fi

# ═══ #1036: admin-set TEMPORARY password forces replacement first ══════════
jar_first="${flow_dir}/jar-first.txt"
cb_first=$(dashboard_login_flow "${jar_first}" first-login-test 'TempOneTime1!Extra')
case "${cb_first}" in
  "${app_base}/auth/callback"?*)
    # The callback alone can't distinguish forced replacement from Keycloak
    # quietly accepting the temp credential -- assert the chain really passed
    # through UPDATE_PASSWORD before anything granted access.
    chain_first=""
    [ -f "${flow_dir}/chain-first-login-test.log" ] && chain_first="$(cat "${flow_dir}/chain-first-login-test.log")"
    if grep -qx 'update-password' <<<"${chain_first}"; then
      ok "first-login temporary password forced UPDATE_PASSWORD ahead of granting access (#1036 semantics preserved)"
    else
      bad "temporary credential never hit an UPDATE_PASSWORD page -- Keycloak accepted it straight through? chain: $(echo "${chain_first}" | tr '\n' ',')"
    fi
    curl -s -o /dev/null -c "${jar_first}" -b "${jar_first}" "${cb_first}"
    p1=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar_first}" "${app_base}/")
    if [ "${p1}" != "200" ]; then
      bad "post-reset login session did not grant the protected page (HTTP ${p1})"
    else
      ok "post-replacement session serves the protected page (HTTP 200)"
    fi
    ;;
  *)
    # The flow also fails loudly if replacement wasn't forced -- Keycloak
    # would have accepted TempOneTime1!Extra straight through.
    bad "temporary-password account never reached a real callback: $(redact_code "${cb_first:-<empty>}")"
    ;;
esac

if [ "${fail}" -ne 0 ]; then
  printf '\nFAIL: one or more dashboard-next OIDC PKCE+TOTP assertions failed\n' >&2
  exit 1
fi
printf '\nPASS: real PKCE + mandatory-TOTP login against the real built BFF and a real disposable Keycloak held\n'
