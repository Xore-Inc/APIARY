#!/usr/bin/env bash
# test-keycloak-realm-import.sh — boots an ephemeral, disposable
# Keycloak + PostgreSQL and imports keycloak/realm/apiary-realm.json through
# the exact bootstrap path arcane/home/honeypot-keycloak/compose.yml uses on every real
# fresh install (`kc.sh start --import-realm`), then asserts it actually
# succeeds.
#
# #982 phase 1 / #1040: keycloak/realm/validate.sh's jq checks are static --
# they check structure and policy, never what a real Keycloak+Postgres
# import does with the file. That gap let a 263-char role description (over
# Postgres's KEYCLOAK_ROLE.DESCRIPTION varchar(255) column) crash-loop the
# container on any genuinely fresh install, undetected until this script's
# manual precursor caught it live. This is the regression test for that
# class of bug -- it does not exercise login, roles, or client behavior
# (that's the rest of #982), only "does the realm this repo ships actually
# import into a real Keycloak."
#
# Uses no arcane/home/honeypot-keycloak/compose.yml secrets/volumes -- this is a
# throwaway topology (plain `docker run`, ephemeral network, ephemeral
# ports, ephemeral admin credentials), never real production Keycloak.
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
reap_stale_fixtures 'kctest-import-'

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
realm_file="${repo_root}/arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json"  # #1502

command -v docker >/dev/null || { printf 'docker is required\n' >&2; exit 1; }

network="kctest-import-$$"
pg="kctest-import-pg-$$"
kc="kctest-import-kc-$$"
kc_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
rendered_realm="$(mktemp)"

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
  docker rm -fv "${kc}" "${pg}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -f "${rendered_realm}"
}
trap cleanup EXIT

# Test-only substitution, never applied to the checked-in file: the real
# realm's redirect URIs are all https://<subdomain>.example.invalid/... --
# this fixture has no TLS termination in front of it (unlike the real
# deployment, where VPS Traefik always terminates TLS before Keycloak ever
# sees a request), so every subdomain collapses onto one plain-http
# 127.0.0.1:<port> origin. Fine here: this script only proves the *import*
# succeeds, it never drives a login through these URLs.
sed -E "s|https://[a-zA-Z0-9.-]*\\.example\\.invalid|http://127.0.0.1:${kc_port}|g" \
  "${realm_file}" > "${rendered_realm}"
# mktemp defaults to 0600, owned by whatever host UID runs this script. The
# Keycloak container reads this bind-mounted file as its own non-root
# in-container user -- on a CI runner that UID doesn't match the host UID
# that created the file, so the read fails outright ("Permission denied").
# Worked locally only by UID coincidence. No secrets in this file -- it's
# the same realm template already checked into the repo, just with the
# domain substituted -- so world-readable is fine.
chmod 644 "${rendered_realm}"

docker network create "${network}" >/dev/null

docker run -d --name "${pg}" --network "${network}" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=test-only-not-real \
  postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382 >/dev/null

for _ in $(seq 1 30); do
  docker exec "${pg}" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break
  sleep 1
done

docker run -d --name "${kc}" --network "${network}" -p "127.0.0.1:${kc_port}:8080" \
  -e KC_DB=postgres -e KC_DB_URL_HOST="${pg}" -e KC_DB_URL_PORT=5432 -e KC_DB_URL_DATABASE=keycloak \
  -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=test-only-not-real \
  -e "KC_HOSTNAME=http://127.0.0.1:${kc_port}" -e KC_HTTP_ENABLED=true -e KC_HEALTH_ENABLED=true \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=test-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=test-only-not-real \
  -v "${rendered_realm}:/opt/keycloak/data/import/apiary-realm.json:ro" \
  quay.io/keycloak/keycloak:26.8.1@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b \
  start --http-port=8080 --import-realm >/dev/null

printf 'Waiting for realm import against a real Postgres (up to 240s)...\n'
for i in $(seq 1 240); do
  if docker logs "${kc}" 2>&1 | grep -q "KC-SERVICES0032: Import finished successfully"; then
    printf 'PASS: apiary-realm.json imported cleanly\n'
    exit 0
  fi
  if docker logs "${kc}" 2>&1 | grep -q "ERROR: Failed to start server"; then
    printf 'FAIL: realm import crashed the server -- log follows\n' >&2
    docker logs "${kc}" 2>&1 | tail -60 >&2
    exit 1
  fi
  sleep 1
  if [[ "$i" -eq 240 ]]; then
    printf 'FAIL: timed out waiting for import to finish -- log follows\n' >&2
    docker logs "${kc}" 2>&1 | tail -60 >&2
    exit 1
  fi
done
