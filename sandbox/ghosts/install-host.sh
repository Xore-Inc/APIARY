#!/usr/bin/env bash
# install-host.sh — stand up the GHOSTS host stack (#324) on this host.
#
# Brings up two containers, isolated from every other stack this repo
# deploys:
#
#   ghosts-postgres   postgres:18.6, GHOSTS' own database
#   ghosts-api        CMU SEI's Ghosts.Api, built from source, pinned to v9.0.0
#
# Frontend/Grafana/n8n are deliberately not deployed -- see the header on
# compose.yml. ghosts-api publishes on 10.20.30.1:5000 -- virbr-ghosts's own
# gateway address (#325), not a docker-internal IP; see compose.yml's header
# for why direct docker-backend-IP routing doesn't work here. Requires the
# `ghosts` libvirt network (sandbox/ghosts/network.xml) to already exist --
# run sandbox/ghosts/install-network.sh net-setup first on a fresh host.
#
# On a host running Dockge the compose file is deployed into a stack
# directory under /opt/stacks, same as every other stack this repo manages,
# so it shows up as a stack Dockge can start/stop/tail rather than a stray
# container. That directory is a deployment copy: edit compose.yml in this
# repository and re-run this script, do not edit it there.
#
# Idempotent: safe to re-run after a pull or a reboot. An existing .env in
# the stack directory (holding POSTGRES_PASSWORD) is never overwritten.
#
# Usage:
#   sandbox/ghosts/install-host.sh                 # containers + enrollment test
#   sandbox/ghosts/install-host.sh --skip-enroll-test
#
# Options:
#   --skip-enroll-test  Bring up the containers and stop; skip building and
#                        running the throwaway test client.
#   --stack-dir PATH    Where to deploy the compose file. Defaults to
#                        /opt/stacks/ghosts when /opt/stacks exists, else the
#                        repository directory. Pass "" to run in place.
#   -h, --help          This text.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_file="$here/compose.yml"
env_file=/etc/default/honeypot-ghosts
GHOSTS_API_ADDR=10.20.30.1:5000

SKIP_ENROLL_TEST=0
STACK_DIR="$([ -d /opt/stacks ] && echo /opt/stacks/ghosts || true)"
env_file_arg=""

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-enroll-test) SKIP_ENROLL_TEST=1; shift ;;
    --stack-dir) STACK_DIR="${2?--stack-dir needs a value}"; shift 2 ;;
    -h|--help) awk 'NR>1 && !/^#/{exit} NR>1{sub(/^# ?/,""); print}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n== %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "docker is required"
command -v curl >/dev/null 2>&1 || die "curl is required (the readiness/enrollment checks use it)"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is required"
docker info >/dev/null 2>&1 ||
  die "cannot talk to the docker daemon (not running, or this user is not in the docker group)"

# ── Deploy the compose file ──────────────────────────────────────────────────
if [ -n "$STACK_DIR" ]; then
  say "deploying the compose file to $STACK_DIR"
  mkdir -p "$STACK_DIR"
  cp "$compose_file" "$STACK_DIR/compose.yml"
  if [ ! -e "$STACK_DIR/.env" ]; then
    pw="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
    printf 'POSTGRES_PASSWORD=%s\n' "$pw" > "$STACK_DIR/.env"
    chmod 600 "$STACK_DIR/.env"
    echo "  generated $STACK_DIR/.env"
  else
    echo "  kept the existing $STACK_DIR/.env"
  fi
  # Deliberately NOT reassigning compose_file to the copy: since #2444 this
  # stack builds from a LOCAL context (`context: .` + Dockerfile.api-prep, and
  # ./vendor/ghosts-src for the Windows client), and compose resolves a
  # relative build context against the project directory. Building out of
  # $STACK_DIR -- which holds compose.yml and .env and nothing else -- fails:
  #
  #   failed to solve: failed to read dockerfile:
  #   open Dockerfile.api-prep: no such file or directory
  #
  # Confirmed live on 2026-09-05 (#1609 Phase 8), where it took the whole
  # ghosts-host step down. The copy still goes to $STACK_DIR so Arcane/Dockge
  # can see and manage the stack; the build and the run stay rooted in the
  # checkout that actually holds the context, reading the secret from the
  # deployed .env.
  env_file_arg="$STACK_DIR/.env"
fi

dc() {
  docker compose -f "$compose_file" --project-directory "$(dirname "$compose_file")" \
    ${env_file_arg:+--env-file "$env_file_arg"} --profile test "$@"
}

# ── Containers ───────────────────────────────────────────────────────────────
say "building ghosts-api from cmu-sei/GHOSTS@v9.0.0 (this takes a while: a full dotnet publish)"
dc build ghosts-api
dc up -d ghosts-postgres ghosts-api

say "waiting for ghosts-api to answer"
tries=60
until curl -sf -m 3 "http://$GHOSTS_API_ADDR/" >/dev/null 2>&1; do
  tries=$((tries - 1))
  [ "$tries" -gt 0 ] || { dc ps --format '{{.Name}}	{{.Status}}' >&2 || true; die "ghosts-api did not answer at http://$GHOSTS_API_ADDR after 5 minutes"; }
  sleep 5
done
echo "  ghosts-api is up at http://$GHOSTS_API_ADDR"

# ── Record the fixed address for later issues in the #331 chain ────────────
if [ "$(id -u)" -eq 0 ] && [ ! -e "$env_file" ]; then
  printf 'GHOSTS_API_ADDR=%s\n' "$GHOSTS_API_ADDR" > "$env_file"
  echo "  wrote $env_file"
elif [ "$(id -u)" -eq 0 ]; then
  echo "  kept the existing $env_file (compare against GHOSTS_API_ADDR=$GHOSTS_API_ADDR)"
else
  echo "  not root: skipped writing $env_file (GHOSTS_API_ADDR=$GHOSTS_API_ADDR)"
fi

if [ "$SKIP_ENROLL_TEST" = 1 ]; then
  say "containers only - stopping here"
  exit 0
fi

# ── Test machine enrollment ─────────────────────────────────────────────────
# Builds the same source tree's cross-platform client and runs it briefly on
# ghosts_net, where the client's own default config (ApiRootUrl pointing at
# the ghosts-api service name) resolves without any override. Confirms the
# API + Postgres path end to end, not just that the API answers HTTP.
# The API seeds ~26 demo machines (WS-SOC-01, ...) into a fresh database, so
# "a machine exists" is true before any real client ever runs -- the bar has
# to be a rising count, not presence.
count_machines() {
  curl -sf -m 3 "http://$GHOSTS_API_ADDR/api/machines/list" 2>/dev/null | grep -o '"id"' | wc -l
}
before="$(count_machines)"

say "building the test client from the same pinned source"
dc build ghosts-client-test

say "running the test client and watching for its machine registration"
dc run -d --name ghosts-enroll-test ghosts-client-test
trap 'docker rm -f ghosts-enroll-test >/dev/null 2>&1 || true' EXIT

registered=0
tries=24
while [ "$tries" -gt 0 ]; do
  after="$(count_machines)"
  if [ -n "$after" ] && [ "$after" -gt "$before" ]; then
    registered=1
    break
  fi
  tries=$((tries - 1))
  sleep 5
done

[ "$registered" = 1 ] || die "machine count stayed at $before after the test client ran; no enrollment happened"
say "test machine enrolled successfully ($before -> $after machines)"
curl -sf "http://$GHOSTS_API_ADDR/api/machines/list" | tail -c 400
echo

say "done"
echo "Fixed address for the #331 chain's later issues (#325's LAN-block exception,"
echo "#328's spool integration): GHOSTS_API_ADDR=$GHOSTS_API_ADDR"
