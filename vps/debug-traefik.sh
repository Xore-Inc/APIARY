#!/usr/bin/env bash
# debug-traefik.sh — Traefik vhost routing diagnostic
#
# Architecture on this VPS:
#   Internet → Cloudflare (proxy) → VPS :443 → Traefik
#              Traefik routes by Host header → WireGuard 10.8.0.2:PORT
#   (socat containers are NOT in the routing path for Traefik vhosts)
#
# Layers checked:
#   1. Traefik API  — routers defined for this host?
#   2. WireGuard    — tunnel up, home port open?
#   3. Keycloak     — is the identity provider itself actually healthy?
#                      (distinct from any per-app 401/302/502 below, all of
#                      which depend on this one passing first — #981)
#   4. End-to-end   — HTTPS via Host: header returns sane HTTP code
#
# How to enable Traefik API on localhost only (add to traefik.yml):
#   api:
#     dashboard: true
#   entryPoints:
#     traefik-local:
#       address: "127.0.0.1:8080"
#   Then add this to traefik.yml under 'api:' section:
#     insecure: false   # NOT exposed publicly
#   And in dynamic.yml add a router for the local entrypoint:
#     http:
#       routers:
#         api:
#           rule: "PathPrefix(`/api`) || PathPrefix(`/dashboard`)"
#           entryPoints: [traefik-local]
#           service: api@internal
#
# Usage:  ./debug-traefik.sh [DOMAIN]

DOMAIN="${1:?usage: debug-traefik.sh <domain>}"
WG_HOME="10.8.0.2"
TRAEFIK_API="http://127.0.0.1:8080"
PASS=0; FAIL=0; WARN=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; ((WARN++)); }
info() { echo -e "\n${CYAN}${BOLD}$*${NC}"; }
sep()  { echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"; }
tcp_open() { timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

# label | subdomain | home-port (10.8.0.2:PORT) | expected-status-hint
# 421 = Cloudflare Misdirected Request (Traefik has no router for this Host)
# 502 = Traefik has router but backend is down
# 200/30x = working
VHOSTS=(
  "www               |www      |8080  |static site (nginx on home)"
  "EveBox            |evebox   |19636 |Suricata EVE GUI"
  "Honeypot dashboard|honeypot |19092 |live attack dashboard (apiary-dashboard)"
  "Kibana            |kibana   |19601 |ELK Kibana"
  "Tanner web        |tanner   |19091 |SNARE/tanner web UI"
  "Snare honeypot    |snare    |19082 |fake website honeypot"
  "Flask API         |api      |5000  |working reference"
  "Go API            |go       |5003  |working reference"
  "Rust API          |rust     |5004  |working reference"
  "C# API            |csharp   |5002  |working reference"
  "Node API          |node     |3000  |working reference"
  "Uptime Kuma       |status   |3001  |uptime monitor"
  "FileBrowser       |files    |8070  |file browser"
)

echo
sep
echo -e "${CYAN}${BOLD}  Traefik vhost routing diagnostic${NC}"
echo -e "  Domain : $DOMAIN"
echo -e "  WG home: $WG_HOME"
echo -e "  Note   : Cloudflare proxy active — DNS will show CF IPs, not VPS IP"
sep

# ============================================================
# 0. Traefik API
# ============================================================
info "[0] Traefik API (127.0.0.1:8080)"
if curl -sf --max-time 3 "$TRAEFIK_API/api/rawdata" -o /dev/null; then
  pass "Traefik API reachable"
  TRAEFIK_DATA=$(curl -sf --max-time 5 "$TRAEFIK_API/api/rawdata" 2>/dev/null)
else
  warn "Traefik API not available. To enable on localhost only, add to traefik.yml:"
  echo
  echo "    api:"
  echo "      dashboard: true"
  echo "    entryPoints:"
  echo "      traefik-local:"
  echo "        address: \"127.0.0.1:8080\""
  echo
  echo "    Then in dynamic.yml:"
  echo "    http:"
  echo "      routers:"
  echo "        traefik-api:"
  echo "          rule: \"PathPrefix(\`/api\`) || PathPrefix(\`/dashboard\`)\""
  echo "          entryPoints: [traefik-local]"
  echo "          service: api@internal"
  echo
  TRAEFIK_DATA=""
fi

# ============================================================
# 1. WireGuard
# ============================================================
info "[1] WireGuard tunnel → $WG_HOME"
if ping -c1 -W2 "$WG_HOME" &>/dev/null; then
  pass "$WG_HOME is pingable (tunnel up)"
  WG_OK=1
else
  fail "$WG_HOME unreachable — WireGuard tunnel down"
  WG_OK=0
fi

# ============================================================
# 2. Keycloak identity provider health
# ============================================================
# APIARY#981: every investigation UI's 401/302 in the per-vhost loop below
# gets waved through as "expected, sits behind Keycloak" -- but that only
# means *a* redirect happened, not that Keycloak itself is actually healthy.
# A dead/misconfigured Keycloak, a dead gateway, and a dead upstream app can
# all surface as the same 401/302/502 there. This section checks the one
# thing none of those generic per-vhost codes can tell apart: is Keycloak
# itself actually serving the real realm, as opposed to the backend port
# merely being open (TCP-open does not mean Keycloak finished startup) or
# Traefik/Cloudflare returning a plausible-looking code for an unrelated
# reason.
info "[2] Keycloak identity provider health"
KC_HOME_PORT=18080
KC_HOST="auth.${DOMAIN}"
if [[ $WG_OK -eq 1 ]]; then
  if tcp_open "$WG_HOME" "$KC_HOME_PORT"; then
    pass "Keycloak backend $WG_HOME:$KC_HOME_PORT open"
  else
    fail "Keycloak backend $WG_HOME:$KC_HOME_PORT CLOSED — Keycloak container down or not started"
  fi
fi
kc_realm_body=$(curl -sk --max-time 8 --resolve "${KC_HOST}:443:127.0.0.1" \
  "https://${KC_HOST}/realms/apiary" 2>/dev/null)
if [[ -n "$kc_realm_body" ]] && echo "$kc_realm_body" | grep -q '"realm":"apiary"'; then
  pass "https://${KC_HOST}/realms/apiary responds with valid realm metadata — Keycloak itself is healthy"
else
  fail "https://${KC_HOST}/realms/apiary did not return valid realm metadata — Keycloak is down, unhealthy, or the realm import failed (this is NOT the same failure as a per-app 401/302/502 below; every one of those depends on this passing first)"
fi

# ============================================================
# 3. Traefik dynamic.yml — dump active routers
# ============================================================
if [[ -n "$TRAEFIK_DATA" ]]; then
  info "[3] Active Traefik HTTP routers"
  echo "$TRAEFIK_DATA" | python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  routers = d.get('routers', d.get('http', {}).get('routers', {}))
  for name, r in sorted(routers.items()):
    rule = r.get('rule','?')
    svc  = r.get('service','?')
    mids = ','.join(r.get('middlewares',[]) or [])
    status = r.get('status','?')
    print(f'  {name:<35} {rule:<55} svc={svc} mw={mids} [{status}]')
except Exception as e:
  print(f'  parse error: {e}')
" 2>/dev/null || echo "  (python3 unavailable)"
fi

# ============================================================
# 4. Per-vhost checks
# ============================================================
info "[4] Per-vhost checks"

for entry in "${VHOSTS[@]}"; do
  IFS='|' read -r label sub home_port notes <<< "$entry"
  label=$(echo "$label" | xargs)
  sub=$(echo "$sub" | xargs)
  home_port=$(echo "$home_port" | xargs)
  notes=$(echo "$notes" | xargs)
  host="${sub}.${DOMAIN}"

  echo -e "\n  ${BOLD}${host}${NC}  ($notes)"

  # Traefik router present?
  if [[ -n "$TRAEFIK_DATA" ]]; then
    if echo "$TRAEFIK_DATA" | grep -qi "$host"; then
      pass "Traefik router defined for $host"
    else
      fail "NO Traefik router for $host — add router+service to dynamic.yml"
    fi
  fi

  # Home backend port over WireGuard
  if [[ $WG_OK -eq 1 ]]; then
    if tcp_open "$WG_HOME" "$home_port"; then
      pass "Backend $WG_HOME:$home_port open"
    else
      fail "Backend $WG_HOME:$home_port CLOSED — service down on home server?"
    fi
  fi

  # End-to-end via Host header (bypasses Cloudflare, hits Traefik directly)
  http_code=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' \
    --resolve "${host}:443:127.0.0.1" "https://${host}/" 2>/dev/null)

  case "$http_code" in
    200|20*)      pass   "HTTPS → $http_code (OK)" ;;
    401|302|307)  warn   "HTTPS → $http_code (auth redirect — expected IF section [2]'s Keycloak check passed; if that failed, this code means nothing and the real problem is Keycloak itself)" ;;
    404)          warn   "HTTPS → 404 (router matched but app returned not-found)" ;;
    421)          fail   "HTTPS → 421 Misdirected Request — Traefik has NO router for '$host' (or SNI cert mismatch)" ;;
    502)          fail   "HTTPS → 502 Bad Gateway — router exists but backend $WG_HOME:$home_port not responding" ;;
    000|'')       fail   "HTTPS → no response (connection refused or TLS error)" ;;
    *)            warn   "HTTPS → $http_code" ;;
  esac

done

# ============================================================
# Summary + fix guide
# ============================================================
echo
sep
echo -e "  ${BOLD}Results:${NC} ${GREEN}$PASS passed${NC}  ${RED}$FAIL failed${NC}  ${YELLOW}$WARN warnings${NC}"
sep
echo

echo -e "${BOLD}How to read the results:${NC}"
echo "  HTTP 421 → dynamic.yml is missing a router+service entry for that Host"
echo "  HTTP 502 → router is defined but Traefik can't reach the backend"
echo "            Check: is home service running? Is WireGuard up? Correct port?"
echo "  Backend CLOSED → home service not started (check home docker ps)"
echo
echo "  Home ports use 19xxx prefix for honeypot services:"
echo "    evebox.<domain>   → Traefik backend: 10.8.0.2:19636"
echo "    honeypot (dash)   → 10.8.0.2:19092"
echo "    kibana            → 10.8.0.2:19601"
echo "    tanner            → 10.8.0.2:19091"
echo "    snare             → 10.8.0.2:19082"
echo

[[ $FAIL -eq 0 ]]
