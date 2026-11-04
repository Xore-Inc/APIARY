#!/usr/bin/env bash
# debug-backends.sh — Layer-7 backend probe over WireGuard
#
# Traefik shows 502 even when the backend TCP port is open if:
#   - The app crashes after accepting the connection
#   - The app speaks HTTP/2 but Traefik sends HTTP/1.1 (or vice versa)
#   - The app binds to 127.0.0.1 inside the container but the port
#     is forwarded to 0.0.0.0 on the host — so TCP connects but HTTP fails
#   - Wrong path / vhost expected by the backend
#
# This script curls each backend directly over WireGuard so you can
# see the real HTTP response without Traefik in the way.
#
# The probed inventory mirrors vps/traefik/dynamic.yml's own socat-hp-*
# table (see that file's header comment): the port probed here is the
# home-exposed port on the right of that table's "->" (10.8.0.2:<port>),
# not the VPS-side socat listen port on the left. When a new socat-hp-*
# bridge is added there, add its home port here too, or this drifts
# again (#2297).
#
# Usage:  ./debug-backends.sh
#         WG=127.0.0.1 ./debug-backends.sh   # point at a different target

WG="${WG:-10.8.0.2}"
PASS=0; FAIL=0; WARN=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; ((WARN++)); }
info() { echo -e "\n${CYAN}${BOLD}▶ $*${NC}"; }
sep()  { echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"; }

# probe HOST PORT LABEL [PATH]
probe() {
  local host="$1" port="$2" label="$3" path="${4:-/}"
  local url="http://${host}:${port}${path}"
  local out code headers

  out=$(curl -s --max-time 6 -D - -o /dev/null -w "\n__CODE__:%{http_code}" "$url" 2>&1)
  code=$(echo "$out" | grep '__CODE__:' | cut -d: -f2)
  headers=$(echo "$out" | grep -v '__CODE__' | head -8)

  if [[ -z "$code" || "$code" == "000" ]]; then
    fail "$label ($url) — connection failed (app not listening or crashing)"
    echo "    curl output: $(echo "$out" | head -3)"
  elif [[ "$code" =~ ^[1-5][0-9]{2}$ ]]; then
    pass "$label ($url) — HTTP $code"
    # Show server header if present (reveals what's actually serving)
    srv=$(echo "$headers" | grep -i '^server:' | head -1)
    [[ -n "$srv" ]] && echo "    $srv"
  else
    warn "$label ($url) — unexpected response: '$code'"
  fi
}

tcp_open() { timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

echo
sep
echo -e "${CYAN}${BOLD}  Backend layer-7 probe  ·  WireGuard home: $WG${NC}"
sep

# ============================================================
info "HTTP services on home server (10.8.0.2) — always expected up"
# ============================================================

# Honeypot dashboard (502 in Traefik but port open)
probe $WG 19090 "Honeypot dashboard"

# Standalone apiary-dashboard (staging port; 19090 is dashboard-next)
probe $WG 19092 "Standalone apiary-dashboard"

# EveBox (was 302 via Traefik — verify direct)
probe $WG 19636 "EveBox"

# Kibana
probe $WG 19601 "Kibana"

# Tanner
probe $WG 19091 "Tanner web"

# Arkime viewer
probe $WG 19080 "Arkime viewer"

# Keycloak
probe $WG 18080 "Keycloak"

# Arcane (deploy control plane)
probe $WG 3552  "Arcane"

# ============================================================
info "Services expected CLOSED on home (one-shot dependency or opt-in profile)"
# ============================================================

# Snare — depends on the snare-clone one-shot persona installer
echo -e "  Checking snare 10.8.0.2:19082..."
if tcp_open $WG 19082; then
  probe $WG 19082 "Snare honeypot"
else
  warn "Snare (10.8.0.2:19082) CLOSED — container not running"
  echo "    Likely cause: snare-clone (one-shot persona installer, container"
  echo "    hp-snare-clone) has not completed successfully."
  echo "    Fix: on home server run:"
  echo "      docker logs hp-snare-clone"
  echo "      cd /opt/stacks/honeypot-init && docker compose up -d snare-clone"
  echo "      cd /opt/stacks/honeypot-tanner && docker compose up -d snare"
fi

# RevDeck — behind the opt-in 'revdeck' compose profile, not started by default
echo -e "  Checking revdeck 10.8.0.2:19500..."
if tcp_open $WG 19500; then
  probe $WG 19500 "RevDeck"
else
  warn "RevDeck (10.8.0.2:19500) CLOSED — behind the 'revdeck' compose profile, not started by default"
fi

# ============================================================
info "Diagnosing 502s: TCP-open-but-HTTP-broken"
# ============================================================

for spec in "$WG:19090:dashboard" "$WG:19092:apiary-dashboard"; do
  IFS=: read -r h p lbl <<< "$spec"
  if tcp_open "$h" "$p"; then
    # Try with explicit HTTP/1.1
    resp=$(curl -s --max-time 5 --http1.1 -o /dev/null -w '%{http_code}' "http://$h:$p/" 2>/dev/null)
    echo -e "  $lbl HTTP/1.1 forced: HTTP $resp"
    # Try with verbose to see first line of response
    banner=$(curl -s --max-time 5 --http1.1 -i "http://$h:$p/" 2>/dev/null | head -5)
    echo "  $lbl response headers:"
    echo "$banner" | sed 's/^/    /'
  fi
done

# ============================================================
sep
echo -e "  ${BOLD}Results:${NC} ${GREEN}$PASS passed${NC}  ${RED}$FAIL failed${NC}  ${YELLOW}$WARN warnings${NC}"
sep
echo
echo -e "${BOLD}502 root causes to check if backend is TCP-open but HTTP-broken:${NC}"
echo "  1. App binds to 127.0.0.1 inside container — port is forwarded to host"
 echo "     but HTTP layer rejects requests without correct Host header"
echo "  2. Traefik backend URL has wrong scheme (https:// vs http://)"
echo "  3. App expects a specific path prefix (e.g. /dashboard not /)"
echo "  4. Check Traefik dynamic.yml: url: 'http://10.8.0.2:PORT' (not https)"
echo

[[ $FAIL -eq 0 ]]
