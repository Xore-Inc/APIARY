#!/usr/bin/env bash
# debug-homeserver.sh — run ON THE HOME SERVER to check all services
# that are tunnelled to the VPS via WireGuard socat containers.
#
# Checks:
#   1. Docker containers running (and healthy)
#   2. Port actually bound on host (netstat/ss)
#   3. HTTP layer-7 response direct to the app
#   4. Whether the port is reachable FROM the VPS side (requires ssh)
#
# Usage:  ./debug-homeserver.sh
#         ./debug-homeserver.sh --vps root@203.0.113.10     # documentation-only example

VPS_SSH="${2:-}"
VPS_SSH_PORT="${VPS_SSH_PORT:-2222}"
HOME_WG_IP="${HOME_WG_IP:-10.8.0.2}"
# Since #258 split the single stack into one Dockge project per
# /opt/stacks/honeypot-<name>, there is no longer one authoritative compose
# file to check -- COMPOSE_FILE (if set) still checks a single file for
# testing/override, otherwise every /opt/stacks/honeypot-*/compose.yml is
# checked in turn.
COMPOSE_FILE="${COMPOSE_FILE:-}"
STACKS_GLOB="${STACKS_GLOB:-/opt/stacks/honeypot-*}"
PASS=0; FAIL=0; WARN=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; ((WARN++)); }
info() { echo -e "\n${CYAN}${BOLD}▶ $*${NC}"; }
sep()  { echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"; }
tcp_open() { timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

# probe LABEL HOST PORT [PATH]
probe() {
  local lbl="$1" host="$2" port="$3" path="${4:-/}"
  local url="http://${host}:${port}${path}"
  local code
  code=$(curl -s --max-time 6 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
  local srv
  srv=$(curl -sI --max-time 4 "$url" 2>/dev/null | grep -i '^server:' | head -1 | xargs)
  case "$code" in
    2*|3*|401) pass "$lbl → HTTP $code  $srv" ;;
    000|"")    fail "$lbl ($url) → no response (app down or wrong port)" ;;
    *)         warn "$lbl → HTTP $code  $srv" ;;
  esac
}

echo
sep
echo -e "${CYAN}${BOLD}  Home server service diagnostic${NC}"
echo -e "  Hostname : $(hostname)"
echo -e "  Date     : $(date)"
sep

# ============================================================
info "[1] WireGuard interface"
# ============================================================
if ip link show wg0 &>/dev/null; then
  WG_IP=$(ip -4 addr show wg0 2>/dev/null | grep 'inet ' | awk '{print $2}')
  pass "wg0 interface up — $WG_IP"
  # Check VPS endpoint reachable
  VPS_WG="10.8.0.1"
  if ping -c1 -W2 "$VPS_WG" &>/dev/null; then
    pass "VPS WireGuard endpoint $VPS_WG pingable"
  else
    fail "VPS WireGuard endpoint $VPS_WG not reachable"
  fi
else
  fail "wg0 interface missing — WireGuard not running?"
fi

# ============================================================
info "[2] Dockge Compose projects"
# ============================================================

# These are deliberately one-shot initialization jobs or an optional profile.
# Every other service in a stack's compose file is expected to remain running.
ONE_SHOT_RE='^(log-init|elasticsearch-setup|honeypot-kibana-setup|arkime-init|snare_clone|geoipupdate)$'

check_compose_file() {
  local compose_file="$1"
  if [[ ! -f "$compose_file" ]]; then
    fail "Compose file missing: $compose_file"
    return
  fi
  if docker compose -f "$compose_file" config -q; then
    pass "Compose configuration valid: $compose_file"
  else
    fail "Compose configuration invalid: $compose_file"
    return
  fi
  while IFS= read -r service; do
    [[ -n "$service" ]] || continue
    if [[ "$service" =~ $ONE_SHOT_RE ]]; then
      info "Compose service $service is one-shot/optional"
      continue
    fi
    cid=$(docker compose -f "$compose_file" ps -q "$service" 2>/dev/null)
    if [[ -z "$cid" ]]; then
      fail "Compose service $service has no container"
      continue
    fi
    state=$(docker inspect --format '{{.State.Status}}' "$cid" 2>/dev/null)
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null)
    if [[ "$state" != "running" ]]; then
      fail "Compose service $service is $state"
    elif [[ "$health" == "unhealthy" ]]; then
      fail "Compose service $service is running but unhealthy"
    else
      pass "Compose service $service running (health: $health)"
    fi
  done < <(docker compose -f "$compose_file" config --services)
}

if [[ -n "$COMPOSE_FILE" ]]; then
  check_compose_file "$COMPOSE_FILE"
else
  shopt -s nullglob
  # shellcheck disable=SC2206 # STACKS_GLOB is meant to expand as a glob here
  stack_dirs=(${STACKS_GLOB}/)
  shopt -u nullglob
  if [[ ${#stack_dirs[@]} -eq 0 ]]; then
    fail "No stacks found matching $STACKS_GLOB"
  else
    for stack_dir in "${stack_dirs[@]}"; do
      info "Stack: $(basename "${stack_dir%/}")"
      check_compose_file "${stack_dir}compose.yml"
    done
  fi
fi

# ============================================================
info "[3] HTTP layer-7 probes (direct to app, no Traefik)"
# ============================================================

echo
probe "EveBox"              "$HOME_WG_IP" 19636
probe "Honeypot dashboard" "$HOME_WG_IP" 19092
probe "Kibana"             "$HOME_WG_IP" 19601
probe "Tanner web"         "$HOME_WG_IP" 19091
probe "Snare"              "$HOME_WG_IP" 19082
probe "Arkime"             "$HOME_WG_IP" 19080
probe "HTTP honeypot"      "$HOME_WG_IP" 19081
probe "API honeypot"       "$HOME_WG_IP" 18083

# ============================================================
info "[4] WireGuard-bound listener inventory"
# ============================================================
echo
if ss -lntup 2>/dev/null | grep -F "$HOME_WG_IP"; then
  pass "Services are listening on the home WireGuard address"
else
  warn "No listeners found on $HOME_WG_IP; check HP_BIND and deployed Dockge stacks"
fi

# ============================================================
if [[ -n "$VPS_SSH" ]]; then
info "[5] Port visibility from VPS ($VPS_SSH)"
# ============================================================
  echo "  SSH-ing to VPS to check which ports are reachable over WireGuard..."
  HOME_WG=$(ip -4 addr show wg0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
  if [[ -z "$HOME_WG" ]]; then
    warn "Could not determine WireGuard IP — skipping VPS-side checks"
  else
    for spec in "19636:evebox" "19092:dashboard" "19601:kibana" "19091:tanner" "19082:snare" "19080:arkime" "19081:http-honeypot" "18083:api-honeypot"; do
      IFS=: read -r port lbl <<< "$spec"
      result=$(ssh -p "$VPS_SSH_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$VPS_SSH" \
        "timeout 3 bash -c '</dev/tcp/${HOME_WG}/${port}' 2>/dev/null && echo OPEN || echo CLOSED" 2>/dev/null)
      if [[ "$result" == "OPEN" ]]; then
        pass "VPS can reach $HOME_WG:$port ($lbl)"
      elif [[ "$result" == "CLOSED" ]]; then
        fail "VPS CANNOT reach $HOME_WG:$port ($lbl) — port not exposed or firewall"
      else
        warn "Could not SSH to VPS to check $port ($lbl)"
      fi
    done
  fi
fi

# ============================================================
sep
echo -e "  ${BOLD}Results:${NC} ${GREEN}$PASS passed${NC}  ${RED}$FAIL failed${NC}  ${YELLOW}$WARN warnings${NC}"
sep
echo
echo "  Re-run with VPS SSH to also verify port visibility from VPS:"
echo "    VPS_SSH_PORT=2222 ./debug-homeserver.sh --vps root@203.0.113.10"
echo

[[ $FAIL -eq 0 ]]
