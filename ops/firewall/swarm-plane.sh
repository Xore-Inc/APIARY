#!/usr/bin/env bash
# swarm-plane.sh: least-privilege firewalld rules for the Docker Swarm
# control and data plane (#3588, epic #3587).
#
# The swarm plane is TCP 2377 (manager API / raft), TCP+UDP 7946 (gossip),
# UDP 4789 (VXLAN data plane) and IP protocol 50 (ESP, used by overlays
# created with `--opt encrypted`). It must only be reachable on the
# interfaces listed in SWARM_IFACES (the direct fibre today, the WireGuard
# interfaces after phase 1, #3589) and only from SWARM_PEERS. It must never
# be reachable on a LAN or public interface.
#
# Why a dedicated zone and not source-scoped rich rules in `public`:
# firewalld rich rules cannot match an input interface, so a rule like
# "accept 7946 from 10.254.250.1" in the `public` zone also accepts a
# spoofed packet that arrives on the LAN uplink. On precision the uplink
# runs loose rp_filter (multihome, sysctl 90-apiary-multihome.conf), so a
# LAN host that routes 10.254.250.2 via precision's uplink got a SYN-ACK
# from 7946 (probe 2026-10-10, see docs/SWARM-NETWORK.md). Binding the
# fibre interface into its own zone makes the interface the first match.
#
# Which chain sees the packets: the swarm ports are dockerd listeners and
# the kernel VXLAN socket, not docker-published ports, so they traverse the
# INPUT hook (inet firewalld filter_INPUT), not DOCKER/DOCKER-USER. ESP is
# also INPUT; after xfrm decryption the inner VXLAN packet re-enters INPUT
# on the same interface. Docker-published ports are DNAT + FORWARD and are
# not touched by this script.
#
# Usage (as root, from the repo checkout on the host):
#   swarm-plane.sh backup  hosts/<host>.env        # prints the backup dir
#   swarm-plane.sh arm     <backup-dir> [5min]     # dead-man rollback timer
#   swarm-plane.sh apply   hosts/<host>.env        # idempotent converge
#   swarm-plane.sh status  hosts/<host>.env
#   swarm-plane.sh disarm                          # cancel the timer
#   <backup-dir>/rollback.sh                       # restore by hand
#
# Every subcommand is idempotent. `apply` converges: rules this script owns
# that are no longer in the env file are removed. A rule it does not own
# (any other port or shape, e.g. a hand-added accept) is never removed; it is
# reported as "unmanaged" by apply and status, so it can be reviewed (#3712).
set -euo pipefail

ROLLBACK_UNIT="${ROLLBACK_UNIT:-fw-rollback-3588}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/lib/apiary-firewall}"
LOG_PREFIX_DENY="apiary-swarm-deny: "
LOG_PREFIX_LAN="apiary-swarm-lan: "
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "swarm-plane: $*" >&2; exit 1; }
log() { echo "swarm-plane: $*"; }

need_root() { [ "$(id -u)" -eq 0 ] || die "run as root"; }

load_env() {
  local env="$1"
  [ -f "$env" ] || die "env file not found: $env"
  # shellcheck source=/dev/null
  . "$env"
  : "${SWARM_ZONE:=apiary-swarm}"
  : "${SWARM_IFACES:?SWARM_IFACES must list the swarm-plane interfaces}"
  : "${SWARM_PEERS:?SWARM_PEERS must list the allowed peer sources}"
  : "${SWARM_MANAGER:?SWARM_MANAGER must be 0 or 1}"
  [[ "$SWARM_MANAGER" = 0 || "$SWARM_MANAGER" = 1 ]] || die "SWARM_MANAGER must be 0 or 1"
  : "${LAN_ZONES:=public}"
  for z in $LAN_ZONES; do
    [ "$z" != "$SWARM_ZONE" ] || die "LAN_ZONES must not contain $SWARM_ZONE"
  done
}

# Run a firewall-cmd change against both the permanent and the runtime
# config, so no reload is needed for rule changes (a reload re-applies the
# docker zone bindings and is only used when a zone is created).
fw_both() {
  firewall-cmd --permanent "$@" >/dev/null
  firewall-cmd "$@" >/dev/null
}

# The rules this script owns in the swarm zone, one per line, in the
# canonical form `firewall-cmd --list-rich-rules` prints.
desired_swarm_rules() {
  local peer
  for peer in $SWARM_PEERS; do
    # Manager API and raft: workers have no 2377 listener.
    if [ "$SWARM_MANAGER" = 1 ]; then
      echo "rule family=\"ipv4\" source address=\"$peer\" port port=\"2377\" protocol=\"tcp\" accept"
    fi
    # Node gossip (memberlist): TCP push/pull and UDP probes, both ways.
    echo "rule family=\"ipv4\" source address=\"$peer\" port port=\"7946\" protocol=\"tcp\" accept"
    echo "rule family=\"ipv4\" source address=\"$peer\" port port=\"7946\" protocol=\"udp\" accept"
    # Overlay data plane (VXLAN). Unauthenticated, so peer-only.
    echo "rule family=\"ipv4\" source address=\"$peer\" port port=\"4789\" protocol=\"udp\" accept"
    # IPsec ESP for overlays created with --opt encrypted (BFF, #3579).
    echo "rule family=\"ipv4\" source address=\"$peer\" protocol value=\"esp\" accept"
    # Ops SSH on the admin path, and the Arcane agent's ssh -L to the
    # manager (arcane-fibre-tunnel on precision). SWARM_SSH_PORT overrides
    # port 22 where sshd listens elsewhere (VPS: 2222; 22 is a honeypot).
    if [ -n "${SWARM_SSH_PORT:-}" ]; then
      echo "rule family=\"ipv4\" source address=\"$peer\" port port=\"$SWARM_SSH_PORT\" protocol=\"tcp\" accept"
    else
      echo "rule family=\"ipv4\" source address=\"$peer\" service name=\"ssh\" accept"
    fi
  done
  # ICMP stays open: PMTU discovery across the 9000 / 1420 MTU boundary
  # depends on "fragmentation needed" messages, and ping is the health probe.
  echo 'rule protocol value="icmp" accept'
  echo 'rule protocol value="ipv6-icmp" accept'
  if [ -n "${WG_FIBRE_PEER:-}" ]; then
    echo "rule family=\"ipv4\" source address=\"$WG_FIBRE_PEER\" port port=\"51821\" protocol=\"udp\" accept"
  fi
  # Default deny, logged and rate-limited. Priority 32767 puts it in the
  # zone's _post chain, after every accept above.
  echo "rule priority=\"32767\" log prefix=\"$LOG_PREFIX_DENY\" level=\"info\" limit value=\"10/m\" drop"
}

# Logged, rate-limited drops of the swarm plane on LAN/public zones. The
# zone target would reject these anyway; the explicit rules make the intent
# visible in the config and the journal, and drop instead of reject so a
# scan sees "filtered" with no ICMP answer.
desired_lan_rules() {
  if [ -n "${WG_LAN_PEER:-}" ]; then
    echo "rule family=\"ipv4\" source address=\"$WG_LAN_PEER\" port port=\"51822\" protocol=\"udp\" accept"
  fi
  for p in 2377/tcp 7946/tcp 7946/udp 4789/udp; do
    echo "rule family=\"ipv4\" port port=\"${p%/*}\" protocol=\"${p#*/}\" log prefix=\"$LOG_PREFIX_LAN\" level=\"warning\" limit value=\"6/m\" drop"
  done
  echo "rule protocol value=\"esp\" log prefix=\"$LOG_PREFIX_LAN\" level=\"warning\" limit value=\"6/m\" drop"
}

# Rules in a LAN zone that this script owns or that it replaces: the
# legacy source-scoped swarm accepts (added by hand on 2026-10-09) and its
# own logged drops.
owned_lan_rule() {
  local r="$1"
  case "$r" in
    *"prefix=\"$LOG_PREFIX_LAN\""*) return 0 ;;
    *"port=\"51822\""*" accept") return 0 ;;
  esac
  if [[ "$r" =~ port\ port=\"(2377|7946|4789)\" ]] && [[ "$r" == *" accept" ]]; then
    return 0
  fi
  return 1
}

converge_rules() {
  local zone="$1" desired="$2" owned_fn="$3" current r
  current="$(firewall-cmd --permanent --zone="$zone" --list-rich-rules)"
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    grep -qxF -- "$r" <<<"$desired" && continue
    if "$owned_fn" "$r"; then
      log "$zone: remove $r"
      fw_both --zone="$zone" --remove-rich-rule="$r"
    else
      log "$zone: keep unmanaged $r"
    fi
  done <<<"$current"
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    if ! grep -qxF -- "$r" <<<"$current"; then
      log "$zone: add $r"
      fw_both --zone="$zone" --add-rich-rule="$r"
    fi
  done <<<"$desired"
}

# Rules in the swarm zone that this script owns: exactly the shapes
# desired_swarm_rules can emit, for any source. Everything else in the zone
# was added by someone else and is kept. Until #3712 this was "every rule",
# and an apply on the homeserver deleted a hand-added Arcane accept.
owned_swarm_rule() {
  local r="$1" p
  case "$r" in
    *"prefix=\"$LOG_PREFIX_DENY\""*) return 0 ;;
    'rule protocol value="icmp" accept' | 'rule protocol value="ipv6-icmp" accept') return 0 ;;
    'rule family="ipv4" source address="'*'" protocol value="esp" accept') return 0 ;;
    'rule family="ipv4" source address="'*'" service name="ssh" accept') return 0 ;;
  esac
  for p in 2377/tcp 7946/tcp 7946/udp 4789/udp 51821/udp ${SWARM_SSH_PORT:+$SWARM_SSH_PORT/tcp}; do
    [[ "$r" == 'rule family="ipv4" source address="'*'" port port="'"${p%/*}"'" protocol="'"${p#*/}"'" accept' ]] && return 0
  done
  return 1
}

# Rich rules in a zone that the owner function does not claim.
unmanaged_rules() {
  local zone="$1" owned_fn="$2" r
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    "$owned_fn" "$r" || echo "$r"
  done <<<"$(firewall-cmd --permanent --zone="$zone" --list-rich-rules)"
}

nm_connection_for() {
  # wg-quick devices appear as external NM connections; firewalld owns their zone.
  nmcli -g GENERAL.STATE device show "$1" 2>/dev/null | grep -q 'externally' && return 0
  # A WireGuard interface that is not up yet has no device: no connection.
  nmcli -g GENERAL.CONNECTION device show "$1" 2>/dev/null | head -n1 || true
}

bind_interface() {
  local ifc="$1" con
  ip link show "$ifc" >/dev/null 2>&1 || { log "skip $ifc: interface does not exist yet"; return 0; }
  con="$(nm_connection_for "$ifc")"
  if [ -n "$con" ]; then
    # NetworkManager owns the zone binding of the interfaces it manages.
    if [ "$(nmcli -g connection.zone connection show "$con")" != "$SWARM_ZONE" ]; then
      log "nm: $con connection.zone=$SWARM_ZONE"
      nmcli connection modify "$con" connection.zone "$SWARM_ZONE"
    fi
  elif ! firewall-cmd --permanent --zone="$SWARM_ZONE" --query-interface="$ifc" >/dev/null 2>&1; then
    log "permanent: $ifc -> $SWARM_ZONE"
    firewall-cmd --permanent --zone="$SWARM_ZONE" --change-interface="$ifc" >/dev/null
  fi
  if [ "$(firewall-cmd --get-zone-of-interface="$ifc" 2>/dev/null || true)" != "$SWARM_ZONE" ]; then
    log "runtime: $ifc -> $SWARM_ZONE"
    firewall-cmd --zone="$SWARM_ZONE" --change-interface="$ifc" >/dev/null
  fi
}

cmd_apply() {
  need_root
  load_env "$1"
  if ! firewall-cmd --permanent --get-zones | tr ' ' '\n' | grep -qx "$SWARM_ZONE"; then
    log "create zone $SWARM_ZONE"
    firewall-cmd --permanent --new-zone="$SWARM_ZONE" >/dev/null
    firewall-cmd --permanent --zone="$SWARM_ZONE" \
      --set-description="Swarm control/data plane only (#3588). Default deny, logged." >/dev/null
    # Zone creation is permanent-only; a reload makes it exist at runtime.
    # Docker re-adds its bridges to the docker zone on the reload signal.
    firewall-cmd --reload >/dev/null
  fi
  # target default = reject what no rule accepts; the priority-32767 rule
  # turns that into a logged drop.
  [ "$(firewall-cmd --permanent --zone="$SWARM_ZONE" --get-target)" = "default" ] \
    || firewall-cmd --permanent --zone="$SWARM_ZONE" --set-target=default >/dev/null
  # No services: the stock zone template adds none, and ssh is peer-scoped.
  local s
  for s in $(firewall-cmd --permanent --zone="$SWARM_ZONE" --list-services); do
    log "$SWARM_ZONE: remove service $s"
    fw_both --zone="$SWARM_ZONE" --remove-service="$s"
  done
  converge_rules "$SWARM_ZONE" "$(desired_swarm_rules)" owned_swarm_rule
  local ifc
  for ifc in $SWARM_IFACES; do bind_interface "$ifc"; done
  local z
  for z in $LAN_ZONES; do
    converge_rules "$z" "$(desired_lan_rules)" owned_lan_rule
  done
  cmd_status_loaded
}

cmd_status_loaded() {
  echo "--- zone $SWARM_ZONE"
  firewall-cmd --zone="$SWARM_ZONE" --list-all
  local um
  um="$(unmanaged_rules "$SWARM_ZONE" owned_swarm_rule)"
  if [ -n "$um" ]; then
    echo "--- zone $SWARM_ZONE: unmanaged rules (kept by apply, not in the flow matrix)"
    echo "$um"
  fi
  local ifc
  for ifc in $SWARM_IFACES; do
    printf '%s -> %s\n' "$ifc" "$(firewall-cmd --get-zone-of-interface="$ifc" 2>/dev/null || echo none)"
  done
  local z
  for z in $LAN_ZONES; do
    echo "--- zone $z (swarm-plane rules)"
    firewall-cmd --zone="$z" --list-rich-rules | grep -E 'port="(2377|7946|4789|51822)"|value="esp"' || true
  done
  firewall-cmd --check-config >/dev/null && echo "check-config: ok"
}

cmd_status() { need_root; load_env "$1"; cmd_status_loaded; }

cmd_backup() {
  need_root
  load_env "$1"
  local dir ifc con
  dir="$BACKUP_ROOT/backup-$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -m 0700 "$dir"
  tar -C / -cpf "$dir/etc-firewalld.tar" etc/firewalld
  nft list ruleset >"$dir/nft-ruleset.txt" 2>/dev/null
  : >"$dir/nm-zones.txt"
  for ifc in $SWARM_IFACES; do
    con="$(nm_connection_for "$ifc")"
    [ -n "$con" ] || continue
    printf '%s\t%s\n' "$con" "$(nmcli -g connection.zone connection show "$con")" >>"$dir/nm-zones.txt"
  done
  install -m 0700 "$SCRIPT_DIR/swarm-plane-rollback.sh" "$dir/rollback.sh"
  echo "$dir"
}

cmd_arm() {
  need_root
  local dir="$1" delay="${2:-5min}"
  [ -x "$dir/rollback.sh" ] || die "no rollback.sh in $dir"
  systemctl is-active --quiet "$ROLLBACK_UNIT.timer" && die "rollback timer already armed"
  systemctl reset-failed "$ROLLBACK_UNIT.service" 2>/dev/null || true
  systemd-run --on-active="$delay" --unit="$ROLLBACK_UNIT" /bin/bash "$dir/rollback.sh" "$dir"
  log "rollback armed: $ROLLBACK_UNIT fires in $delay unless disarmed"
}

cmd_disarm() {
  need_root
  systemctl stop "$ROLLBACK_UNIT.timer"
  log "rollback timer $ROLLBACK_UNIT stopped"
}

case "${1:-}" in
  apply)  shift; cmd_apply "$@" ;;
  status) shift; cmd_status "$@" ;;
  backup) shift; cmd_backup "$@" ;;
  arm)    shift; cmd_arm "$@" ;;
  disarm) shift; cmd_disarm ;;
  *) sed -n '2,40p' "$0" | sed -n '/^# Usage/,/^# Every/p'; exit 2 ;;
esac
