#!/usr/bin/env bash
# Host-local dead-man for phase-1 WireGuard, routes, Arcane and Docker forward policy.
set -euo pipefail
unit=swarm-net-rollback-3589

backup() {
  local dir service path
  umask 077
  install -d -m 0700 /var/lib/apiary-swarm
  dir=$(mktemp -d "/var/lib/apiary-swarm/backup-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
  if [ -d /etc/wireguard ]; then tar -C / -cpf "$dir/wireguard.tar" etc/wireguard; fi
  for service in wg0 wg-fibre wg-lan; do
    systemctl is-active "wg-quick@$service" >"$dir/$service.active" || true
    systemctl is-enabled "wg-quick@$service" >"$dir/$service.enabled" 2>/dev/null || true
  done
  systemctl is-active peer-route.service >"$dir/peer-route.active" || true
  systemctl is-enabled peer-route.service >"$dir/peer-route.enabled" 2>/dev/null || true
  if [ -f /home/xore/.config/systemd/user/arcane-fibre-tunnel.service ]; then
    cp -a /home/xore/.config/systemd/user/arcane-fibre-tunnel.service "$dir/arcane-fibre-tunnel.service"
  fi
  for peer in 10.8.0.2 10.8.0.3; do ip -o route show exact "$peer/32" >"$dir/route-$peer"; done
  systemctl is-active home-wg-forward.service >"$dir/home-wg-forward.active" || true
  systemctl is-enabled home-wg-forward.service >"$dir/home-wg-forward.enabled" 2>/dev/null || true
  case "$(cat "$dir/home-wg-forward.enabled")" in
    enabled|disabled|not-found) ;;
    *) echo 'unsupported home-wg-forward.service enablement state' >&2; exit 1 ;;
  esac
  if iptables -w -n -L APIARY-WG-IN >/dev/null 2>&1 &&
     [ "$(cat "$dir/home-wg-forward.active")" != active ]; then
    echo 'APIARY-WG-IN exists without active home-wg-forward.service; cannot restore its previous state' >&2
    exit 1
  fi
  for path in /etc/systemd/system/home-wg-forward.service /usr/local/libexec/apiary-home-wg-forward /etc/apiary/homeserver-wg-ports.txt; do
    if [ -e "$path" ]; then cp -a --parents "$path" "$dir"; fi
  done
  if [ "$(cat "$dir/home-wg-forward.active")" = active ]; then
    if [ ! -f "$dir/etc/systemd/system/home-wg-forward.service" ] ||
       [ ! -f "$dir/usr/local/libexec/apiary-home-wg-forward" ] ||
       [ ! -f "$dir/etc/apiary/homeserver-wg-ports.txt" ]; then
      echo 'active home-wg-forward.service lacks restorable files' >&2; exit 1;
    fi
  fi
  install -m 0700 "$(dirname "${BASH_SOURCE[0]}")/../firewall/home-wg-forward.sh" "$dir/forward-rollback.sh"
  install -m 0700 "${BASH_SOURCE[0]}" "$dir/rollback.sh"
  echo "$dir"
}

restore_unit() {
  local service="$1" dir="$2"
  if [ "$(cat "$dir/$service.enabled")" = enabled ]; then
    systemctl enable "wg-quick@$service" >/dev/null
  else
    systemctl disable "wg-quick@$service" >/dev/null 2>&1 || true
  fi
  if [ "$(cat "$dir/$service.active")" = active ]; then
    if [ "$service" = wg0 ] && ip link show wg0 >/dev/null 2>&1; then
      wg syncconf wg0 <(wg-quick strip wg0)
    else
      systemctl start "wg-quick@$service"
    fi
  else
    systemctl stop "wg-quick@$service" || true
  fi
}

rollback() {
  local dir="$1" peer path
  local -a route
  [ -d "$dir" ] || { echo "backup missing: $dir" >&2; exit 1; }
  systemctl stop home-wg-forward.service 2>/dev/null || true
  systemctl disable home-wg-forward.service >/dev/null 2>&1 || true
  "$dir/forward-rollback.sh" rollback
  systemctl stop peer-route.service 2>/dev/null || true
  systemctl stop wg-quick@wg-fibre wg-quick@wg-lan 2>/dev/null || true
  if [ -f "$dir/wireguard.tar" ]; then
    tar -C / -xpf "$dir/wireguard.tar"
    find /etc/wireguard -type f -exec chmod 0600 {} +
  fi
  systemctl daemon-reload
  for service in wg0 wg-fibre wg-lan; do restore_unit "$service" "$dir"; done
  for peer in 10.8.0.2 10.8.0.3; do
    ip route del "$peer/32" 2>/dev/null || true
    if [ -s "$dir/route-$peer" ]; then
      read -r -a route <"$dir/route-$peer"
      ip route replace "${route[@]}"
    fi
  done
  if [ -f "$dir/arcane-fibre-tunnel.service" ]; then
    cp -a "$dir/arcane-fibre-tunnel.service" /home/xore/.config/systemd/user/arcane-fibre-tunnel.service
    runuser -u xore -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user daemon-reload
    runuser -u xore -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user restart arcane-fibre-tunnel.service
  fi
  if [ "$(cat "$dir/peer-route.enabled")" = enabled ]; then systemctl enable peer-route.service >/dev/null; else systemctl disable peer-route.service >/dev/null 2>&1 || true; fi
  if [ "$(cat "$dir/peer-route.active")" = active ]; then systemctl start peer-route.service; fi
  for path in /etc/systemd/system/home-wg-forward.service /usr/local/libexec/apiary-home-wg-forward /etc/apiary/homeserver-wg-ports.txt; do
    if [ -e "$dir$path" ]; then
      install -d "$(dirname "$path")"
      cp -a "$dir$path" "$path"
    else
      rm -f "$path"
    fi
  done
  systemctl daemon-reload
  if [ "$(cat "$dir/home-wg-forward.enabled")" = enabled ]; then
    systemctl enable home-wg-forward.service >/dev/null
  fi
  if [ "$(cat "$dir/home-wg-forward.active")" = active ]; then
    systemctl start home-wg-forward.service
  fi
}

case "${1:-}" in
  backup) backup ;;
  arm)
    [ -x "${2:-}/rollback.sh" ] || { echo 'rollback script missing' >&2; exit 1; }
    systemctl is-active --quiet "$unit.timer" && { echo 'rollback already armed' >&2; exit 1; }
    systemctl reset-failed "$unit.service" 2>/dev/null || true
    systemd-run --on-active="${3:-20min}" --unit="$unit" /bin/bash "$2/rollback.sh" rollback "$2"
    ;;
  disarm) systemctl stop "$unit.timer" ;;
  rollback) rollback "$2" ;;
  *) echo 'usage: network-rollback.sh backup|arm DIR [20min]|disarm|rollback DIR' >&2; exit 2 ;;
esac
