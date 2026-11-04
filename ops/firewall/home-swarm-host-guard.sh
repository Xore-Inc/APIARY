#!/bin/sh
# home-swarm-host-guard.sh: keep swarm host-mode sensor ports off the LAN (#3593).
#
# A Compose sensor publishes on 10.8.0.2 only. A swarm service cannot bind a
# published port to one address: `mode: host` publishes on every address of
# the node, so the same port would also answer on the homeserver LAN
# interfaces, on the fibre tunnels and from local Docker bridges. Published
# ports are DNATed and filtered in FORWARD, so the DOCKER-USER chain is the
# control (firewalld INPUT zones never see them).
#
# For every port in the list, only the hub path stays open: NEW flows from
# the VPS (10.8.0.1) on wg0 to 10.8.0.2, which home-wg-forward.sh
# (APIARY-WG-IN) then checks against its own port list. Every other NEW flow
# to that port is logged (rate-limited) and dropped. Ports not in the list
# are not touched.
#
# Usage (root): home-swarm-host-guard.sh apply PORTS_FILE | rollback | status
# PORTS_FILE rows: `tcp 25` / `udp 69`; '#' comments. The list must name the
# published (host) port of every swarm sensor service; scripts/check-swarm-stacks.py
# fails a sensor stack whose host-mode port is missing from
# ops/firewall/hosts/homeserver-swarm-host-ports.txt.
set -eu
chain=APIARY-SWARM-HOST
hub_if=${HUB_IF:-wg0}
hub_peer=${HUB_PEER:-10.8.0.1/32}
hub_addr=${HUB_ADDR:-10.8.0.2}

usage() { echo 'usage: home-swarm-host-guard.sh apply PORTS_FILE|rollback|status' >&2; exit 2; }

validate() {
    while read -r proto port extra; do
        case "$proto" in ''|'#'*) continue ;; tcp|udp) ;; *) echo "invalid protocol: $proto" >&2; exit 2 ;; esac
        case "$port" in ''|*[!0-9]*) echo "invalid port: $port" >&2; exit 2 ;; esac
        if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] || [ -n "${extra:-}" ]; then
            echo "invalid port row: $proto $port" >&2
            exit 2
        fi
    done < "$1"
}

[ "$#" -ge 1 ] || usage
case "$1" in
    apply)
        { [ "$#" -eq 2 ] && [ -r "$2" ]; } || { echo 'readable port list required' >&2; exit 2; }
        validate "$2"
        checksum=$(sha256sum "$2" | cut -c1-12)
        if iptables -w -n -L "$chain" >/dev/null 2>&1; then
            if iptables -w -C DOCKER-USER -j "$chain" 2>/dev/null &&
               iptables -w -S "$chain" | grep -q -- "--comment $checksum"; then
                exit 0
            fi
            echo "$chain already exists; rollback before changing the port list" >&2
            exit 1
        fi
        iptables -w -N "$chain"
        iptables -w -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
        iptables -w -A "$chain" -i "$hub_if" -s "$hub_peer" -m conntrack --ctorigdst "$hub_addr" -j RETURN
        while read -r proto port extra; do
            case "$proto" in ''|'#'*) continue ;; esac
            iptables -w -A "$chain" -m conntrack --ctstate NEW --ctproto "$proto" --ctorigdstport "$port" \
                -m limit --limit 6/min -j LOG --log-prefix "apiary-swarm-host: " --log-level 4
            iptables -w -A "$chain" -m conntrack --ctstate NEW --ctproto "$proto" --ctorigdstport "$port" -j DROP
        done < "$2"
        iptables -w -A "$chain" -m comment --comment "$checksum" -j RETURN
        iptables -w -I DOCKER-USER 1 -j "$chain"
        ;;
    rollback)
        while iptables -w -C DOCKER-USER -j "$chain" 2>/dev/null; do
            iptables -w -D DOCKER-USER -j "$chain"
        done
        if iptables -w -n -L "$chain" >/dev/null 2>&1; then
            iptables -w -F "$chain"
            iptables -w -X "$chain"
        fi
        ;;
    status)
        iptables -w -S DOCKER-USER
        iptables -w -S "$chain"
        ;;
    *) echo "unknown action: $1" >&2; exit 2 ;;
esac
