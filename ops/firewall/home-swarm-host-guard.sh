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
# Scope (#3769): only flows Docker's publish DNAT rewrote are dropped
# (`--ctstate DNAT`). On the homeserver the only DNAT entry point is nat
# PREROUTING/OUTPUT `-m addrtype --dst-type LOCAL -j DOCKER`, so a flow is in
# DNAT state exactly when its original destination was one of the host's own
# addresses (LAN, fibre, tunnels, 10.8.0.2, bridge gateways). Container-to-
# container traffic, container egress to a remote host and routed VM traffic
# keep their original destination, are never DNATed, and pass whatever their
# destination port: a guarded port may also be a port that other workloads
# use internally (8080, 8090, 3389).
#
# Local containers may still reach the hub address 10.8.0.2 (LOCAL_IFS,
# default the Docker bridges), as they could while the sensors were Compose
# services published on 10.8.0.2: e.g. the sonicwall-sma decoy's AMC relay hop
# to api-honeypot at 10.8.0.2:18083. The LAN interfaces are not in that list.
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
local_ifs=${LOCAL_IFS:-docker0 docker_gwbridge br-+}
# Part of the applied-state checksum, so a changed rule shape with an
# unchanged port list is not mistaken for the applied state.
rules_version=scope-dnat-1

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
        checksum=$({ cat "$2"; echo "$rules_version"; } | sha256sum | cut -c1-12)
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
        for local_if in $local_ifs; do
            iptables -w -A "$chain" -i "$local_if" -m conntrack --ctorigdst "$hub_addr" -j RETURN
        done
        while read -r proto port extra; do
            case "$proto" in ''|'#'*) continue ;; esac
            iptables -w -A "$chain" -m conntrack --ctstate NEW --ctproto "$proto" --ctorigdstport "$port" \
                -m conntrack --ctstate DNAT \
                -m limit --limit 6/min -j LOG --log-prefix "apiary-swarm-host: " --log-level 4
            iptables -w -A "$chain" -m conntrack --ctstate NEW --ctproto "$proto" --ctorigdstport "$port" \
                -m conntrack --ctstate DNAT -j DROP
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
