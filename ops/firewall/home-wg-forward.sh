#!/bin/sh
# Restrict Docker-published services on the existing homeserver hub tunnel.
set -eu
chain=APIARY-WG-IN

[ "$#" -ge 1 ] || { echo 'usage: home-wg-forward.sh apply PORTS_FILE|rollback|status' >&2; exit 2; }
case "$1" in
    apply)
        if [ "$#" -ne 2 ] || [ ! -r "$2" ]; then
            echo 'readable port list required' >&2
            exit 2
        fi
        while read -r proto port extra; do
            case "$proto" in ''|'#'*) continue ;; tcp|udp) ;; *) echo "invalid protocol: $proto" >&2; exit 2 ;; esac
            case "$port" in ''|*[!0-9]*) echo "invalid port: $port" >&2; exit 2 ;; esac
            if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] || [ -n "${extra:-}" ]; then
                echo "invalid port row: $proto $port" >&2
                exit 2
            fi
        done < "$2"
        checksum=$(sha256sum "$2" | cut -c1-12)
        if iptables -w -n -L "$chain" >/dev/null 2>&1; then
            if iptables -w -C DOCKER-USER -i wg0 -j "$chain" 2>/dev/null &&
               iptables -w -S "$chain" | grep -q -- "--comment $checksum"; then
                exit 0
            fi
            echo "$chain already exists; rollback before changing the port list" >&2
            exit 1
        fi
        iptables -w -N "$chain"
        iptables -w -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
        while read -r proto port extra; do
            case "$proto" in ''|'#'*) continue ;; tcp|udp) ;; *) echo "invalid protocol: $proto" >&2; exit 2 ;; esac
            iptables -w -A "$chain" -s 10.8.0.1/32 -m conntrack --ctstate NEW --ctproto "$proto" --ctorigdst 10.8.0.2 --ctorigdstport "$port" -j RETURN
        done < "$2"
        iptables -w -A "$chain" -m comment --comment "$checksum" -j DROP
        iptables -w -I DOCKER-USER 1 -i wg0 -j "$chain"
        ;;
    rollback)
        while iptables -w -C DOCKER-USER -i wg0 -j "$chain" 2>/dev/null; do
            iptables -w -D DOCKER-USER -i wg0 -j "$chain"
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
