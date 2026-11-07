#!/bin/sh
# Keep the other manager's hub address on the direct encrypted path (#3589).
#
# Fibre WireGuard is preferred; LAN WireGuard is used only while the fibre
# tunnel fails; the VPS hub is never used (its wg0 peer does not carry the
# other manager's /32, so a missing route drops instead of detouring).
#
#   peer-route.sh PEER_HUB LOCAL_HUB FIBRE_PEER LAN_PEER          one decision
#   peer-route.sh --watch PEER_HUB LOCAL_HUB FIBRE_PEER LAN_PEER  1 s loop (service)
#
# Watch mode switches to LAN after DOWN_AFTER consecutive fibre probe
# failures and back after UP_AFTER consecutive successes, so a fibre cut
# costs about 3 s instead of the Raft election timeout (about 10 s).
# If both tunnels fail it keeps the last route. It logs only on change.
set -eu

usage() { echo 'usage: peer-route.sh [--watch] PEER_HUB LOCAL_HUB FIBRE_PEER LAN_PEER' >&2; exit 2; }
watch=0
if [ "${1:-}" = --watch ]; then watch=1; shift; fi
[ "$#" -eq 4 ] || usage
peer=$1 local=$2 fibre=$3 lan=$4
DOWN_AFTER=${DOWN_AFTER:-2}
UP_AFTER=${UP_AFTER:-3}
INTERVAL=${INTERVAL:-1}

probe() { ping -n -q -I "$1" -c 1 -W 1 "$2" >/dev/null 2>&1; }
current() { ip -o route show exact "$peer/32" | sed -n 's/.* dev \([^ ]*\).*/\1/p'; }
use() {
    [ "$(current)" = "$1" ] && return 0
    if ip route replace "$peer/32" dev "$1" src "$local"; then
        echo "peer-route: $peer via $1"
    else
        echo "peer-route: cannot route $peer via $1" >&2
        return 1
    fi
}

if [ "$watch" = 0 ]; then
    if probe wg-fibre "$fibre"; then use wg-fibre
    elif probe wg-lan "$lan"; then use wg-lan
    else echo 'neither direct WireGuard path is healthy; retaining the last route' >&2; exit 1
    fi
    exit 0
fi

ok=0 bad=0
while :; do
    if probe wg-fibre "$fibre"; then ok=$((ok + 1)); bad=0; else bad=$((bad + 1)); ok=0; fi
    cur=$(current)
    if [ "$ok" -gt 0 ] && { [ -z "$cur" ] || [ "$ok" -ge "$UP_AFTER" ]; }; then
        use wg-fibre || true
    elif [ "$bad" -ge "$DOWN_AFTER" ] && [ "$cur" != wg-lan ] && probe wg-lan "$lan"; then
        use wg-lan || true
    fi
    # A failed probe already waited about 1 s for its reply.
    [ "$bad" -gt 0 ] || sleep "$INTERVAL"
done
