#!/usr/bin/env bash
# swarm-membership.sh: phase-1 swarm membership on the WireGuard hub (#3589).
#
# Runs on the admin workstation, the one place with SSH to all three nodes
# (aliases `homeserver`, `precision`, `vps`; passwordless sudo on each), so
# it can also roll membership back automatically when a session dies.
#
#   swarm-membership.sh snapshot          save node/cluster state under $STATE
#   swarm-membership.sh arm [10min]       dead-man: rollback unless disarmed
#   swarm-membership.sh disarm
#   swarm-membership.sh managers          re-init homeserver on 10.8.0.2 (Pause),
#                                         join precision as manager on 10.8.0.3
#   swarm-membership.sh join-vps          join the VPS as worker on 10.8.0.1
#   swarm-membership.sh labels            node labels for later phases
#   swarm-membership.sh rollback          back to phase 0: homeserver sole manager on
#                                         the raw fibre 10.254.250.1, precision worker
#   swarm-membership.sh status
#
# There are no services, stacks, secrets or configs in phase 1, so re-init is
# cheap. Refuse to run if that stops being true. Join tokens travel over
# stdin and are never printed. The VPS is never a manager.
set -euo pipefail

STATE=${STATE:-$HOME/.local/state/apiary-swarm}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
UNIT=swarm-membership-rollback-3589
# Keep the existing pool: Docker's default 10.0.0.0/8 overlaps the 10.8.x tunnels.
POOL=(--default-addr-pool 10.200.0.0/16 --default-addr-pool-mask-length 24)
# Ingress spans the VPS hub path (WireGuard 1420 - VXLAN 50 - ESP headroom 60).
INGRESS_MTU=1310

# Quote each argument for the remote shell: ssh joins its arguments with spaces.
d() { local host=$1; shift; ssh -o ConnectTimeout=10 "$host" "sudo -n docker $(printf '%q ' "$@")"; }
state_of() { d "$1" info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo unreachable; }
log() { echo "swarm-membership: $*"; }

assert_empty() {
  [ "$(state_of homeserver)" = active ] || return 0
  local n
  n=$(d homeserver service ls -q | wc -l)
  n=$((n + $(d homeserver secret ls -q | wc -l) + $(d homeserver config ls -q | wc -l)))
  [ "$n" -eq 0 ] || { echo "swarm has $n services/secrets/configs; re-init would destroy them" >&2; exit 1; }
}

dns_rejoin() { ssh -o ConnectTimeout=10 "$1" sudo -n bash -s -- rejoin < "$SCRIPT_DIR/container-dns.sh"; }
leave() {
  if [ "$(state_of "$1")" != inactive ]; then
    d "$1" swarm leave --force >/dev/null || return
    log "$1 left"
  fi
  dns_rejoin "$1" # swarm leave can erase Compose bridge-network DNS records (#3621).
}

join() { # host token-kind manager-addr advertise-addr [extra args]
  local host=$1 kind=$2 mgr=$3 addr=$4; shift 4
  # Token on stdin, never in this script's output; addresses expand locally on purpose.
  # shellcheck disable=SC2029
  d homeserver swarm join-token -q "$kind" |
    ssh "$host" "sudo -n docker swarm join --token \"\$(cat)\" --advertise-addr $addr --listen-addr $addr:2377 $* $mgr:2377" >/dev/null
  log "$host joined as $kind on $addr"
}

recreate_ingress() {
  printf 'y\n' | d homeserver network rm ingress >/dev/null
  # Removal is asynchronous on the other nodes; give the dispatcher a moment.
  sleep 3
  d homeserver network create --driver overlay --ingress --subnet 10.200.0.0/24 \
    --gateway 10.200.0.1 --opt com.docker.network.driver.mtu="$INGRESS_MTU" ingress >/dev/null
  log "ingress recreated with MTU $INGRESS_MTU"
}

cmd_snapshot() {
  local dir; dir="$STATE/snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$dir"; chmod 700 "$STATE" "$dir"
  for h in homeserver precision vps; do
    d "$h" info --format '{{json .Swarm}}' >"$dir/$h-swarm.json" 2>&1 || true
  done
  d homeserver node ls >"$dir/node-ls.txt" 2>&1 || true
  d homeserver node inspect self >"$dir/homeserver-node.json" 2>&1 || true
  echo "$dir"
}

cmd_managers() {
  assert_empty
  leave precision
  leave homeserver
  d homeserver swarm init --advertise-addr 10.8.0.2 --listen-addr 10.8.0.2:2377 \
    --data-path-addr 10.8.0.2 "${POOL[@]}" >/dev/null
  log "homeserver initialised on 10.8.0.2"
  d homeserver node update --availability pause "$(d homeserver info --format '{{.Swarm.NodeID}}')" >/dev/null
  recreate_ingress
  join precision manager 10.8.0.2 10.8.0.3 --data-path-addr 10.8.0.3
  dns_rejoin homeserver
  dns_rejoin precision
}

cmd_join_vps() {
  [ "$(state_of vps)" = inactive ] || leave vps
  join vps worker 10.8.0.2 10.8.0.1 --data-path-addr 10.8.0.1
  dns_rejoin vps
}

cmd_labels() {
  # Nodes are matched by hub address: the VPS hostname is not unique ("localhost").
  # ssh inside the loop must not read the heredoc, hence </dev/null.
  local addr role edge sensor gpu storage id
  while read -r addr role edge sensor gpu storage; do
    # shellcheck disable=SC2046  # node IDs are single words
    id=$(d homeserver node inspect --format '{{.ID}} {{.Status.Addr}}' $(d homeserver node ls -q </dev/null) </dev/null |
      awk -v a="$addr" '$2 == a {print $1}')
    [ -n "$id" ] || { echo "no node with address $addr" >&2; exit 1; }
    d homeserver node update --label-add role="$role" --label-add edge="$edge" \
      --label-add sensor="$sensor" --label-add gpu="$gpu" --label-add storage="$storage" "$id" </dev/null >/dev/null
    log "labels on $addr"
  done <<'EOF2'
10.8.0.2 manager false true true true
10.8.0.3 manager false false false true
10.8.0.1 worker true false false false
EOF2
}

cmd_rollback() {
  assert_empty
  local failed=0
  leave vps || { log "vps leave or DNS rejoin failed"; failed=1; }
  leave precision || { log "precision leave or DNS rejoin failed"; failed=1; }
  leave homeserver
  d homeserver swarm init --advertise-addr 10.254.250.1 --listen-addr 10.254.250.1:2377 "${POOL[@]}" >/dev/null
  d homeserver node update --availability pause "$(d homeserver info --format '{{.Swarm.NodeID}}')" >/dev/null
  join precision worker 10.254.250.1 10.254.250.2
  dns_rejoin homeserver
  dns_rejoin precision
  log "rolled back to phase 0"
  return "$failed"
}

cmd_status() {
  d homeserver node ls --format '{{.Hostname}} {{.Status}} {{.Availability}} {{.ManagerStatus}}' || true
  for h in homeserver precision vps; do
    echo "$h: $(d "$h" info --format '{{.Swarm.LocalNodeState}} addr={{.Swarm.NodeAddr}} manager={{.Swarm.ControlAvailable}}' 2>&1)"
  done
}

case "${1:-}" in
  snapshot) cmd_snapshot ;;
  arm)
    systemctl --user is-active --quiet "$UNIT.timer" && { echo 'rollback already armed' >&2; exit 1; }
    systemctl --user reset-failed "$UNIT.service" 2>/dev/null || true
    install -d -m 0700 "$STATE"
    install -m 0700 "$0" "$STATE/swarm-membership.sh"
    install -m 0700 "$SCRIPT_DIR/container-dns.sh" "$STATE/container-dns.sh"
    systemd-run --user --on-active="${2:-10min}" --timer-property=AccuracySec=1s --unit="$UNIT" "$STATE/swarm-membership.sh" rollback
    ;;
  disarm) systemctl --user stop "$UNIT.timer" ;;
  managers) cmd_managers ;;
  join-vps) cmd_join_vps ;;
  labels) cmd_labels ;;
  rollback) cmd_rollback ;;
  status) cmd_status ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
