#!/usr/bin/env bash
# swarm-membership.sh: swarm membership on the WireGuard hub (#3589, #3712).
#
# Runs on the admin workstation, the one place with SSH to all three nodes
# (aliases `homeserver`, `precision`, `vps`; passwordless sudo on each).
#
# Topology since 2026-10-19 (#3587, #3712): three managers on their hub
# addresses, homeserver 10.8.0.2 (availability Pause, #3583), precision
# 10.8.0.3 and the VPS 10.8.0.1. Raft keeps quorum with any one of them down.
# The VPS keeps the node label role=worker on purpose, so placements on
# `node.labels.role == manager` never land on the edge host.
#
# Day to day (safe on a swarm with services):
#   swarm-membership.sh status            node list from any manager, per-host state
#   swarm-membership.sh snapshot          save node/cluster state under $STATE
#   swarm-membership.sh join HOST [manager|worker]
#                                         join HOST on its hub address through a live
#                                         manager (default manager), or promote it if
#                                         it is already a worker; homeserver is paused
#   swarm-membership.sh labels            (re)apply the node labels
#   swarm-membership.sh restore-quorum SURVIVOR --yes
#                                         lost quorum: back up SURVIVOR's raft state,
#                                         then --force-new-cluster on its hub address
#   swarm-membership.sh forget HOST --yes remove HOST's dead node entry (after
#                                         restore-quorum, before HOST rejoins)
# Runbook: docs/HOMESERVER-VAR-RECOVERY.md part 12, ops/swarm/README.md.
#
# Bootstrap only (each refuses once the swarm has services, secrets or configs):
#   swarm-membership.sh managers          re-init homeserver on 10.8.0.2 (Pause),
#                                         join precision as manager on 10.8.0.3
#   swarm-membership.sh join-vps          join the VPS as manager on 10.8.0.1
#   swarm-membership.sh arm [10min]       dead-man: rollback unless disarmed
#   swarm-membership.sh disarm
#   swarm-membership.sh rollback          back to phase 0: homeserver sole manager on
#                                         the raw fibre 10.254.250.1, precision worker
#
# Join tokens travel over stdin and are never printed.
set -euo pipefail

STATE=${STATE:-$HOME/.local/state/apiary-swarm}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
UNIT=swarm-membership-rollback-3589
# Keep the existing pool: Docker's default 10.0.0.0/8 overlaps the 10.8.x tunnels.
POOL=(--default-addr-pool 10.200.0.0/16 --default-addr-pool-mask-length 24)
# Ingress spans the VPS hub path (WireGuard 1420 - VXLAN 50 - ESP headroom 60).
INGRESS_MTU=1310
HOSTS=(homeserver precision vps)

# Quote each argument for the remote shell: ssh joins its arguments with spaces.
d() { local host=$1; shift; ssh -o ConnectTimeout=10 "$host" "sudo -n docker $(printf '%q ' "$@")"; }
state_of() { d "$1" info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo unreachable; }
log() { echo "swarm-membership: $*"; }
die() { echo "swarm-membership: $*" >&2; exit 1; }

# Hub (plane) address of a host. Never a LAN or public address.
addr_of() {
  case "$1" in
    homeserver) echo 10.8.0.2 ;;
    precision) echo 10.8.0.3 ;;
    vps) echo 10.8.0.1 ;;
    *) die "unknown host '$1' (homeserver, precision, vps)" ;;
  esac
}

# The first host whose manager answers `node ls`, i.e. one in a cluster with
# quorum. Prints nothing and returns 1 when no manager has quorum.
mgr() {
  local h
  for h in "${HOSTS[@]}"; do
    if d "$h" node ls -q >/dev/null 2>&1 </dev/null; then echo "$h"; return 0; fi
  done
  return 1
}
need_mgr() { mgr || die "no manager with quorum (see restore-quorum)"; }

# Node ID by hub address: the VPS hostname is not unique ("localhost").
node_id_by_addr() {
  local m=$1 a=$2
  # shellcheck disable=SC2046  # node IDs are single words
  d "$m" node inspect --format '{{.ID}} {{.Status.Addr}}' $(d "$m" node ls -q </dev/null) </dev/null |
    awk -v a="$a" '$2 == a {print $1}'
}

assert_empty() {
  local m n
  m=$(mgr) || return 0
  n=$(d "$m" service ls -q | wc -l)
  n=$((n + $(d "$m" secret ls -q | wc -l) + $(d "$m" config ls -q | wc -l)))
  [ "$n" -eq 0 ] || die "swarm has $n services/secrets/configs; re-init would destroy them"
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
  local host=$1 kind=$2 maddr=$3 addr=$4 src; shift 4
  src=$(need_mgr)
  # Token on stdin, never in this script's output; addresses expand locally on purpose.
  # shellcheck disable=SC2029
  d "$src" swarm join-token -q "$kind" |
    ssh "$host" "sudo -n docker swarm join --token \"\$(cat)\" --advertise-addr $addr --listen-addr $addr:2377 $* $maddr:2377" >/dev/null
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
  local dir m h
  dir="$STATE/snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$dir"; chmod 700 "$STATE" "$dir"
  for h in "${HOSTS[@]}"; do
    d "$h" info --format '{{json .Swarm}}' >"$dir/$h-swarm.json" 2>&1 || true
    d "$h" node inspect self >"$dir/$h-node.json" 2>&1 || true
  done
  if m=$(mgr); then
    d "$m" node ls >"$dir/node-ls.txt" 2>&1 || true
    d "$m" service ls >"$dir/service-ls.txt" 2>&1 || true
  fi
  echo "$dir"
}

# Join HOST through any live manager, or promote it if it is already a worker.
cmd_join() {
  local host=${1:?usage: join HOST [manager|worker]} kind=${2:-manager} m addr id
  [[ $kind = manager || $kind = worker ]] || die "kind must be manager or worker"
  addr=$(addr_of "$host")
  m=$(need_mgr)
  if [ "$(state_of "$host")" = active ]; then
    [ "$kind" = manager ] || die "$host is already a swarm member"
    id=$(node_id_by_addr "$m" "$addr")
    [ -n "$id" ] || die "$host is active but no node has address $addr"
    d "$m" node promote "$id" >/dev/null
    log "$host promoted to manager"
  else
    join "$host" "$kind" "$(addr_of "$m")" "$addr" --data-path-addr "$addr"
    id=$(node_id_by_addr "$m" "$addr")
  fi
  # homeserver takes no tasks until its stacks are rebuilt (#3583). Set it
  # active again before Ollama/Galah start: a paused node cannot attach Compose
  # containers to an overlay (#3722).
  if [ "$host" = homeserver ]; then
    d "$m" node update --availability pause "$id" >/dev/null
    log "homeserver paused for its rebuild; set it active before Ollama/Galah start (#3722)"
  fi
  dns_rejoin "$host"
  log "next: swarm-membership.sh labels, then status"
}

# Lost quorum (e.g. #3708): keep SURVIVOR's raft state (services, configs,
# secrets, labels) and make it a one-node cluster on its hub address.
cmd_restore_quorum() {
  local host=${1:?usage: restore-quorum SURVIVOR --yes} addr m st
  [ "${2:-}" = --yes ] || die "restore-quorum rewrites the raft membership; re-run with --yes"
  addr=$(addr_of "$host")
  if m=$(mgr); then die "$m still answers with quorum; nothing to restore"; fi
  st=$(d "$host" info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')
  [ "$st" = "active true" ] || die "$host is '$st'; want 'active true' (a manager with raft state)"
  # Without a raft WAL, --force-new-cluster would start an empty swarm.
  # shellcheck disable=SC2016  # expanded on the remote host
  ssh -o ConnectTimeout=10 "$host" 'sudo -n sh -c '\''[ -n "$(ls -A /var/lib/docker/swarm/raft/wal-v3-encrypted 2>/dev/null)" ]'\''' ||
    die "$host has no raft WAL under /var/lib/docker/swarm"
  # The archive holds the node key, which carries the raft data key: root-only
  # on the survivor, never copied off by this script.
  ssh -o ConnectTimeout=10 "$host" 'sudo -n bash -s' <<'EOF'
set -eu
umask 077
f=/root/swarm-backup-$(date -u +%Y%m%dT%H%M%SZ).tgz
tar czf "$f" -C /var/lib/docker swarm
sha256sum "$f"
EOF
  d "$host" swarm init --force-new-cluster --advertise-addr "$addr" \
    --listen-addr "$addr:2377" --data-path-addr "$addr" >/dev/null
  log "$host is a one-node cluster on $addr; live nodes reconnect within about 20 s"
  d "$host" node ls
  log "next: forget each dead node, firewall its host, then join it again"
}

# Remove a dead host's node entry so it can rejoin cleanly.
cmd_forget() {
  local host=${1:?usage: forget HOST --yes} m id st
  [ "${2:-}" = --yes ] || die "forget removes a node entry; re-run with --yes"
  m=$(need_mgr)
  [ "$m" != "$host" ] || die "$host is the manager answering; it is not dead"
  id=$(node_id_by_addr "$m" "$(addr_of "$host")")
  if [ -z "$id" ]; then log "no node entry for $host"; return 0; fi
  st=$(d "$m" node inspect --format '{{.Status.State}}' "$id")
  [ "$st" != ready ] || die "$host ($id) is ready; refusing to remove a live node"
  d "$m" node rm --force "$id" >/dev/null
  log "removed $host ($id, was $st)"
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
  # Bootstrap path. The VPS joins as the third manager (#3712); it was a
  # worker until 2026-10-19.
  assert_empty
  [ "$(state_of vps)" = inactive ] || leave vps
  join vps manager 10.8.0.2 10.8.0.1 --data-path-addr 10.8.0.1
  dns_rejoin vps
}

cmd_labels() {
  # Nodes are matched by hub address: the VPS hostname is not unique ("localhost").
  # ssh inside the loop must not read the heredoc, hence </dev/null.
  # role is a placement label, not the raft role: the VPS is a raft manager
  # but keeps role=worker, so `node.labels.role == manager` skips the edge host.
  local addr role edge sensor gpu storage id m
  m=$(need_mgr)
  while read -r addr role edge sensor gpu storage; do
    id=$(node_id_by_addr "$m" "$addr" </dev/null)
    [ -n "$id" ] || die "no node with address $addr"
    d "$m" node update --label-add role="$role" --label-add edge="$edge" \
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
  local m h
  if m=$(mgr); then
    echo "via $m:"
    d "$m" node ls --format '{{.Hostname}} {{.Status}} {{.Availability}} {{.ManagerStatus}}' || true
  else
    echo "no manager answers with quorum"
  fi
  for h in "${HOSTS[@]}"; do
    echo "$h: $(d "$h" info --format '{{.Swarm.LocalNodeState}} addr={{.Swarm.NodeAddr}} manager={{.Swarm.ControlAvailable}}' 2>&1)"
  done
}

case "${1:-}" in
  snapshot) cmd_snapshot ;;
  arm)
    assert_empty
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
  join) shift; cmd_join "$@" ;;
  labels) cmd_labels ;;
  restore-quorum) shift; cmd_restore_quorum "$@" ;;
  forget) shift; cmd_forget "$@" ;;
  rollback) cmd_rollback ;;
  status) cmd_status ;;
  *) sed -n '2,37p' "$0"; exit 2 ;;
esac
