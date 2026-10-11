#!/usr/bin/env bash
# Check Docker's embedded DNS on Compose bridge networks; #3621.
# Run on the Docker host as root: container-dns.sh check|rejoin
set -euo pipefail

mode=${1:-}
case "$mode" in check|rejoin) ;; *) echo 'usage: container-dns.sh check|rejoin' >&2; exit 2 ;; esac
for tool in docker nsenter python3; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }; done

dns_resolves() {
  local pid
  pid=$(docker container inspect "$1" --format '{{.State.Pid}}') || return 2
  nsenter -t "$pid" -n python3 - "$2" <<'PY'
import socket
import sys

name = sys.argv[1].encode()
query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
query += b''.join(bytes([len(label)]) + label for label in name.split(b'.')) + b'\x00\x00\x01\x00\x01'
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(2)
    sock.sendto(query, ('127.0.0.11', 53))
    answer = sock.recv(512)
    if len(answer) < 12 or answer[:2] != b'\x12\x34':
        sys.exit(2)
    rcode = answer[3] & 15
    if rcode == 3 or (rcode == 0 and not int.from_bytes(answer[6:8], 'big')):
        sys.exit(10)
    if rcode:
        sys.exit(2)
PY
}

networks=$(docker network ls --filter driver=bridge --format '{{.Name}}')
failed=0
checked=0
if [ "$mode" = rejoin ] && docker container inspect hp-elasticsearch >/dev/null 2>&1; then
  if dns_resolves hp-elasticsearch hp-elasticsearch 2>/dev/null; then :; else
    rc=$?
    if [ "$rc" -ne 10 ]; then echo "could not check hp-elasticsearch (probe exit $rc)" >&2; exit 1; fi
    echo 'rejoining hp-elasticsearch before consumers' >&2
    docker restart hp-elasticsearch >/dev/null
    dns_resolves hp-elasticsearch hp-elasticsearch 2>/dev/null || { echo 'hp-elasticsearch DNS rejoin failed' >&2; exit 1; }
  fi
fi
while IFS= read -r network; do
  if [ -z "$network" ] || [ "$network" = bridge ]; then continue; fi
  members=$(docker network inspect "$network" --format '{{range .Containers}}{{.Name}}{{"\n"}}{{end}}')
  [ -n "$members" ] || continue
  compose_members=()
  while IFS= read -r member; do
    [ -n "$member" ] || continue
    # Docker's ingress sandbox is a network endpoint, not a container.
    project=$(docker container inspect "$member" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null) || continue
    if [ -n "$project" ] && [ "$project" != '<no value>' ]; then compose_members+=("$member"); fi
  done <<< "$members"
  for member in "${compose_members[@]}"; do
    checked=$((checked + 1))
    if dns_resolves "$member" "$member" 2>/dev/null; then continue; else rc=$?; fi
    if [ "$rc" -ne 10 ]; then
      echo "$network: could not check $member (probe exit $rc); no restart attempted" >&2
      failed=1
      continue
    fi
    if [ "$mode" = check ]; then
      echo "$network: $member is missing from embedded DNS" >&2
      failed=1
      continue
    fi
    echo "$network: rejoining $member by restarting it" >&2
    if ! docker restart "$member" >/dev/null || ! dns_resolves "$member" "$member" 2>/dev/null; then
      echo "$network: $member is still missing from embedded DNS" >&2
      failed=1
    fi
  done
done <<< "$networks"

echo "checked $checked Compose bridge-network names"
exit "$failed"
