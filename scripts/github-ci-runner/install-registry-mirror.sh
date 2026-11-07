#!/usr/bin/env bash
# Install a Docker Hub pull-through cache on this CI executor (#2819).
#
# Why this exists
# ---------------
# Docker Hub meters ANONYMOUS pulls per source IP, at roughly 100 per 6h.
# Every `Containers` matrix row leaves this box through one address, and
# the tree carries 74 non-`scratch` Hub `FROM` lines across 18 images, so
# one cold run spends most of the budget and the next run 429s -- which is
# exactly how #2819 presented, as arbitrary rows failing with
# `toomanyrequests` while their neighbours built fine.
#
# Authenticating (secrets DOCKERHUB_USERNAME / DOCKERHUB_TOKEN, wired into
# containers.yml) moves the meter from the shared IP to the account and is
# the necessary half of the fix. This script is the durable half: a
# `registry:3` proxy that collapses 18 rows x N bases into ONE upstream
# fetch and keeps serving them across runs. It cuts registry traffic to a
# rounding error instead of merely raising the ceiling we hit.
#
# What it does NOT do
# -------------------
# It does not touch /etc/docker/daemon.json. buildx's `docker-container`
# driver runs its own containerd and never reads the host daemon's
# `registry-mirrors`, so a mirror configured there is silently ignored by
# every build in this repo. The mirror reaches buildkit through the
# `buildkitd-config` that containers.yml composes from repo variable
# CI_REGISTRY_MIRROR. Setting up this service without ALSO setting that
# variable changes nothing.
#
# And since #3380 the variable is a claim the workflow VERIFIES rather than
# believes: containers.yml probes `$CI_REGISTRY_MIRROR/v2/` on the executor
# it is actually running on, and writes the mirror into the buildkit config
# only if that answers 200. So on a host that never ran this script the
# variable no longer buys a silently-dead mirror -- the run says so, in its
# annotations and its job summary, and builds without a cache. Which is
# exactly the state #3380 was filed from: the variable was set, no host had
# run this script, and every run pulled from Hub directly with nothing to
# say so. `gh variable set` is therefore only half the install; this script
# is the other half, and the two have to land on the same box.
#
# The address is a per-host fact that a repository variable can only
# approximately express. The `honeypot-ci` pool spans more than one box
# (the homeserver and `precision`, #3379), so one value is right on one and
# wrong on the other. Run this script on every executor that should have a
# mirror; the hosts that do not will report the disagreement themselves.
#
# Usage:
#   sudo scripts/github-ci-runner/install-registry-mirror.sh \
#       --username <hub-user> --token <hub-read-only-PAT>
#
#   # then, once, from a machine with `gh` admin on the repo:
#   gh variable set CI_REGISTRY_MIRROR --repo Xore/APIARY --body '172.16.0.1:5555'
#
# --token accepts a Docker Hub personal access token with "Public repo
# read-only" scope. It is the same account containers.yml authenticates
# as; the proxy needs it because an unauthenticated pull-through cache
# inherits the very anonymous limit we are escaping. It is written to a
# root-only env file, never to the container's `docker inspect` output.
set -euo pipefail

IMAGE=registry:3
NAME=ci-registry-mirror
# Bound to the docker0 gateway, NOT 0.0.0.0. Containers on any bridge
# network can dial a host address, so buildkit reaches it, while nothing
# on the LAN can -- an unauthenticated proxy that pulls using our Hub
# credentials should not be an open relay for the whole subnet.
BIND_ADDR=172.16.0.1
BIND_PORT=5555
# /var is the docker data root and sits near full on this box; the cache
# grows with every distinct base image, so it lives on the roomy spindle.
DATA_DIR=/var/ci-registry-mirror
ENV_FILE=/etc/apiary-registry-mirror.env
UNIT=/etc/systemd/system/ci-registry-mirror.service
# Upstream blobs expire out of the proxy after a week, so a base image
# that stops being referenced does not pin disk forever.
PROXY_TTL=168h

username=""
token=""
while [ $# -gt 0 ]; do
  case "$1" in
    --username) username="$2"; shift 2 ;;
    --token)    token="$2";    shift 2 ;;
    --bind)     BIND_ADDR="${2%%:*}"; BIND_PORT="${2##*:}"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    # Print the header, whatever length it has grown to: everything between
    # the shebang and the first line of code. A hardcoded range silently
    # truncated the usage text the moment #3380 lengthened the header.
    -h|--help)  awk 'NR==1{next} /^set -euo/{exit} {print}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (docker socket, /etc, systemd)" >&2
  exit 1
fi
if [ -z "$username" ] || [ -z "$token" ]; then
  echo "--username and --token are required" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed on this host" >&2
  exit 1
fi
if ! ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -qx "$BIND_ADDR"; then
  echo "warning: $BIND_ADDR is not a local address on this host" >&2
  echo "         buildkit dials it from inside a container, so it must be" >&2
  echo "         an address the host itself answers on." >&2
fi

install -d -m 0755 "$DATA_DIR"

# Credentials live in a root-only env file rather than in the container
# spec, so they stay out of `docker inspect` and out of anyone's shell
# history when the unit is restarted.
umask 077
cat >"$ENV_FILE" <<EOF
REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io
REGISTRY_PROXY_USERNAME=$username
REGISTRY_PROXY_PASSWORD=$token
REGISTRY_PROXY_TTL=$PROXY_TTL
REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY=/var/lib/registry
REGISTRY_LOG_LEVEL=warn
EOF
chmod 0600 "$ENV_FILE"
umask 022

# Authenticate the host daemon before pulling the mirror's own image.
# Bootstrap trap: the reason this script exists is that anonymous pulls
# from this IP are already exhausted, so `docker pull registry:3` is
# itself liable to 429 -- the install failed exactly that way the first
# time. Same credentials the proxy will use upstream.
printf '%s' "$token" | docker login --username "$username" --password-stdin
docker pull "$IMAGE"

cat >"$UNIT" <<EOF
[Unit]
Description=Docker Hub pull-through cache for the APIARY CI executor (#2819)
Documentation=https://github.com/Xore/APIARY/issues/2819
After=docker.service
Requires=docker.service

[Service]
Restart=always
RestartSec=5
# --rm plus an ExecStartPre rm: a container left behind by an ungraceful
# stop otherwise makes every subsequent start fail on a name collision,
# which would look to CI like the mirror simply vanished.
ExecStartPre=-/usr/bin/docker rm -f $NAME
ExecStart=/usr/bin/docker run --rm --name $NAME \\
  --env-file $ENV_FILE \\
  -p $BIND_ADDR:$BIND_PORT:5000 \\
  -v $DATA_DIR:/var/lib/registry \\
  $IMAGE
ExecStop=/usr/bin/docker stop $NAME

[Install]
# Requires=docker.service stops this unit when Docker stops (#3664: the
# mirror stayed down after a Docker restart). Only a WantedBy on
# docker.service starts it again when Docker comes back, so both targets
# are listed. Related failure shape: #3640.
WantedBy=multi-user.target docker.service
EOF

systemctl daemon-reload
systemctl enable --now ci-registry-mirror.service
systemctl restart ci-registry-mirror.service

for _ in $(seq 1 30); do
  if curl -fsS "http://$BIND_ADDR:$BIND_PORT/v2/" >/dev/null 2>&1; then
    echo "mirror answering on http://$BIND_ADDR:$BIND_PORT/v2/"
    echo
    echo "now set the repo variable so containers.yml actually uses it:"
    echo "  gh variable set CI_REGISTRY_MIRROR --repo Xore/APIARY --body '$BIND_ADDR:$BIND_PORT'"
    exit 0
  fi
  sleep 1
done

echo "mirror did not answer on http://$BIND_ADDR:$BIND_PORT/v2/ within 30s" >&2
systemctl --no-pager status ci-registry-mirror.service >&2 || true
exit 1
