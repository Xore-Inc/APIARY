#!/bin/sh
# render-arcane-compose.sh <repo_dir> <out_file> <auto|off>
#
# The one place that decides what honeypot-arcane's compose.yml looks like on
# this host (#3340). install-homeserver.sh's step_arcane_install and
# deploy.yml's "Synchronize honeypot-arcane" both call it, so a deploy can no
# longer write a different file than the installer did.
#
# #2950: the base compose is deliberately GPU-free -- Arcane's GPU-monitoring
# panel needs a hard NVIDIA device reservation, and Docker refuses to start a
# container with one when the nvidia runtime is absent. Arcane materializes
# every other stack, so it must start on a host whose driver is missing or not
# yet loaded. The overlay is merged only after a real GPU container ran, not on
# a flag: "GPU requested" and "GPU usable" differ until the driver's post-
# install reboot.
#
#   auto  merge docker-compose.arcane.gpu.yml iff the nvidia runtime works
#   off   base file only (installer with ENABLE_GPU_STACK=false)
#
# --no-interpolate matters: a plain `config` would resolve ${...} against the
# stack's .env and bake the encryption key and the OIDC secret as literals
# into a world-readable compose.yml.
#
# POSIX sh on purpose: deploy.yml runs this inside docker:cli, which has no bash.
set -eu

repo=$1
out=$2
gpu=${3:-auto}
base="$repo/docker-compose.arcane.yml"
overlay="$repo/docker-compose.arcane.gpu.yml"
smoke_image=${GPU_SMOKE_IMAGE:-nvidia/cuda:12.4.0-base-ubuntu22.04}

case "$gpu" in
  auto|off) ;;
  *) echo "usage: $0 <repo_dir> <out_file> <auto|off>" >&2; exit 2 ;;
esac

if [ "$gpu" = auto ] && [ -f "$overlay" ] \
   && docker run --rm --gpus all "$smoke_image" true >/dev/null 2>&1; then
  if docker compose -f "$base" -f "$overlay" config --no-interpolate > "$out.tmp" 2>/dev/null; then
    mv "$out.tmp" "$out"
    echo "Arcane: GPU monitoring enabled (nvidia runtime verified)"
    exit 0
  fi
  rm -f "$out.tmp"
  echo "Arcane: GPU overlay failed to render -- continuing without GPU monitoring" >&2
elif [ "$gpu" = auto ]; then
  echo "Arcane: no usable NVIDIA runtime -- GPU monitoring left off (see #2950)"
fi
cp "$base" "$out"
