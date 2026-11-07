#!/usr/bin/env bash
# Provision the shared local buildx cache root for the CI runner users (#3606).
#
# containers.yml exports each image's layer cache to type=local under
# /var/buildx-cache/<runner>/<image> (#2822, #3605). /var is root-owned, so the
# runner cannot create the root itself, and a runner user outside the shared
# group makes the workflow fall back to the quota-limited type=gha cache.
#
# Idempotent: it only changes what differs and prints nothing but "ok" lines
# when the host is already correct. Run it as root on every CI executor
# (install-homeserver.sh and install-ci-runner.sh both call it).
#
#   BUILDX_CACHE_DIR     cache root (default /var/buildx-cache)
#   BUILDX_CACHE_TARGET  optional real location; BUILDX_CACHE_DIR becomes a
#                        symlink to it (precision keeps the cache on its big
#                        data volume). An existing symlink is always honoured.
#   BUILDX_CACHE_GROUP   shared group (default github-ci-runner)
set -euo pipefail

cache_dir=${BUILDX_CACHE_DIR:-/var/buildx-cache}
target=${BUILDX_CACHE_TARGET:-}
group=${BUILDX_CACHE_GROUP:-github-ci-runner}

[[ ${EUID} -eq 0 ]] || { echo "provision-buildx-cache: run as root" >&2; exit 1; }
changed=0
note() { echo "  $*"; changed=1; }

# 1. shared group
if ! getent group "$group" >/dev/null; then
  groupadd --system "$group"
  note "created group $group"
fi

# 2. membership: every runner user (github-ci-runner, github-ci-runner-N)
mapfile -t users < <(getent passwd | cut -d: -f1 | grep -E '^github-ci-runner(-[0-9]+)?$' | sort)
for u in "${users[@]}"; do
  if ! id -nG "$u" | tr ' ' '\n' | grep -qx "$group"; then
    usermod -aG "$group" "$u"
    note "added $u to $group (running services pick it up on next restart)"
  fi
done

# 3. root directory (optionally a symlink to a bigger volume)
if [[ -L $cache_dir ]]; then
  real=$(readlink -f "$cache_dir")
  if [[ -n $target && $real != "$(readlink -f "$target")" ]]; then
    echo "  warn: $cache_dir points to $real, not $target; leaving it" >&2
  fi
elif [[ -n $target ]]; then
  if [[ -e $cache_dir ]]; then
    echo "provision-buildx-cache: $cache_dir exists and is not a symlink; refusing to replace it with $target" >&2
    exit 1
  fi
  install -d -m 0755 "$(dirname "$target")"
  install -d -m 2775 -o root -g "$group" "$target"
  ln -s "$target" "$cache_dir"
  note "linked $cache_dir -> $target"
  real=$(readlink -f "$cache_dir")
else
  real=$cache_dir
fi
if [[ ! -d $real ]]; then
  install -d -m 2775 -o root -g "$group" "$real"
  note "created $real"
fi
[[ $(stat -c %G "$real") == "$group" ]] || { chgrp "$group" "$real"; note "chgrp $group $real"; }
[[ $(stat -c %a "$real") == 2775 ]] || { chmod 2775 "$real"; note "chmod 2775 $real"; }

# 4. default + access ACL so group members can write whatever any runner creates
acl_ok() { # $1 = "default:" to check the default ACL, "" for the access ACL
  local out pre=$1
  out=$(getfacl -p "$real" 2>/dev/null)
  if [[ -z $pre ]]; then out=$(grep -v '^default:' <<<"$out"); fi
  grep -qx "${pre}group:${group}:rwx" <<<"$out" && return 0
  # the owning group is stored as the unnamed group:: entry
  [[ $(stat -c %G "$real") == "$group" ]] && grep -qx "${pre}group::rwx" <<<"$out"
}
acl_ok "" || { setfacl -m "g:${group}:rwx" "$real"; note "access ACL g:$group:rwx on $real"; }
acl_ok default: || { setfacl -d -m "g:${group}:rwx" "$real"; note "default ACL g:$group:rwx on $real"; }

# 5. repair existing content: directories setgid+group-rwx, files group-rw,
#    all group-owned (a runner with umask 022 leaves 2755/0644 behind)
n=$(find "$real" -type d ! -perm -2070 -print -exec chmod g+rwxs {} + | wc -l)
if (( n )); then note "repaired mode on $n directories"; fi
n=$(find "$real" -type f ! -perm -060 -print -exec chmod g+rw {} + | wc -l)
if (( n )); then note "repaired mode on $n files"; fi
n=$(find "$real" ! -type l ! -group "$group" -print -exec chgrp "$group" {} + | wc -l)
if (( n )); then note "regrouped $n entries to $group"; fi

# 6. prove it: every runner user can create and remove a file in the root and
#    in each existing per-runner directory
fail=0
for u in "${users[@]}"; do
  for d in "$real" "$real"/*/; do
    [[ -d $d ]] || continue
    probe="${d%/}/.probe-3606-$u-$$"
    # shellcheck disable=SC2016  # $1 expands in the inner sh
    if ! runuser -u "$u" -- sh -c 'touch "$1" && rm -f "$1"' sh "$probe" 2>/dev/null; then
      echo "  ERROR: $u cannot create/remove a file in $d" >&2
      fail=1
    fi
  done
done
if (( fail )); then exit 1; fi
(( changed )) || echo "  ok: $cache_dir already correct (${#users[@]} runner users verified)"
echo "  $cache_dir ($real) writable by ${users[*]} (verified)"
