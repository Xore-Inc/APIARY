#!/usr/bin/env bash
# nm-profiles.sh: NetworkManager profiles of the swarm hosts as code (#3589).
#
#   nm-profiles.sh check hosts/HOST.nm   exit 1 and list drift, change nothing
#   nm-profiles.sh apply hosts/HOST.nm   nmcli connection modify every drifted value
#
# A spec line is `CONNECTION PROPERTY VALUE` (VALUE may be empty). ${VAR}
# placeholders are filled from /etc/apiary/host.env, which stays on the host
# (the homeserver LAN address is not published in this repository).
# `apply` only edits the stored profile. Re-activating a live link is
# disruptive, so it prints the `nmcli connection up` to run inside an
# armed rollback window (see README.md) instead of doing it.
set -euo pipefail

if [ "$#" -ne 2 ] || [ ! -r "$2" ]; then echo 'usage: nm-profiles.sh check|apply SPEC' >&2; exit 2; fi
mode=$1 spec=$2
# shellcheck source=/dev/null
[ -r /etc/apiary/host.env ] && . /etc/apiary/host.env

expand() {
  local v=$1 name
  while [[ $v =~ \$\{([A-Z_]+)\} ]]; do
    name=${BASH_REMATCH[1]}
    [ -n "${!name:-}" ] || { echo "unset placeholder \${$name} (set it in /etc/apiary/host.env)" >&2; exit 2; }
    v=${v//\$\{$name\}/${!name}}
  done
  printf '%s' "$v"
}

drift=0
declare -A touched=()
while read -r con prop value; do
  case "$con" in ''|'#'*) continue ;; esac
  want=$(expand "${value:-}")
  have=$(nmcli -g "$prop" connection show "$con" 2>/dev/null) || { echo "$con: no such connection" >&2; drift=1; continue; }
  # nmcli prints lists as "a,b"; specs use the same form.
  [ "$have" = "$want" ] && continue
  drift=1
  echo "$con $prop: have '$have' want '$want'"
  if [ "$mode" = apply ]; then
    nmcli connection modify "$con" "$prop" "$want"
    touched[$con]=1
  fi
done <"$spec"

if [ "$mode" = apply ] && [ "${#touched[@]}" -gt 0 ]; then
  echo "modified: ${!touched[*]}; activate inside an armed rollback window with: nmcli connection up <name>"
fi
[ "$mode" = apply ] || exit "$drift"
