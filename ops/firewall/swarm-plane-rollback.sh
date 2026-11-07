#!/usr/bin/env bash
# swarm-plane-rollback.sh <backup-dir>: restore the firewalld config saved by
# `swarm-plane.sh backup` (#3588).
#
# `swarm-plane.sh backup` copies this script into the backup dir as
# rollback.sh, so the dead-man timer (`swarm-plane.sh arm`) never depends on
# the repo checkout. It restores /etc/firewalld, puts the NetworkManager zone
# of each swarm interface back, and reloads firewalld. Docker re-adds its
# bridges to the docker zone on the reload signal; established flows (SSH,
# sensors) survive through conntrack.
#
# Out-of-band path if SSH is lost anyway: the console (homeserver IPMI,
# precision local console), log in, run `systemctl stop firewalld` or this
# script by hand. See docs/SWARM-NETWORK.md, "Rollback".
set -euo pipefail

dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "$dir/etc-firewalld.tar" ] || { echo "rollback: no etc-firewalld.tar in $dir" >&2; exit 1; }

echo "rollback: restoring firewalld config from $dir"
# Remove zones added since the backup, then unpack the saved tree over it.
saved_zones="$(tar -tf "$dir/etc-firewalld.tar" | sed -n 's#^etc/firewalld/zones/\([^/]*\.xml\)$#\1#p')"
for f in /etc/firewalld/zones/*.xml; do
  [ -e "$f" ] || continue
  b="$(basename "$f")"
  grep -qxF -- "$b" <<<"$saved_zones" || { echo "rollback: remove $f"; rm -f -- "$f"; }
done
tar -C / -xpf "$dir/etc-firewalld.tar"
restorecon -R /etc/firewalld 2>/dev/null || true

if [ -s "$dir/nm-zones.txt" ]; then
  while IFS=$'\t' read -r con zone; do
    [ -n "$con" ] || continue
    echo "rollback: nm $con connection.zone='${zone}'"
    nmcli connection modify "$con" connection.zone "$zone" || true
  done <"$dir/nm-zones.txt"
fi

firewall-cmd --reload
# NetworkManager re-asserts its zones after a reload; make the runtime match
# the restored NM value (empty = default zone).
if [ -s "$dir/nm-zones.txt" ]; then
  while IFS=$'\t' read -r con zone; do
    ifc="$(nmcli -g connection.interface-name connection show "$con" 2>/dev/null || true)"
    [ -n "$ifc" ] || continue
    target="${zone:-$(firewall-cmd --get-default-zone)}"
    firewall-cmd --zone="$target" --change-interface="$ifc" >/dev/null || true
  done <"$dir/nm-zones.txt"
fi
echo "rollback: done"
firewall-cmd --get-active-zones
