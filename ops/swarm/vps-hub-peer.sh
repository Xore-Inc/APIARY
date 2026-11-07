#!/bin/sh
# vps-hub-peer.sh: spoke peers of the VPS hub wg0 (#3589, #3619).
#
# add/arm/disarm/remove are strictly additive. They never run wg syncconf,
# wg-quick down/up or a wg0 restart, so the existing VPS <-> homeserver peer
# (live sensor forwarding) keeps its session and its roamed endpoint. render
# only prints. Run as root on the VPS.
#
#   vps-hub-peer.sh add    PUBKEY_FILE PSK_FILE ADDR NAME   # live peer + wg0.conf block
#   vps-hub-peer.sh arm    PUBKEY_FILE [10min]              # dead-man: remove peer, restore wg0.conf
#   vps-hub-peer.sh disarm
#   vps-hub-peer.sh remove PUBKEY_FILE CONF_BACKUP          # what the dead-man runs
#   vps-hub-peer.sh render PEERS_FILE [HOME_ADDR [HOME_PUB]] # [Peer] blocks for every spoke
#
# Keys are read from root-only files and never appear on a command line.
set -eu
wg_dir=${APIARY_WG_DIR:-/etc/wireguard}
conf=$wg_dir/wg0.conf
unit=vps-hub-peer-rollback-3589
backup_root=/var/lib/apiary-swarm

# Value of FIELD in the wg0.conf [Peer] block whose AllowedIPs holds ADDR/32.
conf_field() {
  [ -r "$conf" ] || return 0
  awk -v want="$1" -v addr="$2/32" '
    # exit runs END, which flushes again: "done" keeps it to one line.
    function flush() { if (!done && peer && hit && val != "") { print val; done = 1; exit } }
    /^[ \t]*\[/ { flush(); peer = ($0 ~ /^[ \t]*\[Peer\][ \t]*$/); hit = 0; val = ""; next }
    peer {
      line = $0; sub(/^[ \t]+/, "", line)
      key = line; sub(/[ \t]*=.*/, "", key)
      v = line; if (!sub(/^[^=]*=[ \t]*/, "", v)) next
      sub(/[ \t]+$/, "", v)
      if (key == "AllowedIPs") {
        n = split(v, ips, /[ \t]*,[ \t]*/)
        for (i = 1; i <= n; i++) if (ips[i] == addr) hit = 1
      } else if (key == want) val = v
    }
    END { flush() }' "$conf"
}

# A WireGuard key is 32 bytes of base64: 44 characters ending in "=".
is_key() {
  case $1 in *[!A-Za-z0-9+/=]* | '') return 1 ;; esac
  [ "${#1}" -eq 44 ]
}

file_key() { if [ -s "$1" ]; then tr -d ' \t\r\n' <"$1"; fi; }

# Print one [Peer] block per spoke in PEERS_FILE. Keys per spoke, first hit:
#   public key:    HOME_PUB (home spoke only), current wg0.conf, $wg_dir/NAME.pub
#   preshared key: current wg0.conf, $wg_dir/NAME.psk
# wg0.conf first: it is what the running hub was loaded from, and a dead-man
# rollback restores it but not the key files. The files cover a host whose
# wg0.conf does not have the spoke (fresh install, or one that dropped it).
# The home spoke (address HOME_ADDR) falls back to a throwaway placeholder key
# and no PSK, which install-homeserver.sh's step_wireguard_sync_vps_peer
# replaces; a malformed home key is fatal (exit 2). Any other spoke without
# two well-formed keys is skipped with a warning and the exit status is 3;
# the blocks that were printed are still valid.
render() {
  peers_file=$1 home_addr=$2 home_pub=$3
  [ -r "$peers_file" ] || { echo "cannot read hub peer list $peers_file" >&2; return 2; }
  status=0 seen_names=' ' seen_addrs=' ' home_found=
  # The list is read on fd 3 so nothing in the loop (wg, awk) can eat it.
  while read -r name addr extra <&3; do
    case $name in '' | '#'*) continue ;; esac
    case $name in *[!a-z0-9-]*) echo "bad hub peer name '$name' in $peers_file" >&2; return 2 ;; esac
    case $addr in '' | *[!0-9.]*) echo "bad hub address '$addr' for $name in $peers_file" >&2; return 2 ;; esac
    [ -z "$extra" ] || { echo "unexpected column '$extra' for $name in $peers_file" >&2; return 2; }
    case $seen_names in *" $name "*) echo "duplicate hub peer $name" >&2; return 2 ;; esac
    case $seen_addrs in *" $addr "*) echo "duplicate hub address $addr" >&2; return 2 ;; esac
    seen_names="$seen_names$name " seen_addrs="$seen_addrs$addr "

    pub='' psk=''
    if [ "$addr" = "$home_addr" ]; then home_found=1; pub=$home_pub; fi
    [ -n "$pub" ] || pub=$(conf_field PublicKey "$addr")
    [ -n "$pub" ] || pub=$(file_key "$wg_dir/$name.pub")
    psk=$(conf_field PresharedKey "$addr")
    [ -n "$psk" ] || psk=$(file_key "$wg_dir/$name.psk")

    if [ -z "$pub" ] && [ "$addr" = "$home_addr" ]; then
      # Syntactically valid but not the spoke's real key: wg-quick accepts it,
      # it just never handshakes until the real one lands.
      pub=$(wg genkey | wg pubkey)
      echo "No public key for $name ($addr): wrote a placeholder peer entry." >&2
      echo "Run install-homeserver.sh's step_wireguard_sync_vps_peer against this VPS." >&2
    fi
    for k in "$pub" "$psk"; do
      if [ -z "$k" ] || is_key "$k"; then continue; fi
      # Never drop the home spoke: it carries the live sensor forwarding.
      if [ "$addr" = "$home_addr" ]; then
        echo "hub peer $name ($addr): malformed key (still a <PLACEHOLDER>?)" >&2
        return 2
      fi
      echo "WARNING: hub peer $name ($addr) skipped: malformed key" >&2
      status=3; continue 2
    done
    if [ "$addr" != "$home_addr" ] && { [ -z "$pub" ] || [ -z "$psk" ]; }; then
      echo "WARNING: hub peer $name ($addr) skipped: no $wg_dir/$name.pub and $wg_dir/$name.psk," >&2
      echo "  and no block for $addr/32 in $conf. Restore them from the backup (vps/wireguard/)" >&2
      echo "  or re-add the peer with vps-hub-peer.sh add (ops/swarm/README.md)." >&2
      status=3; continue
    fi

    printf '\n[Peer]\n# %s\nPublicKey = %s\n' "$name" "$pub"
    [ -z "$psk" ] || printf 'PresharedKey = %s\n' "$psk"
    printf 'AllowedIPs = %s/32\nPersistentKeepalive = 25\n' "$addr"
  done 3<"$peers_file"
  if [ -n "$home_addr" ] && [ -z "$home_found" ]; then
    echo "home spoke address $home_addr is not in $peers_file" >&2
    return 2
  fi
  return "$status"
}

case "${1:-}" in
  add)
    [ "$#" -eq 5 ] || { echo 'usage: add PUBKEY_FILE PSK_FILE ADDR NAME' >&2; exit 2; }
    pub=$(cat "$2")
    wg set wg0 peer "$pub" preshared-key "$3" allowed-ips "$4/32" persistent-keepalive 25
    if ! grep -qxF "PublicKey = $pub" "$conf"; then
      umask 077
      { printf '\n[Peer]\n# %s\nPublicKey = %s\nPresharedKey = ' "$5" "$pub"
        cat "$3"
        printf 'AllowedIPs = %s/32\nPersistentKeepalive = 25\n' "$4"; } >>"$conf"
    fi
    # Keep the keys where install-vps.sh's render looks for them (#3619).
    for kind in pub psk; do
      if [ "$kind" = pub ]; then src=$2; else src=$3; fi
      [ "$(readlink -f "$src")" = "$(readlink -f "$wg_dir/$5.$kind")" ] ||
        install -m 0600 "$src" "$wg_dir/$5.$kind"
    done
    ;;
  arm)
    [ "$#" -ge 2 ] || { echo 'usage: arm PUBKEY_FILE [10min]' >&2; exit 2; }
    systemctl is-active --quiet "$unit.timer" && { echo 'rollback already armed' >&2; exit 1; }
    install -d -m 0700 "$backup_root"
    saved="$backup_root/wg0.conf.$(date -u +%Y%m%dT%H%M%SZ)"
    install -m 0600 "$conf" "$saved"
    install -m 0700 "$0" "$backup_root/vps-hub-peer.sh"
    systemctl reset-failed "$unit.service" 2>/dev/null || true
    systemd-run --on-active="${3:-10min}" --unit="$unit" \
      /bin/sh "$backup_root/vps-hub-peer.sh" remove "$2" "$saved"
    echo "$saved"
    ;;
  disarm) systemctl stop "$unit.timer" ;;
  remove)
    [ "$#" -eq 3 ] || { echo 'usage: remove PUBKEY_FILE CONF_BACKUP' >&2; exit 2; }
    wg set wg0 peer "$(cat "$2")" remove
    install -m 0600 "$3" "$conf"
    ;;
  render)
    case $# in 2 | 3 | 4) ;; *) echo 'usage: render PEERS_FILE [HOME_ADDR [HOME_PUB]]' >&2; exit 2 ;; esac
    rc=0
    render "$2" "${3:-}" "${4:-}" || rc=$?
    exit "$rc"
    ;;
  *) sed -n '2,15p' "$0" >&2; exit 2 ;;
esac
