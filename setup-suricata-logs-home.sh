#!/usr/bin/env bash
set -euo pipefail

# Install boot ordering and retry support for the read-only VPS log mounts.
# The sshfs entries themselves must already exist in /etc/fstab.

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root: sudo ./setup-suricata-logs-home.sh" >&2
  exit 1
fi

wireguard_unit=${WIREGUARD_UNIT:-wg-quick@wg0.service}
# /opt/stacks/apiary, not the pre-#783-rebrand honeypot-stack -- this must
# match install-homeserver.sh's step_sshfs_mounts fstab entries exactly, or
# findmnt below never finds them. Found live during #787's homeserver
# reinstall (2026-08-09) right after fixing that fstab path in #1087:
# this script still had the old one, so sshfs-boot-ordering started
# failing on "Missing /etc/fstab entry" even though the mounts themselves
# were up. See #1088 for the ~20 other files still carrying this same
# stale path.
# Must stay in step with SSHFS_LOG_DIRS in scripts/install-homeserver.sh --
# that script writes the fstab entries, this one gives them WireGuard-aware
# boot ordering. A directory in one list and not the other either has no
# ordering (races WireGuard at boot) or no fstab entry at all (this script
# then exits on "Missing /etc/fstab entry").
#
# #1742 added zeek, zeek-extract, huginn and traefik for the S5 sensing layer.
mount_paths=(
  /opt/stacks/apiary/logs/suricata
  /opt/stacks/apiary/logs/portbridge
  /opt/stacks/apiary/logs/zeek
  /opt/stacks/apiary/logs/zeek-extract
  /opt/stacks/apiary/logs/huginn
  /opt/stacks/apiary/logs/traefik
)
mount_units=()

for mount_path in "${mount_paths[@]}"; do
  if ! findmnt --fstab --mountpoint "$mount_path" >/dev/null; then
    echo "Missing /etc/fstab entry for $mount_path" >&2
    exit 1
  fi

  # Dockge commonly exposes /opt/stacks as a symlink into /var/dockge/stacks.
  # fstab-generator names the unit from the canonical destination.
  canonical_path=$(readlink -f "$mount_path")
  mount_unit=$(systemd-escape --path --suffix=mount "$canonical_path")
  mount_units+=("$mount_unit")
  install -d -m 0755 "/etc/systemd/system/${mount_unit}.d"
  cat >"/etc/systemd/system/${mount_unit}.d/10-wireguard.conf" <<EOF
[Unit]
Requires=${wireguard_unit}
After=${wireguard_unit}

[Mount]
TimeoutSec=30s
EOF
done

units_block=$(printf "  '%s'\n" "${mount_units[@]}")
paths_block=$(printf "  %s\n" "${mount_paths[@]}")

cat >/usr/local/sbin/honeypot-log-mounts <<EOF
#!/usr/bin/env bash
set -euo pipefail

units=(
${units_block}
)
paths=(
${paths_block}
)

systemctl reset-failed "\${units[@]}" || true
systemctl start "\${units[@]}"

for path in "\${paths[@]}"; do
  mountpoint --quiet "\$path" || {
    echo "Expected mount is unavailable: \$path" >&2
    exit 1
  }
done
EOF
chmod 0755 /usr/local/sbin/honeypot-log-mounts

cat >/etc/systemd/system/honeypot-log-mounts.service <<EOF
[Unit]
Description=Recover honeypot VPS log mounts
Requires=${wireguard_unit}
After=${wireguard_unit} docker.service
Wants=docker.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-log-mounts
ExecStartPost=/bin/sh -c 'for container in hp-evebox hp-filebeat hp-pcap-sync; do docker inspect "\$container" >/dev/null 2>&1 && docker restart "\$container" >/dev/null || true; done'
RemainAfterExit=yes
Restart=on-failure
RestartSec=15s
TimeoutStartSec=2min

[Install]
# wg0 can be stopped and started independently of the host boot. Requires=
# stops this service when wg0 goes down; this WantedBy starts it again when
# wg0 returns, remounting VPS logs and refreshing their container bind mounts.
WantedBy=multi-user.target ${wireguard_unit}
EOF

systemctl daemon-reload
systemctl enable honeypot-log-mounts.service
systemctl restart honeypot-log-mounts.service

echo
systemctl --no-pager --full status honeypot-log-mounts.service
for mount_path in "${mount_paths[@]}"; do
  findmnt --target "$mount_path"
done
