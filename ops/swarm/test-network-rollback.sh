#!/bin/bash
# Run inside a disposable Debian container: docker run --rm -v "$PWD":/src:ro python:3.12-slim-bookworm bash /src/ops/swarm/test-network-rollback.sh
set -euo pipefail
mkdir -p /tmp/mock/bin /etc/systemd/system /usr/local/libexec /etc/apiary
export PATH=/tmp/mock/bin:$PATH
cat >/tmp/mock/bin/systemctl <<'EOF'
#!/bin/bash
unit=${@: -1}
case "$1" in
  is-active) cat "/tmp/mock/$unit.active" 2>/dev/null || echo inactive; [ "$(cat "/tmp/mock/$unit.active" 2>/dev/null || true)" = active ] ;;
  is-enabled) cat "/tmp/mock/$unit.enabled" 2>/dev/null || echo disabled; [ "$(cat "/tmp/mock/$unit.enabled" 2>/dev/null || true)" = enabled ] ;;
  stop) [ "$unit" = home-wg-forward.service ] && echo inactive >"/tmp/mock/$unit.active"; exit 0 ;;
  start)
    if [ "$unit" = home-wg-forward.service ]; then
      grep -qx old /etc/systemd/system/home-wg-forward.service
      grep -qx old /usr/local/libexec/apiary-home-wg-forward
      grep -qx old /etc/apiary/homeserver-wg-ports.txt
      touch /tmp/mock/chain
      echo 1 >/tmp/mock/jumps
    fi
    echo active >"/tmp/mock/$unit.active" ;;
  enable) echo enabled >"/tmp/mock/$unit.enabled" ;;
  disable) echo disabled >"/tmp/mock/$unit.enabled" ;;
  daemon-reload|reset-failed) ;;
  *) exit 1 ;;
esac
EOF
cat >/tmp/mock/bin/ip <<'EOF'
#!/bin/sh
case "$*" in
  '-o route show exact '*) exit 0 ;;
  'route del '*) exit 0 ;;
  *) exit 1 ;;
esac
EOF
cat >/tmp/mock/bin/iptables <<'EOF'
#!/bin/bash
case "$*" in
  '-w -n -L APIARY-WG-IN') test -e /tmp/mock/chain ;;
  '-w -C DOCKER-USER -i wg0 -j APIARY-WG-IN') test "$(cat /tmp/mock/jumps 2>/dev/null || echo 0)" -gt 0 ;;
  '-w -D DOCKER-USER -i wg0 -j APIARY-WG-IN') echo 0 >/tmp/mock/jumps ;;
  '-w -F APIARY-WG-IN') ;;
  '-w -X APIARY-WG-IN') rm /tmp/mock/chain ;;
  *) echo "unexpected iptables: $*" >&2; exit 1 ;;
esac
EOF
cat >/tmp/mock/bin/systemd-run <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >/tmp/mock/systemd-run.args
EOF
chmod +x /tmp/mock/bin/*

script=/src/ops/swarm/network-rollback.sh
backup=$(bash "$script" backup)
bash "$script" arm "$backup" 5min
grep -qx -- "$backup/rollback.sh" /tmp/mock/systemd-run.args
grep -qx -- '--on-active=5min' /tmp/mock/systemd-run.args
echo new >/etc/systemd/system/home-wg-forward.service
echo new >/usr/local/libexec/apiary-home-wg-forward
echo new >/etc/apiary/homeserver-wg-ports.txt
touch /tmp/mock/chain
echo 1 >/tmp/mock/jumps
bash "$backup/rollback.sh" rollback "$backup"
test ! -e /tmp/mock/chain
test "$(cat /tmp/mock/jumps)" = 0
test ! -e /etc/systemd/system/home-wg-forward.service
test ! -e /usr/local/libexec/apiary-home-wg-forward
test ! -e /etc/apiary/homeserver-wg-ports.txt

echo old >/etc/systemd/system/home-wg-forward.service
echo old >/usr/local/libexec/apiary-home-wg-forward
echo old >/etc/apiary/homeserver-wg-ports.txt
echo active >/tmp/mock/home-wg-forward.service.active
echo enabled >/tmp/mock/home-wg-forward.service.enabled
touch /tmp/mock/chain
echo 1 >/tmp/mock/jumps
backup=$(bash "$script" backup)
echo changed >/etc/systemd/system/home-wg-forward.service
echo changed >/usr/local/libexec/apiary-home-wg-forward
echo changed >/etc/apiary/homeserver-wg-ports.txt
echo disabled >/tmp/mock/home-wg-forward.service.enabled
bash "$backup/rollback.sh" rollback "$backup"
test "$(cat /tmp/mock/home-wg-forward.service.active)" = active
test "$(cat /tmp/mock/home-wg-forward.service.enabled)" = enabled
test -e /tmp/mock/chain
test "$(cat /tmp/mock/jumps)" = 1
echo 'network rollback restores absent and previously active forward policy'
