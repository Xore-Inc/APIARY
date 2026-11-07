#!/bin/sh
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

cat > "$dir/ping" <<'EOF'
#!/bin/sh
sleep 0.05
while [ "$#" -gt 0 ]; do
    [ "$1" = -I ] && { [ "$2" = "$PING_OK" ]; exit; }
    shift
done
exit 1
EOF
cat > "$dir/ip" <<'EOF'
#!/bin/sh
if [ "$1" = -o ]; then
    printf '%s\n' "${FAKE_ROUTE:-}"
else
    printf '%s\n' "$*" >> "$FAKE_LOG"
fi
EOF
chmod +x "$dir/ping" "$dir/ip"
export PATH="$dir:$PATH" FAKE_LOG="$dir/routes"
script=$(dirname "$0")/peer-route.sh

PING_OK=wg-fibre "$script" 10.8.0.3 10.8.0.2 10.8.1.2 10.8.2.2
grep -qx 'route replace 10.8.0.3/32 dev wg-fibre src 10.8.0.2' "$FAKE_LOG"
: > "$FAKE_LOG"
PING_OK=wg-lan "$script" 10.8.0.3 10.8.0.2 10.8.1.2 10.8.2.2
grep -qx 'route replace 10.8.0.3/32 dev wg-lan src 10.8.0.2' "$FAKE_LOG"
: > "$FAKE_LOG"
FAKE_ROUTE='10.8.0.3 dev wg-fibre scope link src 10.8.0.2' PING_OK=wg-fibre "$script" 10.8.0.3 10.8.0.2 10.8.1.2 10.8.2.2
[ ! -s "$FAKE_LOG" ]
if PING_OK=none "$script" 10.8.0.3 10.8.0.2 10.8.1.2 10.8.2.2 2>/dev/null; then
    echo 'both-down path unexpectedly succeeded' >&2
    exit 1
fi
[ ! -s "$FAKE_LOG" ]

# Watch mode: fibre down from boot switches to LAN after two failed probes.
: > "$FAKE_LOG"
PING_OK=wg-lan INTERVAL=0 timeout 1 "$script" --watch 10.8.0.3 10.8.0.2 10.8.1.2 10.8.2.2 >/dev/null || true
grep -qx 'route replace 10.8.0.3/32 dev wg-lan src 10.8.0.2' "$FAKE_LOG"
if grep -q 'dev wg-fibre' "$FAKE_LOG"; then exit 1; fi
# Watch mode: healthy fibre while routed via LAN switches back.
: > "$FAKE_LOG"
FAKE_ROUTE='10.8.0.3 dev wg-lan scope link src 10.8.0.2' PING_OK=wg-fibre INTERVAL=0 timeout 1 "$script" --watch 10.8.0.3 10.8.0.2 10.8.1.2 10.8.2.2 >/dev/null || true
grep -qx 'route replace 10.8.0.3/32 dev wg-fibre src 10.8.0.2' "$FAKE_LOG"
echo 'peer-route tests passed'
