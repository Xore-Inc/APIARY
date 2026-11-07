#!/bin/sh
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cat > "$dir/iptables" <<'EOF'
#!/bin/sh
[ "$2" = -n ] && [ "$3" = -L ] && exit 1
printf '%s\n' "$*" >> "$FAKE_LOG"
EOF
chmod +x "$dir/iptables"
export PATH="$dir:$PATH" FAKE_LOG="$dir/iptables.log"
script=$(dirname "$0")/home-wg-forward.sh

printf 'tcp 70000\n' > "$dir/invalid"
if "$script" apply "$dir/invalid" 2>/dev/null; then
    echo 'invalid port unexpectedly accepted' >&2
    exit 1
fi
[ ! -e "$FAKE_LOG" ]

"$script" apply "$(dirname "$0")/hosts/homeserver-wg-ports.txt"
grep -q -- '--ctorigdst 10.8.0.2 --ctorigdstport 3552 -j RETURN' "$FAKE_LOG"
grep -q -- '--ctproto udp --ctorigdst 10.8.0.2 --ctorigdstport 53 -j RETURN' "$FAKE_LOG"
grep -q -- '-A APIARY-WG-IN -m comment --comment .* -j DROP' "$FAKE_LOG"
grep -q -- '-I DOCKER-USER 1 -i wg0 -j APIARY-WG-IN' "$FAKE_LOG"
