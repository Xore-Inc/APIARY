#!/usr/bin/env bash
# Verify that branding/vendor/xore-theme/theme.css is still the exact
# stylesheet recorded in branding/vendor/xore-theme/theme.lock.
#
# The hash check is offline and always runs. When the upstream repository is
# reachable (or a local clone is passed as $1) the vendored copy is also
# compared byte-for-byte against the pinned commit, which catches a lock file
# that was edited without re-copying the stylesheet.
#
# Usage: scripts/check-vendored-theme.sh [path-to-local-theme-clone]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# #1659: repointed at frontend-next after the Go dashboard's retirement;
# #3749: moved to branding/vendor/xore-theme when frontend-next was removed.
# The copy now backs the branding token check (branding/scripts/check_theme_sync.py).
lock="$root/branding/vendor/xore-theme/theme.lock"
vendored="$root/branding/vendor/xore-theme/theme.css"

[ -f "$lock" ] || { echo "missing $lock" >&2; exit 1; }
[ -f "$vendored" ] || { echo "missing $vendored" >&2; exit 1; }

read_pin() {
  sed -n "s/^$1=//p" "$lock" | head -n1
}

repository="$(read_pin repository)"
commit="$(read_pin commit)"
expected="$(read_pin sha256)"

if [ -z "$commit" ] || [ -z "$expected" ]; then
  echo "theme.lock must define commit= and sha256=" >&2
  exit 1
fi

actual="$(sha256sum "$vendored" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
  echo "branding/vendor/xore-theme/theme.css does not match theme.lock" >&2
  echo "  expected sha256 $expected (Xore/theme@${commit:0:7})" >&2
  echo "  actual   sha256 $actual" >&2
  echo "Re-run scripts/sync-theme.sh to vendor the pinned stylesheet." >&2
  exit 1
fi

echo "hash ok: theme.css matches Xore/theme@${commit:0:7}"

upstream=""
clone="${1:-}"
if [ -n "$clone" ] && [ -d "$clone/.git" ]; then
  upstream="$(mktemp)"
  if ! git -C "$clone" show "$commit:theme.css" >"$upstream" 2>/dev/null; then
    echo "local clone $clone does not contain commit $commit — fetch it first" >&2
    rm -f "$upstream"
    exit 1
  fi
elif command -v curl >/dev/null 2>&1; then
  raw="${repository/https:\/\/github.com/https://raw.githubusercontent.com}/$commit/theme.css"
  upstream="$(mktemp)"
  if ! curl -fsSL --max-time 30 "$raw" -o "$upstream"; then
    echo "note: upstream unreachable, hash check only" >&2
    rm -f "$upstream"
    upstream=""
  fi
fi

if [ -n "$upstream" ]; then
  if ! cmp -s "$upstream" "$vendored"; then
    echo "branding/vendor/xore-theme/theme.css differs from Xore/theme@$commit" >&2
    diff -u "$upstream" "$vendored" | head -n 40 >&2 || true
    rm -f "$upstream"
    exit 1
  fi
  rm -f "$upstream"
  echo "upstream ok: byte-identical to Xore/theme@${commit:0:7}"
fi
