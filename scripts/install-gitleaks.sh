#!/usr/bin/env bash
# install-gitleaks.sh -- put one pinned, checksum-verified `gitleaks` in front
# of the calling job. #3501.
#
# Same discipline, and for the same reason, as scripts/install-trivy.sh: every
# `uses:` in this repo is pinned to a full commit SHA, and a scanner binary
# is the same class of third-party code. Pinned version + checksum instead of
# the upstream install.sh curl-|-sh pattern (SAST-flagged, #3115) -- download
# the release tarball directly and verify it against a hardcoded sha256 before
# extracting anything. The checksum is the archive's own, carried here rather
# than fetched from a sidecar next to the download: a sidecar fetched over the
# same TLS session as the artefact detects transport corruption, which TLS
# already covers, not a compromised upstream.
#
# Installed into a runner-writable dir rather than /usr/local/bin: the
# self-hosted honeypot-ci runner has no write access to /usr/local/bin
# (install: Permission denied), and $RUNNER_TEMP is writable on both runner
# types -- the same constraint install-trivy.sh works under.
#
# Usage:
#   install-gitleaks.sh              install, then prepend the dir to $GITHUB_PATH
#   install-gitleaks.sh --print-path  install, then print ONLY the binary path,
#                                    on stdout -- progress goes to stderr, so
#                                    `$(install-gitleaks.sh --print-path)` is
#                                    safe to assign
#
# Overrides (all three must move together; see the guard below):
#   GITLEAKS_VERSION  release tag, e.g. 8.30.0
#   GITLEAKS_SHA256   sha256 of the release tarball for that version
#   GITLEAKS_BIN_DIR  where to unpack (default $RUNNER_TEMP/gitleaks-bin)
#   GITLEAKS_BIN      use this gitleaks verbatim and skip the fetch (trusted as
#                     given; no version check is applied to it)
set -euo pipefail

# The pin. Bump these together, after checking the release's own checksum
# file: GITLEAKS_SHA256 is the sha256 of the asset named below.
readonly PINNED_GITLEAKS_VERSION=8.30.0
readonly PINNED_GITLEAKS_SHA256=79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e

print_path=0
case "${1:-}" in
  '') ;;
  --print-path) print_path=1 ;;
  -h | --help)
    awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
    exit 0
    ;;
  *)
    echo "install-gitleaks: unknown argument: $1 (expected --print-path)" >&2
    exit 2
    ;;
esac

version=${GITLEAKS_VERSION:-$PINNED_GITLEAKS_VERSION}
checksum=${GITLEAKS_SHA256:-}

# An explicit GITLEAKS_BIN short-circuits the fetch entirely and is trusted as
# given: a caller that supplies one (a test stub, an operator pointing at an
# internally mirrored build) has already decided which gitleaks answers the
# question, and re-deriving a version from the pin would only reject it.
if [ -n "${GITLEAKS_BIN:-}" ]; then
  [ -x "$GITLEAKS_BIN" ] || {
    echo "install-gitleaks: GITLEAKS_BIN=$GITLEAKS_BIN is not executable" >&2
    exit 1
  }
  got=$("$GITLEAKS_BIN" version 2>/dev/null || true)
  if [ "$print_path" -eq 1 ]; then
    printf '%s\n' "$GITLEAKS_BIN"
  else
    echo "install-gitleaks: using GITLEAKS_BIN=$GITLEAKS_BIN (gitleaks ${got:-unknown})" >&2
  fi
  exit 0
fi

if [ -z "$checksum" ]; then
  if [ "$version" != "$PINNED_GITLEAKS_VERSION" ]; then
    # Silent reuse of the pinned checksum for a different version would
    # either fail the sha256sum step with a confusing message or, worse,
    # pass on a collision. Refuse instead.
    echo "install-gitleaks: GITLEAKS_VERSION=$version has no pinned sha256 in this script." >&2
    echo "install-gitleaks: set GITLEAKS_SHA256 to that release tarball's digest, or update" >&2
    echo "install-gitleaks: PINNED_GITLEAKS_VERSION and PINNED_GITLEAKS_SHA256 together." >&2
    exit 1
  fi
  checksum=$PINNED_GITLEAKS_SHA256
fi
asset="gitleaks_${version}_linux_x64.tar.gz"

bindir=${GITLEAKS_BIN_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gitleaks-bin}
bin=$bindir/gitleaks

# Idempotent within a job: a second call reuses the binary instead of
# re-downloading ~8 MiB. Version-matched, so a stale RUNNER_TEMP from a
# previous pin is replaced rather than reused.
if [ -x "$bin" ] && [ "$("$bin" version 2>/dev/null || true)" = "$version" ]; then
  echo "install-gitleaks: reusing $bin (gitleaks $version)" >&2
else
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  curl -sfL -o "$work/$asset" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${asset}"
  # `sha256sum -c -` prints "<file>: OK" to stdout. Under --print-path that
  # would land in the caller's command substitution and corrupt the assigned
  # path (it became the first PATH element, so gitleaks was not found at all),
  # so the verification's own output is progress and goes to stderr.
  echo "${checksum}  ${work}/${asset}" | sha256sum -c - >&2
  rm -rf -- "$bindir"
  mkdir -p -- "$bindir"
  tar -xzf "$work/$asset" -C "$bindir" gitleaks
  chmod +x "$bin"
fi

# Fail loudly here rather than three steps later as "gitleaks: command not
# found", which reads like a PATH problem instead of a bad download.
got=$("$bin" version 2>/dev/null || true)
if [ "$got" != "$version" ]; then
  echo "install-gitleaks: $bin reports version '$got', expected '$version'" >&2
  exit 1
fi

if [ "$print_path" -eq 1 ]; then
  printf '%s\n' "$bin"
  exit 0
fi

# GITHUB_PATH only exists inside Actions, and only affects *later* steps.
# Outside CI, say where the binary landed so the caller can add it to PATH
# itself instead of silently losing the tool.
if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$bindir" >>"$GITHUB_PATH"
  echo "install-gitleaks: added $bindir to GITHUB_PATH (gitleaks $version)" >&2
else
  echo "install-gitleaks: gitleaks $version installed at $bin" >&2
  echo "install-gitleaks: GITHUB_PATH is unset (not running under Actions) -- add it to PATH yourself." >&2
fi
