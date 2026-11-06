#!/usr/bin/env bash
# install-trivy.sh -- put one pinned, checksum-verified `trivy` in front of
# the calling job. #3321.
#
# Two workflows need trivy and they must answer the same question the same
# way:
#
#   * image-security-scan.yml scans every base image the tree's Dockerfiles and
#     compose files pull;
#   * containers.yml scans the digest-bound SBOM generated for the two
#     dashboard images (backend-service; dashboard-next until #3749).
#
# Those are the same CVE question asked of two different artefacts, and
# "are we affected?" is only answerable if the two agree. A version + asset +
# sha256 triple copied into two YAML files is precisely how they stop
# agreeing -- one gets bumped, the other does not, and the same advisory gets
# graded two ways with no visible cause. One installer, one pin.
#
# Pinned version + checksum instead of the upstream contrib/install.sh
# curl-|-sh pattern (SAST-flagged, #3115): download the release tarball
# directly and verify it against a hardcoded sha256 before extracting
# anything. The checksum is the archive's own, taken once at authoring time
# and carried here rather than fetched from a sidecar next to the download --
# a sidecar fetched over the same TLS session as the artefact detects
# transport corruption, which TLS already covers, not a compromised upstream.
#
# Installed into a runner-writable dir rather than /usr/local/bin: the
# self-hosted honeypot-ci runner has no write access to /usr/local/bin
# (install: Permission denied), and $RUNNER_TEMP is writable on both runner
# types.
#
# Usage:
#   install-trivy.sh             install, then prepend the dir to $GITHUB_PATH
#   install-trivy.sh --print-path  install, then print the binary path
#
# Overrides (all three must move together; see the guard below):
#   TRIVY_VERSION  release tag, e.g. 0.74.0
#   TRIVY_SHA256   sha256 of the release tarball for that version
#   TRIVY_BIN_DIR  where to unpack (default $RUNNER_TEMP/trivy-bin)
#   TRIVY_BIN      use this trivy verbatim and skip the fetch (trusted as
#                  given; no version check is applied to it)
set -euo pipefail

# The pin. Bump these together, after checking the release's own checksum
# file: TRIVY_SHA256 is the sha256 of the asset named below.
readonly PINNED_TRIVY_VERSION=0.74.0
readonly PINNED_TRIVY_SHA256=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a

print_path=0
case "${1:-}" in
  '') ;;
  --print-path) print_path=1 ;;
  -h | --help)
    awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
    exit 0
    ;;
  *)
    echo "install-trivy: unknown argument: $1 (expected --print-path)" >&2
    exit 2
    ;;
esac

version=${TRIVY_VERSION:-$PINNED_TRIVY_VERSION}
checksum=${TRIVY_SHA256:-}

# An explicit TRIVY_BIN short-circuits the fetch entirely and is trusted as
# given: a caller that supplies one (a test stub, an operator pointing at an
# internally mirrored build) has already decided which trivy answers the CVE
# question, and re-deriving a version from the pin would only reject it.
if [ -n "${TRIVY_BIN:-}" ]; then
  [ -x "$TRIVY_BIN" ] || {
    echo "install-trivy: TRIVY_BIN=$TRIVY_BIN is not executable" >&2
    exit 1
  }
  got=$("$TRIVY_BIN" --version 2>/dev/null | sed -n 's/^Version: //p')
  if [ "$print_path" -eq 1 ]; then
    printf '%s\n' "$TRIVY_BIN"
  else
    echo "install-trivy: using TRIVY_BIN=$TRIVY_BIN (trivy ${got:-unknown})"
  fi
  exit 0
fi

if [ -z "$checksum" ]; then
  if [ "$version" != "$PINNED_TRIVY_VERSION" ]; then
    # Silent reuse of the pinned checksum for a different version would
    # either fail the sha256sum step with a confusing message or, worse,
    # pass on a collision. Refuse instead.
    echo "install-trivy: TRIVY_VERSION=$version has no pinned sha256 in this script." >&2
    echo "install-trivy: set TRIVY_SHA256 to that release tarball's digest, or update" >&2
    echo "install-trivy: PINNED_TRIVY_VERSION and PINNED_TRIVY_SHA256 together." >&2
    exit 1
  fi
  checksum=$PINNED_TRIVY_SHA256
fi
asset="trivy_${version}_Linux-64bit.tar.gz"

bindir=${TRIVY_BIN_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/trivy-bin}
bin=$bindir/trivy

# Idempotent within a job: a second call (containers.yml installs for the
# SBOM scan, an operator re-runs the script by hand) reuses the binary
# instead of re-downloading 40-odd MiB. Version-matched, so a stale
# RUNNER_TEMP from a previous pin is replaced rather than reused.
if [ -x "$bin" ] && "$bin" --version 2>/dev/null | grep -qx "Version: $version"; then
  echo "install-trivy: reusing $bin (trivy $version)"
else
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  curl -sfL -o "$work/$asset" \
    "https://github.com/aquasecurity/trivy/releases/download/v${version}/${asset}"
  echo "${checksum}  ${work}/${asset}" | sha256sum -c -
  rm -rf -- "$bindir"
  mkdir -p -- "$bindir"
  tar -xzf "$work/$asset" -C "$bindir" trivy
  chmod +x "$bin"
fi

# Fail loudly here rather than three steps later as "trivy: command not
# found", which reads like a PATH problem instead of a bad download.
got=$("$bin" --version 2>/dev/null | sed -n 's/^Version: //p')
if [ "$got" != "$version" ]; then
  echo "install-trivy: $bin reports version '$got', expected '$version'" >&2
  exit 1
fi

if [ "$print_path" -eq 1 ]; then
  printf '%s\n' "$bin"
  exit 0
fi

# GITHUB_PATH only exists inside Actions, and only affects *later* steps --
# which is why scripts/scan-image-sbom.sh uses --print-path instead of
# relying on it. Outside CI, say where the binary landed so the caller can
# add it to PATH itself instead of silently losing the tool.
if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$bindir" >>"$GITHUB_PATH"
  echo "install-trivy: added $bindir to GITHUB_PATH (trivy $version)"
else
  echo "install-trivy: trivy $version installed at $bin"
  echo "install-trivy: GITHUB_PATH is unset (not running under Actions) -- add it to PATH yourself."
fi
