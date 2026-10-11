#!/usr/bin/env bash
# Shared provisioning framework for scripts/install-homeserver.sh and
# scripts/install-vps.sh -- #1609 Phase 5.
#
# Both installers used to carry their own copy of this: status tracking,
# marker-based resumability, retry-with-backoff, and the end-of-run summary.
# install-vps.sh's header claimed the two were "identical ... deliberately not
# reimplemented differently". They were not: its with_retry used
# `if "$@"; then return 0; fi` followed by `rc=$?`, and an if/fi that takes
# neither branch exits 0, so rc read 0 for a FAILED command and the last
# attempt returned success. Every with_retry call in that script -- package
# installs, git clone, cert restore, compose up -- was structurally incapable
# of reporting failure. That is #787's defect, fixed on the homeserver side in
# August and never ported. #2963 fixed the copy and landed a parity test;
# this file removes the second copy so there is nothing left to drift.
#
# Sourced, never executed. Each installer sets its own identity before
# sourcing (see install_common_require below):
#
#   INSTALLER_NAME          used in the summary banner and messages
#   LOG_DIR / MARKER_DIR    per-installer, deliberately not shared
#   SUMMARY_WIDTH           step-id column width in the summary (optional)
#   INSTALLER_CONF_EXAMPLE  named in --help and in config errors
#
# An installer may define print_summary_extra() to append its own trailer to
# the summary (install-vps.sh prints the fresh WireGuard public key there).
#
# ---------------------------------------------------------------------------
# Why this is safe to source, given how these scripts actually run
# ---------------------------------------------------------------------------
# The extraction was deferred once because install-homeserver.sh does not only
# run from the checkout: systemd under SELinux cannot exec it from /home or
# /root, so the live homeserver runs a copy at
# /usr/local/sbin/apiary-install-homeserver.sh. A bare
# `source "$(dirname "$0")/lib/install-common.sh"` breaks there -- and under
# `set -uo pipefail` (no -e) a failed source only warns, after which every
# framework call becomes "command not found" and the run limps on. That is a
# worse failure than the drift it fixes, which is why it wasn't landed blind.
#
# So the resolver in each installer searches, in order:
#   1. $APIARY_INSTALL_LIB          -- explicit override
#   2. <dir of the script>/lib/     -- running from a checkout
#   3. /usr/local/lib/apiary/       -- running from an installed copy
# and hard-exits with an actionable message if none are readable, instead of
# continuing into a half-defined shell. `--install-self` puts both the script
# and this library in place so the copy-out path cannot lose one of the two.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "install-common.sh is a library; source it, don't execute it." >&2
  exit 2
fi

# Bumped when a sourcing script needs to require a newer library than an
# installed copy at /usr/local/lib/apiary/ might be.
# shellcheck disable=SC2034  # read by sourcing scripts, not by this file
INSTALL_COMMON_VERSION=1

declare -A STEP_STATUS
declare -a STEP_ORDER
RUN_LOG=""
FORCE_FROM=""
RESET_MARKERS=0
FORCE_ACTIVE=0
CONFIG_FILE=""

# install_common_require -- fail loudly if the sourcing script skipped its
# identity block, rather than producing an unnamed summary against an empty
# marker dir.
install_common_require() {
  local missing=()
  for var in INSTALLER_NAME LOG_DIR MARKER_DIR; do
    [[ -n "${!var:-}" ]] || missing+=("$var")
  done
  if (( ${#missing[@]} )); then
    echo "install-common.sh: sourcing script did not set: ${missing[*]}" >&2
    exit 2
  fi
}

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*"; }

# with_retry <max_attempts> <sleep_base_seconds> -- cmd args...
# Retries transient (network/pull) failures with linear backoff. Does NOT
# swallow the final failure -- after the last attempt the real exit code
# propagates so run_step still records FAILED correctly.
with_retry() {
  local max="$1" base="$2"; shift 2
  local attempt=1 rc=0
  while (( attempt <= max )); do
    # Must be `"$@" && return 0`, NOT `if "$@"; then return 0; fi` -- when a
    # plain if/fi (no else) takes neither branch, POSIX defines the if
    # statement's own exit status as zero regardless of the condition's real
    # exit code. `rc=$?` on the next line then reads 0 for a command that just
    # failed, so with_retry can never detect failure for ANY wrapped command.
    # Found live twice: #787's homeserver reinstall (every scp in
    # step_restore_env_files was failing while with_retry reported success for
    # all 17 stacks) and again in install-vps.sh during #1609's rebuild.
    # `&&` short-circuits without touching $? when the command fails, so the
    # following `rc=$?` captures the real code.
    "$@" && return 0
    rc=$?
    if (( attempt == max )); then
      return "$rc"
    fi
    local wait=$(( base * attempt ))
    echo "attempt $attempt/$max failed (exit $rc), retrying in ${wait}s: $*" >&2
    sleep "$wait"
    attempt=$(( attempt + 1 ))
  done
  return "$rc"
}

run_step() {
  local id="$1" desc="$2"
  shift 2
  STEP_ORDER+=("$id")

  # --force-rerun-from <id> reruns that step and every step after it, even if
  # markers exist -- must activate BEFORE the marker skip-check below, or the
  # named step itself (and everything after it) still gets skipped on its own
  # marker. Confirmed live (#518 test run 2): passing --force-rerun-from
  # shared-resources still skipped shared-resources itself plus every step
  # after it, because FORCE_ACTIVE was being set only *after* run_step had
  # already returned early.
  if [[ -n "$FORCE_FROM" && "$id" == "$FORCE_FROM" ]]; then
    FORCE_ACTIVE=1
  fi

  local marker="$MARKER_DIR/$id.done"
  if [[ $RESET_MARKERS -eq 0 && -f "$marker" && "$FORCE_ACTIVE" -eq 0 ]]; then
    STEP_STATUS["$id"]="SKIPPED (already done -- marker $marker)"
    log "==> [$id] $desc -- SKIPPED (marker present)"
    return 0
  fi

  log "==> [$id] $desc"
  if "$@" >>"$RUN_LOG" 2>&1; then
    STEP_STATUS["$id"]="OK"
    log "    [$id] OK"
    mkdir -p "$MARKER_DIR"
    date -Iseconds > "$marker"
  else
    local rc=$?
    STEP_STATUS["$id"]="FAILED (exit $rc)"
    log "    [$id] FAILED (exit $rc) -- see $RUN_LOG"
  fi
}

skip_step() {
  local id="$1" desc="$2" reason="$3"
  STEP_ORDER+=("$id")
  STEP_STATUS["$id"]="SKIPPED ($reason)"
  log "==> [$id] $desc -- SKIPPED ($reason)"
}

print_summary() {
  local width="${SUMMARY_WIDTH:-32}"
  echo
  echo "==================== $INSTALLER_NAME summary ===================="
  local failed=0
  for id in "${STEP_ORDER[@]}"; do
    local status="${STEP_STATUS[$id]}"
    printf "  %-${width}s %s\n" "$id" "$status"
    [[ "$status" == FAILED* ]] && failed=1
  done
  echo "=========================================================================="
  echo "Full log: $RUN_LOG"
  if [[ $failed -eq 1 ]]; then
    echo "One or more steps FAILED. Fix the underlying issue and re-run this"
    echo "script -- completed steps are skipped via markers under $MARKER_DIR,"
    echo "so re-running only retries what actually failed. Use"
    echo "--force-rerun-from <step-id> to redo a step whose marker exists but"
    echo "whose result you don't trust."
    declare -F print_summary_extra >/dev/null && print_summary_extra
    return 1
  fi
  echo "All steps completed."
  declare -F print_summary_extra >/dev/null && print_summary_extra
  return 0
}

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------
# Both installers took exactly the same flags; only the help text and the
# named .conf.example differed. --install-self is new (see the header): it
# stages the script AND this library together into the supported
# outside-the-checkout location.
install_common_usage() {
  echo "Usage: sudo $0 --config /path/to/answers.conf [--force-rerun-from <step-id>] [--reset-markers]"
  echo "       sudo $0 --install-self [<dir>]   # copy this script + its library to $INSTALL_SELF_DIR"
  echo "See ${INSTALLER_CONF_EXAMPLE:-scripts/install-*.conf.example} for the template."
}

INSTALL_SELF_DIR="/usr/local/sbin"
INSTALL_SELF_LIB_DIR="/usr/local/lib/apiary"
# Extra run-time files an installer wants staged with it (set before
# install_common_parse_args). Empty for install-homeserver.sh.
INSTALL_SELF_EXTRA_FILES=()

# install_common_install_self <script-path> [dest-dir]
# The homeserver runs install-homeserver.sh from /usr/local/sbin because
# systemd under SELinux cannot exec it out of a /home or /root checkout. That
# copy was made by hand, which is exactly how a sourced library goes missing.
# This does both halves, labels them, and says where they landed.
install_common_install_self() {
  local src="$1" dest_dir="${2:-$INSTALL_SELF_DIR}"
  local lib_src="${APIARY_INSTALL_LIB_RESOLVED:-}"
  if [[ -z "$lib_src" || ! -r "$lib_src" ]]; then
    echo "install-self: cannot locate the library this script was sourced from." >&2
    return 1
  fi
  local dest
  dest="$dest_dir/apiary-$(basename "$src")"
  mkdir -p "$dest_dir" "$INSTALL_SELF_LIB_DIR" || return 1
  install -m 0700 "$src" "$dest" || return 1
  install -m 0644 "$lib_src" "$INSTALL_SELF_LIB_DIR/install-common.sh" || return 1
  # Data files the installer reads at run time, staged flat beside the library
  # (install-vps.sh: the hub spoke list and its renderer, #3619). An installer
  # that declared one it could not resolve must not stage a copy that fails
  # later, mid-run.
  local extra staged=()
  for extra in "${INSTALL_SELF_EXTRA_FILES[@]}"; do
    if [[ -z "$extra" || ! -r "$extra" ]]; then
      echo "install-self: a file this installer needs at run time is missing: '${extra}'." >&2
      echo "Run --install-self from a full checkout." >&2
      return 1
    fi
    staged+=("$INSTALL_SELF_LIB_DIR/$(basename "$extra")")
    [[ "$(readlink -f "$extra")" == "$(readlink -f "${staged[-1]}")" ]] && continue
    install -m 0644 "$extra" "${staged[-1]}" || return 1
  done
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$dest" "$INSTALL_SELF_LIB_DIR/install-common.sh" "${staged[@]}" >/dev/null 2>&1 || true
  fi
  echo "Installed:"
  echo "  $dest"
  echo "  $INSTALL_SELF_LIB_DIR/install-common.sh"
  for extra in "${staged[@]}"; do echo "  $extra"; done
  echo
  echo "Run the installed copy with the same flags; it resolves the library from"
  echo "$INSTALL_SELF_LIB_DIR. Re-run --install-self after every checkout update,"
  echo "or the installed copy keeps running the old code."
  return 0
}

# install_common_parse_args "$@" -- sets CONFIG_FILE / FORCE_FROM /
# RESET_MARKERS, handles --help and --install-self, and exits itself for the
# terminal flags. Called before the root check so --help works unprivileged.
# shellcheck disable=SC2034  # CONFIG_FILE is consumed by the sourcing installer
install_common_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config) CONFIG_FILE="${2:-}"; shift 2 ;;
      --force-rerun-from) FORCE_FROM="${2:-}"; shift 2 ;;
      --reset-markers) RESET_MARKERS=1; shift ;;
      --install-self)
        if [[ $EUID -ne 0 ]]; then
          echo "--install-self writes to $INSTALL_SELF_DIR; run it with sudo." >&2
          exit 1
        fi
        install_common_install_self "$INSTALLER_SELF_PATH" "${2:-}"
        exit $?
        ;;
      -h|--help) install_common_usage; exit 0 ;;
      *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
  done
}

# install_common_open_run_log -- create the log/marker dirs and start a fresh
# per-run log. Identical in both installers before the extraction.
install_common_open_run_log() {
  mkdir -p "$LOG_DIR" "$MARKER_DIR"
  RUN_LOG="$LOG_DIR/install-$(date -u +%Y%m%dT%H%M%SZ).log"
  : >"$RUN_LOG"
}

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
# Resolved at source time, deliberately, so a step can never disagree with
# preflight -- and so a resumed run whose preflight step is marker-skipped
# still has it. install-vps.sh set its own $PKG inside step_preflight_os,
# which meant `--force-rerun-from base-packages` on a box whose preflight
# marker already existed hit `$PKG: unbound variable` under `set -u`.
# Package *lists* stay in each installer: the two genuinely install different
# sets, and the VPS side passes --setopt=install_weak_deps=False where the
# homeserver does not.
install_common_detect_distro() {
  local id="" id_like=""
  if [[ -r /etc/os-release ]]; then
    id="$(. /etc/os-release && echo "${ID:-}")"
    id_like="$(. /etc/os-release && echo "${ID_LIKE:-}")"
  fi
  DISTRO_ID="$id"
  DISTRO_ID_LIKE="$id_like"
  case "$DISTRO_ID" in
    ubuntu|debian)                      DISTRO_FAMILY=debian ;;
    rocky|rhel|centos|almalinux|fedora) DISTRO_FAMILY=rhel ;;
    *)
      case " $DISTRO_ID_LIKE " in
        *debian*)        DISTRO_FAMILY=debian ;;
        *rhel*|*fedora*) DISTRO_FAMILY=rhel ;;
        *)               DISTRO_FAMILY=unknown ;;
      esac
      ;;
  esac
  export DISTRO_FAMILY
}
