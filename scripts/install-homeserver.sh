#!/usr/bin/env bash
# Unattended homeserver provisioning for APIARY — the Linux-side
# equivalent of a Windows autounattend.xml. This is the single entry point
# described in issue #518; it covers everything smoke-test-verified so far
# (see docs/research/518-smoke-test-research.md) and is expected to grow.
#
# Scope: this script provisions a MANUALLY installed base Ubuntu Server or
# Rocky Linux 10 system into a running APIARY homeserver (Docker, NVIDIA/GPU
# stack, Arcane, WireGuard, the repo checkout, secret restore, and starting
# the Compose stacks in dependency order). It does NOT partition disks or
# install the OS itself — that's docs/autoinstall/homeserver-user-data.yaml
# on Ubuntu, or a kickstart on Rocky (#2730), run once, separately, before
# this script ever sees the box.
#
# Distro support: every package operation goes through the pkg_* shim rather
# than calling apt-get directly, and $DISTRO_FAMILY (debian|rhel) is resolved
# once at source time. Only genuinely distro-specific things branch on it --
# package names, repository format, and the NVIDIA driver path.
#
# Design goals (per #518): a single entry point, live status as it runs,
# a clear non-fatal-by-default failure report at the end so a partial run
# can be diagnosed and re-run, resumability (already-completed steps are
# skipped on re-run via markers under $MARKER_DIR), and retries for
# network-flaky steps (apt, git, rsync, docker pull) rather than a hard
# failure on the first transient blip.
#
# Usage:
#   sudo ./scripts/install-homeserver.sh --config /path/to/answers.conf
#   sudo ./scripts/install-homeserver.sh --config answers.conf --force-rerun-from docker-install
#   sudo ./scripts/install-homeserver.sh --config answers.conf --reset-markers   # ignore all markers, redo everything
#   sudo ./scripts/install-homeserver.sh --install-self      # stage this script + its library under /usr/local
#
# scripts/install.sh --profile home is the same thing with the answers file
# defaulted to /etc/apiary/install-home.conf.
#
# --install-self exists because this script does not only run from the
# checkout: systemd under SELinux cannot exec it out of /home or /root, so the
# homeserver runs a copy at /usr/local/sbin/apiary-install-homeserver.sh. That
# copy was made by hand, which is how the shared library it now sources would
# go missing; --install-self stages both halves together. Re-run it after every
# checkout update, or the installed copy keeps running the old code.
#
# The answers file follows scripts/install-homeserver.conf.example --
# copy it, fill in every <PLACEHOLDER>, keep the filled-in copy OUT of
# version control (it will contain real IPs, keys, and a real git remote).

set -uo pipefail

# ---------------------------------------------------------------------------
# Status tracking / resumability — every phase reports through run_step so
# one failure doesn't abort the whole run; everything attempted gets
# recorded and printed in a final summary. Steps that already succeeded on a
# prior run (a marker file exists under $MARKER_DIR) are skipped unless
# --reset-markers or --force-rerun-from <step-id> is passed.
#
# That framework now lives in scripts/lib/install-common.sh, shared with
# install-vps.sh (#1609 Phase 5) instead of being copied into both. Only this
# script's own identity is set here.
# ---------------------------------------------------------------------------
INSTALLER_NAME="install-homeserver.sh"
INSTALLER_CONF_EXAMPLE="scripts/install-homeserver.conf.example"
INSTALLER_SELF_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
LOG_DIR="/var/log/honeypot-install"
MARKER_DIR="/var/lib/honeypot-install/markers"
SUMMARY_WIDTH=36

# Resolve the shared library: explicit override, then next to this script (a
# checkout), then the installed location. This script does not only run from
# the checkout — systemd under SELinux cannot exec it from /home or /root, so
# the live homeserver runs a copy at /usr/local/sbin (see --install-self).
# Hard-exit rather than sourcing nothing: `set -u` without `-e` lets a failed
# `source` continue, after which every framework call is a "command not found"
# and the run limps on half-executed. That risk is why this extraction was
# deferred once; this is the guard that closes it.
APIARY_INSTALL_LIB_RESOLVED=""
for _cand in \
  "${APIARY_INSTALL_LIB:-}" \
  "$(dirname "$INSTALLER_SELF_PATH")/lib/install-common.sh" \
  "/usr/local/lib/apiary/install-common.sh"; do
  if [[ -n "$_cand" && -r "$_cand" ]]; then APIARY_INSTALL_LIB_RESOLVED="$_cand"; break; fi
done
if [[ -z "$APIARY_INSTALL_LIB_RESOLVED" ]]; then
  echo "Cannot find install-common.sh (the shared installer framework)." >&2
  echo "Looked at: \$APIARY_INSTALL_LIB, $(dirname "$INSTALLER_SELF_PATH")/lib/, /usr/local/lib/apiary/" >&2
  echo "Run this script from a repo checkout, or re-run 'sudo $0 --install-self'" >&2
  echo "from one so the script and its library are staged together." >&2
  exit 2
fi
# shellcheck source=lib/install-common.sh
source "$APIARY_INSTALL_LIB_RESOLVED"
install_common_require

# ---------------------------------------------------------------------------
# Args / config
# ---------------------------------------------------------------------------
install_common_parse_args "$@"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 --config <file>" >&2
  exit 1
fi

if [[ -z "$CONFIG_FILE" || ! -f "$CONFIG_FILE" ]]; then
  echo "Missing or unreadable --config file." >&2
  echo "Copy scripts/install-homeserver.conf.example, fill in every" >&2
  echo "<PLACEHOLDER>, and pass it with --config." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

for var in GIT_REPO_URL GIT_REF REPO_DIR HOME_WG_ADDRESS \
           VPS_WG_ADDRESS VPS_WG_ENDPOINT VPS_WG_PUBLIC_KEY \
           VPS_SSH_HOST VPS_SSH_PORT VPS_SSH_USER VPS_SSH_KEY ENABLE_GPU_STACK \
           INSTALL_TIMEZONE BACKUP_HOST BACKUP_HOST_USER BACKUP_HOST_KEY BACKUP_HOST_PATH \
           TECHNITIUM_LAN_IP ENABLE_SANDBOX_RESTORE AUTH_THEME_REPO_URL \
           KEYCLOAK_PUBLIC_DOMAIN ARCANE_URL ARCANE_API_TOKEN; do
  if [[ -z "${!var:-}" || "${!var}" == *'<'*'>'* ]]; then
    echo "Config value $var is unset or still a <PLACEHOLDER> in $CONFIG_FILE." >&2
    echo "Fill in every field before running unattended." >&2
    exit 1
  fi
done

# KEYCLOAK_PUBLIC_DOMAIN is the BASE domain -- every public hostname is derived
# from it by prefixing a service label (auth.<domain>, arcane.<domain>,
# dashboard.<domain>, ...). Handing it a hostname that already carries one of
# those labels silently produces a second-level subdomain: the 2026-09-03
# rebuild was configured with the auth HOSTNAME rather than the base domain,
# and generated https://arcane.auth.<domain> plus issuer
# https://auth.auth.<domain> -- neither of which resolves or is covered by the
# wildcard origin certificate (*.<domain> matches one label only). Nothing
# downstream validated it, so it
# surfaced as OIDC discovery failures far from the cause. Reject it here.
for label in auth arcane dashboard kibana arkime evebox traefik tanner snare rev; do
  if [[ "$KEYCLOAK_PUBLIC_DOMAIN" == "$label."* ]]; then
    echo "KEYCLOAK_PUBLIC_DOMAIN is \"$KEYCLOAK_PUBLIC_DOMAIN\", which already starts with the" >&2
    echo "service label \"$label.\". This value must be the BASE domain only --" >&2
    echo "the installer derives auth.<domain>, arcane.<domain> and friends from it," >&2
    echo "so this would generate ${label}.${KEYCLOAK_PUBLIC_DOMAIN} (a second-level" >&2
    echo "subdomain that a *.<domain> wildcard certificate does not cover)." >&2
    echo "Use \"${KEYCLOAK_PUBLIC_DOMAIN#"$label".}\" instead." >&2
    exit 1
  fi
done
# INSTALL_HOSTNAME is intentionally excluded from the loop above and
# allowed to be genuinely empty -- this file's own header comment (and
# install-homeserver.conf.example's) already documented "leave empty to
# keep whatever's already set" as supported, but nothing actually was:
# the validation loop rejected an empty value outright, and even past
# that, step_set_hostname unconditionally called `hostnamectl
# set-hostname ""`, which errors rather than leaving the hostname alone.
# Caught live (#787's actual homeserver reinstall, 2026-08-09) -- worked
# around at the time by filling in the box's real current hostname
# explicitly, but the documented empty-value behavior is real and worth
# actually supporting, not just documenting.
# HOME_WG_PRIVATE_KEY is intentionally allowed to be empty/absent — if the
# original tunnel private key wasn't part of the backup (it wasn't captured
# by the .env-only backup pass, see #518 comment history), step_wireguard_config
# generates a fresh keypair and step_wireguard_sync_vps_peer pushes the new
# public key to the VPS side automatically.
#
# ARCANE_URL/ARCANE_API_TOKEN (#1502): step_arcane_import_stacks needs an
# already-running Arcane with an API key generated through its own UI
# (Settings -> API Keys, after Arcane's first interactive login -- an
# unattended installer can't complete Arcane's own OIDC/passkey login
# itself). #1504 closed half of this gap: step_arcane_install (formerly
# step_dockge_install) now stands Arcane itself up from
# docker-compose.arcane.yml, so it's installed and reachable before this
# script reaches the import step, rather than the plain Dockge it used to
# install. The remaining, irreducible part is a genuine two-pass bootstrap:
# minting ARCANE_API_TOKEN still requires a first human login, and once
# Keycloak is up that login is OIDC-only, so the very first from-scratch run
# lands Arcane + Keycloak, a human logs in and mints a token, and a second
# run with the filled-in token completes the honeypot-* import. Nothing in
# this installer can complete Arcane's own interactive login for you.
#
# KEYCLOAK_PUBLIC_DOMAIN (#1504): the base domain the honeypot's public
# hostnames hang off (auth.<domain>, arcane.<domain>, ...) -- step_arcane_install
# derives Arcane's own APP_URL and OIDC issuer URL from it for the .env it
# generates, matching the Keycloak realm's own example.invalid -> <domain>
# substitution. Same value as honeypot-keycloak's KEYCLOAK_PUBLIC_DOMAIN.

# BACKUP_HOST_SANDBOX_PATH is only needed when ENABLE_SANDBOX_RESTORE=true --
# don't force every user to fill it in just to skip a 170G+ optional restore.
if [[ "$ENABLE_SANDBOX_RESTORE" == "true" ]]; then
  if [[ -z "${BACKUP_HOST_SANDBOX_PATH:-}" || "${BACKUP_HOST_SANDBOX_PATH}" == *'<'*'>'* ]]; then
    echo "ENABLE_SANDBOX_RESTORE=true but BACKUP_HOST_SANDBOX_PATH is unset or still a <PLACEHOLDER>." >&2
    exit 1
  fi
fi

install_common_open_run_log

# ---------------------------------------------------------------------------
# Distro shim
# ---------------------------------------------------------------------------
# The homeserver is moving from Ubuntu to Rocky Linux 10, so every package
# operation goes through pkg_* rather than calling apt-get directly. Only the
# places where the two distros genuinely differ -- package names, repository
# format, the NVIDIA driver path -- branch on $DISTRO_FAMILY. Everything else
# (Docker, WireGuard, libvirt, the whole APIARY provisioning flow) is
# identical once the packages are on disk.
#
# Set once, at source time, so a step cannot disagree with preflight. The
# detection itself lives in the shared library (#1609 Phase 5) -- install-vps.sh
# needs exactly the same answer and used to derive it inside a step, where a
# marker-skipped preflight left it unset.
install_common_detect_distro

pkg_update() {
  case "$DISTRO_FAMILY" in
    debian) with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get update -y ;;
    rhel)   with_retry 3 10 dnf -y makecache ;;
    *) echo "unsupported distro family: $DISTRO_FAMILY" >&2; return 1 ;;
  esac
}

pkg_install() {
  case "$DISTRO_FAMILY" in
    debian) with_retry 3 15 env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
    rhel)   with_retry 3 15 dnf install -y "$@" ;;
    *) echo "unsupported distro family: $DISTRO_FAMILY" >&2; return 1 ;;
  esac
}

# Arcane materializes each stack's directory with its compose file named exactly
# as the manifest's dockerComposePath says -- which is compose.yml for the 33
# honeypot-* stacks but docker-compose.yml for auth-events-worker, llm-worker
# and ml-worker. Steps that hardcoded compose.yml silently did nothing for
# those three (#2817). Resolve it instead of assuming.
stack_compose_file() {
  local dir="$1" f
  for f in compose.yml docker-compose.yml; do
    [[ -f "$dir/$f" ]] && { printf '%s\n' "$f"; return 0; }
  done
  return 1
}

# ---------------------------------------------------------------------------
# Phase 0 — preflight
# ---------------------------------------------------------------------------
step_preflight_os() {
  case "$DISTRO_FAMILY" in
    debian|rhel) : ;;
    *) echo "Unsupported OS '$DISTRO_ID' (need an Ubuntu/Debian or Rocky/RHEL family host)" >&2; return 1 ;;
  esac
  echo "OS: ${DISTRO_ID} (family: ${DISTRO_FAMILY})"
}

# Rocky enforces SELinux and ships firewalld enabled; Ubuntu did neither.
# Both can silently break a honeypot host -- containers hitting EACCES on a
# bind mount, or published sensor ports being filtered. Deliberately REPORTS
# rather than changes: turning off a firewall or SELinux is a security
# decision for the operator, not something an installer should do quietly.
# Non-fatal by design, exactly like step_preflight_disks.
step_preflight_rhel_platform() {
  [[ "$DISTRO_FAMILY" == "rhel" ]] || { echo "not a RHEL-family host, nothing to check"; return 0; }

  local mode="unknown"
  command -v getenforce >/dev/null 2>&1 && mode="$(getenforce 2>/dev/null)"
  echo "SELinux: $mode"
  if [[ "$mode" == "Enforcing" ]]; then
    echo "WARNING: SELinux is enforcing. Compose bind mounts written for Ubuntu"
    echo "         carry no :z/:Z labels, so containers can fail with permission"
    echo "         denied on paths under /var/dockge/stacks. Verify container"
    echo "         health after the run and check 'ausearch -m avc -ts recent'."
  fi

  if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "WARNING: firewalld is active. The Ubuntu build installed ufw but never"
    echo "         enabled it, so this host previously ran with no host firewall."
    echo "         Confirm the sensor ports are actually reachable from outside"
    echo "         before treating the install as good."
  else
    echo "firewalld: inactive"
  fi
  return 0
}

step_preflight_disks() {
  # Non-fatal check: warn (in the log) if the layout from
  # docs/HOMESERVER-DISK-LAYOUT.md isn't present, but don't block —
  # a second build server may legitimately use a different layout.
  for mnt in /var; do
    mountpoint -q "$mnt" || echo "WARNING: $mnt is not a separate mount — see docs/HOMESERVER-DISK-LAYOUT.md"
  done
  return 0
}

step_set_hostname() {
  [[ -n "${INSTALL_HOSTNAME:-}" ]] && hostnamectl set-hostname "$INSTALL_HOSTNAME"
  timedatectl set-timezone "$INSTALL_TIMEZONE"
}

# ---------------------------------------------------------------------------
# Phase 1 — base packages
# ---------------------------------------------------------------------------
step_pkg_update() {
  pkg_update
}

step_base_packages() {
  # Same tools either way; four of them are simply named differently.
  #   dnsutils      -> bind-utils        (dig, nslookup)
  #   gnupg         -> gnupg2
  #   openssh-client -> openssh-clients  (note the plural)
  #   ufw           -> firewalld         (RHEL's host firewall; see
  #                                       step_preflight_rhel_platform, which
  #                                       reports rather than configures it)
  # lsb-release is Debian-only and unused on RHEL, where /etc/os-release
  # carries the same information.
  case "$DISTRO_FAMILY" in
    debian)
      pkg_install ca-certificates curl dnsutils gnupg lsb-release git jq rsync ufw \
        xfsprogs nvme-cli openssh-client
      ;;
    rhel)
      # EPEL first, and unconditionally: Rocky's own repos do not carry
      # fuse-sshfs (step_sshfs_install) or dkms (the GPU branch). It used to be
      # installed only inside the GPU branch, so a host with
      # ENABLE_GPU_STACK=false reached step_sshfs_install with no repo
      # providing sshfs at all and failed there -- hit live on the 2026-09-03
      # Rocky 10 rebuild ("No match for argument: fuse-sshfs"). Installing it
      # here makes it available to every later step regardless of profile.
      pkg_install epel-release
      pkg_install ca-certificates curl bind-utils gnupg2 git jq rsync firewalld \
        xfsprogs nvme-cli openssh-clients
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Phase 2 — Docker + Compose plugin
# ---------------------------------------------------------------------------
step_docker_repo() {
  case "$DISTRO_FAMILY" in
    debian)
      install -m 0755 -d /etc/apt/keyrings
      with_retry 3 10 curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
      chmod a+r /etc/apt/keyrings/docker.asc
      . /etc/os-release
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list
      with_retry 3 10 apt-get update -y
      ;;
    rhel)
      # Docker's own CentOS repofile, dropped in verbatim rather than added
      # via `dnf config-manager`: that plugin's syntax changed between dnf4
      # and dnf5, and writing the file works identically on both.
      #
      # Its baseurl interpolates $releasever, which on Rocky resolves to the
      # major version ("10") and not the point release -- checked, because
      # Docker publishes centos/10 but no centos/10.2, so a point-release
      # $releasever would 404 every package.
      with_retry 3 10 curl -fsSL https://download.docker.com/linux/centos/docker-ce.repo \
        -o /etc/yum.repos.d/docker-ce.repo
      chmod 0644 /etc/yum.repos.d/docker-ce.repo
      with_retry 3 10 dnf -y makecache
      ;;
  esac
}

step_docker_install() {
  # Package names are the same on both -- Docker ships them under identical
  # names in the deb and rpm repos.
  pkg_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

step_docker_daemon_config() {
  # Matches the live homeserver's /etc/docker/daemon.json: bounded log
  # rotation (containers run forever, unbounded logs will fill /var), wider
  # default-address-pools (STACK-REBUILD.md documents this box exhausting
  # Docker's default pools once ~15+ Compose projects are up — fix it before
  # that happens rather than after), the nvidia runtime registered once the
  # container toolkit is installed (safe to declare even before the toolkit
  # exists — dockerd just won't use it until nvidia-container-runtime is on
  # $PATH), and a builder GC policy (#2743): `docker builder prune -af`
  # reclaimed 179GB of buildkit cache with zero active entries the day /var
  # hit 96% and took down two ES-backed CI legs (unavailable_shards_exception
  # on primary allocation) -- `builder.gc` is on by default, but dockerd
  # infers its threshold as a *percentage* of the filesystem
  # (defaultReservedSpacePercentage = 10 in moby's builder-next/worker/gc.go;
  # in 29.x the full path is daemon/internal/builder-next/worker/gc.go),
  # which on this 1.8T /var computes to exactly 179GB -- the same 179GB
  # `docker builder prune -af` reclaimed. Exactly, because diskPercentage()
  # rounds as `(total*pct/100 / (1<<30) + 1) * 1e9`: 178 GiB-units + 1, times
  # 1e9. Note that makes it 179 *decimal* GB (166.7 GiB), and that the knob is
  # ReservedSpace -- a floor GC will not prune below -- not a ceiling; the
  # nominal ceiling is the inferred MaxUsedSpace (80% = 1.43 TB). On this host
  # the floor is what binds, so 179GB was the operative target.
  # The GC was working; its inferred
  # threshold was simply far too large for this box. `builder.gc` is buildkit's own
  # supported policy mechanism (no separate systemd timer needed): it runs
  # automatically as part of normal build activity once enabled, keeping
  # cache usage near the explicit values below rather than the inferred
  # default.
  # 20GB is generous for any single build on this box (the largest image
  # here, backend-service's Rust release build, has nowhere near that much
  # unique layer churn) while still well below the 179GB this issue found.
  # Careful with the unit: dockerd parses these values with units.RAMInBytes
  # (confirmed for all three fields, not just the deprecated one --
  # daemon/internal/builder-next/controller.go on the docker-29.x branch
  # calls units.RAMInBytes on ReservedSpace, MaxUsedSpace and MinFreeSpace
  # alike), which is binary, so "20GB" is read as 20 GiB (21,474,836,480 B)
  # and `docker buildx inspect` renders it back as "20GiB". Real reduction
  # from the pre-#2743 inferred floor is 179.0 GB -> 21.5 GB, about 157.5 GB
  # tighter.
  #
  # #2750: `defaultKeepStorage` alone was wrong in two ways. First, setting
  # only it means `reservedSpace != 0` in DefaultGCPolicy's guard below, so
  # the whole percentage-inference block that used to also fill in
  # MaxUsedSpace/MinFreeSpace never runs -- both silently stay 0 (disabled).
  # Confirmed directly against the moby source for the docker-29.x branch
  # (the version actually running here, `docker version` -> 29.7.2),
  # daemon/internal/builder-next/worker/gc.go:
  #   if reservedSpace == 0 && maxUsedSpace == 0 && minFreeSpace == 0 {
  #       reservedSpace = diskPercentage(dstat, defaultReservedSpacePercentage)  // 10%
  #       maxUsedSpace  = diskPercentage(dstat, defaultMaxUsedPercentage)        // 80%
  #       minFreeSpace  = diskPercentage(dstat, defaultMinFreePercentage)        // 20%
  #   }
  # Before #2743 this host had an inferred MinFreeSpace of ~358GB (20% of
  # 1.8T) -- a guard that pruned build cache whenever /var free space fell
  # below that, regardless of what was actually consuming the disk. Setting
  # only defaultKeepStorage silently dropped that guard entirely; buildkit
  # now holds its 20GB cap and never reacts to disk pressure from a
  # non-buildkit source (Elasticsearch growth, a large writable container
  # layer, log growth).
  # Second, `defaultKeepStorage` is deprecated -- confirmed in
  # daemon/config/builder.go's own doc comment ("Deprecated option is now
  # equivalent to DefaultReservedSpace") -- with no deprecation warning
  # logged when set, so a future Docker upgrade could drop the key outright
  # and silently revert to the inferred ~179GB cap on this 1.8T /var while
  # this comment still promised 20GB.
  # Fix: the non-deprecated spelling plus an explicit floor. /var sits at
  # 93% (131G free of 1.8T) as of 2026-08-31 -- tighter than the 90% this
  # script's other guidance assumes -- so 100GB is a real, load-bearing
  # floor here, not a formality: buildkit GC now starts pruning once /var
  # free space drops within about 31GB of that floor, not after the disk is
  # already critical.
  cat >/etc/docker/daemon.json <<'EOF'
{
    "log-driver": "local",
    "log-opts": {
        "max-file": "3",
        "max-size": "10m"
    },
    "default-address-pools": [
        { "base": "172.16.0.0/12", "size": 24 }
    ],
    "runtimes": {
        "nvidia": {
            "args": [],
            "path": "nvidia-container-runtime"
        }
    },
    "builder": {
        "gc": {
            "enabled": true,
            "defaultReservedSpace": "20GB",
            "defaultMaxUsedSpace": "100GB",
            "defaultMinFreeSpace": "100GB"
        }
    }
}
EOF
  systemctl restart docker
}

# #1388: short-lived Docker veth interfaces vanish before networkd-dispatcher,
# libvirtd, and systemd-resolved get around to inspecting them, producing a
# continuous "not found"/"ethtool ioctl error"/"Failed to determine whether
# the interface is managed" flood at warning/error severity that buries real
# host/network failures -- confirmed live: 16,593 networkd-dispatcher and
# 4,754 libvirtd priority-3 entries in 24 hours, almost entirely veth noise.
#
# networkd-dispatcher has zero configured hook scripts under any
# /etc/networkd-dispatcher/*.d/ on this host (confirmed live), so it does no
# actual work here -- disabling it entirely, rather than trying to filter its
# output, is the clean fix its own noise volume (the majority of the flood)
# deserves. Idempotent to a box where it isn't installed at all.
#
# libvirtd/systemd-resolved still do real work for real interfaces, so they
# stay running; systemd's own LogFilterPatterns= (v253+, this fleet runs
# 259) drops exactly the veth-shaped messages by content before they reach
# journald, leaving every other warning/error -- real NICs, bridges,
# WireGuard, libvirt-managed taps -- fully intact. A broad severity/rate
# suppression was deliberately rejected (see the issue): this is the
# narrowest mechanism systemd offers that's actually message-content-aware.
step_quiet_veth_noise() {
  if systemctl list-unit-files networkd-dispatcher.service 2>/dev/null | grep -q networkd-dispatcher; then
    systemctl disable --now networkd-dispatcher.service || true
  fi

  if systemctl list-unit-files libvirtd.service 2>/dev/null | grep -q libvirtd; then
    mkdir -p /etc/systemd/system/libvirtd.service.d
    cat >/etc/systemd/system/libvirtd.service.d/99-veth-noise.conf <<'EOF'
[Service]
LogFilterPatterns=~ethtool ioctl error on veth[0-9a-f]+: No such device
EOF
  fi

  if systemctl list-unit-files systemd-resolved.service 2>/dev/null | grep -q systemd-resolved; then
    mkdir -p /etc/systemd/system/systemd-resolved.service.d
    cat >/etc/systemd/system/systemd-resolved.service.d/99-veth-noise.conf <<'EOF'
[Service]
LogFilterPatterns=~veth[0-9a-f]+: Failed to determine whether the interface is managed
EOF
  fi

  systemctl daemon-reload
  if systemctl is-active --quiet libvirtd.service 2>/dev/null; then
    systemctl restart libvirtd.service
  fi
  if systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
    systemctl restart systemd-resolved.service
  fi
}

# ---------------------------------------------------------------------------
# Phase 3 — NVIDIA GPU stack (driver + container toolkit), skippable
# ---------------------------------------------------------------------------
step_gpu_driver() {
  case "$DISTRO_FAMILY" in
    debian)
      pkg_install ubuntu-drivers-common
      # `ubuntu-drivers autoinstall` was removed in this box's ubuntu-drivers-common
      # (1:0.10.9, Ubuntu 26.04) -- the CLI now uses `install` with no args to mean
      # "install the recommended driver for every detected device", confirmed via
      # `ubuntu-drivers -h` live on this box. Keep the old subcommand as a fallback
      # in case a different target runs an older ubuntu-drivers-common.
      ubuntu-drivers install || ubuntu-drivers autoinstall
      ;;
    rhel)
      # There is no ubuntu-drivers equivalent, so this is explicit: NVIDIA's
      # CUDA repository plus the `cuda-drivers` meta-package, which pulls the
      # proprietary driver and its DKMS kernel module.
      #
      # dkms lives in EPEL, not in Rocky's own repos, and the module will not
      # build without headers matching the *running* kernel -- so both are
      # installed before the driver rather than letting the driver fail late.
      pkg_install epel-release
      pkg_install dkms gcc make "kernel-devel-$(uname -r)" "kernel-headers-$(uname -r)" \
        || pkg_install dkms gcc make kernel-devel kernel-headers
      with_retry 3 10 curl -fsSL \
        "https://developer.download.nvidia.com/compute/cuda/repos/rhel10/$(uname -m)/cuda-rhel10.repo" \
        -o /etc/yum.repos.d/cuda-rhel10.repo
      chmod 0644 /etc/yum.repos.d/cuda-rhel10.repo
      with_retry 3 10 dnf -y makecache
      # Deliberately `cuda-drivers` (proprietary) and not `nvidia-open`: the
      # open kernel modules only support Turing and newer. This box also holds
      # a Pascal Quadro P2200 alongside the Ada compute card, and while the
      # P2200 is meant to be bound to vfio-pci for the Windows sandbox rather
      # than driven by the host, picking the open modules here would make that
      # card unusable if it ever is needed on the host.
      pkg_install cuda-drivers
      ;;
  esac
}

step_gpu_container_toolkit() {
  case "$DISTRO_FAMILY" in
    debian)
      curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
      curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        > /etc/apt/sources.list.d/nvidia-container-toolkit.list
      with_retry 3 10 apt-get update -y
      ;;
    rhel)
      with_retry 3 10 curl -fsSL \
        https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
        -o /etc/yum.repos.d/nvidia-container-toolkit.repo
      chmod 0644 /etc/yum.repos.d/nvidia-container-toolkit.repo
      with_retry 3 10 dnf -y makecache
      ;;
  esac
  pkg_install nvidia-container-toolkit
  nvidia-ctk runtime configure --runtime=docker
  # SELinux blocks a container from touching the GPU device nodes unless the
  # toolkit's own boolean is set. No-op where SELinux is not enforcing.
  if [[ "$DISTRO_FAMILY" == "rhel" ]] && command -v setsebool >/dev/null 2>&1; then
    setsebool -P container_use_devices 1 || echo "WARNING: could not set container_use_devices"
  fi
  systemctl restart docker
}

# One pin, used by both step_gpu_verify and step_arcane_install's #2950 check
# for whether the nvidia runtime actually works on this host.
GPU_SMOKE_IMAGE="nvidia/cuda:12.4.0-base-ubuntu22.04"

step_gpu_verify() {
  nvidia-smi -L || return 1
  docker run --rm --gpus all "$GPU_SMOKE_IMAGE" nvidia-smi -L
}

# GPU driver installs a new kernel module -- on a genuinely fresh box this
# usually needs a reboot before `nvidia-smi` sees the card. Detect that
# instead of treating it as a hard failure so the operator knows to reboot
# and re-run rather than debug a phantom GPU problem.
step_gpu_verify_or_note_reboot() {
  if step_gpu_verify; then
    return 0
  fi
  if ! lsmod | grep -q '^nvidia '; then
    echo "nvidia kernel module not loaded yet -- this is expected right after"
    echo "a fresh driver install and usually just needs a reboot. Reboot the"
    echo "box, then re-run: $0 --config $CONFIG_FILE --force-rerun-from gpu-verify"
    return 1
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Phase 4 — WireGuard tunnel to the VPS
# ---------------------------------------------------------------------------
step_wireguard_install() {
  # Ubuntu's `wireguard` is a metapackage; RHEL ships the userspace tools as
  # wireguard-tools (the kernel module is in-tree on both).
  case "$DISTRO_FAMILY" in
    debian) pkg_install wireguard ;;
    rhel)   pkg_install wireguard-tools ;;
  esac
}

step_wireguard_config() {
  install -d -m 0700 /etc/wireguard

  # wg0.conf gets an explicit `chmod 600` below, so no umask override is
  # needed here -- and a bare (unscoped) `umask 077` would be actively
  # harmful: umask is a shell-wide setting that persists for the rest of
  # this script's process, not just this function. Found live during
  # #787's homeserver reinstall (2026-08-09): it silently downgraded every
  # file `git clone` wrote in step_clone_repo (Phase 5, runs right after
  # this) from the tracked 100644/100755 modes to 0600/0700, breaking any
  # bind-mounted repo file a container reads as a non-root user --
  # elasticsearch-setup.sh landed at 0600 root:root and the elasticsearch
  # container (runs as a non-root uid) got "Permission denied" trying to
  # read it. The other two umask uses in this file ((umask 027; ...) for
  # postgres-password/bootstrap-admin-password) correctly scope it to a
  # subshell instead -- this one didn't, and there's no reason to: this
  # function already chmods its one sensitive file explicitly.

  # The home side's WireGuard private key AND preshared key were never part
  # of the .env-only backup (system config, not a Dockge stack secret) --
  # see #518 comment history. If the config didn't supply a private key,
  # generate a fresh keypair (and always generate a fresh PSK alongside it,
  # since a stale/mismatched PSK is exactly as fatal to the handshake as a
  # stale pubkey -- see the incident below). step_wireguard_sync_vps_peer
  # pushes both to the VPS's peer config, rather than silently failing to
  # bring the tunnel up with keys the other end doesn't have.
  #
  # #518 incident: an earlier version of this script only generated/synced
  # the keypair, not a PSK. The VPS's peer config required one (predating
  # this script entirely). Every run silently produced a wg0.conf that
  # associated cleanly (`wg show` displayed the interface fine) but never
  # completed a handshake -- 0 bytes received, forever, no error anywhere.
  # `step_wireguard_verify` below only checked the interface existed, not
  # that a handshake had actually happened, so this went undetected for the
  # entire rest of that session: real attacker traffic never reached the
  # honeypot sensors the whole time, silently. Both gaps are fixed here.
  # step_wireguard_sync_vps_peer always re-derives the current pubkey/PSK
  # from the wg0.conf written below and pushes them unconditionally -- no
  # need to track "was this freshly generated" separately (that tracking
  # via .new marker files was itself the source of the SSH-argument bug
  # documented on that function).
  local priv="${HOME_WG_PRIVATE_KEY:-}"
  local psk="${HOME_WG_PRESHARED_KEY:-}"
  if [[ -z "$priv" ]]; then
    priv="$(wg genkey)"
    echo "Generated a fresh WireGuard private key (no HOME_WG_PRIVATE_KEY in config)."
    echo "New home public key: $(echo "$priv" | wg pubkey)"
  fi
  if [[ -z "$psk" ]]; then
    psk="$(wg genpsk)"
    echo "Generated a fresh WireGuard preshared key (no HOME_WG_PRESHARED_KEY in config)."
  fi

  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${HOME_WG_ADDRESS}
PrivateKey = ${priv}
ListenPort = 51820

[Peer]
PublicKey = ${VPS_WG_PUBLIC_KEY}
PresharedKey = ${psk}
Endpoint = ${VPS_WG_ENDPOINT}
AllowedIPs = ${VPS_WG_ADDRESS}/32
PersistentKeepalive = 25
EOF
  chmod 600 /etc/wireguard/wg0.conf
  systemctl enable wg-quick@wg0
  systemctl restart wg-quick@wg0
}

# Always push home's CURRENT effective pubkey+PSK (from the just-written
# local wg0.conf), not just "whatever was freshly generated this run" --
# confirmed live (#518), two separate bugs with the old "only sync if a
# .new marker file exists" approach:
#  1. A stale .new marker from an earlier run lingered forever (nothing
#     ever cleaned it up), so a run that used already-persisted config
#     values still thought a fresh key had been generated and tried to
#     resync unnecessarily.
#  2. Worse: SSH does not preserve individual argv separation to the
#     remote command the way a local exec does -- per ssh(1), the command
#     and its arguments are concatenated into a SINGLE space-joined string
#     before being sent, then re-split by the remote shell. An empty-string
#     argument (e.g. "no new PSK this run") contributes nothing but a
#     space, which collapses away in that re-split -- every argument after
#     it silently shifts down one position. `peer_ip="$3"` on the remote
#     end became unbound because $psk had been empty, not because
#     anything was wrong with $VPS_WG_ADDRESS itself. Always deriving and
#     sending real, non-empty values sidesteps the whole class of bug --
#     the remote side becomes an unconditional idempotent replace instead
#     of a conditional one.
step_wireguard_sync_vps_peer() {
  rm -f /etc/wireguard/wg0.pub.new /etc/wireguard/wg0.psk.new
  local pubkey psk
  pubkey="$(grep '^PrivateKey' /etc/wireguard/wg0.conf | awk '{print $3}' | wg pubkey)"
  psk="$(grep '^PresharedKey' /etc/wireguard/wg0.conf | awk '{print $3}')"
  [[ -n "$pubkey" && -n "$psk" ]] || { echo "could not read local wg0.conf pubkey/PSK"; return 1; }

  # #1059 investigation: this must be HOME_WG_ADDRESS (stripped of its /24),
  # not VPS_WG_ADDRESS -- the block being matched is the VPS's own peer
  # entry FOR the home side, so its AllowedIPs is home's tunnel IP
  # (confirmed live against the real VPS config: AllowedIPs = 10.8.0.2/32,
  # not 10.8.0.1/32). Using VPS_WG_ADDRESS here matched zero peer blocks on
  # the real config -- a silent no-op with no error, the exact failure
  # class this function's own comments already describe from #518 (wrong
  # keys, clean `wg show`, 0 bytes received, forever). The match-count
  # guard below now also fails loudly instead of silently no-op-ing if this
  # regresses again.
  local home_ip="${HOME_WG_ADDRESS%%/*}"
  ssh -i "$VPS_SSH_KEY" -p "$VPS_SSH_PORT" -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 "${VPS_SSH_USER}@${VPS_SSH_HOST}" bash -s -- "$pubkey" "$psk" "$home_ip" <<'REMOTE'
set -euo pipefail
new_pub="$1"
new_psk="$2"
peer_ip="$3"
conf="/etc/wireguard/wg0.conf"
[[ -f "$conf" ]] || { echo "no $conf on VPS" >&2; exit 1; }
cp -p "$conf" "$conf.bak.$(date +%s)"
# Replace the PublicKey/PresharedKey lines inside the [Peer] block matching
# this home peer's AllowedIPs, not any other peer that might exist.
python3 - "$conf" "$new_pub" "$new_psk" "$peer_ip" <<'PY'
import re, sys
conf, new_pub, new_psk, peer_ip = sys.argv[1:5]
text = open(conf).read()
blocks = re.split(r'(?=\[Peer\])', text)
out = []
matched = 0
# Every pattern here is line-anchored with re.M and uses [ \t] rather than
# \s around the '=', deliberately. \s matches newlines, so the previous
# `PresharedKey\s*=\s*\S+` would, on a key line with an EMPTY value, run
# past the end of its own line and swallow the first token of the next one:
#
#   PresharedKey =            ->  PresharedKey = <psk> = 10.8.0.2/32
#   AllowedIPs = 10.8.0.2/32
#
# because \s* crossed the newline and \S+ then matched "AllowedIPs". That is
# not hypothetical -- the live VPS had exactly `PresharedKey = ` with no
# value, and this produced a wg0.conf that wg-quick refused outright:
#   Key is not the correct length or format: `<psk>=10.8.0.2/32'
#   Configuration parsing error
# It then deleted the interface, so the step failed with the tunnel DOWN
# rather than merely unchanged. Measured on the 2026-09-04 rebuild.
#
# \S* (not \S+) so an empty value is matched and replaced in place instead of
# falling through to the insert branch and producing a duplicate key line.
for b in blocks:
    if b.startswith('[Peer]') and f"{peer_ip}/32" in b:
        matched += 1
        b = re.sub(r'^PublicKey[ \t]*=[ \t]*\S*[ \t]*$',
                   f'PublicKey = {new_pub}', b, flags=re.M)
        if re.search(r'^PresharedKey[ \t]*=', b, re.M):
            b = re.sub(r'^PresharedKey[ \t]*=[ \t]*\S*[ \t]*$',
                       f'PresharedKey = {new_psk}', b, flags=re.M)
        else:
            b = re.sub(r'^(PublicKey[ \t]*=[ \t]*\S*[ \t]*)$',
                       rf'\1\nPresharedKey = {new_psk}', b, flags=re.M)
    out.append(b)
# Fail loudly on 0 or >1 matches instead of silently no-op-ing (0 matches)
# or updating the wrong/multiple peers (>1) -- exactly the kind of mistake
# a clean `wg show` and no error would otherwise hide until the next real
# handshake attempt fails.
if matched != 1:
    print(f"expected exactly 1 peer block with AllowedIPs {peer_ip}/32, found {matched}", file=sys.stderr)
    sys.exit(1)
open(conf, 'w').write(''.join(out))
PY
# Validate the rewritten config BEFORE restarting. wg-quick's failure mode
# here is to `ip link delete dev wg0` on a parse error, so a bad edit does
# not leave the tunnel merely unchanged -- it takes it DOWN, on the one host
# whose reachability everything else on the homeserver depends on. `wg-quick
# strip` parses without touching the interface, so a malformed file is caught
# while the tunnel is still up and the backup taken above is restored.
if ! wg-quick strip wg0 >/dev/null 2>&1; then
  echo "rewritten $conf does not parse -- restoring the backup, tunnel untouched" >&2
  wg-quick strip wg0 2>&1 | tail -3 >&2 || true
  cp -p "$(ls -1t "$conf".bak.* | head -1)" "$conf"
  exit 1
fi
systemctl restart wg-quick@wg0
# Confirm the interface actually came back; a restart that fails leaves no
# device at all, and the caller should hear about it here rather than three
# steps later when an sshfs mount times out.
ip link show wg0 >/dev/null 2>&1 || { echo "wg0 did not come up after restart" >&2; exit 1; }
REMOTE
}

step_wireguard_verify() {
  # Confirmed live (#518): `wg show wg0` succeeding only proves the
  # interface exists, not that a handshake ever completed -- a stale/missing
  # PSK produces exactly this false-positive (interface up, 0 bytes
  # received, forever). Actually check for a completed handshake, with a
  # short retry window since one can take a few seconds after a fresh
  # restart.
  wg show wg0 >/dev/null

  local waited=0
  while (( waited < 30 )); do
    local hs
    hs=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
    if [[ -n "$hs" && "$hs" != "0" ]]; then
      echo "WireGuard handshake confirmed ($(date -d "@$hs" -Iseconds 2>/dev/null || echo "$hs"))."
      return 0
    fi
    sleep 3
    waited=$(( waited + 3 ))
  done
  echo "No WireGuard handshake after ${waited}s -- tunnel interface is up but not" >&2
  echo "actually passing traffic. Check the peer's PublicKey/PresharedKey match on" >&2
  echo "both ends (this is exactly the #518 incident this check was added for)." >&2
  return 1
}

# ---------------------------------------------------------------------------
# Phase 5 — repo checkout (must land at REPO_DIR exactly — other stacks'
# `build:` directives reference this path as an absolute string, see
# docker-compose.yml's #258 header comment)
# ---------------------------------------------------------------------------
step_clone_repo() {
  mkdir -p /opt
  ln -sfn "$(dirname "$REPO_DIR")" /opt/stacks 2>/dev/null || true
  if [[ -d "$REPO_DIR/.git" ]]; then
    with_retry 3 10 git -C "$REPO_DIR" fetch origin
    git -C "$REPO_DIR" checkout "$GIT_REF"
    with_retry 3 10 git -C "$REPO_DIR" pull --ff-only origin "$GIT_REF"
  else
    # REPO_DIR can already exist and be non-empty even on a fresh box:
    # other stacks' sshfs mounts live under it (e.g. apiary/logs/suricata,
    # set up by step_sshfs_boot_ordering's fstab entries), and systemd
    # creates a mount unit's mountpoint directory at boot regardless of
    # whether the mount itself actually succeeds. A plain `git clone`
    # refuses to clone into a non-empty directory -- found live during
    # #787's homeserver reinstall (2026-08-09), and only surfaced now
    # because with_retry actually propagates failure correctly (#1078);
    # before that fix this step silently "succeeded" while never cloning
    # anything, and everything downstream cascaded off a missing repo.
    # `git init` + fetch + checkout works fine into a pre-populated
    # directory as long as there's no tracked-path collision (there isn't
    # -- logs/ and state/ aren't part of this repo's tree).
    mkdir -p "$REPO_DIR"
    if [[ ! -d "$REPO_DIR/.git" ]]; then
      git -C "$REPO_DIR" init -q
      git -C "$REPO_DIR" remote add origin "$GIT_REPO_URL"
    fi
    with_retry 3 10 git -C "$REPO_DIR" fetch origin "$GIT_REF"
    git -C "$REPO_DIR" checkout -f -B "$GIT_REF" FETCH_HEAD
  fi
}

# ---------------------------------------------------------------------------
# Phase 6 — Arcane (#1504: replaces the old step_dockge_install)
# ---------------------------------------------------------------------------
# #1504: every already-provisioned APIARY homeserver replaced Dockge with
# Arcane (#1185) months before #1502's migration -- deploy.yml and
# docker-compose.arcane.yml both assume Arcane. This step stands Arcane up on
# a genuinely from-scratch host so step_arcane_import_stacks (later in this
# same run) has a running instance at ARCANE_URL to import the honeypot-*
# stacks into. It models docker-compose.arcane.yml's own live-verified
# service definition exactly (same image, same WireGuard-only port binding,
# same env-var names) -- that file, not this step, stays the source of truth
# for the service shape; this step only supplies the .env it reads.
#
# Bootstrap ordering (the part that genuinely needed a live host to verify,
# #1504's own caveat): Arcane's REST API -- the only thing this installer
# talks to -- authenticates by the pre-minted ARCANE_API_TOKEN, NOT by an
# OIDC session, so Arcane is fully usable by the installer the moment it's
# healthy here, before Keycloak exists. OIDC (interactive human login) is a
# separate concern that only has to work once a person visits the UI, which
# is necessarily after honeypot-keycloak has itself been imported-and-started
# by step_arcane_import_stacks. So this step writes a *placeholder*
# ARCANE_OIDC_CLIENT_SECRET good enough to satisfy the compose file's `:?`
# guard and start the container; step_provision_arcane_oidc_secret later
# replaces it with the real per-realm secret Keycloak generates on
# --import-realm (same pattern as apiary-dashboard's own client secret --
# see provision-arcane-oidc-secret.sh) and re-ups Arcane.
#
# Unresolved from-scratch chicken-and-egg (#1504, still needs a live call):
# minting ARCANE_API_TOKEN requires a first human login, and that login is
# OIDC-only (OIDC_AUTO_REDIRECT_TO_PROVIDER=true) once Keycloak is up, so a
# truly-first install is inherently two-pass -- see ARCANE_URL/
# ARCANE_API_TOKEN's own comment near the top of this file.
step_arcane_install() {
  mkdir -p /var/dockge/data /var/dockge/stacks
  local dir="/var/dockge/stacks/honeypot-arcane"
  install -d -m 755 "$dir"

  # Arcane's ENCRYPTION_KEY/JWT_SECRET/OIDC_CLIENT_SECRET have no *_FILE
  # variant it supports (confirmed against its own env-var reference, see
  # docker-compose.arcane.yml's inline comment) -- they live in this stack's
  # own .env, generated once here the same "start from zero, don't restore a
  # prior value" way step_provision_keycloak_secrets treats Keycloak's own
  # secrets. Idempotent: an existing .env is left untouched so a re-run never
  # rotates a key out from under an already-encrypted arcane-data volume
  # (rotating ENCRYPTION_KEY would make every stored secret undecryptable).
  local env_file="$dir/.env"
  if [[ ! -f "$env_file" ]]; then
    # Derive the two public URLs Arcane's OIDC needs from the same
    # KEYCLOAK_PUBLIC_DOMAIN the Keycloak realm's own example.invalid ->
    # <domain> substitution uses (arcane.<domain> for redirect URIs,
    # auth.<domain> for the issuer) -- matches docker-compose.arcane.yml's
    # and honeypot-keycloak/compose.yml's own default hostnames.
    local app_url="https://arcane.${KEYCLOAK_PUBLIC_DOMAIN}"
    local issuer_url="https://auth.${KEYCLOAK_PUBLIC_DOMAIN}/realms/apiary"
    (
      umask 077
      cat > "$env_file" <<EOF
# honeypot-arcane -- generated by install-homeserver.sh step_arcane_install
# (#1504). ENCRYPTION_KEY/JWT_SECRET are one-time-generated and MUST NOT be
# rotated once arcane-data holds encrypted secrets. OIDC_CLIENT_SECRET below
# is a bootstrap placeholder -- provision-arcane-oidc-secret.sh overwrites it
# with the real Keycloak-generated value once the realm is imported.
HP_BIND=${HP_BIND:-10.8.0.2}
ARCANE_PORT=${ARCANE_PORT:-3552}
ARCANE_URL=${app_url}
ARCANE_ENCRYPTION_KEY=$(openssl rand -base64 32)
ARCANE_JWT_SECRET=$(openssl rand -hex 32)
OIDC_ISSUER_URL=${issuer_url}
ARCANE_OIDC_CLIENT_SECRET=$(openssl rand -hex 32)
TZ=${INSTALL_TIMEZONE}
EOF
    )
    chmod 600 "$env_file"
    echo "generated honeypot-arcane .env (placeholder OIDC secret -- synced later from Keycloak)"
  else
    echo "honeypot-arcane .env already present -- leaving secrets untouched"
  fi

  # Same "copy the file, don't symlink it" shape deploy.yml's own
  # Synchronize honeypot-arcane step uses -- honeypot-arcane is deliberately
  # NOT one of the Arcane-managed Git syncs (syncing the thing that has to
  # run before any sync can happen is a bootstrap loop, see
  # docs/ARCANE-GIT-SYNC.md), so it's installer-/deploy.yml-managed by a
  # plain file copy from the repo checkout.
  # #2950 / #3340: what this file contains (base, or base + GPU overlay when
  # the nvidia runtime demonstrably works) is decided in one place,
  # scripts/render-arcane-compose.sh, which deploy.yml's "Synchronize
  # honeypot-arcane" step also runs -- so a routine deploy writes exactly what
  # the installer did instead of silently dropping the GPU overlay.
  local gpu_mode=off
  [[ "$ENABLE_GPU_STACK" == "true" ]] && gpu_mode=auto
  GPU_SMOKE_IMAGE="$GPU_SMOKE_IMAGE" \
    sh "$REPO_DIR/scripts/render-arcane-compose.sh" "$REPO_DIR" "$dir/compose.yml" "$gpu_mode"
  (cd "$dir" && docker compose -f compose.yml config --quiet \
    && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

# ---------------------------------------------------------------------------
# Phase 7 — secret restore from the LAN backup host
# ---------------------------------------------------------------------------
# Maps Dockge stack name -> "<name>.env" file directly under BACKUP_HOST_PATH
# (a flat directory, not "<name>/.env" subdirectories -- confirmed against
# the real backup host live during #787's homeserver reinstall, 2026-08-09).
# 1:1 for everything except the DNS stack, which the backup captured a bare .env for
# (no compose file was ever backed up for it -- see step_technitium_provision,
# which reconstructs a minimal one since it isn't part of this git repo).
# Stacks whose .env is restored from the backup host. This used to be a
# hardcoded list of 17 and had silently drifted: the manifest carries 37
# stacks, and the 2026-09-03 rebuild's backup held 38 real .env files, so 20
# stacks with genuine secrets in the backup were never even looked for and got
# .env.example placeholders from step_bootstrap_missing_envs instead
# (honeypot-canarytokens, -beelzebub, -galah, -hellpot, -elasticpot,
# -sentrypeer, -mailoney, -dicompot, -dns-honeypot, -citrix-honeypot,
# -cisco-asa-honeypot, -rdp-honeypot, -endlessh, -dashboard-backend, the five
# workers, ...). Derived from the Arcane manifest now -- the same single source
# of truth step_arcane_import_stacks and step_bootstrap_missing_envs already
# drive off -- so adding a stack there cannot leave its secrets behind again.
#
# honeypot-stack is appended explicitly: it is not in the manifest but does
# hold a real, populated .env on the live host (confirmed during #1609's backup
# pass), so dropping it would lose real configuration.
env_restore_stacks() {
  local manifest="$REPO_DIR/arcane/manifests/home-production.json"
  if [[ -r "$manifest" ]]; then
    { jq -r '.[].syncName' "$manifest"; echo honeypot-stack; } | sort -u
  else
    # Pre-clone fallback only -- the manifest lives in the repo checkout.
    printf '%s\n' honeypot-keycloak honeypot-init honeypot-cowrie honeypot-dionaea \
      honeypot-conpot honeypot-dnp3 honeypot-http honeypot-multipot honeypot-dashboard \
      honeypot-payload-analysis honeypot-tanner honeypot-elk honeypot-utilities \
      honeypot-stack ghidra ghosts technitium
  fi
}

step_restore_env_files() {
  # A missing *individual* .env is a warning -- a stack may genuinely not have
  # existed before the rebuild. But *every* restore failing is not that: it
  # means the backup host, key or path is wrong, and there are no real secrets
  # on this host at all. That case used to return 0 anyway, so the step marked
  # itself done, step_bootstrap_missing_envs filled all 38 stacks in from
  # .env.example placeholders, and the whole stack came up authenticated
  # against nothing with no failed step to show for it. Hit live on the
  # 2026-09-03 Rocky 10 rebuild: BACKUP_HOST_KEY pointed at a key file that did
  # not exist, all 38 scps failed, and the run reported restore-env-files OK.
  # Fail closed instead, and say which of the three inputs to check.
  local restored=0 missing=0
  if [[ ! -r "$BACKUP_HOST_KEY" ]]; then
    echo "BACKUP_HOST_KEY is not readable: $BACKUP_HOST_KEY" >&2
    echo "  Nothing can be restored without it -- fix the path or place the key." >&2
    return 1
  fi
  local name
  while read -r name; do
    [[ -n "$name" ]] || continue
    local src="${BACKUP_HOST_PATH}/${name}.env"
    local dest_dir="/var/dockge/stacks/${name}"
    mkdir -p "$dest_dir"
    if with_retry 3 5 scp -i "$BACKUP_HOST_KEY" -P 22 -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 "${BACKUP_HOST_USER}@${BACKUP_HOST}:${src}" "$dest_dir/.env" 2>/dev/null; then
      chmod 600 "$dest_dir/.env"
      echo "restored .env for $name"
      restored=$((restored + 1))
    else
      echo "WARNING: no backed-up .env found for $name at $src (may not have existed pre-rebuild)"
      missing=$((missing + 1))
    fi
  done < <(env_restore_stacks)
  echo "restored $restored .env file(s), $missing missing"
  if [[ $restored -eq 0 ]]; then
    echo "FAILED: not a single .env was restored from ${BACKUP_HOST_USER}@${BACKUP_HOST}:${BACKUP_HOST_PATH}" >&2
    echo "  Check BACKUP_HOST / BACKUP_HOST_PATH / BACKUP_HOST_KEY. The path must" >&2
    echo "  hold one <stack>.env per stack (e.g. \$BACKUP_HOST_PATH/honeypot-elk.env)." >&2
    echo "  Continuing would bootstrap every stack from .env.example placeholders." >&2
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Phase 8 — stack provisioning + startup, in dependency order
# ---------------------------------------------------------------------------
# Format: "dockge-stack-name|repo-relative-compose-file"
# Order matters for the first three entries only (see STACK-REBUILD.md):
# Elasticsearch (honeypot-elk) must be healthy BEFORE honeypot-init runs its
# elasticsearch-setup/arkime-init one-shot jobs, which is the OPPOSITE of
# what a naive alphabetical/README-table order would suggest and is the #1
# trap STACK-REBUILD.md documents from the first live reset (2026-08-02).
# Everything after honeypot-init has no real cross-stack ordering
# requirement (shared volumes are non-external and get created empty by
# whichever stack starts first).
# #1502: the 32 honeypot-* stacks (STACK_DEFS' old 21 plus the 11 that had
# drifted out of it -- see arcane/manifests/home-production.json's own
# generation history) are no longer symlinked in from a shared
# /var/stacks/apiary checkout. Each one's build context and config now
# lives self-contained under arcane/home/<name>/ (or, for the 6 stacks that
# were already self-contained before this migration -- auth-events-worker,
# llm-worker, ml-worker, analysis/ghidra, sandbox/ghosts, technitium -- at its
# existing path), and Arcane's own directory-aware Git sync owns
# materializing and deploying it, driven by this manifest.
#
# #1505: of those 6, three (auth-events-worker, llm-worker, ml-worker) are
# now ALSO imported by step_arcane_import_stacks below -- confirmed to have
# no host-local state beyond .env (no bind-mounted persistent directories,
# no ownership requirements a generic directory sync wouldn't already get
# right), so folding them in was safe without a disposable host to verify
# against. Their old dedicated steps (step_auth_events_worker_start,
# step_ml_worker_start, step_llm_worker_selftest) are kept, but trimmed down
# to just the parts Arcane's own sync can't do: readiness verification
# (polling each container's own log line, since neither has a Docker
# HEALTHCHECK Arcane's `up --wait` could rely on alone -- see each step's
# own comment, #593) and, for llm-worker, its actual --selftest invocation.
#
# The other 3 stay fully on their own dedicated steps, deliberately not
# folded in:
#   - technitium (step_technitium_provision/-start/-verify): real host-local state
#     beyond .env -- config/ (zones, settings, blocklists)
#     directory that needs non-root ownership for its distroless image
#     (chown 65532:65532). #1502's own cutover lost this exact state once
#     already (disclosed in that issue's own comments) when it wasn't
#     accounted for -- a generic Arcane directory sync has no way to know
#     about it either.
#   - analysis/ghidra (step_ghidra_stack_provision/-start): needs a second,
#     conditional compose file layered on top (docker-compose.ghidra.gpu.yml,
#     only when ENABLE_GPU_STACK=true) that the Arcane manifest's single
#     dockerComposePath can't express, plus the relative-build-context
#     breakage this step's own comment already documents from the first
#     live attempt to symlink only the compose file instead of the whole
#     directory. GPU-stack correctness is expensive to get wrong and hard
#     to verify without a GPU-enabled disposable host.
#   - sandbox/ghosts (step_ghosts_host_install): ghosts-api's remote Git
#     build context (GHOSTS.git#<ref>:src) hits a confirmed Arcane v2.8.0
#     limitation (#1506 -- its image-prep step only resolves refs under
#     refs/heads/, so a tag or commit SHA both fail) -- not unverified, but
#     confirmed *broken* through Arcane's own directory sync today. Folding
#     this in would trade a working installer step for a non-functional one.
# All three needed the same kind of live verification this honeypot-*
# replacement got before being deemed safe to fold in; pihole/ghidra/ghosts
# either failed that bar for a real reason above, or -- for pihole and
# ghidra specifically -- couldn't be checked at all without a disposable
# test host to break, which wasn't a safe call to make unilaterally.
ARCANE_STACK_MANIFEST="$REPO_DIR/arcane/manifests/home-production.json"

# The four Keycloak provisioner scripts moved under arcane/home/honeypot-keycloak/
# in #1502's per-stack restructure; the installer kept calling them at the
# pre-#1502 top-level $REPO_DIR/keycloak/ path. That made all four steps fail
# with "No such file or directory" on the 2026-09-03 rebuild -- leaving the
# dashboard, Arcane and the events poller without their real OIDC secrets.
# One variable so a single fix keeps covering all four, as their own comments
# intend.
KEYCLOAK_PROVISION_DIR="$REPO_DIR/arcane/home/honeypot-keycloak/keycloak"

# Rev·Deck's upstream source (see step_revdeck_source). Deliberately NOT in the
# required-config list above: revdeck is an optional analyst UI, and a host that
# cannot reach GitHub should still complete an install without it. Override in
# the answer file to build from a fork or an internal mirror.
REVDECK_REPO_URL="${REVDECK_REPO_URL:-https://github.com/biniamf/ai-reverse-engineering}"

# arcane_api <method> <path> [json-body] -- authenticated call against this
# host's own Arcane instance. ARCANE_URL/ARCANE_API_TOKEN are operator-
# provided config (see install-homeserver.conf.example): an unattended
# installer can't complete Arcane's own interactive OIDC/passkey login, so
# bootstrapping requires a pre-generated API key (Arcane's own UI, Settings
# -> API Keys, after its first login) the same way step_provision_keycloak_secrets
# requires the Keycloak realm to already exist rather than creating one
# from nothing.
# Arcane authenticates API keys with its own `X-API-Key` header, NOT
# `Authorization: Bearer`. Sending Bearer returns 401 with an ErrorModel body
# and no `data` field, which every caller below then reads as an empty result
# rather than as an auth failure -- so the import "failed" with an empty error
# message and every downstream step cascaded off it. Measured live on the
# 2026-09-03 Rocky 10 rebuild against Arcane v2.9.0:
#   Authorization: Bearer <key> -> 401 {"title":"Unauthorized",...}
#   X-API-Key: <key>            -> 200 {"success":true,"data":[...]}
arcane_api() {
  local method="$1" path="$2" body="${3:-}"
  local -a curl_args=(-sS -X "$method" "${ARCANE_URL%/}/api${path}" \
    -H "X-API-Key: $ARCANE_API_TOKEN" -H "Content-Type: application/json")
  [[ -n "$body" ]] && curl_args+=(-d "$body")
  curl "${curl_args[@]}"
}

# arcane_repo_id <manifest gitRepo> -- prints the Arcane Git repository ID for
# a manifest source, registering it first if absent (idempotent: Arcane has no
# upsert-by-name endpoint, so check first). Both are public HTTPS clones, no
# credentials. An existing registration under that name must point at the
# expected URL: a wrong association would materialize another repository's
# tree into the stack directory, so it fails rather than being reused.
arcane_repo_id() {
  local repo="$1" url
  case "$repo" in
    apiary) url="$GIT_REPO_URL" ;;
    apiary-dashboard) url="https://github.com/Xore/apiary-dashboard.git" ;;
    *) echo "unknown gitRepo '$repo' in $ARCANE_STACK_MANIFEST" >&2; return 1 ;;
  esac
  local existing
  existing=$(arcane_api GET /customize/git-repositories \
    | jq -c --arg name "$repo" '[.data[] | select(.name==$name)][0] // empty')
  if [[ -n "$existing" ]]; then
    if [[ "$(jq -r '.url' <<<"$existing")" != "$url" ]]; then
      echo "Arcane git repository '$repo' points at $(jq -r '.url' <<<"$existing"), expected $url" >&2
      return 1
    fi
    jq -r '.id' <<<"$existing"
    return 0
  fi
  local resp id
  resp=$(arcane_api POST /customize/git-repositories \
    "$(jq -n --arg name "$repo" --arg url "$url" \
      '{name:$name, url:$url, authType:"none", enabled:true}')")
  id=$(jq -r '.data.id' <<<"$resp")
  [[ -n "$id" && "$id" != "null" ]] || {
    echo "failed to register $repo git repository in Arcane: $resp" >&2
    return 1
  }
  echo "$id"
}

step_arcane_import_stacks() {
  [[ -f "$ARCANE_STACK_MANIFEST" ]] || { echo "missing $ARCANE_STACK_MANIFEST"; return 1; }

  # Manifest entries name their source by gitRepo. apiary is this checkout's
  # own remote; apiary-dashboard is the standalone dashboard, whose compose
  # directory lives in that repository. Register each one the manifest uses.
  local -A repo_ids=()
  local repo
  while read -r repo; do
    repo_ids[$repo]=$(arcane_repo_id "$repo") || return 1
  done < <(jq -r '[.[].gitRepo] | unique | .[]' "$ARCANE_STACK_MANIFEST")

  # environmentId 0 is Arcane's own "Local Docker" environment -- the only
  # one this single-host deployment has (confirmed live: /api/environments
  # returns exactly one entry, id "0", for every APIARY homeserver).
  #
  # Confirmed live during #1502's own migration: Arcane's directory sync
  # refuses to create a project if anything already exists at that path
  # ("a directory with that name already exists; refusing to create a
  # duplicate") -- it fails closed rather than merging into or wiping it,
  # which is good for safety but means step_restore_env_files running
  # before this step (it pre-creates /var/dockge/stacks/<name>/.env for
  # anything the backup had) would block every one of those stacks from
  # ever being imported. Stage any pre-existing .env aside, let Arcane
  # create the directory fresh, then put it back and re-deploy -- the same
  # backup/remove/sync/restore sequence used for every stack in the real
  # #1502 cutover, just automated here instead of run by hand.
  local failures=0 name compose_path git_repo branch
  while IFS=$'\t' read -r name compose_path git_repo branch; do
    local dir="${ARCANE_STACKS_ROOT:-/var/dockge/stacks}/$name"
    [[ -f "$dir/compose.yml" ]] && { echo "$name: already synced, skipping"; continue; }

    local staged_env=""
    if [[ -f "$dir/.env" ]]; then
      staged_env="$(mktemp)"
      mv "$dir/.env" "$staged_env"
    fi
    [[ -d "$dir" ]] && rm -rf "$dir"

    echo "-- importing $name via Arcane directory sync"
    local resp status
    resp=$(arcane_api POST /environments/0/gitops-syncs \
      "$(jq -n --arg name "$name" --arg repo "${repo_ids[$git_repo]}" \
             --arg branch "$branch" --arg path "$compose_path" \
        '{name:$name, repositoryId:$repo, branch:$branch, composePath:$path,
          autoSync:false, syncDirectory:true, syncInterval:300}')")
    status=$(echo "$resp" | jq -r '.data.lastSyncStatus // "unknown"')

    if [[ -n "$staged_env" ]]; then
      mkdir -p "$dir"
      mv "$staged_env" "$dir/.env"
      chmod 600 "$dir/.env"
    fi
    # #2959: deliberately NO deploy here. This loop walks the manifest in file
    # order, and honeypot-init sorts before honeypot-elk -- so bringing each
    # stack up as it is imported started honeypot-init's one-shot jobs while
    # the stack that defines elasticsearch was still queued behind them in this
    # same loop. They then looped forever on
    #   curl: (6) Could not resolve host: elasticsearch
    # while the import blocked on their `up --wait`, and the whole step
    # deadlocked on itself until honeypot-elk was imported out of band by hand.
    #
    # Deploy order is not this step's job. start-elasticsearch -> start-init ->
    # start-remaining exist precisely to honour the ordering
    # docs/STACK-REBUILD.md documents, they run immediately after this step,
    # and they cover every stack imported here. Syncing without deploying keeps
    # exactly one place responsible for start order.

    if [[ "$status" != "success" ]]; then
      # Reported for every stack now, not only ones without a staged .env: the
      # old carve-out existed because this loop used to deploy, so a stack that
      # had its secrets was expected to come up. Nothing deploys here any more,
      # so a non-success sync means the same thing either way -- and it is
      # informational regardless, since the start-* steps below re-deploy once
      # real secrets are in place.
      echo "  $name: sync reported '$status' (often expected pre-secrets -- see: $resp)"
      failures=$((failures + 1))
    fi
  # #1505: also imports auth-events-worker/llm-worker/ml-worker -- see this
  # file's own header comment (Phase 8) for why those 3 of the 6 non-
  # honeypot-* stacks were safe to fold in and the other 3 (pihole, ghidra,
  # ghosts) deliberately weren't.
  # Entries from another repository are always imported (that repository
  # owns its own stack list). apiary entries sync the installer's GIT_REF, as
  # the checkout itself does; other repositories sync the branch their entry
  # names (apiary-dashboard has no production branch).
  done < <(jq -r --arg ref "$GIT_REF" '.[] | select((.gitRepo != "apiary") or (.syncName | startswith("honeypot-")) or (.syncName as $n | ["auth-events-worker","llm-worker","ml-worker"] | index($n) != null)) | [.syncName, .dockerComposePath, .gitRepo, (if .gitRepo == "apiary" then $ref else .branch end)] | @tsv' "$ARCANE_STACK_MANIFEST")

  echo "$failures stack(s) reported a non-success initial sync (see above -- often just missing secrets, not a hard failure)."
  return 0
}

# #1019: arcane/home/honeypot-keycloak/compose.yml's realm-template mount was fixed to an
# absolute /opt/stacks/apiary path, but the login theme
# (KEYCLOAK_THEME_DIR, default /var/dockge/stacks/honeypot-keycloak/theme/
# apiary) isn't part of this repo at all -- it's Xore/auth-backend's
# themes/apiary, presentation-only, checked out separately.
# .github/workflows/deploy.yml's CI path already does this (a dedicated
# `actions/checkout` of Xore/auth-backend, then `rsync --delete` into
# theme/apiary); this step is install-homeserver.sh's equivalent for a
# from-scratch homeserver rebuild, which has no CI runner to do it.
step_stage_keycloak_theme() {
  local theme_repo_dir="$(dirname "$REPO_DIR")/auth-backend"
  if [[ -d "$theme_repo_dir/.git" ]]; then
    with_retry 3 10 git -C "$theme_repo_dir" fetch origin
    git -C "$theme_repo_dir" checkout main
    with_retry 3 10 git -C "$theme_repo_dir" pull --ff-only origin main
  else
    mkdir -p "$(dirname "$theme_repo_dir")"
    with_retry 3 10 git clone --branch main "$AUTH_THEME_REPO_URL" "$theme_repo_dir"
  fi
  local destination="/var/dockge/stacks/honeypot-keycloak/theme"
  install -d -m 755 "$destination"
  rsync -a --delete "$theme_repo_dir/themes/apiary/" "$destination/apiary/"
}

step_provision_keycloak_secrets() {
  # #787: step_provision_stack_dirs only creates an empty secrets/ dir --
  # nothing populated postgres-password/bootstrap-admin-password before this,
  # so a genuinely fresh, unattended install would fail here (Postgres'
  # POSTGRES_PASSWORD_FILE and Keycloak's own entrypoint both read files that
  # never existed). This test/reinstall path resets Keycloak to a known
  # initial admin rather than restoring a prior one -- same "start from
  # zero" treatment as the rest of the honeypot stack's data, not an
  # exception carved out just for identity.
  local dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  install -d -m 750 "$dir"
  if [[ ! -f "$dir/postgres-password" ]]; then
    (umask 027; openssl rand -base64 48 > "$dir/postgres-password")
    echo "generated postgres-password"
  fi
  if [[ ! -f "$dir/bootstrap-admin-password" ]]; then
    (umask 027; printf 'admin123\n' > "$dir/bootstrap-admin-password")
    echo "wrote initial bootstrap-admin-password (admin/admin123 -- rotate after first login)"
  fi
  chown root:root "$dir"/postgres-password "$dir"/bootstrap-admin-password
  chmod 440 "$dir"/postgres-password "$dir"/bootstrap-admin-password
  local env_file="/var/dockge/stacks/honeypot-keycloak/.env"
  if [[ -f "$env_file" ]] && grep -q '^KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=' "$env_file"; then
    sed -i 's/^KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=.*/KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=admin/' "$env_file"
  fi
}

step_bootstrap_missing_envs() {
  # Belt-and-suspenders after step_restore_env_files: any stack that still
  # has no .env at all (backup genuinely never had one, e.g. a stack created
  # after the last backup pass) gets bootstrapped from its .env.example so
  # `docker compose up` doesn't fail outright on a missing required file --
  # it'll be full of CHANGE_ME placeholders and won't be fully functional,
  # but that's a visible, fixable gap instead of a silent compose failure.
  local n=0
  local name compose_path
  while IFS=$'\t' read -r name compose_path; do
    local dir="/var/dockge/stacks/$name"
    [[ -f "$dir/.env" ]] && continue
    # #1502: each stack's .env.example now lives next to its own compose.yml
    # under arcane/home/<name>/ (moved there in the same migration that
    # gave every honeypot-* stack an explicit name: and a self-contained
    # directory) rather than at two special-cased repo-root files plus a
    # generic root fallback.
    local example="$REPO_DIR/$(dirname "$compose_path")/.env.example"
    if [[ -f "$example" ]]; then
      cp "$example" "$dir/.env"
      chmod 600 "$dir/.env"
      n=$((n + 1))
      echo "bootstrapped placeholder .env for $name from ${example#"$REPO_DIR"/}"
    fi
  done < <(jq -r '.[] | select((.syncName | startswith("honeypot-")) or (.syncName as $n | ["auth-events-worker","llm-worker","ml-worker"] | index($n) != null)) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")
  echo "Bootstrapped $n placeholder .env file(s) — review for CHANGE_ME values."
}

# #2498: honeypot-canarytokens' compose interpolates
# ${CANARY_PUBLIC_HOSTNAME:-honeypot.example}, and until now nothing in any
# deploy path ever supplied the real value -- the sed passes reach only
# vps/traefik/dynamic.yml, step_bootstrap_missing_envs copies this stack's
# .env.example verbatim (shipped placeholder included), there is no second
# domain-scoped variable inside this stack's own interpolation scope to chain
# a compose-level fallback onto, and step_restore_env_files can only restore
# what a LAN backup once captured. Every fresh install baked unresolvable
# 'honeypot.example' into every created token unless an operator hand-typed
# the apex afterwards -- the exact same bare-apex string this config already
# knows (and validates non-placeholder, above) as KEYCLOAK_PUBLIC_DOMAIN, and
# the exact string docs/CGNAT-DEPLOYMENT.md instructs typing into this stack's
# .env by hand. Runs AFTER both env steps above so it sees whichever of
# {restored backup, example copy} landed:
#   - key absent                    -> appended with the apex
#   - empty or shipped 'honeypot.example' -> replaced with the apex
#   - anything else                 -> left untouched (a real hand-set override
#                                      always wins; re-runs stay idempotent)
step_seed_canary_public_hostname() {
  # CANARY_STACK_DIR exists purely so the seeding branches can be exercised
  # against a scratch directory in tests; every real invocation takes the
  # default below, matching how every other step addresses stack dirs.
  local env_file="${CANARY_STACK_DIR:-/var/dockge/stacks/honeypot-canarytokens}/.env"
  if [[ ! -f "$env_file" ]]; then
    echo "honeypot-canarytokens has no .env yet -- skipping CANARY_PUBLIC_HOSTNAME seed"
    return 0
  fi
  local current
  current=$(grep -E '^CANARY_PUBLIC_HOSTNAME=' "$env_file" | tail -1 | cut -d= -f2-)
  case "$current" in
    ""|"honeypot.example")
      if grep -qE '^CANARY_PUBLIC_HOSTNAME=' "$env_file"; then
        sed -i "s|^CANARY_PUBLIC_HOSTNAME=.*|CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN}|" "$env_file"
        echo "seeded CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN} in honeypot-canarytokens/.env (replaced '${current}')"
      else
        {
          echo ""
          echo "# seeded by install-homeserver.sh (#2498) from KEYCLOAK_PUBLIC_DOMAIN"
          echo "CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN}"
        } >> "$env_file"
        echo "seeded CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN} in honeypot-canarytokens/.env (key was absent)"
      fi
      chmod 600 "$env_file"
      ;;
    *)
      echo "honeypot-canarytokens/.env already sets CANARY_PUBLIC_HOSTNAME=${current} -- leaving it alone"
      ;;
  esac
  return 0
}

step_create_shared_resources() {
  # arcane/home/honeypot-init/compose.yml declares these as external:true. On a genuinely
  # fresh Docker install none of them exist yet, and honeypot-init's
  # containers will fail to even create rather than run and fail --
  # STACK-REBUILD.md documents this exact trap.
  docker network inspect honeynet >/dev/null 2>&1 || docker network create honeynet

  # arcane/home/honeypot-dashboard/compose.yml also declares honeypot-llm as external:true
  # (its query-time embedding call to Ollama), but unlike honeynet it has a
  # real owner: analysis/ghidra/docker-compose.ghidra.yml defines it for
  # real (internal:true, no external:true) and only creates it when
  # ghidra-start runs -- much later than start-remaining, which is what
  # actually starts honeypot-dashboard. Found live during #787's homeserver
  # reinstall (2026-08-09), only visible now that with_retry propagates
  # failure correctly (#1078): "network honeypot-llm declared as external,
  # but could not be found", honeypot-dashboard never came up. --internal
  # matches ghidra's own definition exactly, so when ghidra-start's compose
  # run later reconciles this same network name it finds a config it
  # already agrees with rather than a conflicting one.
  docker network inspect honeypot-llm >/dev/null 2>&1 || docker network create honeypot-llm --internal

  docker volume inspect dionaea-lib >/dev/null 2>&1 || docker volume create dionaea-lib
  docker volume inspect yara-results >/dev/null 2>&1 || docker volume create yara-results

  # arcane/home/honeypot-init/compose.yml's own header comment: "state/init-markers/ must
  # be mode 777 on the host before this stack's [containers run]" --
  # log-init/elasticsearch-setup/arkime-init/snare-clone each touch a
  # <job>.done marker there on success. Confirmed live (first #518 test run):
  # without this, every one-shot job's actual work succeeds but the final
  # `touch /markers/....done` fails with Permission denied, so the container
  # exits 1 and looks like a real failure even though nothing is actually
  # broken.
  install -d -m 777 "$REPO_DIR/state/init-markers"

  # honeypot-cowrie bind-mounts state/honeyfs/{cowrie,cowrie-share} and runs as
  # uid 2000 (its Dockerfile's `USER cowrie`); hp-honeyfs-implant deliberately
  # shares that uid so both can write the same tree -- see honeypot-cowrie's
  # own compose comment on the honeyfs-implant service. Nothing created these
  # directories on the host, so on a from-scratch install Docker made them as
  # root:root and cowrie's entrypoint could not seed the empty mount from
  # honeyfs.dist. Measured on the 2026-09-03 Rocky 10 rebuild -- hp-cowrie
  # crash-looped indefinitely on:
  #   cp: cannot create directory '/cowrie/cowrie-git/honeyfs/./etc': Permission denied
  # No SELinux denial involved (ausearch clean): plain ownership. Create them
  # owned correctly up front rather than letting the bind mount invent them.
  local d
  for d in "$REPO_DIR/state/honeyfs/cowrie" "$REPO_DIR/state/honeyfs/cowrie-share"; do
    install -d -m 755 -o 2000 -g 2000 "$d"
  done
}

step_provision_buildx_cache() {
  # #2822: .github/workflows/containers.yml exports every image's layer
  # cache to type=local under /var/buildx-cache/<image> when the build
  # lands on this box's self-hosted runners, because the type=gha cache was
  # measured ~2x over GitHub's 10 GB per-repository ceiling and therefore
  # being LRU-evicted while in use.
  #
  # The runners execute as github-ci-runner (systemd User= on the
  # actions.runner.*.supermicro-ci* units), and /var is root:root 0755 --
  # so the workflow cannot create this directory itself. Measured live
  # 2026-09-02: `sudo -u github-ci-runner mkdir -p /var/buildx-cache/x`
  # -> "Permission denied", exit 1, which under a step's default `bash -e`
  # fails every one of the Containers matrix rows. Provisioning it here
  # rather than by hand on the live host is the point: #1609 replays this
  # script on a rebuild, and a hand-made directory would not survive that.
  #
  # 0775 with the runner as group owner (not 0777) so the deploy runner and
  # an interactive admin can also write it without making it world-writable
  # on a filesystem that also holds /var/benchmarks. setgid keeps
  # per-image subdirectories group-owned as builds create them.
  #
  # The group has to be granted to every runner instance, not just the
  # first. Measured live 2026-09-06: the box runs seven runner users
  # (github-ci-runner, github-ci-runner-2 .. -7, one per
  # actions.runner.Xore-APIARY.supermicro-ci-* unit) and only
  # github-ci-runner was in the github-ci-runner group, so a Containers row
  # that landed on supermicro-ci-2 got EACCES from the workflow's own
  # `mkdir -p /var/buildx-cache/<image>` and silently degraded to
  # type=gha -- the exact quota-evicted cache #2822 moved off. Joining them
  # here (rather than by hand) is what makes a #1609 rebuild reproduce it.
  local cache_dir=/var/buildx-cache
  local runner_user=github-ci-runner

  if ! id -u "$runner_user" >/dev/null 2>&1; then
    echo "  $runner_user does not exist yet -- creating $cache_dir root-owned;"
    echo "  re-run this step after the CI runners are installed."
    install -d -m 0755 "$cache_dir"
    return 0
  fi

  install -d -m 2775 -o "$runner_user" -g "$runner_user" "$cache_dir"

  # Empty on a fresh install, where the extra instances do not exist yet --
  # install-ci-runner.sh is a manual runbook step that runs later. The loops
  # below then simply do nothing extra, which is the pre-existing behaviour.
  local extra_users=()
  mapfile -t extra_users < <(getent passwd | cut -d: -f1 | grep -E '^github-ci-runner-[0-9]+$' | sort)

  local u
  for u in "${extra_users[@]}"; do
    if id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$runner_user"; then
      continue
    fi
    usermod -aG "$runner_user" "$u"
    echo "  added $u to the $runner_user group"
  done

  # Group membership alone is not enough for subdirectories that already
  # exist: the workflow creates /var/buildx-cache/<image> with the runner's
  # default umask 022, so a dir made by one runner before the grant existed
  # is 2755 -- group-owned but not group-writable, and the next runner's
  # mkdir/prune inside it still fails. Repair what is there; the workflow
  # sets umask 002 for the ones it creates from now on.
  chown -R "$runner_user:$runner_user" "$cache_dir"
  chmod -R g+rwX "$cache_dir"

  # Prove it, rather than assuming install(1) implies the runner can write:
  # the check that was missing is the whole reason this step exists. Every
  # runner user is checked, because one unlisted user is exactly how the
  # 2026-09-06 fallback went unnoticed.
  for u in "$runner_user" "${extra_users[@]}"; do
    if ! runuser -u "$u" -- test -w "$cache_dir"; then
      echo "  ERROR: $cache_dir is not writable by $u" >&2
      ls -ld "$cache_dir" >&2
      return 1
    fi
  done
  echo "  $cache_dir writable by $runner_user ${extra_users[*]} (verified)"
}

step_provision_image_sbom() {
  # #3321: containers.yml writes a digest-keyed CycloneDX SBOM for the two
  # dashboard images (backend-service, dashboard-next) to
  # /var/image-sbom/<image>/ whenever a build lands on this box's self-hosted
  # runners, so the inventory of what is in a running image sits next to the
  # image rather than only in a CI artifact that expires.
  #
  # The blocker is the same one /var/buildx-cache has, for the same reason:
  # the runners execute as github-ci-runner (systemd User= on the
  # actions.runner.*.supermicro-ci* units) and /var is root:root 0755, so the
  # workflow cannot create a sibling directory here itself. Measured live
  # 2026-09-02: `sudo -u github-ci-runner mkdir -p /var/buildx-cache/x` ->
  # "Permission denied", exit 1. Provisioning it here rather than by hand is
  # the point -- #1609 replays this script on a rebuild, and a hand-made
  # directory would not survive that.
  #
  # Consequence of NOT provisioning: generate-image-sbom.sh warns and carries
  # on, and the SBOM survives only as the CI artifact. That is a degraded
  # capability, not a broken build -- the same degrade-don't-fail line
  # provision-buildx-cache's caller takes for the type=gha cache.
  #
  # 2775 with the runner as group owner, setgid, and a default ACL, for the
  # same multi-runner-user reason as buildx-cache: seven runner users exist on
  # this box and any of them can take any Containers matrix row, so the
  # directory and everything created inside it must be group-writable or the
  # row that did not write last is the row that fails.
  local sbom_dir=/var/image-sbom
  local runner_user=github-ci-runner

  if ! id -u "$runner_user" >/dev/null 2>&1; then
    echo "  $runner_user does not exist yet -- creating $sbom_dir root-owned;"
    echo "  re-run this step after the CI runners are installed."
    install -d -m 0755 "$sbom_dir"
    return 0
  fi

  install -d -m 2775 -o "$runner_user" -g "$runner_user" "$sbom_dir"
  # Default ACL, not just the mode bits: the workflow re-grants g+rwX on what
  # it writes, but a subdirectory created by one runner before the next
  # runner's write is exactly how #2822's 2026-09-06 fallback went unnoticed.
  # `acl` is installed here rather than reused from further down this script
  # (step_fix_apiary_backend_permissions is the first other setfacl caller and
  # it runs long after this step), so a fresh #1609 replay gets a real default
  # ACL here instead of silently falling back to the mode bits alone.
  command -v setfacl >/dev/null 2>&1 || pkg_install acl
  setfacl -d -m "g:${runner_user}:rwx" "$sbom_dir"

  # Same group-grant + repair + prove-it loop as provision-buildx-cache: the
  # extra runner instances are installed by a separate manual runbook step
  # (install-ci-runner.sh) that may run after this one, and a directory that
  # only the first runner can write degrades silently rather than loudly.
  local extra_users=()
  mapfile -t extra_users < <(getent passwd | cut -d: -f1 | grep -E '^github-ci-runner-[0-9]+$' | sort)

  local u
  for u in "${extra_users[@]}"; do
    if id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$runner_user"; then
      continue
    fi
    usermod -aG "$runner_user" "$u"
    echo "  added $u to the $runner_user group"
  done

  chown -R "$runner_user:$runner_user" "$sbom_dir"
  chmod -R g+rwX "$sbom_dir"

  for u in "$runner_user" "${extra_users[@]}"; do
    if ! runuser -u "$u" -- test -w "$sbom_dir"; then
      echo "  ERROR: $sbom_dir is not writable by $u" >&2
      ls -ld "$sbom_dir" >&2
      return 1
    fi
  done
  echo "  $sbom_dir writable by $runner_user ${extra_users[*]} (verified)"
}

step_build_zeek_image() {
  # honeypot-elk's zeek-proxy runs the same Zeek build as the VPS sensor, so
  # both load an identical parser set -- a divergence there would quietly make
  # the two sensors disagree about the same traffic.  The build context stays
  # in vps/zeek rather than being copied into the elk stack, because two
  # copies drift.
  #
  # Arcane syncs one directory per project, so the elk compose cannot use a
  # build: context that escapes its own directory.  It names the local tag
  # with pull_policy: never instead, which means nothing in that compose
  # builds it -- and without pull_policy Arcane tries to `docker pull
  # xore-zeek:local` and fails the entire project deploy on a tag that exists
  # in no registry.  Building it here is what makes that reference resolve on
  # a clean install.
  local ctx="$REPO_DIR/vps/zeek"
  [[ -d "$ctx" ]] || { echo "missing Zeek build context: $ctx" >&2; return 1; }
  docker build -f "$ctx/Containerfile" -t xore-zeek:local "$ctx"
  docker image inspect xore-zeek:local >/dev/null
}

# #2959: start the whole honeypot-elk stack, but only GATE on elasticsearch.
#
# `up -d --wait` waits for every service in the stack, and one of them --
# pcap-sync -- cannot become healthy at this point by construction. Its
# healthcheck asserts that the newest file under /src is recent, and /src is
# the sshfs-backed VPS Suricata pcap directory, which is mounted by
# step_sshfs_mounts. Those mounts need logs/<name> to exist, which
# honeypot-init's log-init job creates, which needs a healthy elasticsearch --
# i.e. this step. The dependency is circular, so on a from-scratch host this
# step burned all three retries and failed every time, on pcap-sync alone,
# while elasticsearch, kibana, evebox, filebeat, zeek-proxy, arkime-capture and
# arkime-viewer all reached Healthy. Measured on the 2026-09-04 rebuild.
#
# Everything still gets started; only the readiness gate is narrowed to the
# service the next step actually depends on. pcap-sync is left to come healthy
# on its own once sshfs-mounts runs -- it has restart: unless-stopped and
# autoheal watches it, and this was confirmed live: the moment the mounts
# appeared it went healthy without intervention.
step_start_elasticsearch_first() {
  cd /var/dockge/stacks/honeypot-elk || return 1
  with_retry 3 15 docker compose -f compose.yml up -d
  with_retry 3 15 docker compose -f compose.yml up -d --wait --no-recreate elasticsearch
}

# #1609 follow-up: make Elasticsearch actually load the GeoIP databases.
#
# ES resolves a geoip processor's database when the processor is instantiated.
# On a from-scratch install it starts (step_start_elasticsearch_first) BEFORE
# honeypot-init's geoipupdate job has downloaded anything, so every processor in
# the geoip-honeypot pipeline caches "database unavailable" and every document
# is tagged _geoip_database_unavailable_GeoLite2-City.mmdb instead of being
# geolocated. The attack-origin map stays empty and no error is raised anywhere.
#
# Measured on the 2026-09-04 rebuild, and the recovery is narrower than it
# looks: ES DOES log "database file changed ... reloading database" when the
# files appear, and that is not enough. Touching the files to re-trigger the
# watcher did not clear it, and neither did re-PUTting the pipeline. A bare
# pipeline created after the databases existed geolocated the same IP correctly
# the whole time, which is what isolated it to stale processor instances rather
# than a missing or unreadable database. Only restarting the node cleared them.
#
# So: restart ES once, after the databases are on disk, and only if the tag is
# actually being produced. Cheap, idempotent, and a no-op on a host where the
# databases were already present at boot.
step_geoip_reload_elasticsearch() {
  local geo_dir="$REPO_DIR/analysis/geoip"
  if ! compgen -G "$geo_dir/GeoLite2-*.mmdb" >/dev/null; then
    echo "no GeoLite2 databases in $geo_dir -- nothing to reload (MaxMind credentials unset?)"
    return 0
  fi

  # Ask the live pipeline whether it can geolocate. Any public IP will do.
  local probe='{"docs":[{"_source":{"honeypot":{"src_ip":"8.8.8.8"}}}]}'
  local out
  out=$(docker run --rm --network honeynet curlimages/curl:latest -sS -m 20 \
        -X POST "http://elasticsearch:9200/_ingest/pipeline/geoip-honeypot/_simulate" \
        -H 'Content-Type: application/json' -d "$probe" 2>/dev/null) || {
    echo "could not reach Elasticsearch to probe the geoip pipeline -- skipping"
    return 0
  }

  if ! grep -q '_geoip_database_unavailable' <<<"$out"; then
    echo "geoip pipeline already resolves its databases -- no restart needed"
    return 0
  fi

  echo "geoip pipeline reports _geoip_database_unavailable despite the databases"
  echo "being present -- restarting Elasticsearch to reinstantiate its processors"
  docker restart hp-elasticsearch >/dev/null
  local waited=0
  while (( waited < 180 )); do
    [[ "$(docker inspect hp-elasticsearch --format '{{.State.Health.Status}}' 2>/dev/null)" == healthy ]] && break
    sleep 5; waited=$(( waited + 5 ))
  done
  out=$(docker run --rm --network honeynet curlimages/curl:latest -sS -m 20 \
        -X POST "http://elasticsearch:9200/_ingest/pipeline/geoip-honeypot/_simulate" \
        -H 'Content-Type: application/json' -d "$probe" 2>/dev/null) || true
  if grep -q '_geoip_database_unavailable' <<<"$out"; then
    echo "geoip STILL unavailable after restart -- check the mmdb mount and file modes" >&2
    return 1
  fi
  echo "geoip databases now resolve; new documents will carry source.geo"
}

step_start_init() {
  # #1255's investigation: honeypot-init.env.example already carries
  # MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY placeholders (optional, empty by
  # default), but nothing ever actually enabled the geoip-update Compose
  # profile those gate -- a fresh install with real credentials filled in
  # would still silently end up with no GeoIP databases, no attack-origin
  # map markers, and every ingested document tagged
  # _geoip_database_unavailable_GeoLite2-*. Enable the profile automatically
  # whenever both values are actually filled in; leave it off (with a clear
  # message, not a silent gap) otherwise.
  local init_env="/var/dockge/stacks/honeypot-init/.env"
  # #1226: threat-cidrs-refresh (Spamhaus/Tor/AWS/GCP -- all free, zero-auth
  # sources per refresh-threat-cidrs.sh's own header) has no credential to
  # gate on the way geoip-update below does, so unlike that one it belongs
  # on unconditionally rather than behind an env-driven check. Nothing
  # enabled it before this: a fresh install left threat-cidrs.csv never
  # created at all, so campaigns.go's Provider/Intel classification (and
  # #1218's correlator-worker Providers grouping) silently had no CIDR data
  # to classify against.
  local -a compose_profile_args=(--profile threat-intel)
  if [[ -f "$init_env" ]] \
    && grep -qE '^MAXMIND_ACCOUNT_ID=.+' "$init_env" \
    && grep -qE '^MAXMIND_LICENSE_KEY=.+' "$init_env"; then
    compose_profile_args+=(--profile geoip-update)
    echo "honeypot-init: MAXMIND_ACCOUNT_ID/LICENSE_KEY are set — enabling the geoip-update profile."
  else
    echo "honeypot-init: MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY not set in $init_env —"
    echo "  skipping GeoIP database provisioning. The attack-origin map and every"
    echo "  GeoIP-derived field will stay empty until you fill those in (a free"
    echo "  MaxMind account + license key, see docs/GEOIP-THREAT-INTEL.md)"
    echo "  and re-run: cd /var/dockge/stacks/honeypot-init && docker compose -f compose.yml --profile geoip-update up -d geoipupdate"
  fi
  if ! (cd /var/dockge/stacks/honeypot-init && with_retry 3 15 docker compose -f compose.yml "${compose_profile_args[@]}" up -d); then
    echo "honeypot-init: docker compose up -d failed" >&2
    return 1
  fi
  # honeypot-init's jobs are one-shots; give them a bounded window to exit 0
  # rather than racing straight into the sensor stacks that assume its log
  # paths/ES templates/persona state already exist. geoipupdate (and
  # threat-cidrs-refresh, same shape) are deliberately long-running
  # (restart: unless-stopped) and excluded from this check -- them still
  # running is the success case, not something to wait out.
  local waited=0
  while (( waited < 120 )); do
    local running
    running=$(docker compose -f /var/dockge/stacks/honeypot-init/compose.yml ps --status running -q 2>/dev/null \
      | xargs -r docker inspect --format '{{.Name}}' 2>/dev/null \
      | grep -vE '/hp-(geoipupdate|threat-cidrs-refresh)$' | wc -l)
    (( running == 0 )) && return 0
    sleep 5
    waited=$(( waited + 5 ))
  done
  echo "honeypot-init still has running containers after 120s — check for the"
  echo "Elasticsearch-not-ready trap described in docs/STACK-REBUILD.md."
  return 1
}

# snare is the one Tanner-group sensor whose log directory must be root-owned.
# honeypot-init's log-init job creates every logs/<sensor> directory uniformly
# as 65534:65534, which is right for all of them except this one, so this runs
# between start-init (which creates the directory) and start-remaining (which
# starts the container that needs it).
#
# The mechanism, which docs/STACK-REBUILD.md already records: hp-snare runs as
# root but with cap_drop: ALL and only SETGID/SETUID added -- deliberately no
# DAC_OVERRIDE, because snare's own check_privileges() runs before it drops
# privileges. Root without DAC_OVERRIDE cannot write a file it does not own,
# so snare's first act, writing /opt/snare/snare.pid, fails:
#
#   PermissionError: [Errno 13] Permission denied: '/opt/snare/snare.pid'
#
# and the container crash-loops (13 restarts before this was caught on the
# 2026-09-04 rebuild). Note the recursion: chowning only the directory is not
# enough once a previous crashing run has already left snare.cfg/.log/.err/.pid
# behind owned by nobody -- measured, the container still failed on the
# pre-existing pid file. The directory is left mode-unchanged; only ownership
# is corrected.
step_fix_snare_ownership() {
  local d="$REPO_DIR/logs/snare"
  [[ -d "$d" ]] || { echo "logs/snare does not exist yet -- did start-init run?"; return 1; }
  chown -R root:root "$d"
  echo "logs/snare (and its contents) set root:root for snare's pre-drop check_privileges()"
}

step_start_remaining_stacks() {
  # #1502: Arcane's own directory sync already brought each stack up as
  # part of step_arcane_import_stacks -- this step is now a safety-net
  # re-assertion (idempotent: `up -d --wait` on an already-running,
  # unchanged stack is a no-op), not the primary start mechanism. Kept
  # rather than removed so a secret provisioned by a step *after* the
  # import (e.g. keycloak's, dashboard's) still gets a real `up` against
  # it even if that step didn't call Arcane's own /up endpoint itself.
  local failures=0 name compose_path
  while IFS=$'\t' read -r name compose_path; do
    [[ "$name" == "honeypot-elk" || "$name" == "honeypot-init" ]] && continue
    local dir="/var/dockge/stacks/$name"
    # Use the manifest's OWN dockerComposePath basename, not a hardcoded
    # "compose.yml". Arcane materializes each stack's directory with the file
    # named exactly as the manifest says, and three of the stacks this loop
    # covers -- auth-events-worker, llm-worker, ml-worker -- carry
    # docker-compose.yml. Testing for compose.yml therefore skipped all three
    # silently (`|| continue`, no message), so they were never started at all
    # on a from-scratch install. Their dedicated readiness steps below then
    # reported nonsense about containers that had never been created
    # ("running but never logged its startup line"), because `docker logs` on a
    # nonexistent container just fails the grep. That is #2817: llm-worker
    # completely undeployed, zero containers, and nothing saying so.
    local compose_file="${compose_path##*/}"
    [[ -n "$compose_file" ]] || compose_file="compose.yml"
    if [[ ! -f "$dir/$compose_file" ]]; then
      echo "-- $name: no $compose_file in $dir, skipping"
      continue
    fi
    # A stack whose every service sits behind a Compose profile has nothing to
    # start by default: `up` exits non-zero with "no service selected". That is
    # the correct state, not a failure -- honeypot-correlator-worker,
    # -attacker-identity-worker, -payload-inventory-worker and
    # -agent-intrusion-worker are all gated behind the "legacy" profile,
    # deliberately off since the #1628 Go-worker retirement. Counting them as
    # failures put four spurious FAILEDs in the summary of every clean install,
    # which is exactly the expected-noise problem that trains an operator to
    # skim past a real one.
    echo "-- $name: docker compose -f $compose_file up -d --wait"
    local out rc
    out=$( (cd "$dir" && with_retry 3 15 docker compose -f "$compose_file" up -d --wait) 2>&1 ); rc=$?
    printf '%s\n' "$out"
    if (( rc != 0 )); then
      if printf '%s' "$out" | grep -qi 'no service selected'; then
        echo "   $name: all services are profile-gated, nothing to start by default -- skipping"
      else
        echo "FAILED: $name"
        failures=$((failures + 1))
      fi
    fi
  done < <(jq -r '.[] | select((.syncName | startswith("honeypot-")) or (.syncName as $n | ["auth-events-worker","llm-worker","ml-worker"] | index($n) != null)) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")
  [[ $failures -eq 0 ]]
}

# ---------------------------------------------------------------------------
# Phase 8a1 — auth-events-worker (#1066): Keycloak/gateway auth-failure
# telemetry. Runs here, after start-remaining, because it needs hp-keycloak
# actually healthy (to grant its service-account client the view-events
# role) -- `up -d --wait` in the previous step already confirmed that.
# ---------------------------------------------------------------------------
step_provision_events_poller_secrets() {
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$KEYCLOAK_PROVISION_DIR/provision-events-poller.sh"
}

# #1609 follow-up: pin the real deploy-runner GID into honeypot-dashboard's .env.
#
# That stack's compose joins dashboard-next to a group so the unprivileged
# `node` user can read the OIDC client secret, and a group_add must be a
# numeric GID because /etc/group does not exist inside the image. It used to be
# the literal 980. System GIDs are assigned in creation order, so they describe
# how a host was built rather than being constants: after the 2026-09-03
# rebuild 980 was github-ci-runner-3 and deploy-runner had become 977. The
# container joined an unrelated CI group, could not read the secret, and every
# sign-in failed with EACCES -- surfaced to users as "Sign-in is temporarily
# unavailable ... the identity provider or session store did not answer", which
# points at Keycloak for a local file-permission problem.
step_pin_deploy_runner_gid() {
  local group="${DASHBOARD_SECRETS_GROUP:-deploy-runner}" gid env_file
  gid="$(getent group "$group" | cut -d: -f3)"
  [[ -n "$gid" ]] || { echo "group '$group' does not exist -- cannot pin DEPLOY_RUNNER_GID" >&2; return 1; }
  # The two directories the enrichment worker writes, group-owned by the same
  # group its container joins. It runs as nobody(65534) and both were left
  # root:root 755 by the rebuild, so it could not write either -- and it says so
  # at WARN and stays healthy, which is how it shipped zero enrichment output
  # while looking fine. 2775: setgid keeps new files in the group.
  local d
  for d in "$REPO_DIR/logs/enriched" "$REPO_DIR/state/ip-enrichment-worker"; do
    install -d -m 2775 -o root -g "$gid" "$d"
  done
  echo "provisioned enrichment output/state dirs group-owned by $group"

  env_file=/var/dockge/stacks/honeypot-dashboard/.env
  [[ -f "$env_file" ]] || { echo "no $env_file yet"; return 1; }
  if grep -q '^DEPLOY_RUNNER_GID=' "$env_file"; then
    sed -i "s/^DEPLOY_RUNNER_GID=.*/DEPLOY_RUNNER_GID=${gid}/" "$env_file"
  else
    printf '\n# GID of %s on THIS host, for honeypot-dashboard compose group_add.\n' "$group" >> "$env_file"
    printf 'DEPLOY_RUNNER_GID=%s\n' "$gid" >> "$env_file"
  fi
  echo "pinned DEPLOY_RUNNER_GID=$gid ($group)"

  # Writing the .env is not enough. group_add is a CREATE-time property: an
  # already-running container keeps whatever supplementary GID it was built
  # with, and `restart: unless-stopped` will never change it -- only a
  # recreate re-reads the value. This step runs after step_start_remaining_
  # stacks, so the containers already exist by now and are still on the
  # compose fallback GID.
  #
  # Left unrecreated, the enrichment worker joins the wrong group and cannot
  # write its own offset files:
  #
  #   WARN apiary_backend::ip_enrichment: ip-enrichment: save offset failed
  #        source=tanner error=Permission denied (os error 13)
  #
  # It logs that at WARN, stays healthy, and re-reads the same input every
  # tick forever -- a spin that ships no enrichment while `docker ps` shows
  # nothing wrong. Confirmed live on the 2026-09-04 rebuild: the container
  # carried GID 979 (the compose fallback) while deploy-runner was 977.
  (cd /var/dockge/stacks/honeypot-dashboard \
    && docker compose up -d backend-worker-enrichment dashboard-next) \
    || echo "could not recreate honeypot-dashboard services -- DEPLOY_RUNNER_GID will not take effect until they are"
}

step_provision_dashboard_oidc_secret() {
  # honeypot-dashboard is one of the generic STACK_DEFS stacks
  # step_start_remaining_stacks already started (and it has no secret yet
  # at that point, so it crash-loops on first boot) -- this step runs
  # after that, once Keycloak is actually up, same as
  # step_provision_events_poller_secrets right above. No need to also
  # restart the dashboard here: it has restart: unless-stopped, so its
  # own crash-restart loop picks up the freshly written secret within
  # seconds.
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$KEYCLOAK_PROVISION_DIR/provision-dashboard-oidc-secret.sh"
}

step_provision_arcane_oidc_secret() {
  # #1504: step_arcane_install stood Arcane up with a placeholder OIDC secret
  # (good enough for the API-token-driven import, not for interactive login).
  # Now that Keycloak is up (start-remaining above waited it healthy, same as
  # for dashboard/events-poller right above), fetch the real per-realm
  # `arcane` client secret Keycloak generated on --import-realm and re-up
  # Arcane with it. Path convention deliberately identical to its two sibling
  # provisioner steps above so a single fix covers all three.
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$KEYCLOAK_PROVISION_DIR/provision-arcane-oidc-secret.sh"
}

step_provision_account_console_scopes() {
  # #1697: Keycloak's built-in account-console client is created by
  # --import-realm with no client scopes at all, which makes the account
  # console 403 on its own REST call (#1690). It cannot be fixed in the realm
  # JSON -- see provision-account-console-scopes.sh's header for the two
  # reasons and the measurements behind them -- so it is reconciled here,
  # alongside the sibling provisioners that also exist because the realm
  # format cannot express what they set.
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$KEYCLOAK_PROVISION_DIR/provision-account-console-scopes.sh"
}

step_fix_apiary_backend_permissions() {
  # apiary-backend's image runs USER nobody (uid 65534) -- deliberately
  # unprivileged, unlike the retired Go dashboard which ran as root and (its
  # own compose comment says explicitly) bypassed file permissions entirely.
  # Every host resource backend-service/backend-service-mounted/backend-
  # worker-payload-inventory touch was provisioned under that old root-bypass
  # assumption and never revisited for #1608/#1612/#1622's cutover to this
  # image. Confirmed live (2026-08-22): `cat /state/dashboard-config.json`
  # inside hp-apiary-backend itself returned Permission denied -- the
  # dashboard's own config/users/audit/threat-intel state was unreadable by
  # the container serving it. Narrow ACL grants (this repo's own existing
  # precedent -- see sandbox/repair-permissions.sh) rather than running these
  # two network-reachable services as root: grants exactly nobody's uid the
  # access it needs, nothing broader. The six honeypot-*/requests/pending
  # spools get the identical grant at their own point of creation (each
  # one's install/process script, not here) since those are host directories
  # this script doesn't own; dashboard-state/dionaea-lib/services-adapter-
  # socket are plain Docker-managed named volumes with no other natural home.
  command -v setfacl >/dev/null 2>&1 || pkg_install acl

  local dashboard_state dionaea_lib adapter_socket
  dashboard_state=$(docker volume inspect dashboard-state --format '{{.Mountpoint}}' 2>/dev/null) || return 0
  dionaea_lib=$(docker volume inspect dionaea-lib --format '{{.Mountpoint}}' 2>/dev/null) || return 0
  adapter_socket=$(docker volume inspect services-adapter-socket --format '{{.Mountpoint}}' 2>/dev/null) || return 0

  # dashboard-state: config/users/audit/intelligence + script-payloads, all
  # root:*00 from the old Go dashboard's root-owned writes. Recursive grant
  # covers what's there today; the default ACL (d:u:...) covers every file
  # either service creates from here on. Explicit mask on every call --
  # combining access and default entries in one `-m` invocation was found
  # live to leave the access mask at `---` (any named entry silently
  # ineffective) despite the entry itself showing correctly in getfacl.
  setfacl -R -m u:65534:rwX "$dashboard_state"
  setfacl -m mask::rwx "$dashboard_state"
  setfacl -m d:u:65534:rwx "$dashboard_state"
  setfacl -m d:mask::rwx "$dashboard_state"

  # dionaea-lib: read-only for backend-service/backend-service-mounted/
  # backend-worker-payload-inventory's PAYLOAD_DIRS reconciliation --
  # read+traverse only, dionaea itself is the only writer. Host-created
  # (owner xore:xore, 0700), not root -- same fix either way.
  setfacl -R -m u:65534:rX "$dionaea_lib"
  setfacl -m mask::rx "$dionaea_lib"
  setfacl -m d:u:65534:rx "$dionaea_lib"
  setfacl -m d:mask::rx "$dionaea_lib"

  # services-adapter-socket: control.sock is recreated by services-adapter
  # (runs as root) on every restart, so a grant on the socket file itself
  # doesn't survive -- the default ACL on its parent directory is what
  # actually persists this across restarts (a new file created in a
  # directory with a default ACL inherits it as its initial ACL). Also
  # grant the current socket directly so this step is effective immediately
  # rather than only after the next services-adapter restart.
  setfacl -m d:u:65534:rw "$adapter_socket"
  setfacl -m d:mask::rw "$adapter_socket"
  [[ -S "$adapter_socket/control.sock" ]] && {
    setfacl -m u:65534:rw "$adapter_socket/control.sock"
    setfacl -m mask::rw "$adapter_socket/control.sock"
  }
  true
}

step_auth_events_worker_start() {
  # #1505: provisioning (materializing the directory, `docker compose up`)
  # is now step_arcane_import_stacks/step_start_remaining_stacks' job, same
  # as any honeypot-* stack -- no more repo-checkout symlink here, which
  # would fight Arcane's own ownership of /var/dockge/stacks/auth-events-worker
  # (a real directory Arcane's sync materializes, not something to replace
  # with a symlink out from under it). This step runs after
  # provision-events-poller-secrets (its secret doesn't exist yet when
  # start-remaining first runs it -- restart: unless-stopped's own
  # crash-loop picks up the freshly written secret within seconds, same
  # reasoning step_provision_dashboard_oidc_secret's own comment already
  # documents for dashboard) and just verifies real readiness.
  #
  # No Docker HEALTHCHECK signal this step can trust alone (#593): poll the
  # log for the line worker.py actually emits once it's genuinely ready,
  # instead of trusting compose's "running" status.
  local waited=0 max_wait=60
  while (( waited < max_wait )); do
    if docker logs hp-auth-events-worker 2>&1 | grep -q 'auth-events-worker starting'; then
      echo "auth-events-worker confirmed ready"
      return 0
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done
  echo "auth-events-worker container is running but never logged its startup line within ${max_wait}s" >&2
  return 1
}

# ---------------------------------------------------------------------------
# Phase 8a2 — read-only sshfs mounts of the VPS's Suricata/portbridge logs
# (and, since #518, the pcap/ subdirectory Suricata's pcap-log writes into
# once its output-directory ownership is fixed VPS-side -- see the earlier
# #518 issue comment on that bug). Filebeat and pcap-sync/Arkime both depend
# on these; must run after start-remaining, since honeypot-init's log-init
# job is what creates the mount-point directories in the first place.
# ---------------------------------------------------------------------------
step_sshfs_install() {
  # Debian calls it sshfs; RHEL ships the same FUSE client as fuse-sshfs.
  case "$DISTRO_FAMILY" in
    debian) pkg_install sshfs ;;
    rhel)   pkg_install fuse-sshfs ;;
  esac
  mkdir -p /root/.ssh
  # Skip the copy when the configured key already IS the destination. `install`
  # errors with "are the same file" and, under set -e, fails the whole step --
  # which is what happened on the 2026-09-04 rebuild once VPS_SSH_KEY was
  # pointed at /root/.ssh/strato_vps (the natural value on a host where the key
  # has already been placed). Nothing was actually wrong.
  if [[ "$(readlink -f "$VPS_SSH_KEY" 2>/dev/null)" != "$(readlink -f /root/.ssh/strato_vps 2>/dev/null)" ]]; then
    install -m 600 "$VPS_SSH_KEY" /root/.ssh/strato_vps.tmp
    mv /root/.ssh/strato_vps.tmp /root/.ssh/strato_vps
  else
    echo "VPS_SSH_KEY is already /root/.ssh/strato_vps -- leaving it in place"
  fi
  chmod 600 /root/.ssh/strato_vps
}

# Every VPS-side log directory Filebeat, pcap-sync or the payload pipeline
# needs to see. One entry here is one sshfs mount; a directory missing from
# this list is simply absent on the homeserver, and the consumer that wanted
# it reports no error -- it just finds nothing, forever. That is the failure
# mode #1409 and #1678 both were, so the list is the single place to add to.
#
# #1742 added zeek, zeek-extract, huginn and traefik for the S5 sensing layer.
SSHFS_LOG_DIRS=(suricata portbridge zeek zeek-extract huginn traefik)

step_sshfs_mounts() {
  local dirs=() name dir
  for name in "${SSHFS_LOG_DIRS[@]}"; do
    dir=$(readlink -f "$REPO_DIR/logs/$name")
    [[ -d "$dir" ]] || {
      echo "logs/$name doesn't exist yet -- honeypot-init's log-init job should have created it."
      return 1
    }
    dirs+=("$dir")
  done

  local opts="_netdev,ro,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,IdentityFile=/root/.ssh/strato_vps,port=2222,allow_other,default_permissions,StrictHostKeyChecking=accept-new"
  # The comment block below is written once; the per-directory lines follow.
  grep -q "read-only VPS log mounts" /etc/fstab || cat >>/etc/fstab <<EOF

# #518: read-only VPS log mounts for Suricata (eve.json + pcap/) and
# portbridge, pulled over the WireGuard tunnel. See docs/SENSORS.md.
# /opt/stacks/apiary, not the pre-#783-rebrand honeypot-stack -- confirmed
# live against the VPS during #787's homeserver reinstall (2026-08-09):
# the old path doesn't exist there anymore, silently failing this mount
# (masked non-fatally without real VPS credentials to notice with, until
# now). NOTE: this same stale honeypot-stack path still appears in ~20
# other files across the repo (docs and other scripts) -- out of scope for
# this fix, tracked separately.
EOF

  # One fstab line per directory, appended only if absent, so re-running the
  # installer after adding a new sensor is safe and additive.
  local i
  for i in "${!SSHFS_LOG_DIRS[@]}"; do
    name="${SSHFS_LOG_DIRS[$i]}"
    dir="${dirs[$i]}"
    grep -q " $dir " /etc/fstab || \
      echo "root@${VPS_WG_ADDRESS}:/opt/stacks/apiary/logs/$name $dir fuse.sshfs $opts 0 0" >>/etc/fstab
  done

  local failed=0
  for dir in "${dirs[@]}"; do
    mountpoint -q "$dir" || mount "$dir" || failed=1
    mountpoint -q "$dir" || { echo "sshfs mount failed: $dir" >&2; failed=1; }
  done
  return "$failed"
}

step_sshfs_boot_ordering() {
  # Installs WireGuard-aware systemd mount ordering/retry (the raw fstab
  # _netdev/reconnect options alone don't guarantee the WG interface is up
  # before the mount is attempted at boot) and restarts filebeat/evebox so
  # they pick up newly-available mounts rather than waiting for their own
  # retry logic.
  bash "$REPO_DIR/setup-suricata-logs-home.sh"
}

# ---------------------------------------------------------------------------
# Phase 8b — Technitium DNS (replaced Pi-hole 2026-09-03). The LAN backup only
# captured the DNS stack .env; the deployment definition lives under technitium/.
# ---------------------------------------------------------------------------
step_technitium_provision() {
  local dir="/var/dockge/stacks/technitium"
  mkdir -p "$dir/config"

  # Binding 0.0.0.0:53 collides with hp-dns-honeypot, which already publishes
  # 53/udp on 10.8.0.2 (the WireGuard bind IP every honeypot sensor uses,
  # per HP_BIND / CGNAT-DEPLOYMENT.md's "never reachable from your home LAN"
  # design) -- 0.0.0.0 overlaps every interface including that one, so
  # Docker's port allocator refuses the bind (confirmed live, #518).
  # Technitium is real home-LAN infra, not a honeypot component, so it binds
  # the actual LAN-facing IP. TECHNITIUM_LAN_IP is an explicit config value,
  # not inferred from the default route (auto-detection picked the wrong one
  # of two NICs on this box, confirmed live #518).
  local lan_ip="$TECHNITIUM_LAN_IP"
  install -m 0644 "$REPO_DIR/technitium/compose.yml" "$dir/compose.yml"

  # Same ${LAN_IP} interpolation mechanism the old pihole stack used since #1502
  # (a `:?required` var in a port-binding host-IP position broke Arcane's
  # own pre-flight check, see docs/ARCANE-GIT-SYNC.md). Written explicitly so
  # a genuinely fresh install gets the operator-configured address rather
  # than silently falling back to compose's 127.0.0.1 default.
  if [[ ! -f "$dir/.env" && -f "$REPO_DIR/technitium/.env.example" ]]; then
    install -m 0644 "$REPO_DIR/technitium/.env.example" "$dir/.env"
  fi
  if [[ -f "$dir/.env" ]]; then
    if grep -q '^LAN_IP=' "$dir/.env"; then
      sed -i "s|^LAN_IP=.*|LAN_IP=$lan_ip|" "$dir/.env"
    else
      printf 'LAN_IP=%s\n' "$lan_ip" >> "$dir/.env"
    fi
    chmod 600 "$dir/.env"
  fi
}

step_technitium_lan_route() {
  # #3068: this host has two NICs on the same /24, and whichever one has
  # the lower route metric wins outbound traffic regardless of which
  # address Technitium is configured and listening on. Technitium's peer
  # identity, zone-transfer ACLs and cluster membership are all pinned to
  # TECHNITIUM_LAN_IP -- if the kernel actually sources LAN traffic from
  # the *other* NIC's address, every AXFR from a real peer gets REFUSED,
  # with a symptom (RCODE=Refused) that looks like a TSIG problem and
  # burns time debugging the wrong layer (confirmed live, #3068). Catch
  # the metric/interface mismatch here, before Technitium ever starts.
  local lan_ip="$TECHNITIUM_LAN_IP"
  local iface lan_cidr prefix probe actual_src
  local ip_int mask base candidate route_out try try_ip a b c d default_gw

  read -r iface lan_cidr < <(ip -o addr show | awk -v ip="$lan_ip" '$4 ~ "^"ip"/" {print $2, $4; exit}')
  if [[ -z "${iface:-}" ]]; then
    echo "no local interface holds TECHNITIUM_LAN_IP=$lan_ip" >&2
    return 1
  fi

  # Probe an address inside the LAN's own subnet, not the default gateway.
  # The property under test is which NIC wins the *connected* route for
  # this /24 -- the route a peer's AXFR is answered over. A gateway probe
  # only happens to test that while the default route stays inside the LAN;
  # point the default route at wg0 or a WAN NIC and it reports a mismatch
  # that has nothing to do with #3068. Broadcast is no good either: it
  # resolves out of the local table and answers from the wrong NIC here
  # (measured). So: first host address in the subnet, skipping any
  # candidate the host holds itself (those route via lo and say nothing
  # about which NIC wins).
  prefix="${lan_cidr#*/}"
  IFS=. read -r a b c d <<<"${lan_cidr%/*}"
  ip_int=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  mask=$(( prefix == 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF) ))
  base=$(( ip_int & mask ))

  probe=""
  for candidate in 1 2 3 4; do
    try=$(( base + candidate ))
    try_ip="$(( (try >> 24) & 255 )).$(( (try >> 16) & 255 )).$(( (try >> 8) & 255 )).$(( try & 255 ))"
    route_out="$(ip route get "$try_ip" 2>/dev/null)" || continue
    [[ "$route_out" == local* ]] && continue
    probe="$try_ip"
    break
  done
  if [[ -z "$probe" ]]; then
    echo "could not pick a probe address inside $lan_cidr to test the LAN route with" >&2
    return 1
  fi

  # Non-fatal sanity note, deliberately not an assertion. The old shape of
  # this check probed the default gateway, which also caught
  # TECHNITIUM_LAN_IP pointing at a tunnel address (wg0) instead of the
  # home LAN -- but it fails spuriously the moment a host's default route
  # legitimately leaves the LAN subnet. Keep the observation, drop the
  # false failure: the hard assertion below is about which NIC wins the
  # LAN, which is what #3068 was.
  default_gw="$(ip route show default | awk '{print $3; exit}')"
  if [[ -n "$default_gw" ]]; then
    IFS=. read -r a b c d <<<"$default_gw"
    if (( ((((a << 24) | (b << 16) | (c << 8) | d)) & mask) != base )); then
      echo "note: TECHNITIUM_LAN_IP=$lan_ip sits on $iface ($lan_cidr), which does not contain the default gateway $default_gw -- if this host's home LAN is really elsewhere, Technitium is bound to the wrong network (a WireGuard/tunnel address will pass the route check below and still be unreachable from LAN peers)" >&2
    fi
  fi

  actual_src="$(ip route get "$probe" | grep -oP 'src \K\S+' | head -1)"
  if [[ "$actual_src" != "$lan_ip" ]]; then
    echo "LAN traffic to $probe sources from ${actual_src:-<none>}, not TECHNITIUM_LAN_IP=$lan_ip on $iface -- a second NIC on the same LAN with a lower route metric will source zone transfers from the wrong address and get every AXFR REFUSED (see #3068); fix the route metric (e.g. nmcli connection modify <conn> ipv4.route-metric <n>) so $lan_ip's interface wins" >&2
    return 1
  fi
}
step_technitium_start() {
  [[ -f /var/dockge/stacks/technitium/.env ]] || { echo "no technitium .env restored — skipping start"; return 1; }
  (cd /var/dockge/stacks/technitium && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

step_technitium_verify() {
  local dir="/var/dockge/stacks/technitium"
  local container_answer lan_answer

  # Probe each hop separately so an unattended install failure identifies
  # whether the container-internal path or the LAN bind is bad.
  container_answer="$(docker exec technitium-dns \
    dig @127.0.0.1 example.com A +time=3 +tries=1 +short)" || return
  lan_answer="$(dig @"$TECHNITIUM_LAN_IP" example.com A +time=3 +tries=1 +short)" || return

  [[ -n "$container_answer" ]] || { echo "Technitium returned no recursive answer" >&2; return 1; }
  [[ -n "$lan_answer" ]] || { echo "Technitium returned no LAN-side answer" >&2; return 1; }
}

# #2974: a fresh/rebuilt host picks up NetworkManager's default resolver
# order (public resolvers first), which the glibc stub resolver treats as
# authoritative -- an NXDOMAIN from 1.1.1.1/8.8.8.8 for a split-horizon
# dmz.xore.lan name stops the lookup right there, it does not fall through
# to Technitium even though Technitium would answer. Confirmed live
# 2026-09-05: `getent hosts <host>.dmz.xore.lan` returned nothing with the
# public-first order and resolved correctly once Technitium was made
# primary.
#
# Order is TECHNITIUM_PRIMARY_IP first, then TECHNITIUM_LAN_IP. This fleet's
# primary Technitium node is the workstation, not the host this installer
# provisions -- zones are edited on the master and replicated to the node
# here, so the node this script sets up is the secondary and belongs second.
# TECHNITIUM_PRIMARY_IP is optional: a fleet with only the one node this
# script provisions leaves it unset and gets a single-entry list.
#
# Public resolvers are opt-in (HOST_RESOLVER_PUBLIC_FALLBACK), not appended
# unconditionally. On this fleet's LAN outbound port 53 to the internet is
# blocked entirely -- confirmed live 2026-09-05, `dig @1.1.1.1` and
# `dig @8.8.8.8` both time out -- so a public entry is not a fallback here,
# it is a full resolver timeout charged to every lookup that has to reach
# past Technitium. A network where they do work can still ask for them.
step_host_resolver_order() {
  local primary_ip="${TECHNITIUM_PRIMARY_IP:-}"
  local conn
  # The connection actually carrying TECHNITIUM_LAN_IP, not a fixed
  # interface name -- NIC naming isn't stable across this fleet's hosts.
  conn=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null \
    | while IFS=: read -r name dev; do
        ip addr show "$dev" 2>/dev/null | grep -q "inet ${TECHNITIUM_LAN_IP}/" && echo "$name" && break
      done)
  if [[ -z "$conn" ]]; then
    echo "no active NetworkManager connection carries $TECHNITIUM_LAN_IP -- set resolver order by hand" >&2
    return 1
  fi

  local dns_list=""
  [[ -n "$primary_ip" ]] && dns_list="$primary_ip,"
  dns_list="${dns_list}${TECHNITIUM_LAN_IP}"
  if [[ "${HOST_RESOLVER_PUBLIC_FALLBACK:-}" != "" ]]; then
    dns_list="$dns_list,${HOST_RESOLVER_PUBLIC_FALLBACK}"
  fi

  nmcli connection modify "$conn" ipv4.dns "$dns_list"
  nmcli connection up "$conn" >/dev/null

  # Assert the property the step exists to establish: a Technitium node is
  # the FIRST nameserver. `grep -q "^nameserver <ip>"` matches anywhere in
  # the file and so passes even with public DNS ahead of it, which is
  # exactly the state this step is here to prevent.
  local first technitium_nodes
  first=$(awk '/^nameserver /{print $2; exit}' /etc/resolv.conf)
  technitium_nodes="${TECHNITIUM_LAN_IP}${primary_ip:+,$primary_ip}"
  if [[ -z "$first" || ",$technitium_nodes," != *",$first,"* ]]; then
    echo "first nameserver in /etc/resolv.conf is '${first:-none}', expected one of $technitium_nodes" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Phase 9 — LLM/ML worker (GPU-dependent, gated behind ENABLE_GPU_STACK)
# ---------------------------------------------------------------------------
step_ghidra_stack_provision() {
  # docker-compose.ghidra.yml uses RELATIVE build contexts (`build: ./statictools`,
  # `context: ./revdeck/ai-reverse-engineering`). Symlinking only compose.yml
  # into a separate /var/dockge/stacks/ghidra directory breaks those --
  # confirmed live (first #518 test run): "unable to prepare context: path
  # .../ghidra/statictools not found", because Compose resolves relative
  # build paths against the compose FILE's own directory, which was the
  # symlink's location, not analysis/ghidra/ where statictools/ actually
  # lives. Symlink the whole directory instead so relative paths resolve
  # correctly, matching what a real Dockge "point at this folder" stack
  # would do.
  local src="$REPO_DIR/analysis/ghidra"
  [[ -d "$src" ]] || { echo "missing $src"; return 1; }
  # step_restore_env_files ran earlier and put ghidra's .env at
  # /var/dockge/stacks/ghidra/.env (a plain directory at that point) --
  # rescue it before replacing that path with a symlink, since Compose
  # will read .env from wherever we `cd` to run it (the real analysis/ghidra
  # directory once symlinked).
  if [[ -f /var/dockge/stacks/ghidra/.env && ! -L /var/dockge/stacks/ghidra ]]; then
    mv /var/dockge/stacks/ghidra/.env "$src/.env"
  fi
  rm -rf /var/dockge/stacks/ghidra
  ln -sfn "$src" /var/dockge/stacks/ghidra
  ln -sf "$src/docker-compose.ghidra.yml" "$src/compose.yml"
  [[ -f "$src/docker-compose.ghidra.gpu.yml" ]] && ln -sf "$src/docker-compose.ghidra.gpu.yml" "$src/compose.gpu.yml"
}

step_revdeck_source() {
  # Rev·Deck's build context is upstream source this repo deliberately does not
  # vendor: analysis/ghidra/docker-compose.ghidra.yml builds it from
  # ./revdeck/ai-reverse-engineering, and that directory has only ever been
  # created by hand. So every rebuild silently loses the service -- the
  # 2026-09-04 rebuild included, where rev.<domain> answered 302 from a healthy
  # oauth2-proxy on the VPS while no revdeck container existed on this host at
  # all. Nothing reported a fault: the profile keeps it out of `docker compose
  # up`, so an absent service is indistinguishable from a disabled one, and a
  # health sweep that counts running containers can never see it.
  #
  # Same class as #2923 (a manual step that no script owned, lost on rebuild).
  # Cloning it here is what makes `--profile revdeck` below safe to pass
  # unconditionally.
  local dest="$REPO_DIR/analysis/ghidra/revdeck/ai-reverse-engineering"
  if [[ -d "$dest/.git" ]]; then
    # Already present: fast-forward, but never fail the install over it. A
    # network blip must not take out the whole run for an optional analyst UI.
    (cd "$dest" && git fetch -q origin && git merge -q --ff-only FETCH_HEAD) 2>/dev/null || \
      echo "revdeck source present but could not be updated -- keeping the existing checkout"
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  if ! with_retry 3 10 git clone -q "$REVDECK_REPO_URL" "$dest"; then
    echo "could not clone revdeck source from $REVDECK_REPO_URL -- revdeck will stay absent"
    rm -rf "$dest"
    return 0
  fi
  # webui/Dockerfile is the build target the compose file names; a clone that
  # lacks it would fail the build rather than skip the service.
  [[ -f "$dest/webui/Dockerfile" ]] || {
    echo "revdeck clone has no webui/Dockerfile -- upstream layout changed, leaving revdeck disabled"
    rm -rf "$dest"
  }
}

step_ghidra_stack_start() {
  # Rocky enables cockpit.socket by default and it listens on *:9090, which is
  # the port analysis/ghidra/docker-compose.ghidra.yml publishes ghidra's API on
  # (127.0.0.1:9090). A wildcard listener blocks the loopback bind, so the
  # container never starts:
  #
  #   failed to bind host port 127.0.0.1:9090/tcp: address already in use
  #
  # and it fails at CREATE, so it sits in "Created" rather than restarting --
  # easy to miss in a `docker ps` that only lists running containers. Hit on the
  # 2026-09-04 rebuild; invisible on Ubuntu, which does not ship cockpit enabled.
  #
  # Cockpit is not part of this deployment: nothing in this repo references it,
  # and the live host had zero cockpit sessions in the preceding week. Disabled
  # rather than moving ghidra's port, because the port is baked into that
  # stack's healthcheck and GHIDRA_API_BASE as well as the published mapping.
  # Re-enable it on a host that wants it, and move ghidra instead.
  if systemctl is-active --quiet cockpit.socket 2>/dev/null; then
    echo "cockpit.socket holds :9090, which ghidra needs -- disabling it"
    systemctl disable --now cockpit.socket 2>/dev/null || true
    systemctl stop cockpit.service 2>/dev/null || true
  fi
  local dir="/var/dockge/stacks/ghidra"
  local files=(-f compose.yml)
  [[ -f "$dir/compose.gpu.yml" ]] && files+=(-f compose.gpu.yml)
  # Bring up revdeck too, but only when step_revdeck_source actually produced a
  # build context. Passing --profile revdeck without one fails the whole
  # `up` ("unable to prepare context"), taking ghidra and ollama down with it --
  # which is exactly why the service is profile-gated in the first place.
  local profiles=()
  [[ -f "$dir/revdeck/ai-reverse-engineering/webui/Dockerfile" ]] && profiles=(--profile revdeck)
  (cd "$dir" && with_retry 3 15 docker compose "${files[@]}" "${profiles[@]}" up -d --wait)
}

step_ollama_model_pull() {
  # Pinned model per analysis/ghidra/models/approved-models.json -- resolved
  # at runtime rather than hardcoded so a model-pin bump doesn't require
  # editing this script too. The file is a manifest object keyed by
  # `slots.<slot>.artifact.tag`, not a plain array -- confirmed live
  # (first #518 test run); the ghidra slot's pinned tag is what
  # ghidra-ollama-1 actually needs loaded.
  local model
  model=$(jq -r '.slots.ghidra.artifact.tag // empty' "$REPO_DIR/analysis/ghidra/models/approved-models.json" 2>/dev/null)
  [[ -n "$model" ]] || { echo "could not resolve pinned model from approved-models.json"; return 1; }
  docker exec ghidra-ollama-1 ollama pull "$model"

  # #1236: the dashboard's own semantic search (dashboard/main.go's
  # LLM_EMBEDDING_MODEL, default "nomic-embed-text:latest") hits this same
  # ollama instance for embeddings -- a completely different kind of model
  # (embedding, not chat/completion) than the three qualification-gated
  # slots above, so it deliberately isn't in approved-models.json's own
  # benchmark/gate manifest. Without this, semantic search 404'd on every
  # fresh install with "model \"nomic-embed-text:latest\" not found, try
  # pulling it first" until someone happened to pull it by hand.
  docker exec ghidra-ollama-1 ollama pull nomic-embed-text:latest

  # galah is a fourth consumer of this same ollama, reaching it through
  # hp-galah-llm-broker, and it needs a model none of the above provide.
  # Exactly the #1236 failure repeated: without this the sensor comes up
  # "healthy", accepts connections, and returns HTTP 500 to every request --
  #
  #   ERRO GALAH: error generating response: contentGenerationError:
  #                model 'qwen2.5:7b-instruct-q4_K_M' not found
  #
  # -- so it captures nothing while looking fine in `docker ps`. Found on the
  # 2026-09-04 rebuild, live, with zero galah events in 24h.
  #
  # Its model is deliberately NOT one of the qwen3 family (galah's vendored
  # langchaingo client cannot send `think: false`, and Qwen3's unsuppressable
  # thinking mode blows past galah's hardcoded 10s WriteTimeout) -- see
  # arcane/home/honeypot-galah/compose.yml's own comment for the full
  # reasoning. Resolved from that compose file rather than hardcoded here so
  # the two cannot drift apart.
  local galah_model
  galah_model=$(sed -n 's/^[[:space:]]*-[[:space:]]*LLM_MODEL=\(.*\)$/\1/p' \
    "$REPO_DIR/arcane/home/honeypot-galah/compose.yml" 2>/dev/null | head -1)
  if [[ -n "$galah_model" ]]; then
    docker exec ghidra-ollama-1 ollama pull "$galah_model"
  else
    echo "could not resolve galah's LLM_MODEL from its compose -- galah will 500 on every request"
  fi
}

step_ghidra_worker_install() {
  # #636: the two steps above only bring up the Docker containers (ghidra
  # REST API, ollama, statictools) -- confirmed live that this alone leaves
  # automated triage completely non-functional. Nothing actually reads
  # captured binaries and submits them; that's ghidra-worker.py, a
  # host-level systemd service install-analysis-host.sh installs and this
  # script never called. Zero completed analyses and no systemd unit at all
  # were found on a "healthy" fresh install before this step existed.
  #
  # --stack-dir "": tells install-analysis-host.sh to reconcile the compose
  # stack in place from this checkout instead of deploying a second copy to
  # /opt/stacks/ghidra. That path resolves to the exact same already-running
  # Dockge stack step_ghidra_stack_provision set up (both share the "ghidra"
  # compose project name, derived from the directory holding the compose
  # file) -- a second deploy path would just be a second file to keep in
  # sync with this one. `docker compose up -d` against an already-matching
  # project is a safe no-op reconciliation here, not a duplicate deployment.
  #
  # --skip-pull: step_ollama_model_pull above already pulled the pinned
  # model; re-pulling here would just be a redundant round trip to verify a
  # manifest that's already known current.
  "$REPO_DIR/analysis/ghidra/install-analysis-host.sh" --stack-dir "" --skip-pull
}

step_ml_worker_start() {
  # #1505: provisioning is now step_arcane_import_stacks/
  # step_start_remaining_stacks' job -- the relative-build-context breakage
  # this step used to work around by symlinking the whole directory
  # (confirmed live, first #518 test run: "failed to read dockerfile: open
  # Dockerfile: no such file or directory") is exactly what Arcane's own
  # directory-aware sync solves generically for every stack, which is the
  # entire point of #1502. Symlinking here now would fight Arcane's
  # ownership of /var/dockge/stacks/ml-worker instead. This step just
  # verifies real readiness.
  #
  # #593: compose's own `--wait` (in step_start_remaining_stacks) only
  # waits for the container to reach "running" -- ml-worker has no Docker
  # HEALTHCHECK defined, so trusting that alone reported OK on every run
  # even while the container was stuck in its own internal 5-minute
  # Elasticsearch-connect retry loop (a real requirements.txt regression,
  # #599) or had built against a broken dependency set entirely. Neither
  # failure mode makes the container exit or crash-loop at the Docker
  # level, so `--wait` alone can never catch either one. Poll the
  # container's own log for the exact line worker.py emits once it's
  # genuinely ready, instead of trusting compose's exit code.
  local waited=0 max_wait=90
  while (( waited < max_wait )); do
    if docker logs hp-ml-worker 2>&1 | grep -q 'Worker ready\.'; then
      echo "ml-worker confirmed ready (found 'Worker ready.' in logs)"
      return 0
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done
  echo "ml-worker container is running but never logged 'Worker ready.' within ${max_wait}s -- likely stuck retrying a dependency (see #593)" >&2
  return 1
}

step_llm_worker_selftest() {
  # llm-worker's compose file (restart: unless-stopped, container_name
  # hp-llm-worker) keeps a persistent but harmless container running by
  # default -- LLM_ENABLED defaults to false and the base compose joins
  # only an internal synthetic-only network (per #66/#83), so "persistent"
  # here means "safely idle", not "actively processing". The worker itself
  # is CPU-only by design (Ollama holds the GPU reservation, see
  # docs/gpu-llm-analysis-worker.md's Architecture Overview) -- no --gpus
  # needed. The actual selftest invocation is documented in
  # docs/llm-worker/README.md's Quick Start: bring the container up, then exec
  # into it. My first attempt here (docker run <image> --selftest as a
  # one-shot) was wrong on both counts -- confirmed live (#518 test run):
  # it failed with "exec: --selftest: executable file not found in $PATH"
  # because the image has no ENTRYPOINT, so args replace CMD rather than
  # appending to it.
  #
  # #1505: runs against Arcane's own materialized directory now, not
  # $REPO_DIR/llm-worker directly -- container_name is fixed (hp-llm-worker)
  # so a stray `up` from the repo checkout would likely still reconcile
  # against the same container rather than duplicate it, but running it
  # from the same directory Arcane manages avoids relying on that and
  # matches step_ghidra_worker_install's own "reconcile in place, don't
  # deploy a second copy" precedent. `up -d --build --wait` on an
  # already-running, unchanged stack is a safe no-op here, same reasoning.
  # Resolve the compose file from the manifest, not by guessing. llm-worker's
  # base docker-compose.yml is the Safe #66 synthetic-only file and forces
  # ES_HOST empty on purpose (#2234); captured-data mode lives in
  # docker-compose.captured-data-deploy.yml, which `include`s both. Starting the
  # base file on a host authorized for captured data gives a container that
  # believes it is in captured-data mode (LLM_ALLOW_CAPTURED_DATA=true) while
  # unable to resolve elasticsearch -- it crash-loops on
  #   configuration error: ES_HOST must be an uncredentialed local/internal HTTP endpoint
  # which is #1751's exact failure, hit again on the 2026-09-04 rebuild.
  local dir="/var/dockge/stacks/llm-worker" cf
  cf="$(jq -r '.[] | select(.syncName=="llm-worker") | .dockerComposePath' \
        "$ARCANE_STACK_MANIFEST" 2>/dev/null)"
  cf="${cf##*/}"
  if [[ -z "$cf" || ! -f "$dir/$cf" ]]; then
    cf="$(stack_compose_file "$dir")" || {
      echo "no compose file in $dir -- was arcane-import-stacks skipped or llm-worker not yet synced?"
      return 1
    }
  fi
  ( cd "$dir" && \
    with_retry 3 15 docker compose -f "$cf" up -d --build --wait && \
    docker exec hp-llm-worker python worker.py --selftest )
}

step_backup_timer_install() {
  # #1413: analysis/backup-honeypot.sh existed but was never actually wired
  # into anything that would run it -- no systemd timer, no cron entry, zero
  # snapshots in the live honeypot-fs repository despite it being registered
  # on the cluster. Same class of "the script exists but nothing invokes it"
  # gap as ghidra-worker-install above.
  "$REPO_DIR/analysis/install-backup-timer.sh"
}

# ---------------------------------------------------------------------------
# Phase 10 — verification
# ---------------------------------------------------------------------------
step_verify_containers_healthy() {
  local unhealthy
  unhealthy=$(docker ps --filter "health=unhealthy" --format '{{.Names}}')
  if [[ -n "$unhealthy" ]]; then
    echo "Unhealthy containers: $unhealthy"
    return 1
  fi
}

step_verify_exited() {
  local exited
  exited=$(docker ps -a --filter "status=exited" --format '{{.Names}}\t{{.Status}}' | grep -v 'Exited (0)' || true)
  if [[ -n "$exited" ]]; then
    echo "Containers exited non-zero:"
    echo "$exited"
    return 1
  fi
}

step_verify_elasticsearch_events() {
  docker run --rm --network honeynet curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 -sf \
    http://elasticsearch:9200/honeypot-v2-*/_count >/dev/null
}

# ---------------------------------------------------------------------------
# Phase 11 — sandbox VM restore (GHOSTS + Windows detonation), gated behind
# ENABLE_SANDBOX_RESTORE since it's a 170G+ transfer and a genuinely separate
# subsystem (KVM/libvirt, not Docker) from everything above.
#
# This phase only restores golden images from backup -- it deliberately does
# NOT install Packer or the PXE build prerequisites (p7zip-full,
# python3-virt-firmware, sbsigntool) or add a build user to the kvm group.
# A from-scratch win11-analysis.qcow2 rebuild is a separate, manual,
# multi-hour production action (see docs/sandbox/windows/IMPLEMENTATION_PLAN.md
# Phase 0) that this unattended install flow should not silently trigger.
# ---------------------------------------------------------------------------
# #1609 Phase 7: bind the passthrough GPU to vfio-pci and make sure IOMMU is
# actually on.
#
# sandbox/windows/packer/win11-kvm.xml passes a discrete GPU through to the
# Windows detonation domain, and its comment used to assert that
# /etc/modprobe.d/vfio-gpu-passthrough.conf already existed and had the card
# "already bound at boot". Neither was true: the file did not exist on the live
# host and no script in this repo wrote it. This step is that missing half.
#
# IOMMU is checked here rather than assumed. #1609 recorded 87 IOMMU groups on
# the old Ubuntu host with no explicit kernel flag and concluded it was enabled
# by default on this hardware. That did not survive the OS change: the Rocky 10
# rebuild came up with ZERO groups, which would have made every hostdev
# assignment fail at domain start with no obvious cause.
#
# Deliberately opt-in via VFIO_PASSTHROUGH_PCI_IDS rather than auto-detected.
# Binding the wrong device to vfio-pci takes it away from the host, and "the
# GPU that is not the compute GPU" is not something to guess at on a box that
# has two NVIDIA cards. The operator names the IDs; this step refuses anything
# that looks like the boot display.
step_vfio_gpu_passthrough() {
  if [[ -z "${VFIO_PASSTHROUGH_PCI_IDS:-}" ]]; then
    echo "VFIO_PASSTHROUGH_PCI_IDS unset -- no GPU passthrough configured, skipping"
    echo "  (set it to the vendor:device IDs of the card to hand to the Windows"
    echo "   sandbox, e.g. from 'lspci -nn'; leave unset if not using passthrough)"
    return 0
  fi

  # Refuse to hand over the card the host is booting its console on. vfio-pci
  # claiming the boot VGA leaves a headless box with no console to recover from.
  local boot_vga id
  for boot_vga in /sys/bus/pci/devices/*/boot_vga; do
    [[ -r "$boot_vga" && "$(cat "$boot_vga" 2>/dev/null)" == "1" ]] || continue
    local dev; dev="$(basename "$(dirname "$boot_vga")")"
    local vd; vd="$(lspci -n -s "${dev#0000:}" 2>/dev/null | awk '{print $3}')"
    for id in ${VFIO_PASSTHROUGH_PCI_IDS//,/ }; do
      if [[ -n "$vd" && "$vd" == "$id" ]]; then
        echo "REFUSING: $id is the boot VGA ($dev). Binding it to vfio-pci would" >&2
        echo "  leave this host with no console. Pick the non-primary card." >&2
        return 1
      fi
    done
  done

  # IOMMU: enable on the kernel cmdline if the groups are not already present.
  local reboot_needed=0
  if [[ ! -d /sys/kernel/iommu_groups ]] || [[ -z "$(ls -A /sys/kernel/iommu_groups 2>/dev/null)" ]]; then
    local iommu_arg="intel_iommu=on"
    grep -qi '^vendor_id.*AuthenticAMD' /proc/cpuinfo && iommu_arg="amd_iommu=on"
    if command -v grubby >/dev/null 2>&1; then
      grubby --update-kernel=ALL --args="$iommu_arg iommu=pt"
      echo "IOMMU was not active; added '$iommu_arg iommu=pt' to the kernel cmdline"
      reboot_needed=1
    else
      echo "WARNING: IOMMU is not active and grubby is unavailable -- add" >&2
      echo "         '$iommu_arg iommu=pt' to the kernel cmdline by hand." >&2
    fi
  else
    echo "IOMMU active ($(ls /sys/kernel/iommu_groups | wc -l) groups)"
  fi

  local conf=/etc/modprobe.d/vfio-gpu-passthrough.conf
  local desired="options vfio-pci ids=${VFIO_PASSTHROUGH_PCI_IDS}"
  if [[ -f "$conf" ]] && grep -qxF "$desired" "$conf"; then
    echo "$conf already binds ${VFIO_PASSTHROUGH_PCI_IDS}"
  else
    cat > "$conf" <<EOF
# Written by install-homeserver.sh (step_vfio_gpu_passthrough, #1609 Phase 7).
# Pre-binds the Windows sandbox's passthrough GPU to vfio-pci so the host's
# own GPU driver never claims it. sandbox/windows/packer/win11-kvm.xml passes
# these functions through with managed='yes', so libvirt can detach them either
# way; pre-binding avoids the host driver grabbing the card first at boot.
$desired
softdep nvidia pre: vfio-pci
softdep nouveau pre: vfio-pci
softdep amdgpu pre: vfio-pci
EOF
    echo "wrote $conf binding ${VFIO_PASSTHROUGH_PCI_IDS} to vfio-pci"
    command -v dracut >/dev/null 2>&1 && dracut --force >/dev/null 2>&1 \
      && echo "regenerated initramfs so the binding applies at boot"
    reboot_needed=1
  fi

  if (( reboot_needed )); then
    echo
    echo "REBOOT REQUIRED for the vfio binding / IOMMU change to take effect."
    echo "After rebooting, re-run with: --force-rerun-from vfio-gpu-passthrough"
    echo "Verify with: lspci -nnk -d ${VFIO_PASSTHROUGH_PCI_IDS%%,*} | grep -i 'driver in use'"
  fi
}

step_libvirt_install() {
  case "$DISTRO_FAMILY" in
    debian)
      pkg_install qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils \
        virtinst libguestfs-tools ovmf
      ;;
    rhel)
      # Same stack, different names throughout: qemu-kvm, libvirt-daemon-kvm,
      # libvirt-client, virt-install, guestfs-tools, edk2-ovmf (the UEFI
      # firmware the Windows sandbox domains boot from).
      #
      # virt-win-reg and libguestfs-winsupport are separate packages here,
      # where Debian's libguestfs-tools carries both. kvm_manage.sh's
      # verify_golden_image_contents reads the guest's SMB share registry keys
      # through virt-win-reg before every clone (#100/#2023), so without them
      # EVERY create fails on a golden image that is perfectly fine:
      #   [ERROR] Could not read the SMB share registry state ... via virt-win-reg
      # winsupport is what makes the guest's NTFS filesystem readable at all.
      pkg_install qemu-kvm libvirt libvirt-daemon-kvm libvirt-client bridge-utils \
        virt-install guestfs-tools virt-win-reg libguestfs-winsupport edk2-ovmf
      ;;
  esac
  # RHEL 9+ splits libvirtd into modular per-driver daemons and may ship no
  # libvirtd.service at all. Enable whichever this host actually has rather
  # than assuming the monolithic one.
  if systemctl list-unit-files libvirtd.service >/dev/null 2>&1 \
     && systemctl cat libvirtd.service >/dev/null 2>&1; then
    # The modular virtproxyd sockets Conflicts= the monolithic libvirtd units
    # and bind the same /run/libvirt/libvirt-sock(-ro) paths. If a package
    # preset leaves both stacks enabled, whichever activates second stops the
    # other via Conflicts= -- permanently, since socket units have no
    # Restart= (#3126). Keep this host on the monolithic stack only.
    #
    # #3312: virtproxyd is not the only conflicting unit. The per-driver
    # modular sockets (virtqemud, virtnetworkd, virtnwfilterd, ...) are
    # preset-enabled on EL too and each Conflicts= libvirtd; after the
    # 2026-09-23 reboot they won the race, libvirtd.socket sat inactive and
    # /run/libvirt/libvirt-sock never existed. Disable every modular driver
    # daemon, not just the proxy.
    local drv sfx modular_units=()
    for drv in virtqemud virtnetworkd virtnwfilterd virtstoraged virtnodedevd \
               virtsecretd virtinterfaced virtproxyd; do
      for sfx in .socket -ro.socket -admin.socket .service; do
        systemctl cat "$drv$sfx" >/dev/null 2>&1 && modular_units+=("$drv$sfx")
      done
    done
    if [ "${#modular_units[@]}" -gt 0 ]; then
      systemctl disable --now "${modular_units[@]}" >/dev/null 2>&1 || true
    fi
    systemctl enable --now libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket
    systemctl enable --now libvirtd
  else
    # Same Conflicts= hazard in reverse: the monolithic units must not stay
    # enabled alongside the modular stack this branch is about to activate.
    systemctl disable --now libvirtd.socket libvirtd-ro.socket libvirtd.service >/dev/null 2>&1 || true
    systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket \
      virtproxyd.socket virtproxyd-ro.socket \
      || echo "WARNING: could not enable the modular libvirt sockets"
  fi

  # libvirt-daemon-config-nwfilter's postinst only copies the built-in
  # filter templates (clean-traffic, no-mac-spoofing, etc.) from
  # /usr/share/libvirt/nwfilter into /etc/libvirt/nwfilter when the package
  # goes from "never configured" to configured. If the package was already
  # marked configured at a prior version -- e.g. /etc/libvirt was wiped by
  # hand without a full `apt purge` first, which is exactly what happened
  # during #518's teardown-and-reinstall verification -- the postinst takes
  # its "regular upgrade, don't touch anything" branch and silently leaves
  # /etc/libvirt/nwfilter without the defaults. win11-ghosts-kvm.xml,
  # win11-sandbox-kvm.xml and the Linux sandbox network all reference these
  # by name (no-mac-spoofing among them), so a VM define fails outright
  # with "referenced filter '...' is missing" the first time a sandbox step
  # runs -- confirmed live, see #518. Restore them unconditionally here so
  # apt's install-vs-upgrade heuristic can't leave the sandbox chain broken.
  mkdir -p /etc/libvirt/nwfilter
  cp -n /usr/share/libvirt/nwfilter/*.xml /etc/libvirt/nwfilter/ 2>/dev/null || true
  systemctl restart libvirtd

  # #3312: install-deploy-runner.sh adds github-deploy-runner to the libvirt
  # group only if that group already exists, and on a fresh host the runner
  # is provisioned before this step installs libvirt -- so the membership
  # was silently skipped and isolation-audit.sh's virsh checks were denied
  # by polkit. Re-assert it here, once the group is guaranteed to exist.
  if id github-deploy-runner >/dev/null 2>&1 && getent group libvirt >/dev/null; then
    usermod -aG libvirt github-deploy-runner
  fi
}

step_sandbox_backup_restore() {
  # /var/dockge/sandbox is a hardcoded absolute path baked into multiple
  # files (win11-ghosts-kvm.xml's <source file=.../>, kvm_manage.sh's
  # SANDBOX_ROOT default, provision-golden-image.sh's default arg) -- it
  # must land exactly there, not somewhere symlinked or renamed.
  mkdir -p /var/dockge/sandbox

  # A "local:" prefix restores from a directory on this host instead of over
  # SSH. The golden images are ~66G and the copy that matters is often already
  # attached to the box being rebuilt: on 2026-09-05 all three images plus
  # isos/, vms/ and libvirt-defs.xml were sitting on the homeserver's own
  # backup drive at /mnt/usb-recovery, while #1609 recorded them as not being
  # in the backup set at all and Phase 8 as blocked on a multi-hundred-GB
  # transfer nobody had scheduled. Pulling 66G out of a local ext4 drive and
  # back over the LAN to the same machine is the only thing that was actually
  # missing.
  if [[ "$BACKUP_HOST_SANDBOX_PATH" == local:* ]]; then
    local src="${BACKUP_HOST_SANDBOX_PATH#local:}"
    if [[ ! -d "$src" ]]; then
      echo "BACKUP_HOST_SANDBOX_PATH names a local path that does not exist: $src" >&2
      echo "  (mount the backup drive first -- an unmounted mountpoint reads as" >&2
      echo "   an empty directory or a missing one, and rsync would happily" >&2
      echo "   'restore' nothing at all)" >&2
      return 1
    fi
    echo "restoring sandbox tree from local path: $src"
    rsync -a --info=progress2 "${src%/}/" /var/dockge/sandbox/
    return
  fi

  with_retry 2 30 rsync -a -e "ssh -i $BACKUP_HOST_KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10" \
    "${BACKUP_HOST_USER}@${BACKUP_HOST}:${BACKUP_HOST_SANDBOX_PATH}/" /var/dockge/sandbox/
}

step_sandbox_checksum_verify() {
  # Golden images are the root of trust for every detonation guest cloned
  # from them (see kvm_manage.sh's own comment on this) -- verify every
  # .sha256 the backup carried rather than trusting the transfer blindly.
  local sums failures=0
  while IFS= read -r -d '' sums; do
    ( cd "$(dirname "$sums")" && sha256sum -c "$(basename "$sums")" ) || failures=$((failures + 1))
  done < <(find /var/dockge/sandbox -name "*.sha256" -print0)

  # The loop above only checks whatever .sha256 files happen to exist --
  # silently a no-op for a golden image whose checksum is missing entirely,
  # which defeats the whole "root of trust" point just as surely as a
  # mismatch would. Found live during #787's homeserver reinstall
  # (2026-08-09): only win11-cape.qcow2 had a .sha256 in the actual LAN
  # backup; win11-analysis.qcow2 and win11-ghosts.qcow2 had none at all and
  # were never verified. Require one for every *.qcow2 under golden-images/.
  local qcow2
  while IFS= read -r -d '' qcow2; do
    if [[ ! -f "${qcow2}.sha256" ]]; then
      echo "no .sha256 for golden image: $qcow2 -- backup did not carry one"
      failures=$((failures + 1))
    fi
  done < <(find /var/dockge/sandbox/golden-images -name "*.qcow2" -print0 2>/dev/null)

  [[ $failures -eq 0 ]]
}

# Both win11-ghosts and win11-sandbox declare <nvram template='.../OVMF_VARS_4M.ms.fd'
# format='qcow2'> -- the template itself is raw, and this box's libvirt
# (12.0.0) refuses to do the raw->qcow2 conversion on first boot: "Operation
# not supported: conversion of the nvram template to another target format
# is not supported". Confirmed live (#518). Pre-creating the target file
# with the right format makes libvirt find it already there and skip the
# conversion path entirely, rather than working around it after the fact
# every time.
ensure_nvram_vars() {
  local target="$1"
  # The vars template and the QEMU file owner are both distro-dependent, and
  # both were hardcoded to Debian's until #1609's Rocky rebuild ran this for
  # the first time on EL:
  #   qemu-img: Could not open '/usr/share/OVMF/OVMF_VARS_4M.ms.fd'
  #   chown: invalid user: 'libvirt-qemu:kvm'
  # It also produced a qcow2, which EL's libvirt then refuses to boot from
  # ("conversion of the nvram template to another target format is not
  # supported") -- so the shared helper makes a raw copy instead, and
  # sandbox_define_domain rewrites the XML to match. Same helper kvm_manage.sh
  # uses, so the installer and a hand-run kvm_manage.sh cannot disagree about
  # which firmware a domain got.
  # shellcheck source=/dev/null
  . "$REPO_DIR/sandbox/windows/setup/host-paths.sh"
  sandbox_ensure_nvram "$(sandbox_nvram_raw_path "$target")"
}

step_ghosts_network_setup() {
  bash "$REPO_DIR/sandbox/ghosts/install-network.sh" net-setup
}

step_ghosts_host_install() {
  # --skip-enroll-test: the full test (build Ghosts.Client.Universal from
  # source, run it once, poll the API for enrollment) is the real
  # confirmation bar per docs/sandbox/ghosts/README.md, but it's slow and this
  # step already follows a `dotnet publish`-from-source container build --
  # run the enrollment test manually after a restore, not on every
  # unattended run.
  bash "$REPO_DIR/sandbox/ghosts/install-host.sh" --skip-enroll-test
}

step_ghosts_vm_start() {
  # win11-ghosts-kvm.xml's <disk> points at vms/win11-ghosts.qcow2 -- a thin
  # qcow2 clone of golden-images/win11-ghosts.qcow2, by its own comment. This
  # step never actually created that clone (unlike
  # step_windows_sandbox_vm_create's equivalent `qemu-img create -b
  # $GOLDEN_IMAGE` for win11-sandbox), so on any box where the disk hadn't
  # already been created some other way it just didn't exist. Found live
  # during #787's homeserver reinstall (2026-08-09): `virsh start
  # win11-ghosts` failed outright -- "Cannot access storage file
  # '/var/dockge/sandbox/vms/win11-ghosts.qcow2': No such file or directory"
  # -- while win11-sandbox came up fine right after, since only it had a
  # create step. sandbox-checksum (run earlier in this same script) already
  # verified the golden image before this step runs, so no second checksum
  # pass here.
  local golden="/var/dockge/sandbox/golden-images/win11-ghosts.qcow2"
  local disk="/var/dockge/sandbox/vms/win11-ghosts.qcow2"
  if [[ ! -e "$disk" ]]; then
    [[ -f "$golden" ]] || { echo "golden image not found: $golden"; return 1; }
    mkdir -p "$(dirname "$disk")"
    qemu-img create -f qcow2 -F qcow2 -b "$golden" "$disk"
  fi
  # Defines through the same helper kvm_manage.sh uses -- this step calls
  # libvirt directly rather than going through kvm_manage.sh, so on EL it
  # failed twice over: "Cannot check QEMU binary /usr/bin/qemu-system-x86_64"
  # at define, then "conversion of the nvram template to another target format
  # is not supported" at start.
  # shellcheck source=/dev/null
  . "$REPO_DIR/sandbox/windows/setup/host-paths.sh"
  virsh list --all --name | grep -qx win11-ghosts \
    || sandbox_define_domain "$REPO_DIR/sandbox/ghosts/win11-ghosts-kvm.xml" \
    || return 1
  virsh domstate win11-ghosts | grep -q running || virsh start win11-ghosts
}

step_windows_sandbox_network_setup() {
  bash "$REPO_DIR/sandbox/windows/setup/kvm_manage.sh" net-setup
}

step_windows_sandbox_vm_create() {
  ensure_nvram_vars /var/lib/libvirt/qemu/nvram/win11-sandbox_VARS.qcow2
  if virsh list --all --name | grep -qx win11-sandbox; then
    echo "win11-sandbox already defined -- skipping create (use kvm_manage.sh revert to reset to golden)"
    return 0
  fi
  # kvm_manage.sh create refuses to run if $VM_DISK already exists (it may
  # hold a detonated guest, see its own comment) -- a restore can leave a
  # pre-existing thin-clone from before the backup that isn't a live
  # detonation. Confirmed live (#518): safe to clear before a first-time
  # restore create, since the domain isn't defined yet at that point.
  rm -f /var/dockge/sandbox/vms/win11-sandbox.qcow2
  bash "$REPO_DIR/sandbox/windows/setup/kvm_manage.sh" create
}

step_windows_sandbox_vm_start() {
  virsh domstate win11-sandbox | grep -q running || virsh start win11-sandbox
}

# #1609 Phase 7: create and start win11-cape.
#
# This was the concrete gap that blocked #1524's "all three golden images boot
# cleanly" acceptance item from being able to pass at all: win11-cape.qcow2 sat
# on disk with no automated path to a running VM. `virsh list --all` showed only
# win11-ghosts and win11-sandbox, and grepping this installer for "cape" found
# nothing but a comment about the golden-image file itself.
#
# Mirrors step_windows_sandbox_vm_create's thin-clone pattern, driven through
# the same kvm_manage.sh -- which needed VM_XML/NET_NAME/NET_XML made
# overridable to be usable for a second domain at all. CAPE's own machinery
# config (sandbox/cape/capev2-overrides/conf/capekvm.conf) already pins the
# same paths and the "win11-cape" label, so these must agree with it:
#   golden_image = /var/dockge/sandbox/golden-images/win11-cape.qcow2
#   vm_disk      = /var/dockge/sandbox/vms/win11-cape.qcow2
step_cape_network_setup() {
  local net_xml="$REPO_DIR/sandbox/cape/network.xml"
  [[ -f "$net_xml" ]] || { echo "missing $net_xml"; return 1; }
  if virsh net-info cape >/dev/null 2>&1; then
    virsh net-info cape | grep -qi 'Active:.*yes' || virsh net-start cape
    echo "cape network already defined"
    return 0
  fi
  virsh net-define "$net_xml"
  virsh net-start cape
  virsh net-autostart cape
}

step_cape_vm_create() {
  local golden="/var/dockge/sandbox/golden-images/win11-cape.qcow2"
  if [[ ! -f "$golden" ]]; then
    echo "no $golden -- win11-cape golden image not restored, skipping VM create"
    echo "  (build it with sandbox/cape/packer/win11-cape.pkr.hcl, or restore it"
    echo "   from the sandbox backup; nothing else here can synthesise it)"
    return 0
  fi
  ensure_nvram_vars /var/lib/libvirt/qemu/nvram/win11-cape_VARS.qcow2
  if virsh list --all --name | grep -qx win11-cape; then
    echo "win11-cape already defined -- skipping create"
    return 0
  fi
  # Same reasoning as win11-sandbox's create: kvm_manage.sh refuses to clone
  # over an existing $VM_DISK, and a restore can leave a stale thin-clone from
  # before the backup. Safe to clear here because the domain is not defined yet.
  rm -f /var/dockge/sandbox/vms/win11-cape.qcow2
  VM_NAME=win11-cape \
  GOLDEN_IMAGE="$golden" \
  GOLDEN_CONTENT_CHECK=none \
  VM_DISK=/var/dockge/sandbox/vms/win11-cape.qcow2 \
  VM_XML="$REPO_DIR/sandbox/cape/win11-cape-kvm.xml" \
  NET_NAME=cape \
  NET_XML="$REPO_DIR/sandbox/cape/network.xml" \
    bash "$REPO_DIR/sandbox/windows/setup/kvm_manage.sh" create
}

step_cape_vm_start() {
  virsh list --all --name | grep -qx win11-cape || {
    echo "win11-cape not defined (golden image absent?) -- nothing to start"
    return 0
  }
  virsh domstate win11-cape | grep -q running || virsh start win11-cape
}

# Detonation guests are started per sample by the pipeline, never left up:
# run_sample.py's revert_to_golden() destroys the domain, makes a fresh CoW
# clone and boots that ("every detonation still starts from the identical
# golden state, which is what makes runs comparable and the guest
# disposable"), and CAPE's capekvm machinery does its own vm.create() per
# task. Leaving one powered on after the install is not merely idle waste --
# detonate_inguest() (#490) stages the sample with libguestfs BEFORE qemu
# opens the disk, and libguestfs and a running qemu process cannot both hold
# the same qcow2 open. An install that leaves them running hands the pipeline
# a state it has to undo, and a 16 GiB guest sits on the host's RAM until it
# does.
#
# So the install still boots each domain once -- that is the check that
# catches firmware/nvram breakage at install time, which is exactly what
# #1609 found on EL -- and then puts them back down.
SANDBOX_DETONATION_DOMAINS=(win11-sandbox win11-cape)

step_sandbox_verify_running() {
  local dom rc=0
  # win11-cape is included only when defined: its golden image is optional (see
  # step_cape_vm_create), and a host without it should not fail this check.
  local doms=(win11-ghosts win11-sandbox)
  virsh list --all --name | grep -qx win11-cape && doms+=(win11-cape)
  for dom in "${doms[@]}"; do
    local state; state=$(virsh domstate "$dom" 2>&1)
    echo "$dom: $state"
    [[ "$state" == "running" ]] || rc=1
  done
  return $rc
}

step_sandbox_park_detonation_vms() {
  # Runs after sandbox-verify has confirmed they boot. Graceful shutdown, then
  # destroy for anything that ignores ACPI within the window -- these are
  # disposable clones, so a hard stop costs nothing that the next
  # revert_to_golden() would not throw away anyway.
  local dom
  for dom in "${SANDBOX_DETONATION_DOMAINS[@]}"; do
    virsh list --all --name | grep -qx "$dom" || continue
    [[ "$(virsh domstate "$dom" 2>/dev/null)" == "running" ]] || { echo "$dom: already off"; continue; }
    echo "$dom: shutting down (started on demand by the detonation pipeline)"
    virsh shutdown "$dom" >/dev/null 2>&1 || true
    local waited=0
    while (( waited < 90 )); do
      [[ "$(virsh domstate "$dom" 2>/dev/null)" == "running" ]] || break
      sleep 5; waited=$(( waited + 5 ))
    done
    [[ "$(virsh domstate "$dom" 2>/dev/null)" == "running" ]] && virsh destroy "$dom" >/dev/null 2>&1 || true
    echo "$dom: $(virsh domstate "$dom" 2>/dev/null)"
  done
}

step_sandbox_host_foundation() {
  # sandbox/install-host.sh: the honeypot-sandbox libvirt network + nftables
  # filter + /var/lib/honeypot-sandbox dir tree, shared foundation for the
  # Linux KVM sample-analysis path (separate from the GHOSTS/Windows
  # networks set up above). Also disables/destroys libvirt's default NAT
  # network as unnecessary and dangerous for malware VMs -- confirmed safe
  # to run after win11-ghosts/win11-sandbox already exist, since it only
  # touches the `default` and `honeypot-sandbox` networks, not theirs.
  bash "$REPO_DIR/sandbox/install-host.sh"
}

step_linux_sandbox_base() {
  # Downloads and GPG-verifies a fresh Ubuntu cloud image rather than
  # restoring one -- unlike the Windows golden images (custom Packer builds,
  # days of hardening work, must be preserved), the Linux base is
  # reproducible on demand and was never part of the sandbox backup.
  [[ -f /var/lib/honeypot-sandbox/base/ubuntu-noble.qcow2 ]] && { echo "base image already present"; return 0; }
  bash "$REPO_DIR/sandbox/prepare-linux-base.sh"
}

step_linux_sandbox_verify() {
  bash "$REPO_DIR/sandbox/verify-linux-sandbox.sh"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
log "install-homeserver.sh starting — log: $RUN_LOG"

run_step preflight-os          "Confirm supported OS"               step_preflight_os
run_step preflight-disks       "Check disk layout against docs"    step_preflight_disks
run_step preflight-platform    "Report SELinux/firewalld state"     step_preflight_rhel_platform
run_step hostname-timezone     "Set hostname/timezone"              step_set_hostname

run_step pkg-update            "Refresh package metadata"           step_pkg_update
run_step base-packages         "Install base packages"              step_base_packages

run_step docker-repo           "Add Docker package repo"            step_docker_repo
run_step docker-install        "Install Docker Engine + Compose"    step_docker_install
run_step docker-daemon-config  "Write /etc/docker/daemon.json"      step_docker_daemon_config

if [[ "$ENABLE_GPU_STACK" == "true" ]]; then
  run_step gpu-driver             "Install NVIDIA driver"                step_gpu_driver
  run_step gpu-container-toolkit  "Install nvidia-container-toolkit"     step_gpu_container_toolkit
  run_step gpu-verify              "Verify GPU visible to Docker"         step_gpu_verify_or_note_reboot
else
  skip_step gpu-driver "Install NVIDIA driver" "ENABLE_GPU_STACK=false"
  skip_step gpu-container-toolkit "Install nvidia-container-toolkit" "ENABLE_GPU_STACK=false"
  skip_step gpu-verify "Verify GPU visible to Docker" "ENABLE_GPU_STACK=false"
fi

run_step wireguard-install     "Install WireGuard"                  step_wireguard_install
run_step wireguard-config      "Write wg0.conf and enable tunnel"   step_wireguard_config
run_step wireguard-sync-vps    "Sync home pubkey+PSK to VPS peer config" step_wireguard_sync_vps_peer
run_step wireguard-verify      "Verify tunnel is up"                step_wireguard_verify

run_step clone-repo            "Clone/update APIARY to $REPO_DIR" step_clone_repo
run_step arcane-install        "Install Arcane (stack-management UI + import target)" step_arcane_install

run_step restore-env-files     "Restore .env files from LAN backup" step_restore_env_files
run_step arcane-import-stacks  "Import honeypot-* + auth-events-worker/llm-worker/ml-worker as Arcane Git syncs" step_arcane_import_stacks
run_step stage-keycloak-theme  "Check out and sync the Keycloak login theme" step_stage_keycloak_theme
run_step bootstrap-missing-envs "Bootstrap any still-missing .env from .example" step_bootstrap_missing_envs
run_step seed-canary-hostname "Seed honeypot-canarytokens' CANARY_PUBLIC_HOSTNAME from KEYCLOAK_PUBLIC_DOMAIN (#2498)" step_seed_canary_public_hostname
run_step provision-keycloak-secrets "Generate Keycloak secrets, reset bootstrap admin to admin/admin123" step_provision_keycloak_secrets

run_step shared-resources      "Create honeynet + placeholder volumes" step_create_shared_resources
run_step provision-buildx-cache "Create /var/buildx-cache for the CI runners (#2822)" step_provision_buildx_cache
run_step provision-image-sbom   "Create /var/image-sbom for digest-bound SBOMs (#3321)" step_provision_image_sbom
run_step build-zeek-image      "Build xore-zeek:local for zeek-proxy" step_build_zeek_image
run_step start-elasticsearch   "Start honeypot-elk, wait healthy"   step_start_elasticsearch_first
run_step start-init            "Start honeypot-init, wait for one-shots" step_start_init
# #2959: the sshfs mounts move up here, ahead of start-remaining. They can only
# run after start-init (honeypot-init's log-init job is what creates the
# logs/<name> mount points), but honeypot-elk's pcap-sync reads them, so
# leaving them until after every sensor had started meant pcap-sync sat
# unhealthy for the whole middle of the run and start-elasticsearch could never
# gate on it. Placed at the first point in the run where they can succeed.
run_step sshfs-install         "Install sshfs, place VPS key"        step_sshfs_install
run_step sshfs-mounts          "Mount VPS Suricata/portbridge logs"  step_sshfs_mounts
run_step sshfs-boot-ordering   "Install WireGuard-aware mount ordering" step_sshfs_boot_ordering

run_step geoip-reload-es       "Reload ES if geoip databases arrived after it started" step_geoip_reload_elasticsearch
run_step fix-snare-ownership   "Set logs/snare root-owned (snare drops caps)" step_fix_snare_ownership
run_step start-remaining       "Start remaining sensor/dashboard stacks" step_start_remaining_stacks

run_step provision-events-poller-secrets "Grant auth-events-poller view-events + write its secret" step_provision_events_poller_secrets
run_step pin-deploy-runner-gid  "Pin deploy-runner GID + enrichment dirs for honeypot-dashboard" step_pin_deploy_runner_gid
run_step provision-dashboard-oidc-secret "Write dashboard's OIDC client secret from Keycloak" step_provision_dashboard_oidc_secret
run_step fix-apiary-backend-permissions "Grant apiary-backend's nobody uid ACL access to dashboard-state/dionaea-lib/services-adapter-socket" step_fix_apiary_backend_permissions
run_step provision-arcane-oidc-secret "Sync Arcane's real OIDC client secret from Keycloak, re-up" step_provision_arcane_oidc_secret
run_step provision-account-console-scopes "Give Keycloak's account-console client its default scopes (#1697)" step_provision_account_console_scopes
run_step auth-events-worker-start "Start auth-events-worker" step_auth_events_worker_start


run_step technitium-provision  "Install Technitium DNS config"       step_technitium_provision
run_step technitium-lan-route  "Assert LAN NIC owns lowest-metric route" step_technitium_lan_route
run_step technitium-start      "Start Technitium DNS"                step_technitium_start
run_step technitium-verify     "Resolve container and LAN"           step_technitium_verify
run_step host-resolver-order   "Point host resolver at Technitium before public DNS" step_host_resolver_order

if [[ "$ENABLE_GPU_STACK" == "true" ]]; then
  run_step ghidra-provision      "Link ghidra compose.yml"            step_ghidra_stack_provision
  run_step revdeck-source        "Clone Rev·Deck build context"       step_revdeck_source
  run_step ghidra-start          "Start ghidra/ollama stack"          step_ghidra_stack_start
  run_step ollama-model-pull     "Pull pinned Ollama model"           step_ollama_model_pull
  run_step ghidra-worker-install "Install ghidra-worker.py systemd service" step_ghidra_worker_install
  run_step ml-worker-start       "Start ml-worker"                    step_ml_worker_start
  run_step llm-worker-selftest   "Run llm-worker --selftest"          step_llm_worker_selftest
else
  skip_step ghidra-provision "Link ghidra compose.yml" "ENABLE_GPU_STACK=false"
  skip_step ghidra-start "Start ghidra/ollama stack" "ENABLE_GPU_STACK=false"
  skip_step ollama-model-pull "Pull pinned Ollama model" "ENABLE_GPU_STACK=false"
  skip_step ghidra-worker-install "Install ghidra-worker.py systemd service" "ENABLE_GPU_STACK=false"
  skip_step ml-worker-start "Start ml-worker" "ENABLE_GPU_STACK=false"
  skip_step llm-worker-selftest "Run llm-worker --selftest" "ENABLE_GPU_STACK=false"
fi

run_step backup-timer-install  "Install daily Elasticsearch/stack backup timer" step_backup_timer_install
run_step verify-containers     "Check for unhealthy containers"     step_verify_containers_healthy
run_step verify-exited         "Check for non-zero-exit containers" step_verify_exited
run_step verify-es-events      "Check Elasticsearch is reachable"   step_verify_elasticsearch_events

if [[ "$ENABLE_SANDBOX_RESTORE" == "true" ]]; then
  run_step libvirt-install        "Install libvirt/KVM/QEMU"              step_libvirt_install
  run_step vfio-gpu-passthrough   "Bind the sandbox GPU to vfio-pci (#1609 Phase 7)" step_vfio_gpu_passthrough
  run_step sandbox-restore        "Pull sandbox backup from LAN host"     step_sandbox_backup_restore
  run_step sandbox-checksum       "Verify golden-image checksums"         step_sandbox_checksum_verify
  run_step ghosts-network         "Set up GHOSTS isolated libvirt network" step_ghosts_network_setup
  run_step ghosts-host            "Deploy ghosts-api/ghosts-postgres"      step_ghosts_host_install
  run_step ghosts-vm              "Define + start win11-ghosts VM"         step_ghosts_vm_start
  run_step windows-sandbox-network "Set up Windows sandbox libvirt network" step_windows_sandbox_network_setup
  run_step windows-sandbox-create "Create win11-sandbox thin-clone VM"     step_windows_sandbox_vm_create
  run_step windows-sandbox-start  "Start win11-sandbox VM"                 step_windows_sandbox_vm_start
  run_step cape-network           "Set up CAPE libvirt network"            step_cape_network_setup
  run_step cape-vm-create         "Create win11-cape thin-clone VM (#1609 Phase 7)" step_cape_vm_create
  run_step cape-vm-start          "Start win11-cape VM"                    step_cape_vm_start
  run_step sandbox-verify         "Verify sandbox VMs running"             step_sandbox_verify_running
  run_step sandbox-park-vms       "Shut the detonation VMs back down"      step_sandbox_park_detonation_vms
  run_step sandbox-host-foundation "Set up Linux sandbox network + dirs"   step_sandbox_host_foundation
  run_step linux-sandbox-base     "Download + verify Linux base image"    step_linux_sandbox_base
  run_step linux-sandbox-verify   "Run Linux sandbox smoke test"          step_linux_sandbox_verify
else
  skip_step libvirt-install "Install libvirt/KVM/QEMU" "ENABLE_SANDBOX_RESTORE=false"
  skip_step vfio-gpu-passthrough "Bind the sandbox GPU to vfio-pci (#1609 Phase 7)" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-restore "Pull sandbox backup from LAN host" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-checksum "Verify golden-image checksums" "ENABLE_SANDBOX_RESTORE=false"
  skip_step ghosts-network "Set up GHOSTS isolated libvirt network" "ENABLE_SANDBOX_RESTORE=false"
  skip_step ghosts-host "Deploy ghosts-api/ghosts-postgres" "ENABLE_SANDBOX_RESTORE=false"
  skip_step ghosts-vm "Define + start win11-ghosts VM" "ENABLE_SANDBOX_RESTORE=false"
  skip_step windows-sandbox-network "Set up Windows sandbox libvirt network" "ENABLE_SANDBOX_RESTORE=false"
  skip_step windows-sandbox-create "Create win11-sandbox thin-clone VM" "ENABLE_SANDBOX_RESTORE=false"
  skip_step windows-sandbox-start "Start win11-sandbox VM" "ENABLE_SANDBOX_RESTORE=false"
  skip_step cape-network "Set up CAPE libvirt network" "ENABLE_SANDBOX_RESTORE=false"
  skip_step cape-vm-create "Create win11-cape thin-clone VM (#1609 Phase 7)" "ENABLE_SANDBOX_RESTORE=false"
  skip_step cape-vm-start "Start win11-cape VM" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-verify "Verify sandbox VMs running" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-park-vms "Shut the detonation VMs back down" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-host-foundation "Set up Linux sandbox network + dirs" "ENABLE_SANDBOX_RESTORE=false"
  skip_step linux-sandbox-base "Download + verify Linux base image" "ENABLE_SANDBOX_RESTORE=false"
  skip_step linux-sandbox-verify "Run Linux sandbox smoke test" "ENABLE_SANDBOX_RESTORE=false"
fi

# Runs last, unconditionally (self-guarding on whether each service is
# actually installed): needs libvirtd already present when
# ENABLE_SANDBOX_RESTORE=true, and is a correct no-op for that part when it
# is not.
run_step quiet-veth-noise      "Quiet expected Docker veth noise from networkd-dispatcher/libvirtd/systemd-resolved" step_quiet_veth_noise

print_summary
exit $?
