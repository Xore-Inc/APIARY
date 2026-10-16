#!/usr/bin/env bash
# Install a GitHub Actions self-hosted runner on this host, dedicated to
# fast CI feedback on already-trusted code -- NOT the deployment runner
# (scripts referenced from docs/CI-CD.md's "Home deployment" section,
# labels self-hosted/linux/x64/honeypot-home, environment production-home).
# This is a second, separate runner registration with its own labels, own
# sudo-less system user, and docker-group access (#2565: containers, the
# frontend lockfile check and the Keycloak/OIDC suites route here). Its
# trust boundary is different from the deployment runner's, but NOT
# because it lacks host-level capability -- docker-group membership is
# effectively root-equivalent on this host (a member can
# `docker run -v /:/host ...` and read/write anything), and this runner's
# checkout at /opt/stacks/apiary is also plain world-readable, so it can
# read e.g. /opt/stacks/honeypot-dashboard/.env directly without even
# touching Docker. #2780 measured both and confirmed neither is a
# containment boundary. What actually keeps this runner's blast radius
# below the deployment runner's is WHICH CODE gets to run on it: the
# ci-target router (push/workflow_dispatch, plus same-repo pull_request
# only when repo variable CI_HOMESERVER_PRS=true -- see docs/CI-CD.md's
# "GitHub CI runner" section, "Docker-group membership is an accepted
# trade-off" subsection, for the full decision) keeps fork-PR (attacker-
# controlled) code off this runner entirely. If that gate is ever wrong,
# the practical blast radius here is not meaningfully smaller than the
# deployment runner's -- treat a compromise of either the same way.
#
# Usage:
#   sudo scripts/github-ci-runner/install-ci-runner.sh --repo Xore/APIARY [--token TOKEN]
#
# --build-only (#3379) provisions a compute-only executor on a box that is
# NOT the homeserver (e.g. precision): same honeypot-ci pool and toolchain,
# but no compose-drift/backup-staleness sudo helpers and no
# honeypot-homeserver label, so the watches that measure the homeserver
# itself never run there. Without it, the default role is the homeserver.
#
# --token is a short-lived (1h) registration token. If omitted, this script
# tries to fetch one itself via `gh api` (needs `gh auth login` done for an
# account with admin on the repo) -- convenient for an operator re-running
# this after a token expires, but never required to be long-lived or
# stored anywhere.
#
# --instance N (#2572): registers a SECOND, THIRD, ... independent instance
# on the same box instead of re-touching the primary one. Before this flag
# existed, RUNNER_HOME/RUNNER_USER were fixed constants no matter what
# --name got passed, so a second `--name second-ci` invocation collided
# with the already-registered $RUNNER_HOME/.runner and either no-opped
# (leaving only one instance actually running) or clobbered it -- there was
# no way to actually scale past one executor. Every instance still
# registers under the SAME RUNNER_LABELS (honeypot-ci): GitHub schedules a
# queued job onto whichever instance is idle, so quality.yml's matrix rows
# (each already independent per #2389/#2565) gain real parallelism instead
# of serializing behind one machine. Default instance "1" reuses the
# original /opt/github-ci-runner + github-ci-runner user + "$HOSTNAME-ci"
# name unchanged, so the already-registered instance needs no migration.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RUNNER_VERSION=2.336.0
RUNNER_SHA256=04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d
RUNNER_LABELS="self-hosted,linux,x64,honeypot-ci"

# Keep the runner's bulky, regenerable data off the root filesystem.
#
# A runner accumulates ~8-11 GB apiece: its checkout and build output (_work),
# plus the caches its jobs populate (.cache, .rustup, .cargo, go). With seven
# instances that is ~60 GB, and $RUNNER_HOME lives under /opt, which on this
# host is the 70 GB root LV while /var has terabytes. Root hit 98% and the Rust
# build died in the LINKER:
#
#   collect2: fatal error: ld terminated with signal 7 [Bus error], core dumped
#
# not with a disk-space message -- /tmp is on / too, and a linker that runs out
# of room mid-mmap gets SIGBUS. It reads as a compiler crash, which is a long
# way from "the disk is full".
#
# Only DATA is relocated. The runner's own executables stay in $RUNNER_HOME on
# /opt deliberately: files under /var are labelled var_t, and systemd's init_t
# cannot exec a var_t file -- the same SELinux rule that broke
# backup-honeypot.service. Moving the whole runner would trade a full disk for a
# runner that will not start.
relocate_runner_data() {
  local base=/var/lib/github-runner-data
  local name; name="$(basename "$RUNNER_HOME")"
  local sub src dst
  install -d -m 755 "$base"
  install -d -m 755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$base/$name"
  # _work is deliberately NOT in this list. It is GITHUB_WORKSPACE's parent,
  # and a symlinked component there breaks setup-node's cache-dependency-path
  # resolution for every job (see the RUNNER_HOME comment above). It needs no
  # relocating anyway now that the whole runner home is on /var.
  #
  # An existing install may still carry the old _work symlink; replace it with
  # the real directory. Both sides are on /var, so this is a rename.
  src="$RUNNER_HOME/_work"
  if [[ -L "$src" ]]; then
    dst="$(readlink -f "$src")"
    if [[ -d "$dst" ]]; then
      rm -f "$src"
      mv "$dst" "$src"
      chown -h "$RUNNER_USER:$RUNNER_USER" "$src"
      echo "  _work un-symlinked (setup-node cache resolution needs a real path)"
    fi
  fi
  for sub in .cache .rustup .cargo go; do
    src="$RUNNER_HOME/$sub"
    dst="$base/$name/$sub"
    [[ -L "$src" ]] && continue                 # already relocated
    install -d -m 755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$dst"
    if [[ -d "$src" ]]; then
      # existing install: move the contents, then replace with the link
      cp -a "$src/." "$dst/" 2>/dev/null || true
      rm -rf "$src"
    fi
    ln -sfn "$dst" "$src"
    chown -h "$RUNNER_USER:$RUNNER_USER" "$src"
  done
  # Prune externals.<version> trees left by runner self-updates -- EXCEPT the
  # one the live `externals` symlink points at.
  #
  # Not hypothetical: assuming every externals.<version> was a stale backup
  # deleted the LIVE tree on two runners. After a self-update the runner does
  # not keep `externals` as a real directory -- it replaces it with a symlink
  # into the new versioned tree:
  #
  #   externals -> /opt/github-ci-runner-6/externals.2.337.0
  #
  # so deleting the versioned directory left a dangling symlink, and the
  # service died with
  #   ./externals/node20/bin/node: No such file or directory   (exit 127)
  local live_ext=""
  [[ -L "$RUNNER_HOME/externals" ]] && live_ext="$(basename "$(readlink -f "$RUNNER_HOME/externals")")"
  local ext
  for ext in "$RUNNER_HOME"/externals.[0-9]*; do
    [[ -e "$ext" ]] || continue
    [[ -n "$live_ext" && "$(basename "$ext")" == "$live_ext" ]] && continue
    rm -rf "$ext"
  done
  echo "runner data relocated to $base/$name (executables stay in $RUNNER_HOME)"
}

# Give actions/setup-python a locally-resolvable interpreter. It looks for
# $RUNNER_TOOL_CACHE/Python/<x.y.z>/x64 plus a sibling <x64>.complete marker,
# and a workflow asking for "3.13" resolves to the newest matching entry.
#
# Symlinks rather than a copied tree: python resolves its own sys.prefix
# through the symlink to /usr, so the stdlib, pip and `python -m venv` all keep
# working from the real installation. Verified on the live runner -- venv
# creation, which is what most jobs actually do, succeeds through the link.
seed_python_tool_cache() {
  local py=/usr/bin/python3.13 ver tool dir
  [[ -x "$py" ]] || { echo "no $py, skipping tool-cache seed" >&2; return 0; }
  ver="$("$py" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])')"
  tool="$RUNNER_HOME/_work/_tool"
  dir="$tool/Python/$ver/x64"
  install -d "$dir/bin"
  local n
  for n in python python3 python3.13; do ln -sf "$py" "$dir/bin/$n"; done
  [[ -x /usr/bin/pip3.13 ]] && for n in pip pip3; do ln -sf /usr/bin/pip3.13 "$dir/bin/$n"; done
  touch "$tool/Python/$ver/x64.complete"
  chown -R "$RUNNER_USER:$RUNNER_USER" "$tool/Python"
  echo "seeded actions/setup-python tool cache with Python $ver at $dir"
}

# --- BEGIN instance derivation (config test: tests/test_install_ci_runner_instances.py) ---
# Instance "1" is the original, unsuffixed layout -- anything else gets its
# own home dir and system user so N instances can run side by side without
# fighting over the same _work directory, .runner registration file, or
# systemd unit's working user. Kept between these markers, and pure
# (no filesystem/network touches), so the test can extract and execute
# exactly this argument-parsing + derivation logic in isolation.
repo=""
token=""
name=""
instance="1"
role="homeserver"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --token) token="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --instance) instance="$2"; shift 2 ;;
    --build-only) role="build"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$repo" ]] || { echo "Usage: $0 --repo OWNER/NAME [--token TOKEN] [--name RUNNER_NAME] [--instance N] [--build-only]" >&2; exit 1; }

if [[ -z "$name" ]]; then
  name="${HOSTNAME:-homeserver}-ci"
  [[ "$instance" == "1" ]] || name="${name}-${instance}"
fi
# The runner home itself lives on /var, not /opt.
#
# /opt is on this host's 70 GB root LV; /var has terabytes. Seven runners at
# ~8-11 GB apiece filled root to 98% and killed the Rust build in the LINKER
# (`ld terminated with signal 7 [Bus error]`) rather than with a disk-space
# message, because /tmp was on / too and a linker that runs out of room
# mid-mmap gets SIGBUS.
#
# The obvious alternative -- keep the home on /opt and symlink only the bulky
# subdirectories to /var -- is what this script used to do, and it broke CI in
# a way that took a while to see: with _work symlinked, GITHUB_WORKSPACE
# contains a symlinked path component, and @actions/glob (which setup-node uses
# to resolve `cache-dependency-path`) does not resolve through one. Every job
# using `cache: npm` died at setup with
#
#   ##[error]Some specified paths were not resolved, unable to cache dependencies.
#
# before running a single test, while the lockfile it named was plainly there.
# So the home moves wholesale and _work stays a real directory inside it.
#
# /opt/<name> is kept as a compatibility symlink: the runner user's HOME, and
# anything else still referring to the old path, keep working.
RUNNER_ROOT=/var/lib/github-runners
if [[ "$instance" == "1" ]]; then
  RUNNER_USER=github-ci-runner
else
  RUNNER_USER="github-ci-runner-${instance}"
fi
RUNNER_HOME="${RUNNER_ROOT}/${RUNNER_USER}"
RUNNER_COMPAT_LINK="/opt/${RUNNER_USER}"
# #3379: the homeserver's instances additionally carry honeypot-homeserver,
# which the watches that measure that host itself (compose-drift,
# backup-staleness, disk-usage) require on top of honeypot-ci. A
# --build-only executor on another box shares the honeypot-ci pool for
# compute jobs but must never pick those up.
if [[ "$role" == "homeserver" ]]; then
  RUNNER_LABELS="${RUNNER_LABELS},honeypot-homeserver"
fi
# --- END instance derivation ---

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

# Only actually needed to register/re-register -- an already-configured
# runner (found $RUNNER_HOME/.runner below) must not fail here just
# because root's own shell has no `gh auth login` of its own.
if [[ -z "$token" && ! -f "$RUNNER_HOME/.runner" ]]; then
  command -v gh >/dev/null 2>&1 || { echo "no --token given and gh is not installed to fetch one" >&2; exit 1; }
  echo "fetching a fresh registration token via gh api..."
  token=$(gh api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
fi

# Dedicated system user -- no sudo. It carries no group grant scoped to
# /var/lib/honeypot-*, /opt/stacks or sensor state specifically, but #2780
# measured that this does not amount to "no access": the checkout at
# /opt/stacks/apiary is plain world-readable (verified: this user can
# `cat` the deploy runner's own .env files without elevation), and the
# docker-group membership below is separately host-root-equivalent. Since
# #2565 it DOES carry that docker-group membership (the same grant
# github-deploy-runner always had) because the homeserver-first routing
# sends docker-bound checks here: containers.yml, the frontend lockfile
# check, the Keycloak/oauth2-proxy/OIDC suites, compose validation. The
# trust gate in quality.yml's ci-target router (and the shared
# ci-router.yml) is what makes carrying that capability an accepted
# trade-off rather than a gap -- only push-to-main, workflow_dispatch, and
# CI_HOMESERVER_PRS'd same-repo pull requests ever execute here; fork PRs
# can never qualify. See docs/CI-CD.md's "Docker-group membership is an
# accepted trade-off" subsection for the full decision.
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$RUNNER_HOME" --shell /usr/sbin/nologin "$RUNNER_USER"
fi
install -d -m 0755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME"

# #3606: join the shared buildx-cache group and make sure /var/buildx-cache
# exists and is writable by every runner user, so Containers uses type=local
# on this executor instead of the gha fallback. Idempotent; set
# BUILDX_CACHE_TARGET=/path to keep the cache on another volume (precision).
"$here/github-ci-runner/provision-buildx-cache.sh"

# SELinux: files under /var are labelled var_t, and systemd's init_t cannot
# exec a var_t file -- the unit fails 203/EXEC with no AVC logged, the same
# rule that broke backup-honeypot.service. The runner's own executables
# (runsvc.sh and everything it spawns) now live here, so the tree has to be
# labelled bin_t.
#
# semanage fcontext, not chcon: chcon is undone by the next restorecon, which
# would silently break every runner on a relabel.
if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -a -t bin_t "${RUNNER_ROOT}(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t bin_t "${RUNNER_ROOT}(/.*)?" 2>/dev/null || true
  restorecon -R "$RUNNER_ROOT" 2>/dev/null || true
fi

# Compatibility symlink so the old /opt path (and the user's recorded HOME)
# keeps resolving. Only ever create it when nothing real is in the way.
if [[ ! -e "$RUNNER_COMPAT_LINK" || -L "$RUNNER_COMPAT_LINK" ]]; then
  ln -sfn "$RUNNER_HOME" "$RUNNER_COMPAT_LINK"
fi

# Homeserver-only watch helpers (#3379). compose-drift-watch and
# backup-staleness-watch measure THE HOMESERVER (/var/dockge/stacks,
# /mnt/usb-recovery), so their sudo grants only make sense there. A
# --build-only executor on another box gets neither grant and registers
# without the honeypot-homeserver label, so those watches never land on it.
# (Heredoc bodies below stay at column 0 -- the terminator has to.)
if [[ "$role" == "homeserver" ]]; then
  # #2764: the one deliberate, narrow exception to "no sudo BY DESIGN" above.
  # compose-drift-watch.py needs `docker compose config` AND `docker compose
  # ps` on every stack under /var/dockge/stacks/, and four of them have a
  # root/deploy-runner-owned .env this user can't read -- confirmed live,
  # permission denied for both subcommands, regardless of the 600/640 split.
  # Widening group membership (e.g. adding this user to deploy-runner) was the
  # simpler option and explicitly rejected: it would hand a scheduled,
  # gh-token-bearing job direct read access to Keycloak admin credentials and
  # every other secret those .env files hold. Instead: a dedicated group whose
  # only grant is running one specific, narrow root-run helper
  # (scripts/compose-project-state.py) that resolves the project as root but
  # returns nothing except {"services": {name: restart_policy}, "containers":
  # [{Service, State}]} -- never a secret value, an image, a label or a
  # command line. Every instance's RUNNER_USER joins this same group, so N
  # runner instances share one sudoers grant instead of needing one per
  # instance.
  #
  # Note this script is NOT invoked by install-homeserver.sh -- it is a manual
  # runbook step (docs/CI-CD.md), so a rebuild only replays this grant if the
  # operator runs it.
  compose_drift_group=compose-drift-ro
  if ! getent group "$compose_drift_group" >/dev/null 2>&1; then
    groupadd --system "$compose_drift_group"
  fi
  usermod -aG "$compose_drift_group" "$RUNNER_USER"

  install -d -m 0755 -o root -g root /opt/github-ci-runner-helpers
  install -m 0755 -o root -g root \
    "$here/compose-project-state.py" \
    /opt/github-ci-runner-helpers/compose-project-state.py

  # The trailing '*' only ever reaches this helper's own argument validation
  # (rejects anything but a clean path under /var/dockge/stacks or
  # /opt/stacks -- see compose-project-state.py's own header), not a general
  # command -- sudoers itself grants nothing broader than "run this one file
  # as root."
  #
  # Written to a temp file and validated BEFORE it is installed: a syntax
  # error in a file already sitting in /etc/sudoers.d breaks sudo host-wide
  # for as long as it is there, however briefly.
  sudoers_file=/etc/sudoers.d/compose-drift-ro
  sudoers_tmp="$(mktemp)"
  cat > "$sudoers_tmp" <<EOF
%${compose_drift_group} ALL=(root) NOPASSWD: /usr/bin/python3 /opt/github-ci-runner-helpers/compose-project-state.py *
EOF
  if ! visudo -cf "$sudoers_tmp"; then
    echo "generated sudoers file failed validation, not installing it" >&2
    rm -f "$sudoers_tmp"
    exit 1
  fi
  install -m 0440 -o root -g root "$sudoers_tmp" "$sudoers_file"
  rm -f "$sudoers_tmp"

  # REVIEW-A/#3030: compose-drift-watch.py's failing-healthcheck-streak
  # duration tracker needs a state file every runner instance can both read
  # and write across scheduled sweeps -- shared /tmp does NOT give it that:
  # the file itself ends up owned by whichever single runner user created it,
  # at that user's umask (confirmed live: 0644 owned by one account, EACCES
  # for the other three github-ci-runner-{2,3,4} accounts). Reuses
  # compose-drift-ro rather than a new group -- every RUNNER_USER is already
  # a member from the grant just above, and this state file is no more
  # sensitive than the drift findings it feeds. setgid (g+s) makes new files
  # inherit the group; compose-drift-watch.py's own write path still chmods
  # each write to 0664 since setgid does not touch permission bits.
  install -d -m 2775 -o root -g "$compose_drift_group" /var/lib/compose-drift-watch

  # REVIEW-A/#3025: same narrow shape as the #2764 grant just above, for a
  # different unreadable-by-this-user directory. `/mnt/usb-recovery/apiary-
  # backups` is `drwx------ xore xore`; widening its mode or this user's
  # group membership was rejected for the same reason as the .env case --
  # it is the only on-disk copy of the essentials backup archives, and
  # should stay closed to every account except xore and root. The helper
  # (scripts/backup-freshness-check.py) returns only a bare mtime or
  # `EMPTY`, never a filename or listing.
  backup_staleness_group=backup-staleness-ro
  if ! getent group "$backup_staleness_group" >/dev/null 2>&1; then
    groupadd --system "$backup_staleness_group"
  fi
  usermod -aG "$backup_staleness_group" "$RUNNER_USER"

  install -m 0755 -o root -g root \
    "$here/backup-freshness-check.py" \
    /opt/github-ci-runner-helpers/backup-freshness-check.py

  # Dir argument pinned to the one known backup dir so sudoers itself only
  # wildcards the glob argument; the helper's own validation (rejects a
  # glob containing '/' or '..') is still the real boundary for that part.
  backup_sudoers_file=/etc/sudoers.d/backup-staleness-ro
  backup_sudoers_tmp="$(mktemp)"
  cat > "$backup_sudoers_tmp" <<EOF
%${backup_staleness_group} ALL=(root) NOPASSWD: /usr/bin/python3 /opt/github-ci-runner-helpers/backup-freshness-check.py /mnt/usb-recovery/apiary-backups *
EOF
  if ! visudo -cf "$backup_sudoers_tmp"; then
    echo "generated sudoers file failed validation, not installing it" >&2
    rm -f "$backup_sudoers_tmp"
    exit 1
  fi
  install -m 0440 -o root -g root "$backup_sudoers_tmp" "$backup_sudoers_file"
  rm -f "$backup_sudoers_tmp"
else
  echo "--build-only: skipping homeserver watch helpers (compose-drift-ro, backup-staleness-ro)"
fi

# Host provision for the routed checks, kept idempotent so re-running this
# script restores a drifted box. The runner user has no general sudo BY
# DESIGN -- the one exception above (#2764) is a single, narrow, output-
# filtered helper, not a shell -- so every sudo-apt path inside a workflow
# check would be a guaranteed relocation failure -- everything a check
# needs is preinstalled here instead, and checks that would install on a
# missing dep fail loudly.
#   redis-server: the frontend-next browser fixture spawns its own
#     (daemon disabled -- only the binary is wanted).
#   nodejs/npm: the dashboard OIDC suites run the BFF build against the
#     node 22 the suites pin.
#   gcc: Cargo's Linux linker and the Go race detector both require a C
#     compiler. The build-only precision runners need it too.
#   the shellcheck binary: the shell-syntax scripts-and-compose row
#     prefers an existing binary and only apt-installs where it was
#     already required. (This comment block is inside that row's scan
#     set: a comment line leading with the word "shellcheck" is parsed
#     as a shellcheck directive, which is why none of these lines
#     starts with it.)
#   chromium libs: playwright's own ubuntu26.04-x64 chromium dependency
#     list, extracted from the playwright-core version pinned by
#     frontend-next/package-lock.json (1.62.1 at the time of writing) --
#     when that pin moves, re-extract the list from the new
#     playwright-core and update here.
#
# Both distro families are handled: the homeserver moved from Ubuntu to Rocky
# Linux 10 in the 2026-09-03 rebuild, where this block was still
# unconditionally apt and every one of the five instances died on
# "apt-get: command not found" (exit 127) before a single runner was
# registered.
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) PKG_FAMILY=debian ;;
  rocky|rhel|centos|almalinux|fedora) PKG_FAMILY=rhel ;;
  *) case "${ID_LIKE:-}" in
       *debian*) PKG_FAMILY=debian ;;
       *rhel*|*fedora*) PKG_FAMILY=rhel ;;
       *) echo "unsupported distro '${ID:-unknown}' -- add a branch here" >&2; exit 1 ;;
     esac ;;
esac

case "$PKG_FAMILY" in
debian)
  apt-get update -qq
  apt-get install -y -qq \
    redis-server nodejs npm shellcheck gcc \
    libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 libatspi2.0-0t64 \
    libcairo2 libcups2t64 libdbus-1-3 libdrm2 libgbm1 libglib2.0-0t64 \
    libnspr4 libnss3 libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 \
    libxdamage1 libxext6 libxfixes3 libxkbcommon0 libxrandr2
  systemctl disable --now redis-server.service 2>/dev/null || true
  ;;
rhel)
  # Two repos beyond the Rocky defaults, both required:
  #   EPEL -- ShellCheck.
  #   CRB  -- lttng-ust, which the runner's OWN bin/installdependencies.sh
  #           (called further down) hard-requires. CRB ships disabled on
  #           Rocky, so without this that script exits with
  #           "Error: Unable to find a match: lttng-ust" ->
  #           "Can't install dotnet core dependencies" and the install fails.
  dnf install -y epel-release
  dnf config-manager --set-enabled crb
  # Same roles as the Debian list above, RHEL names. Two differ in substance
  # rather than spelling:
  #   npm   is a separate package here (nodejs-npm), not bundled with nodejs.
  #   redis is not packaged for EL10 at all -- valkey replaced it. Valkey 8 is
  #         a fork of Redis 7.2 and speaks the same protocol, which is all the
  #         frontend-next browser fixture wants from it.
  dnf install -y \
    valkey nodejs nodejs-npm ShellCheck gcc \
    alsa-lib at-spi2-atk atk at-spi2-core \
    cairo cups-libs dbus-libs libdrm mesa-libgbm glib2 \
    nspr nss pango libX11 libxcb libXcomposite \
    libXdamage libXext libXfixes libxkbcommon libXrandr
  systemctl disable --now valkey.service 2>/dev/null || true

  # actions/setup-python ships no prebuilt interpreter for RHEL-family hosts.
  # After the homeserver moved to Rocky 10 every job using it failed with:
  #
  #   The version '3.13' with architecture 'x64' was not found for rocky 10.2
  #
  # ...which took out 58 checks at once, because setup-python is a shared step
  # rather than one job's dependency. It was invisible before the OS change:
  # the runners were Ubuntu, which that action does publish builds for.
  #
  # The fix is the standard self-hosted one: give the action a tool-cache entry
  # it can find locally, so no workflow has to know the runner is not Ubuntu.
  # Seeded from the distro's own python3.13 rather than downloading a build,
  # since EPEL already packages it.
  dnf install -y python3.13 python3.13-devel python3.13-pip
  seed_python_tool_cache
  relocate_runner_data
  # quality.yml checks `command -v redis-server` and fails the row loudly if
  # it is absent (see its own "#2565's homeserver provision list" error).
  # Valkey installs only valkey-server, so bridge the name rather than
  # teaching every consumer a second one.
  #
  # /usr/bin, NOT /usr/local/bin. The runner user's PATH on this distro is
  #   /opt/<runner>/.local/bin:/opt/<runner>/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin
  # -- it carries /usr/local/sbin but NOT /usr/local/bin, so a shim placed
  # there exists and is still invisible to every job. Measured after the first
  # attempt did exactly that: the symlink was correct, pointed at the right
  # binary, and quality.yml still failed with "redis-server missing on the
  # runner host". No package owns /usr/bin/redis-server on EL10 (redis is not
  # packaged for it at all), so there is nothing to collide with.
  # The whole redis-* command set, not just redis-server. The frontend-next
  # browser harness spawns `redis-cli` to seed state, and a server-only shim
  # left it failing with `spawn redis-cli ENOENT` -- the same mistake twice in
  # one fix. Valkey ships each of these under its own name.
  # No `local` here: this block is top-level inside a case, not a function, and
  # `local` outside a function is a hard bash error (SC2168) -- it would have
  # aborted the rhel branch at runtime under set -e.
  for rn in server cli benchmark check-aof check-rdb sentinel; do
    [[ -x "/usr/bin/valkey-$rn" ]] || continue
    ln -sf "/usr/bin/valkey-$rn" "/usr/bin/redis-$rn"
  done
  echo "linked redis-* -> valkey-* in /usr/bin (EL10 has no redis package)"
  ;;
esac
if ! id -nG "$RUNNER_USER" | tr ' ' '\n' | grep -qx docker; then
  usermod -aG docker "$RUNNER_USER"
  echo "added $RUNNER_USER to the docker group -- the runner service will be restarted below to pick it up"
fi

if [[ ! -f "$RUNNER_HOME/run.sh" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/runner.tar.gz" \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
  echo "${RUNNER_SHA256}  $tmp/runner.tar.gz" | sha256sum -c -
  tar -xzf "$tmp/runner.tar.gz" -C "$RUNNER_HOME"
  chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_HOME"
  echo "extracted actions-runner v${RUNNER_VERSION} to $RUNNER_HOME"
  # The runner's .NET job-worker process needs libicu/openssl versions the
  # base OS may not have -- confirmed live: without this, the extracted
  # runner starts and connects fine (the listener is Node-based) but the
  # actual job-execution worker is missing libcoreclr.so and friends.
  "$RUNNER_HOME/bin/installdependencies.sh"
else
  echo "runner already extracted at $RUNNER_HOME, skipping download"
fi

if [[ ! -f "$RUNNER_HOME/.runner" ]]; then
  sudo -u "$RUNNER_USER" "$RUNNER_HOME/config.sh" \
    --url "https://github.com/$repo" \
    --token "$token" \
    --name "$name" \
    --labels "$RUNNER_LABELS" \
    --work "_work" \
    --unattended \
    --replace
else
  echo "runner already configured (found $RUNNER_HOME/.runner) -- not re-registering"
  echo "to re-register (e.g. after moving hosts), remove $RUNNER_HOME/.runner first"
fi

# The runner's own svc.sh wraps systemd unit creation -- installing that
# way rather than hand-writing a unit keeps it in sync with whatever this
# specific runner version's own supported service shape is. Not idempotent
# on its own (errors if the unit file already exists), so only install
# once; restart rather than reinstall on a later re-run of this script.
cd "$RUNNER_HOME"
service_file="/etc/systemd/system/actions.runner.$(tr '/' '-' <<<"$repo").$name.service"
if [[ ! -f "$service_file" ]]; then
  ./svc.sh install "$RUNNER_USER"
else
  ./svc.sh stop || true
fi

# #3021: reclaim ownership of anything a root process left behind in this
# runner's _work checkout before the runner (re)starts and actions/checkout@v7
# hits an EACCES it can never resolve as an unprivileged user. `+` runs the
# ExecStartPre line as root regardless of the unit's own User=.
#
# $here (absolute, resolved before any cd) rather than a path relative to
# BASH_SOURCE: this block runs after `cd "$RUNNER_HOME"` above, and the
# documented invocation (docs/CI-CD.md) is relative, so a relative source
# path resolves to nothing here -- under `set -e` that aborts the script
# after ./svc.sh stop has already run, leaving the runner down.
install -d -m 0755 -o root -g root /opt/github-ci-runner-helpers
install -m 0755 -o root -g root \
  "$here/github-ci-runner/fix-work-ownership.sh" \
  /opt/github-ci-runner-helpers/fix-work-ownership.sh
unit_dropin_dir="${service_file}.d"
install -d -m 0755 -o root -g root "$unit_dropin_dir"
cat > "$unit_dropin_dir/fix-work-ownership.conf" <<EOF
[Service]
ExecStartPre=+/opt/github-ci-runner-helpers/fix-work-ownership.sh $RUNNER_USER $RUNNER_HOME/_work
EOF

# #3105: /var/buildx-cache is shared across every runner instance's user so
# a docker/build-push-action cache-to/cache-from can be reused between them,
# but the default UMask=0022 this unit ships with writes new cache files
# 0644 -- the next build that lands on a DIFFERENT instance's user can read
# them but not open them for write, and fails with EACCES on oci-layout or a
# blob. UMask=0002 keeps new writes group-writable (the cache root is
# already setgid to a shared group), so the drop only needs to happen once
# per file rather than being repaired after the fact by a recurring chmod.
cat > "$unit_dropin_dir/buildx-cache-umask.conf" <<EOF
[Service]
UMask=0002
EOF
systemctl daemon-reload

./svc.sh start

echo "done. status:"
./svc.sh status

# #2742: writing and starting a unit is necessary but not sufficient. The
# 2026-08-29 outage was two units -- byte-identical in shape to the ones
# that worked -- that were simply never `enable`d, so they silently vanished
# on the next reboot without a single command failing anywhere along the
# way. `svc.sh install` above already calls `systemctl enable` internally
# and fails loudly if that call itself fails, but nothing previously
# confirmed the enabled state actually stuck, and nothing confirmed
# GitHub's own view of this runner -- a unit can be enabled and running
# locally and still never show up `online` (wrong labels, a stale/duplicate
# registration, a network path that can't reach GitHub). Assert both below
# and fail loudly rather than leaving either silently unknown.
unit_name="$(basename "$service_file")"
if ! systemctl is-enabled --quiet "$unit_name"; then
  echo "FATAL: $unit_name is not enabled after provisioning -- it will not survive a reboot" >&2
  exit 1
fi
echo "confirmed enabled: $unit_name"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  echo "confirming \"$name\" shows online to GitHub (up to 60s)..."
  online=""
  status=""
  for _ in $(seq 1 12); do
    status=$(gh api "repos/$repo/actions/runners" --paginate \
      --jq ".runners[] | select(.name==\"$name\") | .status" 2>/dev/null | tail -1) || status=""
    if [[ "$status" == "online" ]]; then
      online="1"
      break
    fi
    sleep 5
  done
  if [[ -z "$online" ]]; then
    echo "FATAL: \"$name\" did not report status=online to the GitHub API within 60s (last seen: '${status:-none}'). The unit is enabled and running locally but GitHub does not consider this runner available -- check $RUNNER_HOME/_diag for the runner's own connection log." >&2
    exit 1
  fi
  echo "confirmed online: $name"
else
  echo "WARNING: gh is not authenticated -- could not verify \"$name\" shows online to the GitHub API. Verify manually:" >&2
  echo "  gh api repos/$repo/actions/runners --jq '.runners[] | select(.name==\"'\"$name\"'\")'" >&2
fi
