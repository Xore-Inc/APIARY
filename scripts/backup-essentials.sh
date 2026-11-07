#!/usr/bin/env bash
# backup-essentials.sh — pull the minimum state needed to rebuild the APIARY
# stack from scratch onto the workstation's three backup locations.
#
# This is the *rebuild* backup, deliberately not a data backup. It captures
# the things that cannot be recreated from the git repo — secrets, keys,
# certificates, the identity database, operator-edited config, and the
# operator-authored Elasticsearch documents the dashboard keeps — and
# nothing else. Everything captured here is small; the whole archive is
# single-digit megabytes, so all three copies can be kept for a long
# retention window.
#
# Explicitly NOT backed up, because it is bulk capture data that the stack
# does not need in order to come back up (sizes measured on the live
# homeserver 2026-08-23):
#
#   es-data                  30 GB   Elasticsearch store — events, alerts
#   state/elasticsearch-snapshots
#                            14 GB   the ES snapshot repository itself
#   dionaea-lib              90 GB   captured malware samples
#   /var/dockge/sandbox     105 GB   Windows sandbox golden images + ISOs
#   ghidra_ollama_models     18 GB   re-pullable model weights
#   arcane-trivy-cache      5.6 GB   rebuildable scanner cache
#   reporter-data           2.8 GB   generated reports
#   ghidra_ghidra_projects  158 MB   analysis output, derived from payloads
#   pihole gravity.db /
#     pihole-FTL.db          689 MB  regenerated blocklists + DNS query log
#   all sensor logs, PCAP, Filebeat registries
#
# Losing those means a rebuilt stack starts with no history. That is the
# intended trade: this backup is about getting the stack *running* again with
# its own identity intact, not about preserving what it captured. The one
# exception, and the reason `homeserver/es-operator-state/` below exists, is
# the small set of `dashboard-*-v1` indices holding state an operator typed
# rather than captured — see the ledger in scripts/es-operator-state-backup.py.
#
# Runs on the workstation (the backup host), reaching both servers over SSH.
# It only ever reads from them.
#
# Usage:
#   scripts/backup-essentials.sh            # collect and fan out to all destinations
#   scripts/backup-essentials.sh --dry-run  # collect, report size, discard
#   scripts/backup-essentials.sh --list     # list what each destination holds
#   scripts/backup-essentials.sh --check    # exit non-zero if the newest archive
#                                            # anywhere is missing or >MAX_AGE_HOURS old,
#                                            # or the installed copy of this script is
#                                            # older than the checkout (#3709)
#
# Exit status (#3709): 0 only when every REQUIRED item was collected and the
# archive reached all three destinations. The required items are the
# installer answers file, the es-operator-state export, the Keycloak dump,
# the stack .env files and the WireGuard keys; a missing one, or a
# destination that could not be written, makes the run exit 1 with an
# ERROR line naming it -- the archive is still written to whatever is
# reachable, because a partial backup beats none, but the unit goes red.
#
# Env:
#   HOMESERVER_SSH   ssh target for the homeserver      (default: homeserver)
#   VPS_SSH          ssh target for the VPS             (default: vps)
#   DEST_LOCAL_USB   workstation USB mount              (default: the Crucial X8 by UUID)
#   DEST_LOCAL_DISK  workstation internal disk          (default: ~/apiary-backups)
#   DEST_SERVER_USB  path on the homeserver's USB       (default: /mnt/usb-recovery/apiary-backups)
#   REPO_DIR         checkout to take runbooks from     (default: ~/Github/APIARY)
#   RETENTION        archives to keep per destination    (default: 30)
#   BACKUP_ENCRYPT   1 = gpg-encrypt the archive        (default: 1)
#   PASSPHRASE_FILE  gpg symmetric passphrase           (default: /etc/apiary-backup.pass)
#   MAX_AGE_HOURS    --check staleness threshold        (default: 48)
#   INSTALL_STAMP    sha256 stamp install-backup-essentials.sh wrote for this
#                    installed copy                     (default: <this script>.src-sha256)
#
# Restore: docs/BACKUP-ESSENTIALS.md, a copy of which rides inside every
# archive under repo/docs/ along with the rest of the runbooks. The archive is
# a plain gpg-symmetric-encrypted tar.gz — `gpg -d | tar xz` with the
# passphrase is the entire dependency chain, deliberately, so a recovery never
# needs this repo, this script, or GitHub to be reachable.

set -euo pipefail

HOMESERVER_SSH=${HOMESERVER_SSH:-homeserver}
VPS_SSH=${VPS_SSH:-vps}
DEST_LOCAL_USB=${DEST_LOCAL_USB:-/run/media/xore/00586654-e69c-4513-b762-70dd6de80a62/apiary-backups}
DEST_LOCAL_DISK=${DEST_LOCAL_DISK:-$HOME/apiary-backups}
DEST_SERVER_USB=${DEST_SERVER_USB:-/mnt/usb-recovery/apiary-backups}
REPO_DIR=${REPO_DIR:-$HOME/Github/APIARY}
RETENTION=${RETENTION:-30}
BACKUP_ENCRYPT=${BACKUP_ENCRYPT:-1}
PASSPHRASE_FILE=${PASSPHRASE_FILE:-/etc/apiary-backup.pass}
MAX_AGE_HOURS=${MAX_AGE_HOURS:-48}
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
INSTALL_STAMP=${INSTALL_STAMP:-$SELF.src-sha256}

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15)

dry_run=0
list_only=0
check_only=0
for arg in "$@"; do
  case $arg in
    --dry-run) dry_run=1 ;;
    --list)    list_only=1 ;;
    --check)   check_only=1 ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[backup-essentials] %s\n' "$*" >&2; }
fail() { printf '[backup-essentials] ERROR: %s\n' "$*" >&2; exit 1; }

# --- installed-copy staleness (#3709) ---------------------------------------
#
# The systemd unit runs a copy in /usr/local/libexec (SELinux blocks exec from
# /home), so a `git pull` changes nothing the timer runs until the installer is
# re-run. That went unnoticed for six weeks: the copy running on the backup
# host predated the es-operator-state export, and every archive since silently
# lacked the dashboard operator state (incident #3708). install-backup-essentials.sh
# stamps the sha256 of the checkout script it copied; compare it with the
# checkout's current one. Sets installed_stale=1 and says so loudly. Silent
# only when running the checkout copy in place or when there is no checkout.
installed_stale=0
check_installed_copy() {
  local src=$REPO_DIR/scripts/backup-essentials.sh have want
  [ -f "$src" ] || return 0
  [ "$SELF" = "$(readlink -f -- "$src")" ] && return 0
  want=$(sha256sum -- "$src" | cut -d' ' -f1)
  have=$(cut -d' ' -f1 "$INSTALL_STAMP" 2>/dev/null || true)
  if [ -z "$have" ]; then
    installed_stale=1
    log "WARNING: installed copy $SELF has no install stamp ($INSTALL_STAMP) -- it predates stamping and is probably stale; re-run: sudo $REPO_DIR/scripts/install-backup-essentials.sh"
  elif [ "$have" != "$want" ]; then
    installed_stale=1
    log "WARNING: installed copy $SELF is older than the checkout $src -- re-run: sudo $REPO_DIR/scripts/install-backup-essentials.sh"
  fi
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
base="apiary-essentials-$stamp"

# --- listing mode -----------------------------------------------------------

if [ "$list_only" -eq 1 ]; then
  for dest in "$DEST_LOCAL_USB" "$DEST_LOCAL_DISK"; do
    printf '\n== %s\n' "$dest"
    ls -lh "$dest"/apiary-essentials-*.tar.gz* 2>/dev/null || echo "  (nothing)"
  done
  printf '\n== %s:%s\n' "$HOMESERVER_SSH" "$DEST_SERVER_USB"
  ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" \
    "ls -lh '$DEST_SERVER_USB'/apiary-essentials-*.tar.gz* 2>/dev/null" || echo "  (nothing)"
  exit 0
fi

# --- freshness check ---------------------------------------------------------
#
# For a health sweep or manual audit: the timer can silently stop existing
# (a rebuild that drops the unit, an installer never re-run) with nothing
# noticing until someone needs a restore. This finds the newest archive
# across all three destinations and fails loudly if it is missing or stale.

if [ "$check_only" -eq 1 ]; then
  check_installed_copy
  newest=0
  for dir in "$DEST_LOCAL_USB" "$DEST_LOCAL_DISK"; do
    while IFS= read -r t; do
      [ -n "$t" ] && [ "${t%.*}" -gt "$newest" ] && newest=${t%.*}
    done < <(find "$dir" -maxdepth 1 -name 'apiary-essentials-*.tar.gz*' ! -name '*.sha256' \
      -printf '%T@\n' 2>/dev/null)
  done
  remote_t=$(ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" \
    "find '$DEST_SERVER_USB' -maxdepth 1 -name 'apiary-essentials-*.tar.gz*' ! -name '*.sha256' -printf '%T@\n' 2>/dev/null | sort -rn | head -1" \
    2>/dev/null || true)
  remote_t=${remote_t%.*}
  [ -n "$remote_t" ] && [ "$remote_t" -gt "$newest" ] && newest=$remote_t

  [ "$newest" -gt 0 ] || fail "no essentials archive found on any of the three destinations"
  age_h=$(( ($(date +%s) - newest) / 3600 ))
  [ "$age_h" -le "$MAX_AGE_HOURS" ] \
    || fail "newest essentials archive is ${age_h}h old (> ${MAX_AGE_HOURS}h) — check apiary-backup-essentials.timer"
  [ "$installed_stale" -eq 0 ] || fail "installed copy of this script is stale (see WARNING above) -- the timer is not running the code in the checkout"
  log "newest essentials archive is ${age_h}h old — OK"
  exit 0
fi

# --- preflight --------------------------------------------------------------

check_installed_copy

for host in "$HOMESERVER_SSH" "$VPS_SSH"; do
  ssh "${SSH_OPTS[@]}" "$host" true 2>/dev/null \
    || fail "cannot reach '$host' over SSH — check the alias and that ~/.ssh/id_ed25519_honeypot is in place"
done
ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" 'sudo -n true' 2>/dev/null \
  || fail "passwordless sudo is not available on '$HOMESERVER_SSH'; the stack .env files are root-owned and unreadable without it"

if [ "$BACKUP_ENCRYPT" -eq 1 ] && [ "$dry_run" -eq 0 ]; then
  command -v gpg >/dev/null || fail "gpg not installed but BACKUP_ENCRYPT=1"
  [ -s "$PASSPHRASE_FILE" ] \
    || fail "passphrase file '$PASSPHRASE_FILE' missing or empty — run scripts/install-backup-essentials.sh, or set BACKUP_ENCRYPT=0 to write plaintext archives"
fi

staging=$(mktemp -d -t apiary-essentials.XXXXXX)
workdir=$(mktemp -d -t apiary-essentials-out.XXXXXX)
chmod 700 "$staging" "$workdir"
trap 'rm -rf "$staging" "$workdir"' EXIT INT TERM

# --- homeserver -------------------------------------------------------------
#
# Collected remotely into a temp dir and streamed back as one tar, rather than
# scp'ing file by file: almost everything here is root-owned (the stack .env
# files are 0600 github-deploy-runner, the WireGuard key is 0600 root), so it
# all has to be read under sudo on the far side anyway, and one stream beats
# ~50 round trips. The remote script writes the tar to fd 3 and every
# diagnostic to stderr, so nothing can corrupt the stream.

log "collecting homeserver state"
mkdir -p "$staging/homeserver"
ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" 'sudo bash -s' <<'REMOTE' \
  | tar -C "$staging/homeserver" -xf -
set -euo pipefail
exec 3>&1 1>&2

stage=$(mktemp -d /tmp/apiary-ess.XXXXXX)
chmod 700 "$stage"
trap 'rm -rf "$stage"' EXIT

stacks=/var/dockge/stacks

# Every stack's .env — the single most important thing here. These hold the
# generated secrets, OIDC client secrets and host-specific settings that exist
# nowhere in git; deploy.yml has always rsync-excluded them precisely so they
# survive a deploy, which also means nothing else ever copies them anywhere.
mkdir -p "$stage/env"
for dir in "$stacks"/*/; do
  [ -f "$dir/.env" ] || continue
  cp -- "$dir/.env" "$stage/env/$(basename "$dir").env"
done
echo "  env: $(find "$stage/env" -type f | wc -l) stack .env files"

# Secret files kept beside a stack rather than inside its .env.
mkdir -p "$stage/secrets"
while IFS= read -r -d '' f; do
  rel=${f#"$stacks"/}
  mkdir -p "$stage/secrets/$(dirname "$rel")"
  cp -- "$f" "$stage/secrets/$rel"
done < <(find "$stacks" -mindepth 3 -maxdepth 3 -path '*/secrets/*' -type f -print0 2>/dev/null)
echo "  secrets: $(find "$stage/secrets" -type f | wc -l) files"

# WireGuard. The private key here is what makes the homeserver's peer record
# on the VPS valid — reusing it on a rebuild means the tunnel comes straight
# back with no coordinated key rotation on the far side.
if [ -d /etc/wireguard ]; then
  mkdir -p "$stage/wireguard"
  cp -a /etc/wireguard/. "$stage/wireguard/"
  echo "  wireguard: $(find "$stage/wireguard" -type f | wc -l) files"
fi

# The installer's answers file. install-homeserver.sh refuses to run without
# one, and it holds the real hostnames, key paths and git remote that
# install-homeserver.conf.example only placeholds. It lives on the root
# filesystem -- exactly what a reinstall wipes -- so a rebuild that starts
# from a wiped disk has no way to reconstruct it. Collected under sudo
# because it is 0600 and owned by the operator, not root.
#
# Where the answers file really lives (#3709): the installer takes --config
# <path>, so there is no canonical home. install.sh --profile home defaults to
# /etc/apiary/install-home.conf; the live homeserver keeps its copies in
# /root/apiary-install/ and /home/<user>/install/. The old glob
# (/root/ and /home/*/ directly) matched none of them, so every archive since
# the file was moved lacked it. Every plausible location is collected, under a
# name derived from the full source path so two copies can never collide, with
# mtimes kept so the newest is identifiable on restore. *.bak-* siblings are
# deliberately not matched.
mkdir -p "$stage/installer"
for conf in /etc/apiary/install-home.conf \
            /root/install-homeserver.conf /root/apiary-install/install-homeserver.conf \
            /home/*/install-homeserver.conf /home/*/install/install-homeserver.conf; do
  [ -f "$conf" ] || continue
  dest=$(printf '%s' "${conf#/}" | tr '/' '_')
  cp -p -- "$conf" "$stage/installer/$dest"
  chmod 600 "$stage/installer/$dest"
done
if [ "$(find "$stage/installer" -type f | wc -l)" -gt 0 ]; then
  echo "  installer: $(find "$stage/installer" -type f | wc -l) answers file(s)"
else
  rmdir "$stage/installer"
  echo "  installer: NO install-homeserver.conf found -- REQUIRED item missing, a restore will need one written by hand" >&2
fi

# Technitium DNS (replaced Pi-hole 2026-09-03): hand-maintained config only.
# Query logs and statistics databases are rebuildable bulk and are skipped;
# zones, settings and blocklist config come along so the server returns with
# the same behaviour. The .env (LAN_IP etc.) is captured separately with the
# other stack env files.
tns_src=$stacks/technitium/config
if [ -d "$tns_src" ]; then
  mkdir -p "$stage/technitium"
  # Everything except logs* and the stats databases.
  for f in "$tns_src"/*; do
    base=$(basename "$f")
    case "$base" in
      log*|*queryLogs*|*stats*) continue ;;
    esac
    cp -a "$f" "$stage/technitium/"
  done
  echo "  technitium: config only (query logs and stats deliberately skipped)"
fi

# Keycloak identity database. A pg_dump, not a tar of the live PGDATA: the
# volume is 88 MB of running Postgres whose on-disk state is only consistent
# if the server is stopped, and a dump restores into any future Postgres
# version rather than pinning the rebuild to 18.6. This is the realm, the
# clients, their secrets and every user account.
if docker inspect hp-keycloak-postgres >/dev/null 2>&1; then
  mkdir -p "$stage/keycloak"
  if docker exec hp-keycloak-postgres \
       pg_dump -U keycloak -d keycloak --clean --if-exists 2>/dev/null \
       | gzip -9 > "$stage/keycloak/keycloak.sql.gz"; then
    echo "  keycloak: pg_dump $(du -h "$stage/keycloak/keycloak.sql.gz" | cut -f1)"
  else
    rm -f "$stage/keycloak/keycloak.sql.gz"
    echo "  keycloak: pg_dump FAILED — container up but dump did not complete" >&2
  fi
else
  echo "  keycloak: hp-keycloak-postgres is not running -- no identity dump in this archive" >&2
fi

# The dashboard's operator-authored Elasticsearch documents (#3323).
#
# This script deliberately takes no Elasticsearch data, and `es-data` is
# where the dashboard keeps more than telemetry: the admin config singleton,
# the user projections and their preferences, alert acknowledgements,
# canarytoken and bait-credential definitions, the manual IP block list,
# report definitions, workbench recipes, ML anomaly acks and submitted
# problem reports. An operator types those; no pipeline regenerates them;
# and until this step existed they were in no backup anywhere -- the
# settings runbook claimed a snapshot policy covered them, and no SLM
# policy has ever existed (docs/BACKUP-ESSENTIALS.md, History).
#
# Kilobytes, exported as mapping + NDJSON, so they ride along in an archive
# that already goes to three destinations off this host. The index list and
# its deliberate exclusions live in the tool, not here.
#
# The tool runs on this side of the SSH hop, against the deployed checkout
# at /opt/stacks/apiary -- the same tree the volumes above come from. It is
# best effort in the same way the Keycloak dump is: its failure is a loud
# warning, not a reason to abandon an archive that has already collected
# the secrets.
es_state_script=/opt/stacks/apiary/scripts/es-operator-state-backup.py
if [ -f "$es_state_script" ] && command -v python3 >/dev/null 2>&1; then
  python3 "$es_state_script" --dest "$stage/es-operator-state" \
    || echo "  es-operator-state: export FAILED -- this archive does NOT carry dashboard config/users/alert state" >&2
else
  echo "  es-operator-state: $es_state_script missing, or no python3 -- operator state NOT in this archive" >&2
fi

# Small config-bearing volumes. Anything holding capture data or a rebuildable
# cache is left out; see this script's header for the full excluded list and
# the sizes that motivated it.
#
#   dashboard-state              dashboard settings, users, audit log
#   honeypot-arcane_arcane-data  Arcane's project + gitops-sync definitions
#   honeypot-elk_evebox-config   EveBox configuration
#   honeypot-canarytokens_canarytokens-redis-data
#                                the canarytoken definitions themselves
#   honeypot-dashboard_es-importer-state
#                                importer cursors — tiny, avoids a full replay
mkdir -p "$stage/volumes"
for volume in dashboard-state honeypot-arcane_arcane-data honeypot-elk_evebox-config \
              honeypot-canarytokens_canarytokens-redis-data \
              honeypot-dashboard_es-importer-state; do
  docker volume inspect "$volume" >/dev/null 2>&1 || continue
  # Same #2348 digest pin as backup-honeypot.sh (#1955 policy form) -- the
  # on-host copy's header carries the full rationale; this sibling pull is
  # the same unowned input from the workstation side.
  docker run --rm --network none -v "$volume:/source:ro" \
    -v "$stage/volumes:/backup" \
    busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662 \
    tar -C /source -czf "/backup/$volume.tar.gz" . 2>/dev/null || {
      echo "  volume $volume: FAILED" >&2; continue; }
done
echo "  volumes: $(find "$stage/volumes" -type f | wc -l) archives"

# Reference material for whoever does the rebuild. Not restorable state — it
# is the "what did this box actually look like" notes that are painful to
# reconstruct from memory at 3am.
mkdir -p "$stage/manifest"
{
  echo "# collected $(date -u +%FT%TZ) on $(hostname)"
  echo; echo "## stacks"; ls "$stacks"
  echo; echo "## docker volumes"; docker volume ls
  echo; echo "## running containers"; docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
  echo; echo "## disks"; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL
  echo; echo "## filesystem usage"; df -hT
  echo; echo "## wireguard"; wg show 2>/dev/null || echo "(wg not available)"
} > "$stage/manifest/homeserver.txt" 2>&1 || true

tar -C "$stage" -cf - . >&3
REMOTE

# --- vps --------------------------------------------------------------------

log "collecting VPS state"
mkdir -p "$staging/vps"
ssh "${SSH_OPTS[@]}" "$VPS_SSH" 'bash -s' <<'REMOTE' \
  | tar -C "$staging/vps" -xf -
set -euo pipefail
exec 3>&1 1>&2

stage=$(mktemp -d /tmp/apiary-ess.XXXXXX)
chmod 700 "$stage"
trap 'rm -rf "$stage"' EXIT

# The VPS's whole configuration surface is well under a megabyte. Its scripts
# and compose file live in git, but .env, the OIDC client secrets and the
# Traefik origin certificates do not — and deploy.yml explicitly refuses to
# overwrite traefik/ for exactly that reason, so this is their only copy.
if [ -f /root/vps/.env ]; then
  mkdir -p "$stage/env"; cp /root/vps/.env "$stage/env/vps.env"
fi
for dir in secrets traefik; do
  [ -d "/root/vps/$dir" ] || continue
  mkdir -p "$stage/$dir"; cp -a "/root/vps/$dir/." "$stage/$dir/"
done
if [ -d /etc/wireguard ]; then
  mkdir -p "$stage/wireguard"; cp -a /etc/wireguard/. "$stage/wireguard/"
fi
echo "  vps: $(find "$stage" -type f | wc -l) files"

# Reference notes only. Every probe here is best-effort: a missing tool, or a
# `head` closing the pipe on a long ruleset and SIGPIPE-ing the producer, must
# never abort the collection that has already succeeded above.
mkdir -p "$stage/manifest"
{
  echo "# collected $(date -u +%FT%TZ) on $(hostname)"
  echo; echo "## running containers"
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || echo "(docker unavailable)"
  echo; echo "## addresses"; ip -brief address 2>/dev/null || true
  echo; echo "## wireguard"; wg show 2>/dev/null || echo "(wg not available)"
  echo; echo "## nftables ruleset"
  nft list ruleset 2>/dev/null | head -400 || true
} > "$stage/manifest/vps.txt" 2>&1 || true

tar -C "$stage" -cf - . >&3
REMOTE

# --- required items (#3709) --------------------------------------------------
#
# Checked here, on the staged tree, rather than trusted from the remote side's
# own diagnostics: those were all "echo and carry on", which is how an archive
# with no installer conf and no operator state was written, logged as
# success, and sat in three places until the restore in #3708 needed them. A
# missing item does not stop the archive being written (the other contents
# are still worth having) but is collected into `missing`, named in the run's
# output, recorded in MANIFEST.txt, and turns the exit status non-zero.

missing=()
nonempty_dir() { [ -d "$1" ] && [ -n "$(find "$1" -type f -size +0 -print -quit 2>/dev/null)" ]; }
hs=$staging/homeserver
nonempty_dir "$hs/installer"        || missing+=("installer answers file (homeserver/installer/)")
[ -s "$hs/es-operator-state/MANIFEST.txt" ] \
                                    || missing+=("dashboard operator-state export (homeserver/es-operator-state/)")
[ -s "$hs/keycloak/keycloak.sql.gz" ] \
                                    || missing+=("Keycloak dump (homeserver/keycloak/keycloak.sql.gz)")
[ -n "$(find "$hs/env" -name '*.env' -size +0 -print -quit 2>/dev/null)" ] \
                                    || missing+=("stack .env files (homeserver/env/)")
nonempty_dir "$hs/wireguard"        || missing+=("WireGuard keys (homeserver/wireguard/)")
for item in "${missing[@]+"${missing[@]}"}"; do
  [ -n "$item" ] && log "ERROR: REQUIRED item missing: $item"
done

# --- runbooks ---------------------------------------------------------------
#
# The archive carries the repo's own documentation and operational scripts.
# Without this, a rebuild that starts from one of these USB sticks has every
# secret in the fleet and no instructions for what to do with them -- the
# restore procedure, the stack start order, the disk layout and the Keycloak
# runbook would all live only in git, on a host you are trying to reach from a
# machine you have not rebuilt yet. It is under 10 MB; there is no reason for
# it not to travel with the secrets it explains.
#
# Only text and scripts are taken. The repo's heavy directories (container
# build contexts, vendored assets) are reproducible from git and are not the
# point of this copy.

if [ -d "$REPO_DIR/docs" ]; then
  log "collecting runbooks from $REPO_DIR"
  mkdir -p "$staging/repo"
  tar -C "$REPO_DIR" -cf - \
    --exclude='.git' \
    docs README.md SECURITY.md factory-reset.sh scripts analysis 2>/dev/null \
    | tar -C "$staging/repo" -xf - 2>/dev/null || true
  # Keep only what a human reads or runs during a rebuild.
  find "$staging/repo" -type f \
    ! -name '*.md' ! -name '*.sh' ! -name '*.py' ! -name '*.yml' ! -name '*.yaml' \
    ! -name '*.service' ! -name '*.timer' ! -name '*.conf' ! -name '*.example' \
    -delete 2>/dev/null || true
  find "$staging/repo" -type d -empty -delete 2>/dev/null || true
  printf '  repo: %s files, %s\n' \
    "$(find "$staging/repo" -type f | wc -l)" \
    "$(du -sh "$staging/repo" | cut -f1)" >&2
else
  log "WARNING: REPO_DIR '$REPO_DIR' has no docs/ — runbooks NOT included in this archive"
fi

# --- manifest ---------------------------------------------------------------

cat > "$staging/MANIFEST.txt" <<EOF
APIARY essentials backup
created    $(date -u +%FT%TZ)
by         $(id -un)@$(hostname)
stamp      $stamp
status     $([ "${#missing[@]}" -eq 0 ] && echo complete || echo "INCOMPLETE -- missing: $(IFS=';'; echo "${missing[*]}")")

This archive holds only what is needed to rebuild the stack: secrets, keys,
certificates, the Keycloak identity database, operator-edited config, small
config-bearing docker volumes, and the operator-authored Elasticsearch
documents the dashboard keeps.

It deliberately contains NO Elasticsearch bulk data, NO captured payloads or
malware, NO PCAP, NO sandbox images and NO sensor logs. A stack restored from
this archive comes back with its own identity, configuration and dashboard
state intact and with an empty event history.

Layout:
  homeserver/env/*.env        one file per Arcane/Dockge stack
  homeserver/secrets/         out-of-band secret files kept beside a stack
  homeserver/wireguard/       wg0.conf including the private key
  homeserver/installer/       install-homeserver.conf, the installer's answers file
  homeserver/technitium/      hand-maintained Technitium DNS config only
  homeserver/keycloak/        keycloak.sql.gz — pg_dump of the identity DB
  homeserver/es-operator-state/
                               dashboard config/users/alert acks and the rest
                               of the operator-state ledger, as mapping +
                               NDJSON; its own MANIFEST.txt lists what was
                               captured. Restore with the
                               es-operator-state-backup.py that rides along
                               in repo/scripts/.
  homeserver/volumes/         small config-bearing docker volumes
  homeserver/manifest/        host reference notes, not restorable state
  vps/env/vps.env             the VPS's .env
  vps/secrets/                OIDC client secrets
  vps/traefik/                dynamic.yml plus the origin certificates
  vps/wireguard/              wg0.conf including the private key
  vps/manifest/               host reference notes
  repo/docs/                  the runbooks -- start with BACKUP-ESSENTIALS.md
  repo/scripts/, repo/analysis/
                              the operational scripts those runbooks invoke

Restore procedure: repo/docs/BACKUP-ESSENTIALS.md, included in this archive so
it does not depend on reaching GitHub from a half-rebuilt machine.
EOF

# --- package ----------------------------------------------------------------

archive="$workdir/$base.tar.gz"
tar -C "$staging" -czf "$archive" .

if [ "$dry_run" -eq 1 ]; then
  log "dry run — collected tree:"
  ( cd "$staging" && du -ah --max-depth=2 . | sort -k2 ) >&2
  log "archive would be $(du -h "$archive" | cut -f1); nothing written to any destination"
  [ "${#missing[@]}" -eq 0 ] || fail "dry run: ${#missing[@]} required item(s) missing (listed above)"
  exit 0
fi

if [ "$BACKUP_ENCRYPT" -eq 1 ]; then
  gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
    --passphrase-file "$PASSPHRASE_FILE" \
    --output "$archive.gpg" "$archive"
  rm -f "$archive"
  archive="$archive.gpg"
fi
artifact=$(basename "$archive")
chmod 600 "$archive"
( cd "$workdir" && sha256sum "$artifact" > "$artifact.sha256" )

log "packaged $artifact ($(du -h "$archive" | cut -f1))"

# --- fan out ----------------------------------------------------------------
#
# Every destination is verified by checksum after the copy, then pruned. A
# destination that is unavailable (USB unplugged, not writable, server
# unreachable) does not stop the others from being written -- but since #3709
# it is no longer a quiet warning either: it is counted in `failed` and the
# run exits non-zero at the end. The 2026-10-17 run skipped the workstation
# USB as "not writable" and still exited 0, so that archive reached 2 of 3
# targets with nothing anywhere saying so. Losing all three fails at once.
# The mountpoint checks stay: they are what stops an unattended run writing
# into an empty directory on the root filesystem.

written=0
failed=0

# A plaintext note beside the encrypted archives. The runbooks are inside the
# archive, which is exactly the wrong side of the encryption if what you have
# forgotten is how to open it. This one file is deliberately not encrypted and
# deliberately contains no secret -- just the command.
readme=$workdir/RESTORE-README.txt
cat > "$readme" <<'NOTE'
APIARY essentials backup
========================

Each apiary-essentials-<UTC stamp>.tar.gz.gpg here is a GPG symmetric
(AES256) archive holding everything needed to rebuild the APIARY stack:
every stack .env, the WireGuard private keys, the Traefik origin
certificate and key, the OIDC client secrets, a pg_dump of the Keycloak
identity database, small config-bearing docker volumes, the dashboard's
operator-authored Elasticsearch documents (config, users, alert acks,
canarytokens, the manual IP block list), and a copy of the repository's own
runbooks.

It contains NO Elasticsearch bulk data, NO captured payloads or malware, NO
PCAP and NO sandbox images. A stack restored from it comes back configured
and authenticated with an empty event history.

To open one:

    gpg -d apiary-essentials-<stamp>.tar.gz.gpg | tar xz -C /some/empty/dir

The passphrase is in the password manager. It is also on the backup host at
/etc/apiary-backup.pass, which is no help if the backup host is what died.

Then read, in this order:

    MANIFEST.txt              what this archive holds and how it is laid out
    repo/docs/BACKUP-ESSENTIALS.md   the full restore procedure
    repo/docs/STACK-REBUILD.md       stack start order and known pitfalls
    homeserver/manifest/             what the host looked like

Dashboard state (config, users, alert acknowledgements, the manual IP block
list) lives in homeserver/es-operator-state/ as NDJSON. Put it back with the
tool that rides along in the archive, once honeypot-elk is up:

    python3 repo/scripts/es-operator-state-backup.py \
        --restore homeserver/es-operator-state

Add --into 'check-{index}' first if you want to rehearse it into scratch
indices before writing to the live ones.

Verify an archive before trusting it:

    sha256sum -c apiary-essentials-<stamp>.tar.gz.gpg.sha256
NOTE

prune_local() {
  local dir=$1 keep=$2
  find "$dir" -maxdepth 1 -name 'apiary-essentials-*.tar.gz*' ! -name '*.sha256' \
    -printf '%f\n' 2>/dev/null | sort -r | tail -n "+$((keep + 1))" |
  while IFS= read -r old; do
    rm -f -- "$dir/$old" "$dir/$old.sha256"
  done
}

copy_local() {
  local label=$1 dir=$2
  # A udisks auto-mount only exists while the drive is plugged in. Without
  # this check an unattended run would write into an empty directory on the
  # root filesystem and report success, and the "backup" would be invisible
  # the next time the drive was mounted over the top of it.
  case $dir in
    /run/media/*|/media/*|/mnt/*)
      local mnt=$dir
      while [ "$mnt" != "/" ] && ! mountpoint -q "$mnt"; do mnt=$(dirname "$mnt"); done
      # /run is a tmpfs mountpoint on every systemd host, so climbing to it
      # (an unplugged drive: /run/media/<user>/<label> absent) used to count as
      # "mounted" and the mkdir below wrote into RAM. Those are not USB mounts.
      case $mnt in /|/run|/run/media|/media|/mnt) mnt=/ ;; esac
      if [ "$mnt" = "/" ]; then
        log "WARNING: $label ($dir) is not on a mounted filesystem — skipping"
        return 1
      fi ;;
  esac
  mkdir -p "$dir" || { log "WARNING: $label ($dir) not writable — skipping"; return 1; }
  chmod 700 "$dir" 2>/dev/null || true
  cp -- "$workdir/$artifact" "$workdir/$artifact.sha256" "$dir/" \
    || { log "WARNING: $label copy failed — skipping"; return 1; }
  cp -- "$readme" "$dir/RESTORE-README.txt" 2>/dev/null || true
  ( cd "$dir" && sha256sum -c "$artifact.sha256" >/dev/null ) \
    || { log "WARNING: $label checksum mismatch after copy — removing"; rm -f "$dir/$artifact" "$dir/$artifact.sha256"; return 1; }
  prune_local "$dir" "$RETENTION"
  log "wrote $label: $dir/$artifact"
  return 0
}

if copy_local "local USB" "$DEST_LOCAL_USB"; then written=$((written + 1)); else failed=$((failed + 1)); fi
if copy_local "local disk" "$DEST_LOCAL_DISK"; then written=$((written + 1)); else failed=$((failed + 1)); fi

# The server USB was reformatted from Ventoy/exfat to a single ext4 partition
# on 2026-08-23 (label APIARY-BACKUP). ext4 keeps ownership and permission
# bits, so the destination directory is owned by the SSH user and the archive
# arrives 0600 -- neither of which the old exfat filesystem could express.
#
# It is also mounted from /etc/fstab by UUID with nofail, rather than the
# transient read-only mount it had before, which silently failed every write.
# The mountpoint check below stays anyway: nofail means a missing drive is a
# missing mount, not a boot failure, and that has to be caught here.
server_usb_mount=$(dirname "$DEST_SERVER_USB")
if ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" "mountpoint -q '$server_usb_mount'" 2>/dev/null; then
  if ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" "mkdir -p '$DEST_SERVER_USB'" 2>/dev/null \
     && scp "${SSH_OPTS[@]}" -q "$workdir/$artifact" "$workdir/$artifact.sha256" \
          "$readme" "$HOMESERVER_SSH:$DEST_SERVER_USB/" 2>/dev/null \
     && ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" \
          "cd '$DEST_SERVER_USB' && sha256sum -c '$artifact.sha256' >/dev/null" 2>/dev/null; then
    ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" "
      cd '$DEST_SERVER_USB' || exit 0
      ls -1 apiary-essentials-*.tar.gz* 2>/dev/null | grep -v '\.sha256\$' | sort -r \
        | tail -n +$((RETENTION + 1)) | while IFS= read -r old; do rm -f -- \"\$old\" \"\$old.sha256\"; done
    " 2>/dev/null || true
    log "wrote server USB: $HOMESERVER_SSH:$DEST_SERVER_USB/$artifact"
    written=$((written + 1))
  else
    log "WARNING: server USB copy failed — skipping"
    failed=$((failed + 1))
    ssh "${SSH_OPTS[@]}" "$HOMESERVER_SSH" \
      "rm -f '$DEST_SERVER_USB/$artifact' '$DEST_SERVER_USB/$artifact.sha256'" 2>/dev/null || true
  fi
else
  log "WARNING: $server_usb_mount is not mounted on $HOMESERVER_SSH — skipping"
  failed=$((failed + 1))
fi

[ "$written" -gt 0 ] || fail "no destination could be written — nothing was backed up"

log "done — $artifact stored in $written of 3 locations"

status=0
if [ "$failed" -gt 0 ]; then
  log "ERROR: $failed destination(s) FAILED -- $artifact is NOT in all three locations (see WARNING lines above)"
  status=1
fi
if [ "${#missing[@]}" -gt 0 ]; then
  log "ERROR: archive is INCOMPLETE -- ${#missing[@]} required item(s) missing (see ERROR lines above)"
  status=1
fi
if [ "$installed_stale" -eq 1 ]; then
  log "WARNING: this run used a STALE installed copy of the script (see above); re-run scripts/install-backup-essentials.sh"
fi
exit "$status"
