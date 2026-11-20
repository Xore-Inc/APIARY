#!/bin/sh
set -eu

# Manual runs get what systemd's UMask=0077 gives the scheduled ones (#2025):
# under an interactive shell's typical umask 022 the archive set -- including
# .env secrets and the Keycloak dump below -- sat world-readable between
# creation and the trailing chmod -R go-rwx. One line closes the window for
# both invocation paths.
umask 077

# backup-honeypot.sh — on-host snapshot of the state needed to bring the stack
# back, taken on the homeserver itself.
#
# Scope, deliberately narrow: configuration, secrets, small config-bearing
# volumes, the Keycloak identity database, and the operator-authored
# Elasticsearch documents a human typed rather than a pipeline derived
# (dashboard config/users/alert acks and the rest of that ledger -- see
# scripts/es-operator-state-backup.py). NOT Elasticsearch *data*: not events,
# not captured payloads or malware, not derived indices, not PCAP, not sandbox
# images. A stack restored from this comes back configured and authenticated
# with an empty event history, which is the intended trade.
#
# Why the Elasticsearch snapshot that used to live here is gone:
#
#  1. It was the "es store data" this backup is explicitly not meant to hold.
#     The honeypot-fs repository it wrote into had itself grown to 14 GB.
#  2. It had never once succeeded. Every scheduled run since the timer was
#     installed on 2026-08-16 died on `curl: (22) ... error: 400` from the
#     snapshot API, and because that call sits under `set -e`, the run aborted
#     right there -- so the volume archives below never ran either, and
#     neither did retention. Seven consecutive days of "backups" contained a
#     single config tarball, an empty volumes/ directory and a zero-byte
#     elasticsearch-snapshot.json, with the service sitting in `failed`.
#
# Dropping it fixes both at once. Whoever wants Elasticsearch data preserved
# should take a real ES snapshot on its own schedule, with its own retention,
# rather than coupling it to the config backup -- the coupling is what made a
# broken snapshot silently take the config backup down with it.
#
# The off-host copy of this same material is scripts/backup-essentials.sh,
# which runs on the workstation and fans out to three locations. This script
# is the on-host, same-disk copy: faster to reach, useless if the box dies.

stack_dir=${STACK_DIR:-/opt/stacks/apiary}
backup_root=${BACKUP_ROOT:-/opt/backups/honeypot}
retention_days=${RETENTION_DAYS:-14}
# The container resolver (#3596), from the same tree as this script
# (/opt/stacks/apiary/analysis -> /opt/stacks/apiary/scripts/lib).
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
task_container_lib=${TASK_CONTAINER_LIB:-$script_dir/../scripts/lib/task-container.sh}

# Retention runs FIRST, before anything else this script does (#2025). The
# most plausible persistent failure mode for a backup job is a full disk,
# and pruning used to sit at the very END, behind tar/pg_dump/busybox steps
# that need free space to succeed -- so the disk filling up aborted every
# run before the one step that frees space could ever run again: no
# self-healing path short of a human. Retention depends on nothing produced
# below -- only directory names under $backup_root -- so it belongs before
# them, unconditionally.
#
# #1413's history is why position matters as much as presence: it found the
# original script never pruned AT ALL, and once the prune existed every run
# still died on its way down to it (the broken ES snapshot era above).
# Directory names are the UTC stamp itself, all the same fixed width
# (%Y%m%dT%H%M%SZ) -- stripped of its T/Z separators that is a plain
# 14-digit number, safe to compare with -lt. Deliberately not
# `[ "$a" \< "$b" ]`: this script is #!/bin/sh, and on this fleet that is
# dash (`readlink -f /bin/sh` -> /usr/bin/dash), whose test builtin has no
# </> string operators at all -- a bash-only extension that would have
# failed every run.
cutoff=$(date -u -d "-${retention_days} days" +%Y%m%dT%H%M%SZ 2>/dev/null || date -u -v-"${retention_days}"d +%Y%m%dT%H%M%SZ)
cutoff_n=$(echo "$cutoff" | tr -d 'TZ')
for old in "$backup_root"/*/; do
  old_stamp=$(basename "$old")
  old_n=$(echo "$old_stamp" | tr -d 'TZ')
  case $old_n in ''|*[!0-9]*) continue ;; esac
  [ "$old_n" -lt "$cutoff_n" ] || continue
  rm -rf "$old"
done

cd "$stack_dir"

# Resolve the compose file rather than assuming compose.yml. Dockge treated
# compose.yml as canonical and the deployed stack directory carried that name;
# the repo checkout this now runs against has docker-compose.yml, and
# compose.yml has never existed in the repo at all. After the 2026-09-03
# rebuild replaced the deployed tree with a plain checkout, this validation
# gate aborted every run before any backup was written:
#
#   compose file "/opt/stacks/apiary/compose.yml" is invalid: no such file or directory
#
# Accept either name, and skip the gate rather than fail if neither is present:
# its job is to catch a corrupted compose file, not to require one to exist.
compose_file=""
for candidate in compose.yml docker-compose.yml; do
  [ -f "$candidate" ] && { compose_file=$candidate; break; }
done
if [ -n "$compose_file" ]; then
  docker compose -f "$compose_file" config -q
else
  echo "no compose.yml or docker-compose.yml in $stack_dir -- skipping compose validation" >&2
fi

# Only create this run's directories once validation has passed (#2025): a
# failed validation used to leave an empty stamped directory behind for a
# later run's retention to collect.
stamp=$(date -u +%Y%m%dT%H%M%SZ)
destination="$backup_root/$stamp"
mkdir -p "$destination/volumes"
chmod 700 "$destination"

# Config/state archive. Excludes event logs, PCAP, Elasticsearch data, captured
# malware and generated databases.
#
# ./state also carries state/knowledge-vault/ once #2290's worker creates it
# (#1634 stage 2): curated, bounded/redacted markdown notes derived from
# attacker material. #2289's design record decided this inclusion is
# deliberate, not an oversight -- the vault's redaction posture
# (docs/knowledge-store-design.md) already keeps its content closer in
# sensitivity to the config material this script already carries than to
# the bulk payload/PCAP data excluded above, so it inherits this script's
# existing scope rather than needing a separate backup path or an exclusion.
# Same resolution as the validation gate above: back up whichever compose file
# this layout actually has, instead of a name that may not exist.
set --
[ -n "$compose_file" ] && set -- "./$compose_file"
for candidate in ./.env ./README.md ./analysis ./dashboard ./personas ./state; do
  [ ! -e "$candidate" ] || set -- "$@" "$candidate"
done
# --exclude='./state/elasticsearch-snapshots' (#1413): the `fs` repository's
# own live blob storage. ES's post-delete repository cleanup mutates files
# under here concurrently, which aborted the whole run under `set -e` ("file
# removed before we read it"). It is bulk ES data besides, so it stays
# excluded now that nothing snapshots into it from this script at all.
tar -czf "$destination/stack-config-state.tar.gz" \
  --exclude='./logs' --exclude='./analysis/geoip/*.mmdb' \
  --exclude='./analysis/threat-intel/*.csv' \
  --exclude='./state/elasticsearch-snapshots' \
  "$@"

# The Keycloak identity database: the realm, its clients, their secrets and
# every user account. A pg_dump rather than a tar of the live 88 MB PGDATA --
# that directory is only consistent with the server stopped, and a dump
# restores into any later Postgres rather than pinning a rebuild to 18.6.
#
# The container is resolved, not named (#3596): the swarm task of
# keycloak_postgres first, the Compose hp-keycloak-postgres second. When
# neither runs, or the dump fails, the rest of the backup is still written and
# the run then exits 1 (keycloak_failed below): before this, a missing
# container skipped the dump without a word and the unit stayed green.
keycloak_failed=0
pg_ctr=""
if [ ! -r "$task_container_lib" ]; then
  echo "backup-honeypot: ERROR: $task_container_lib missing -- cannot find the Keycloak Postgres container, NO identity dump" >&2
  keycloak_failed=1
else
  # shellcheck disable=SC1090
  if ! pg_ctr=$(. "$task_container_lib" && task_container keycloak_postgres hp-keycloak-postgres); then
    echo "backup-honeypot: ERROR: no running Keycloak Postgres (swarm keycloak_postgres or Compose hp-keycloak-postgres) -- NO identity dump in this backup" >&2
    keycloak_failed=1
    pg_ctr=""
  fi
fi
if [ -n "$pg_ctr" ]; then
  # Two steps, not a pipe. This script is #!/bin/sh -> dash on this fleet
  # (same constraint the retention comment documents below), so a pipeline's
  # exit status could only ever reflect gzip's half: a pg_dump dying midway
  # -- container restart, OOM, dropped connection -- still exited 0 through
  # gzip and kept a silently truncated identity-database backup, whose
  # SHA256SUMS entry then vouches for exactly the wrong bytes. #1413's
  # post-mortem above is the same failure class from the other direction.
  #
  # Split stages make both exit statuses observable; the plaintext also gets
  # checked non-empty AND terminated by pg_dump's completion footer before
  # anything compressed is allowed to exist at rest. pg_dump's stderr is no
  # longer discarded while we're here -- a reason was being hidden from the
  # humans checking a failed run. umask 077 keeps the temporary plaintext
  # keyed at 0600 for its short life; the final chmod below tightens the
  # rest of the archive set.
  if (umask 077 && exec docker exec "$pg_ctr" \
         pg_dump -U keycloak -d keycloak --clean --if-exists \
         > "$destination/keycloak.sql") &&
     [ -s "$destination/keycloak.sql" ] &&
     grep -q "PostgreSQL database dump complete" "$destination/keycloak.sql" &&
     gzip -9 < "$destination/keycloak.sql" > "$destination/keycloak.sql.gz"; then
    rm -f "$destination/keycloak.sql"
  else
    rm -f "$destination/keycloak.sql" "$destination/keycloak.sql.gz"
    echo "backup-honeypot: ERROR: keycloak backup failed (pg_dump from $pg_ctr, truncation/footer check, or gzip)" >&2
    keycloak_failed=1
  fi
fi

# The dashboard's operator-authored Elasticsearch state (#3323).
#
# es-data is out of scope for this script, and it is the only place these
# documents exist: the admin config singleton, the user projections and
# their preferences, alert acknowledgements, canarytoken and bait-credential
# definitions, the manual IP block list, report definitions, workbench
# recipes, ML anomaly acks and submitted problem reports. Nothing in the
# pipeline regenerates any of them -- an operator types them -- and until
# this step ran, none of them was in any backup. They are kilobytes, so
# they cost this daily archive nothing.
#
# The index list, and the deliberate exclusions from it, live in the tool
# (scripts/es-operator-state-backup.py --list) rather than here, so the two
# copies of this script cannot disagree about the scope.
#
# Best effort (unlike the Keycloak dump above, which fails the run): an unreachable
# Elasticsearch must not take the rest of the backup down with it. The tool
# exits non-zero when it captured nothing at all, and this script then says
# so on stderr, but the volume archives below are unaffected either way.
es_state_script="$stack_dir/scripts/es-operator-state-backup.py"
if [ -f "$es_state_script" ] && command -v python3 >/dev/null 2>&1; then
  python3 "$es_state_script" --dest "$destination/es-operator-state" ||
    echo "backup-honeypot: operator-state export FAILED (above) -- this backup does NOT carry dashboard config/users/alert state" >&2
else
  echo "backup-honeypot: $es_state_script missing, or no python3 -- operator state NOT in this backup" >&2
fi

# Small config-bearing named volumes only.
#
# Removed from this list, with the sizes that motivated it (measured live
# 2026-08-23): dionaea-lib (90 GB of captured malware samples), reporter-data
# (2.8 GB of generated reports), yara-results (scan output, derived from
# payloads) and snare-pages (a cloned site, re-clonable). None of them are
# needed to bring the stack up, and dionaea-lib alone would have made this
# archive unusable as a routine daily job.
#
# es-data was never in this list and still is not: it is the Elasticsearch
# store.
for volume in dashboard-state honeypot-arcane_arcane-data honeypot-elk_evebox-config \
              honeypot-canarytokens_canarytokens-redis-data \
              honeypot-dashboard_es-importer-state; do
  docker volume inspect "$volume" >/dev/null 2>&1 || continue
  safe=$(printf '%s' "$volume" | tr -c 'A-Za-z0-9._-' '_')
  # busybox pin (#2348): bare "busybox:1.36" made every run's archive tool
  # an unowned mutable input -- whatever Docker Hub serves under that tag
  # next month would execute inside this security-sensitive path without
  # anyone noticing. Digest-pinned to the multi-arch manifest-list of
  # busybox:1.36 fetched from Docker Hub 2026-08-27, same policy form
  # (tag@sha256:) as the fleet's compose images since #1955's Keycloak pin.
  docker run --rm --network none -v "$volume:/source:ro" \
    -v "$destination/volumes:/backup" \
    busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662 \
    tar -C /source -czf "/backup/$safe.tar.gz" .
done

# Checksum whatever actually got produced -- keycloak.sql.gz is absent if the
# Keycloak stack is not running, volumes/ is empty if none of the named
# volumes exist yet, and es-operator-state/ is absent or partial if the
# operator-state export failed, so none of them can be assumed into the
# argument list.
(
  cd "$destination"
  set -- stack-config-state.tar.gz
  [ -f keycloak.sql.gz ] && set -- "$@" keycloak.sql.gz
  for exported in es-operator-state/*; do
    [ -e "$exported" ] && set -- "$@" "$exported"
  done
  for archive in volumes/*.tar.gz; do
    [ -e "$archive" ] && set -- "$@" "$archive"
  done
  sha256sum "$@" >SHA256SUMS
)
chmod -R go-rwx "$destination"
echo "$destination"
if [ "$keycloak_failed" -ne 0 ]; then
  echo "backup-honeypot: ERROR: $destination has NO Keycloak identity dump (see above)" >&2
  exit 1
fi
