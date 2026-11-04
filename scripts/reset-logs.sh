#!/usr/bin/env bash
# reset-logs.sh — wipe sensor log data and restart fresh.
#
# Usage:
#   ./scripts/reset-logs.sh                  # wipe ALL sensors
#   ./scripts/reset-logs.sh cowrie           # cowrie only
#   ./scripts/reset-logs.sh conpot           # all conpot variants
#   ./scripts/reset-logs.sh multipot         # multipot only
#   ./scripts/reset-logs.sh http             # http-honeypot + api-honeypot
#   ./scripts/reset-logs.sh dionaea          # dionaea logs (not binaries)
#   ./scripts/reset-logs.sh dnp3             # dnp3 honeypot
#   ./scripts/reset-logs.sh dicompot         # dicompot (DICOM) honeypot
#   ./scripts/reset-logs.sh dns              # dns-honeypot (UDP reflection bait)
#   ./scripts/reset-logs.sh citrix           # citrix-honeypot (CVE-2019-19781)
#   ./scripts/reset-logs.sh cisco-asa        # cisco-asa-honeypot (CVE-2018-0101)
#   ./scripts/reset-logs.sh rdp              # rdp-honeypot
#   ./scripts/reset-logs.sh tanner           # tanner + snare
#   ./scripts/reset-logs.sh suricata         # suricata EVE only (pcap preserved)
#   ./scripts/reset-logs.sh suricata --wipe-suricata-pcap  # suricata EVE + pcap
#   ./scripts/reset-logs.sh --dry-run        # preview, no changes
#   ./scripts/reset-logs.sh cowrie conpot    # multiple targets
#
# Run from the stack root (same dir as docker-compose.yml/compose.yml).
# Requires: docker, sudo (log dirs are owned by container UIDs).
#
# Elasticsearch cleanup reaches elasticsearch:9200 via a throwaway
# container on the honeynet network (it has no host-published port), and
# deletes by log.file.path rather than by index-per-sensor pattern:
# honeypot-v2-* is one shared data stream for every sensor, not one index
# each, and the old per-target `DELETE /honeypot-<target>-*` calls matched
# zero real indices for anything but suricata -- confirmed live, this had
# silently deleted nothing for cowrie/conpot/multipot/http/dionaea/dnp3/
# tanner since the day those lines were written.
#
# #258: conpot, cowrie, multipot, http (http-honeypot+api-honeypot), and dnp3
# each now deploy as their own Dockge stack (/opt/stacks/honeypot-<name>/
# compose.yml), not inside APIARY's own compose.yml. A bare
# `docker compose stop/up` run from this directory resolves against *this*
# directory's compose.yml (Compose's default file-discovery prefers
# compose.yml over docker-compose.yml, which is why this already worked
# against the deployed stack rather than the repo-tracked filename) and
# would silently find nothing for those services' names now that they live
# in a different project. Their stop/up runs from each stack's own directory
# instead, matching how they were actually deployed, so Compose resolves the
# same project each was created under.

set -euo pipefail

LOGS_BASE="/opt/stacks/apiary/logs"
STATE_BASE="/opt/stacks/apiary/state"

# Every target that moved into its own stack (#258), and which services live
# there. cowrie is the one target with a foot in both worlds: cowrie itself
# moved out, but payload-dedupe/yara-scanner (which read its captured
# downloads) live in yet another stack of their own now -- see
# PAYLOAD_ANALYSIS_DIR/PAYLOAD_ANALYSIS_SERVICES below, not this array
# (there's no standalone "payload-analysis" CLI target; those two are only
# ever stopped/started as a side effect of `wants cowrie`, same reasoning
# as when they still lived in the main stack).
SPLIT_TARGETS=(conpot cowrie multipot http dnp3 dionaea tanner dicompot dns citrix cisco-asa rdp)
declare -A SPLIT_STACK_DIR=(
  [conpot]="/opt/stacks/honeypot-conpot"
  [cowrie]="/opt/stacks/honeypot-cowrie"
  [multipot]="/opt/stacks/honeypot-multipot"
  [http]="/opt/stacks/honeypot-http"
  [dnp3]="/opt/stacks/honeypot-dnp3"
  [dicompot]="/opt/stacks/honeypot-dicompot"
  [dns]="/opt/stacks/honeypot-dns-honeypot"
  [citrix]="/opt/stacks/honeypot-citrix-honeypot"
  [cisco-asa]="/opt/stacks/honeypot-cisco-asa-honeypot"
  [rdp]="/opt/stacks/honeypot-rdp-honeypot"
  [dionaea]="/opt/stacks/honeypot-dionaea"
  [tanner]="/opt/stacks/honeypot-tanner"
)
declare -A SPLIT_STACK_SERVICES=(
  [conpot]="conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup"
  [cowrie]="cowrie"
  [multipot]="multipot"
  [http]="http-honeypot api-honeypot"
  [dnp3]="dnp3"
  [dicompot]="dicompot"
  [dns]="dns-honeypot"
  [citrix]="citrix-honeypot"
  [cisco-asa]="cisco-asa-honeypot"
  [rdp]="rdp-honeypot"
  [dionaea]="dionaea tftp-relay"
  # tanner_docker/tanner_redis/tanner_phpox are deliberately excluded here,
  # same as before this split: they hold no open handles into logs/tanner
  # or logs/snare (the two directories this script wipes for this target),
  # so stopping/starting them on every wipe is unnecessary churn. Only the
  # four that do -- tanner, tanner_api, tanner_web, snare -- are listed.
  [tanner]="tanner tanner_api tanner_web snare"
)

PAYLOAD_ANALYSIS_DIR="/opt/stacks/honeypot-payload-analysis"
PAYLOAD_ANALYSIS_SERVICES="payload-dedupe yara-scanner"

# evebox (arcane/home/honeypot-elk/compose.yml, #258) is the only ELK service this script
# ever stops/starts -- same reasoning as payload-dedupe/yara-scanner above,
# no standalone CLI target of its own, only a side effect of `wants
# suricata`. elasticsearch/kibana/filebeat/arkime-* hold no open handles
# into logs/suricata (the directory wiped for this target) that would race
# a concurrent wipe, so they were never stopped for this target either,
# before or after this split.
ELK_DIR="/opt/stacks/honeypot-elk"
ELK_SURICATA_SERVICES="evebox"

DRY=false
WIPE_SURICATA_PCAP=false
declare -A TARGETS
have_target=false

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=true ;;
    --wipe-suricata-pcap) WIPE_SURICATA_PCAP=true ;;
    cowrie|conpot|multipot|http|dionaea|dnp3|dicompot|dns|citrix|cisco-asa|rdp|tanner|suricata|all)
      TARGETS["$arg"]=1
      have_target=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# Default to all when no target given. Not "${#TARGETS[@]} -eq 0" -- on a
# freshly `declare -A`'d array with nothing ever assigned into it yet, this
# bash version's `set -u` treats ${#TARGETS[@]} itself as an unbound
# variable reference (confirmed: -v TARGETS[key] does not have this
# problem, only the count expansion does), even though the array was
# properly declared. A plain flag sidesteps the whole question.
$have_target || TARGETS["all"]=1

wants() {
  [[ -v TARGETS["all"] ]] || [[ -v TARGETS["$1"] ]]
}

run() {
  if $DRY; then echo "[dry-run] $*"; else "$@"; fi
}

STEP() { echo; echo "===> $*"; }

wipe_dir() {
  local dir="$1" exclude="${2:-}"
  if [ -d "$dir" ]; then
    if [ -n "$exclude" ]; then
      echo "  wipe: $dir (preserving $exclude/)"
      run sudo find "$dir" -mindepth 1 -path "$dir/$exclude" -prune -o -delete
    else
      echo "  wipe: $dir"
      run sudo find "$dir" -mindepth 1 -delete
    fi
  else
    echo "  (skip, not found: $dir)"
  fi
}

mkown() {
  local dir="$1" uid="$2"
  run sudo mkdir -p "$dir"
  run sudo chown -R "$uid" "$dir"
}

# Elasticsearch has no host-published port (arcane/home/honeypot-elk/compose.yml -- "no
# ports: mapping at all -- reached by name over honeynet/llm-data"), so
# `curl http://localhost:9200` from this host-side script has never
# actually reached it (connection refused, silently swallowed below).
# A throwaway container joined to honeynet is the only way in from here.
es_curl() {
  docker run --rm --network honeynet curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777 "$@"
}

ES_URL="http://elasticsearch:9200"

# honeypot-v2-* is a single shared data stream for every sensor
# (analysis/elasticsearch-setup.sh), not one index per sensor -- a plain
# `DELETE /honeypot-<target>-*` (the old approach) matches zero real
# indices for any of cowrie/conpot/multipot/http/dionaea/dnp3/tanner and
# has always silently deleted nothing. Filtering by event.sensor instead
# of log.file.path was considered and rejected: confirmed live that
# several sensors (cowrie at minimum) self-report a "sensor" field as
# their own container's hostname -- effectively a random hex string that
# changes every restart -- rather than a fixed name, so event.sensor
# values for the same target are inconsistent across restarts.
# log.file.path (the bind-mounted path Filebeat actually read the event
# from) is stable and directly matches the same directories wipe_dir
# already wipes on disk.
delete_es_by_path() {
  local path_glob="$1"
  echo "  DELETE BY QUERY ${ES_URL}/honeypot-v2-* WHERE log.file.path LIKE ${path_glob}"
  $DRY && return
  es_curl -sf -X POST "${ES_URL}/honeypot-v2-*/_delete_by_query?conflicts=proceed" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"wildcard\":{\"log.file.path.keyword\":\"${path_glob}\"}}}" \
    -o /dev/null \
    || echo "  (ES down or query failed — skipped)"
}

# Suricata is the one target where a plain index-pattern DELETE is correct:
# Filebeat ships it into real per-day, per-event-type indices
# (suricata-v2-<type>-YYYY.MM.DD, confirmed live via _cat/indices), not the
# shared honeypot-v2-* data stream.
delete_es_index() {
  local pattern="$1"
  echo "  DELETE ${ES_URL}/${pattern}"
  $DRY && return
  es_curl -sf -X DELETE "${ES_URL}/${pattern}" -o /dev/null \
    || echo "  (not found or ES down — skipped)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Build service list for stop/start
# ─────────────────────────────────────────────────────────────────────────────
# cowrie/multipot/http/dnp3/conpot/dionaea/tanner themselves are
# deliberately excluded from SERVICES -- each lives in its own Dockge
# stack/compose project now (SPLIT_STACK_DIR above) and is stopped/started
# there separately, via split_stack_compose below, not through this array.
# evebox is excluded the same way (arcane/home/honeypot-elk/compose.yml, #258) -- see
# ELK_DIR/ELK_SURICATA_SERVICES/foreign_stack_compose below instead.
SERVICES=()

split_stack_compose() {
  # split_stack_compose <target> <docker compose args...> -- e.g.
  # `split_stack_compose cowrie stop` or `split_stack_compose dnp3 up -d`.
  # A zero-length service list would make `docker compose stop/up` with no
  # arguments act on *everything* in that compose file, not nothing, so
  # callers only ever invoke this for a target actually in SPLIT_TARGETS.
  local target="$1"; shift
  local dir="${SPLIT_STACK_DIR[$target]}"
  # Deliberate word-splitting of a fixed, script-defined list (not user
  # input) into a services array -- SC2206 does not apply here.
  # shellcheck disable=SC2206
  local services=(${SPLIT_STACK_SERVICES[$target]})
  if [ ! -d "$dir" ]; then
    echo "  (skip $target: $dir does not exist -- honeypot-$target not deployed here)"
    return 0
  fi
  ( cd "$dir" && run docker compose "$@" "${services[@]}" )
}

# Shared by payload-dedupe/yara-scanner (arcane/home/honeypot-payload-analysis/compose.yml)
# and evebox (arcane/home/honeypot-elk/compose.yml) -- both #258 splits that get
# stopped/started only as a *side effect* of another target (cowrie,
# suricata respectively), never their own standalone CLI target, because
# they hold reads/hardlinks/handles into a directory that target's wipe
# would otherwise race.
foreign_stack_compose() {
  local label="$1" dir="$2"; shift 2
  local services_str="$1"; shift
  if [ ! -d "$dir" ]; then
    echo "  (skip $label: $dir does not exist -- honeypot-$label not deployed here)"
    return 0
  fi
  # shellcheck disable=SC2206
  local services=(${services_str})
  ( cd "$dir" && run docker compose "$@" "${services[@]}" )
}

split_targets_wanted() {
  local out=() t
  for t in "${SPLIT_TARGETS[@]}"; do
    wants "$t" && out+=("${SPLIT_STACK_SERVICES[$t]}")
  done
  echo "${out[*]}"
}

# ─────────────────────────────────────────────────────────────────────────────
STEP "Stopping: ${SERVICES[*]} $(split_targets_wanted)$(wants cowrie && echo " $PAYLOAD_ANALYSIS_SERVICES")$(wants suricata && echo " $ELK_SURICATA_SERVICES")"
[[ ${#SERVICES[@]} -gt 0 ]] && run docker compose stop "${SERVICES[@]}"
for t in "${SPLIT_TARGETS[@]}"; do wants "$t" && split_stack_compose "$t" stop; done
wants cowrie   && foreign_stack_compose payload-analysis "$PAYLOAD_ANALYSIS_DIR" "$PAYLOAD_ANALYSIS_SERVICES" stop
wants suricata && foreign_stack_compose elk "$ELK_DIR" "$ELK_SURICATA_SERVICES" stop

# ─────────────────────────────────────────────────────────────────────────────
STEP "Wiping log files"

CLEAR_FILEBEAT=false

if wants cowrie; then
  wipe_dir "${LOGS_BASE}/cowrie"
  CLEAR_FILEBEAT=true
fi

if wants conpot; then
  for v in conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup; do
    wipe_dir "${LOGS_BASE}/$v"
  done
  CLEAR_FILEBEAT=true
fi

if wants multipot; then
  wipe_dir "${LOGS_BASE}/multipot"
  CLEAR_FILEBEAT=true
fi

if wants http; then
  wipe_dir "${LOGS_BASE}/http-honeypot"
  wipe_dir "${LOGS_BASE}/api-honeypot"
  CLEAR_FILEBEAT=true
fi

if wants dionaea; then
  # Wipe JSON event logs only — NOT the dionaea-lib Docker volume which
  # holds captured binaries (smb/ftp/tftp roots). To also purge binaries:
  #   docker compose stop dionaea && docker volume rm dionaea-lib
  wipe_dir "${LOGS_BASE}/dionaea"
  CLEAR_FILEBEAT=true
fi

if wants dnp3; then
  wipe_dir "${LOGS_BASE}/dnp3"
  CLEAR_FILEBEAT=true
fi

if wants dicompot; then
  wipe_dir "${LOGS_BASE}/dicompot"
  CLEAR_FILEBEAT=true
fi

if wants dns; then
  wipe_dir "${LOGS_BASE}/dns-honeypot"
  CLEAR_FILEBEAT=true
fi

if wants citrix; then
  wipe_dir "${LOGS_BASE}/citrix-honeypot"
  CLEAR_FILEBEAT=true
fi

if wants cisco-asa; then
  wipe_dir "${LOGS_BASE}/cisco-asa-honeypot"
  CLEAR_FILEBEAT=true
fi

if wants rdp; then
  wipe_dir "${LOGS_BASE}/rdp-honeypot"
  CLEAR_FILEBEAT=true
fi

if wants tanner; then
  wipe_dir "${LOGS_BASE}/tanner"
  wipe_dir "${LOGS_BASE}/snare"
  CLEAR_FILEBEAT=true
fi

if wants suricata; then
  # Wipe EVE JSON (dashboard/Kibana source). Preserve the pcap sub-dir by
  # default since pcaps are also consumed by Arkime -- pass --wipe-suricata-pcap
  # to wipe pcaps too.
  if $WIPE_SURICATA_PCAP; then
    wipe_dir "${LOGS_BASE}/suricata"
  else
    wipe_dir "${LOGS_BASE}/suricata" pcap
  fi
  # Wipe EveBox's own config.sqlite (saved filters/comments/escalations) so
  # those reset too. Named evebox-data here historically but the volume
  # EveBox actually declares is evebox-config (arcane/home/honeypot-elk/compose.yml) --
  # private/unnamed there, so project-prefixed as honeypot-elk_evebox-config.
  # Stop evebox first (foreign_stack_compose above) so Docker doesn't
  # refuse the removal with "volume is in use."
  run docker volume rm --force honeypot-elk_evebox-config 2>/dev/null || true
  CLEAR_FILEBEAT=true
fi

if $CLEAR_FILEBEAT; then
  echo "  wipe: ${STATE_BASE}/filebeat (Filebeat registry)"
  run sudo find "${STATE_BASE}/filebeat" -mindepth 1 -delete
fi

# ─────────────────────────────────────────────────────────────────────────────
STEP "Re-creating log directories with correct ownership"

if wants cowrie; then
  mkown "${LOGS_BASE}/cowrie/downloads" 2000:2000
  mkown "${LOGS_BASE}/cowrie/tty" 2000:2000
fi

if wants conpot; then
  for v in conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup; do
    mkown "${LOGS_BASE}/$v" 2000:2000
  done
fi

if wants multipot; then
  # multipot runs as nobody (65534)
  mkown "${LOGS_BASE}/multipot" 65534:65534
fi

if wants http; then
  mkown "${LOGS_BASE}/http-honeypot" 65534:65534
  mkown "${LOGS_BASE}/api-honeypot"  65534:65534
fi

if wants dionaea; then
  mkown "${LOGS_BASE}/dionaea" 1000:1000
fi

if wants dnp3; then
  mkown "${LOGS_BASE}/dnp3" 65534:65534
fi

if wants dicompot; then
  mkown "${LOGS_BASE}/dicompot" 65534:65534
fi

if wants dns; then
  mkown "${LOGS_BASE}/dns-honeypot" 65534:65534
fi

if wants citrix; then
  mkown "${LOGS_BASE}/citrix-honeypot" 65534:65534
fi

if wants cisco-asa; then
  mkown "${LOGS_BASE}/cisco-asa-honeypot" 65534:65534
fi

if wants rdp; then
  mkown "${LOGS_BASE}/rdp-honeypot" 65534:65534
fi

if wants tanner; then
  mkown "${LOGS_BASE}/tanner" 65534:65534
  # NOT 65534:65534 -- confirmed live during the #258 full-stack reset:
  # snare's own check_privileges() (mushorg/snare's snare_helpers.py) runs
  # os.access(path, W_OK) on /opt/snare *before* its internal
  # drop_privileges() call, so it still runs as uid 0 at that point. With
  # cap_drop: [ALL] (no DAC_OVERRIDE), uid 0 here gets ordinary
  # owner/group/other permission checks like any other UID -- it needs to
  # literally own the directory, not just "be root", to pass W_OK. A
  # 65534-owned /opt/snare crash-loops with "Failed to access path:
  # /opt/snare" every restart cycle.
  mkown "${LOGS_BASE}/snare" root:root
fi

if wants suricata; then
  mkown "${LOGS_BASE}/suricata/pcap" 65534:65534
fi

# ─────────────────────────────────────────────────────────────────────────────
STEP "Deleting Elasticsearch documents (non-fatal)"

wants cowrie   && delete_es_by_path "/logs/cowrie/*"
wants conpot   && delete_es_by_path "/logs/conpot*"
wants multipot && delete_es_by_path "/logs/multipot/*"
wants http     && delete_es_by_path "/logs/http-honeypot/*" && delete_es_by_path "/logs/api-honeypot/*"
wants dionaea  && delete_es_by_path "/logs/dionaea/*"
wants dnp3     && delete_es_by_path "/logs/dnp3/*"
wants dicompot && delete_es_by_path "/logs/dicompot/*"
wants dns        && delete_es_by_path "/logs/dns-honeypot/*"
wants citrix     && delete_es_by_path "/logs/citrix-honeypot/*"
wants cisco-asa  && delete_es_by_path "/logs/cisco-asa-honeypot/*"
wants rdp        && delete_es_by_path "/logs/rdp-honeypot/*"
wants tanner   && delete_es_by_path "/logs/tanner/*"
wants suricata && delete_es_index "suricata-*"

# ─────────────────────────────────────────────────────────────────────────────
STEP "Starting: ${SERVICES[*]} $(split_targets_wanted)$(wants cowrie && echo " $PAYLOAD_ANALYSIS_SERVICES")$(wants suricata && echo " $ELK_SURICATA_SERVICES")"
[[ ${#SERVICES[@]} -gt 0 ]] && run docker compose up -d "${SERVICES[@]}"
for t in "${SPLIT_TARGETS[@]}"; do wants "$t" && split_stack_compose "$t" up -d; done
wants cowrie   && foreign_stack_compose payload-analysis "$PAYLOAD_ANALYSIS_DIR" "$PAYLOAD_ANALYSIS_SERVICES" up -d
wants suricata && foreign_stack_compose elk "$ELK_DIR" "$ELK_SURICATA_SERVICES" up -d

STEP "Done"
echo "Tail logs with:  docker compose logs -f ${SERVICES[*]}"
wants cowrie   && echo "  (cd $PAYLOAD_ANALYSIS_DIR && docker compose logs -f $PAYLOAD_ANALYSIS_SERVICES)"
wants suricata && echo "  (cd $ELK_DIR && docker compose logs -f $ELK_SURICATA_SERVICES)"
for t in "${SPLIT_TARGETS[@]}"; do
  wants "$t" && echo "  (cd ${SPLIT_STACK_DIR[$t]} && docker compose logs -f ${SPLIT_STACK_SERVICES[$t]})"
done
