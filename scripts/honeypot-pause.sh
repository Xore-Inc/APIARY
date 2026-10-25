#!/usr/bin/env bash
# honeypot-pause.sh -- pause the pause-safe honeypot decoy stacks to free host
# CPU for a heavy benchmark or training leg, and resume them afterwards in
# strict reverse order with a real probe per stack (#3135).
#
# Why this exists. #3135 is a standing practice on this box: when a leg needs
# more RAM/CPU than the homeserver has free, pause the decoys, run the leg,
# unpause them after. The rules in the issue are hard, and three of them are
# interlocks rather than advice, so they live in code here rather than in a
# README nobody re-reads at 02:00 before a training leg:
#
#   1. Only pause containers classified pause-safe. A wrong "safe" does not
#      fail loudly -- it silently breaks a decoy that was carrying the honeypot
#      surface, so the classification is default-DENY: a stack that is not in
#      PAUSE_SAFE below cannot be paused at all, and the refusal says why.
#   2. NEVER pause ghidra-ollama-1 while a benchmark holds the GPU slot. The
#      GPU stacks are absent from the allowlist and additionally refused by
#      name, so a typo cannot reach them.
#   3. NEVER pause during the cold-run protocol. That protocol is governed by
#      STOP_WORKERS=1 + the restore trap in sweep_extra.sh and is deliberately
#      NOT touched here. We only refuse to run alongside it.
#
# Two findings from the 2026-09-27 dry run are load-bearing, and both are why
# this script is not a two-line "docker pause $(cat list)":
#
#   AUTOHEAL UNDOES THE PAUSE. Every decoy on this host carries the label
#   `autoheal=true`, and hp-autoheal polls every AUTOHEAL_INTERVAL=30s. A
#   paused container's healthcheck exec cannot complete, so Docker marks it
#   `unhealthy` and autoheal `docker restart`s it -- which unpauses it. Proven
#   on 2026-09-27: hp-elasticpot was paused at 18:12:21Z and autoheal logged
#       18:12:38 Container /hp-elasticpot found to be unhealthy - Restarting
#   17 seconds later, with the container running again and RestartCount still
#   0 (a manual-style restart does not bump it). So a naive pause is a ~30s
#   no-op and the operator is left believing a decoy is dark when it is not --
#   a false posture, which is worse than an honest outage. hp-autoheal is
#   therefore paused FIRST and resumed LAST, and pause refuses to run without
#   that gate in place.
#
#   PAUSE DOES NOT FREE RAM. The issue says "free RAM/CPU". Measured on
#   2026-09-27, cgroup v2 memory.current for hp-elasticpot was 36,339,712 B
#   running and 36,360,192 B while paused -- it went UP by 20 KiB. `docker
#   pause` freezes the cgroup (CPU stops being scheduled) but keeps the memory
#   charged to it. It is a CPU lever, not a RAM lever. For real RAM you must
#   `docker stop`, which is a different and more destructive operation and is
#   NOT what this script does. This is stated in the runbook too, because
#   discovering it after a leg OOMs is the expensive way to learn it.
set -euo pipefail

PAUSE_DIR="${APIARY_PAUSE_DIR:-/var/lib/apiary/honeypot-pause}"
INVENTORY="$PAUSE_DIR/inventory"      # pause order, one container per line
RECORD="$PAUSE_DIR/record.log"        # append-only what/when log
PROBE_HOST="${APIARY_PAUSE_PROBE_HOST:-10.8.0.2}"

# The gate. Paused before any decoy, resumed after every one of them.
AUTOHEAL_CONTAINER="${APIARY_PAUSE_AUTOHEAL:-hp-autoheal}"

# Process patterns that mean "the cold-run protocol owns this host right now".
# Copied from the pgrep guard in analysis/ghidra/benchmarks/corpus/coldrun.sh
# (line 63) so this script and the protocol agree on what "running" means.
COLD_RUN_PATTERNS=(sweep_extra.sh record_baseline.py round7_sweep.sh coldrun.sh round7_coldrun.sh)

# ---------------------------------------------------------------------------
# The classification. This table IS the substance of #3135.
#
# Verdict per stack:
#   SAFE  - may be paused. A decoy whose only effect of being paused is that
#           it stops answering on its own port. No dependent, no capture path,
#           no shared state, not a worker anything waits on.
#   UNIT  - pause-safe only as a whole stack, because the containers have a
#           real dependency on each other. Partial pausing hangs a live
#           session rather than ending it cleanly.
#   NEVER - not pause-safe, and the reason is given.
#
# Columns: verdict|stack|containers|probe|reason
# `probe` is the real request made to prove the decoy answers again after
# resume. tcp:PORT = a completed TCP connect. http:PORT/path = a real HTTP
# request whose status code must be 200.
# ---------------------------------------------------------------------------
read -r -d '' CLASSIFICATION <<'EOF' || true
SAFE|honeypot-elasticpot|hp-elasticpot|http:9201/|Standalone Elasticsearch decoy, no dependents, no shared state. Single container, no in-flight session to strand. Dry-run proven 2026-09-27.
SAFE|honeypot-multipot|hp-multipot|tcp:110|Multi-protocol decoy (pop3/imap/socks/dockerv2/tls/adb/redis/elastic). No dependents, no upstream. Each emulated service answers on connect.
SAFE|honeypot-dicompot|hp-dicompot|tcp:11112|Standalone DICOM decoy. No dependents.
SAFE|honeypot-dnp3|hp-dnp3|tcp:20000|Standalone DNP3 decoy. No dependents.
SAFE|honeypot-sentrypeer|hp-sentrypeer|tcp:5070|Standalone SIP decoy. No dependents, no shared state.
SAFE|honeypot-hellpot|hp-hellpot|tcp:8080|Standalone SMTP/HTTP/FTP decoy. No dependents.
SAFE|honeypot-endlessh|hp-endlessh|tcp:19024|Standalone SSH tarpit. No dependents. Long-lived tarpit sessions are abandoned, which is the intended dark.
SAFE|honeypot-rdp-honeypot|hp-rdp-honeypot|tcp:3389|Standalone RDP decoy. No dependents.
SAFE|honeypot-cisco-asa-honeypot|hp-cisco-asa-honeypot|tcp:8443|Standalone ASA decoy. No dependents.
SAFE|honeypot-sonicwall-sma-honeypot|hp-sonicwall-sma-honeypot|tcp:8543|Standalone SMA decoy. No dependents.
SAFE|honeypot-citrix-honeypot|hp-citrix-honeypot|tcp:443|Standalone Citrix decoy. No dependents.
SAFE|honeypot-mailoney|hp-mailoney|tcp:25|Standalone SMTP decoy. No dependents.
SAFE|honeypot-beelzebub|hp-beelzebub|tcp:2200|Standalone adaptive SSH/HTTP/MCP decoy. No dependents. NOTE: hosts an MCP endpoint; pausing it is a deliberate dark, not a defect.
UNIT|honeypot-conpot|hp-conpot,hp-conpot-guardian,hp-conpot-s7-1500,hp-conpot-s7-1200,hp-conpot-iec104,hp-conpot-kamstrup|tcp:102|One Arcane stack of six OT decoys sharing an image and a project. Pause all six or none: hp-conpot is the shared modbus/s7 front and the others are peers on it, so a partial pause leaves listeners up with no engine behind them.
UNIT|honeypot-cowrie|hp-cowrie,hp-honeyfs-implant|tcp:19022|hp-honeyfs-implant is the FUSE server that serves cowrie its fake filesystem. Pausing the implant alone hangs every filesystem operation inside a live session. Pause cowrie first, implant second; resume implant first, cowrie second.
UNIT|honeypot-dionaea|hp-dionaea,hp-tftp-relay|tcp:21|Largest single decoy (369MiB, ~14% CPU) and the one most worth pausing. hp-tftp-relay is a stack-internal dependency, and dionaea holds an internal MySQL plus live sessions, so it goes as a unit: dionaea first, relay second. Never pause dionaea alone.
UNIT|honeypot-galah|hp-galah,hp-galah-llm-broker|tcp:8888|hp-galah proxies its LLM calls through hp-galah-llm-broker. Pausing the broker alone makes galah's own decoy paths fail in a way that looks like a broken decoy rather than a stand-down.
UNIT|honeypot-canarytokens|hp-canarytokens-http-router,hp-canarytokens-frontend,hp-canarytokens-adapter,hp-canarytokens-switchboard,hp-canarytokens-redis|tcp:19427|Internal dependency chain router->adapter->switchboard->redis. Partial pause leaves the switchboard blocked on a frozen redis. Pause front to back, resume back to front.
NEVER|honeypot-elk|hp-elasticsearch,hp-filebeat,hp-zeek-proxy,hp-arkime-capture,hp-arkime-viewer,hp-kibana,hp-evebox,hp-pcap-sync,hp-extracted-file-importer|-|The capture pipeline. Pausing arkime-capture, zeek-proxy or pcap-sync stops packet capture at the point of arrival, which is silent data loss, and pausing elasticsearch stalls every sensor's event write. Not a decoy; it is what makes the decoys worth running. Highest single allocation on the host (elasticsearch ~10.6GiB) and the least safe to interrupt.
NEVER|honeypot-dashboard|hp-dashboard-next,hp-dashboard-oidc-sessions,hp-apiary-backend-mounted|-|The operator surface. A paused dashboard stops answering, so you cannot observe the stand-down you are performing -- which defeats the point of recording it.
NEVER|honeypot-backend-workers|hp-apiary-worker,hp-apiary-worker-enrichment,hp-apiary-worker-importer,hp-apiary-worker-payload-inventory,hp-services-adapter|-|The ES write consumers and the service-control adapter (#3575). Pausing the workers buffers Elasticsearch bulk queues, and a paused adapter makes every service action hang.
NEVER|honeypot-dashboard-backend|hp-apiary-backend|-|Auth and API surface. A paused backend fails every dashboard and CLI call with a hang, not a clean error.
NEVER|honeypot-keycloak|hp-keycloak,hp-keycloak-postgres|-|Identity tier. Dashboard, arcane and the OIDC login tests all authenticate through it; pausing it breaks logins, not just decoys.
NEVER|honeypot-arcane|hp-arcane|-|GitOps control plane. This is the container that would RE-CREATE a paused decoy on its next sync, so pausing it is arguably necessary -- but it is also the thing that reconciles the fleet, and a control plane held frozen across a long leg cannot report or repair drift. Deliberately excluded: reconcile first, pause decoys, do not freeze the orchestrator.
NEVER|honeypot-utilities|hp-docker-socket-proxy,hp-disk-space-monitor,hp-docker-hygiene,hp-log-maintenance,hp-reporter|-|Host watchdogs. Pausing hp-disk-space-monitor and hp-docker-hygiene during exactly the memory-hungry leg they exist to catch removes the guard against the failure you are creating. hp-docker-socket-proxy is also the socket autoheal drives.
NEVER|honeypot-tanner|hp-tanner,hp-tanner-api,hp-tanner-web,hp-tanner-redis,hp-tanner-docker,hp-tanner-phpox,hp-snare|-|Event sink, not a decoy. cowrie and dionaea POST their events here; pausing it makes live sensors error on their own event path and hp-tanner-redis holds session state in flight. Analysis of collected events is exactly what a leg must not interrupt.
NEVER|honeypot-payload-analysis|hp-yara-scanner,hp-payload-dedupe|-|Downstream payload analysis fed from Elasticsearch. Not a decoy, no listener, but it is a pipeline stage; freezing it mid-file leaves partial state. Out of scope for "honeypot sensors/decoys".
NEVER|honeypot-init|hp-geoipupdate,hp-threat-cidrs-refresh|-|Periodic updaters. Pausing hp-geoipupdate mid-write can leave a truncated GeoIP database, which then fails every enrichment silently.
NEVER|ml-worker|hp-ml-worker|-|Named in the cold protocol's LIVE_WORKERS. The cold-run mechanism governs this container via STOP_WORKERS=1 + trap; pausing it here would create a second, unreconciled source of truth for whether it is running. Do not touch.
NEVER|auth-events-worker|hp-auth-events-worker|-|Consumes Keycloak auth-failure events. Pausing it drops the very signal that tier exists to capture.
NEVER|ghidra|ghidra-ollama-1,ghidra-revdeck-1,ghidra-statictools-1,ghidra-ghidra-1|-|HARD PROHIBITION. ghidra-ollama-1 is the GPU slot holder and is named explicitly in the issue: never pause it while a benchmark holds the GPU. ghidra-revdeck-1 is in the cold protocol's LIVE_WORKERS. These are also the containers a leg is running to make room FOR.
NEVER|unsloth|hp-unsloth-studio|-|The training leg itself. It is the reason for pausing, not a target of it.
NEVER|rex86-eval|rex86-eval|-|The eval leg itself. Same reasoning.
NEVER|technitium|technitium-dns|-|Real recursive DNS for 192.168.42.50, not a decoy. A frozen resolver takes the host's name resolution with it.
NEVER|pentagi|graphiti,neo4j,pentagi,pgvector,pentagi-ollama-embedding,pgexporter,scraper|-|Unrelated product stack, not part of the honeypot. Out of scope.
NEVER|ghosts|ghosts-ghosts-api-1,ghosts-ghosts-postgres-1|-|Belongs to the sandbox isolation stack that #3312 audits. Standing it down is a separate, declared act (scripts/sandbox-standdown.sh), not a decoy pause.
NEVER|dashkcnext-dashkcchaos|dashkcnext-pg-414734,dashkcnext-kc-414734,dashkcnext-redis-414734,dashkcchaos-pg-404812,dashkcchaos-kc-404812,dashkcchaos-redis-404812|-|OIDC chaos-test fixtures. These ARE an active test. "Depended on by an active test" is an explicit NOT pause-safe condition in the issue; pausing them breaks a run in progress.
EOF

log()  { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
warn() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die()  { warn "ABORT: $*"; exit 1; }

# ---------------------------------------------------------------------------
# table accessors
# ---------------------------------------------------------------------------
field() { # field <verdict> <stack> <n>
  printf '%s\n' "$CLASSIFICATION" | awk -F'|' -v v="$1" -v s="$2" -v n="$3" \
    '$1==v && $2==s { print $n; found=1; exit } END { if (!found) exit 1 }'
}
verdict_of() { field "$1" "$2" 1; }
containers_of() { field "$1" "$2" 3; }
probe_of() { field "$1" "$2" 4; }
reason_of() { field "$1" "$2" 5; }

all_stacks() { printf '%s\n' "$CLASSIFICATION" | awk -F'|' '{print $2}'; }

cold_run_active() {
  local p
  for p in "${COLD_RUN_PATTERNS[@]}"; do
    if pgrep -f "$p" >/dev/null 2>&1; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

# A stack may be requested only if it is SAFE or UNIT.
is_pauseable() {
  local v
  v=$(verdict_of SAFE "$1" 2>/dev/null) && [ "$v" = SAFE ] && return 0
  v=$(verdict_of UNIT "$1" 2>/dev/null) && [ "$v" = UNIT ] && return 0
  return 1
}

# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------
# probe_stack <stack> -> prints "ok <detail>" and returns 0, or "fail <detail>".
# A TCP probe is a completed connect, which is the strongest thing a
# non-speaking protocol (POP3, DNP3, SIP) can be asked for. An HTTP probe must
# return 200 from the decoy's own emulated response.
probe_stack() {
  local stack=$1 spec host port path code body
  spec=$(probe_of SAFE "$stack" 2>/dev/null || probe_of UNIT "$stack" 2>/dev/null) || {
    echo "fail no probe defined"; return 1; }
  host=$PROBE_HOST
  case "$spec" in
    tcp:*)
      port=${spec#tcp:}
      if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        echo "ok tcp/$port connected"; return 0
      fi
      echo "fail tcp/$port did not connect"; return 1 ;;
    http:*)
      rest=${spec#http:}; port=${rest%%/*}; path=/${rest#*/}
      body=$(mktemp); trap 'rm -f "$body"' RETURN
      code=$(curl -s --max-time 8 -o "$body" -w '%{http_code}' "http://$host:$port$path" 2>/dev/null) || code=000
      if [ "$code" = "200" ] && [ -s "$body" ]; then
        echo "ok http/$port$path -> $code, $(wc -c <"$body") bytes"
        return 0
      fi
      echo "fail http/$port$path -> $code (expected 200)"; return 1 ;;
  esac
  echo "fail unrecognised probe spec: $spec"; return 1
}

container_healthy() { # -> 0 if running (health reported if a check exists)
  local c=$1 state health
  state=$(docker inspect -f '{{.State.Paused}}' "$c" 2>/dev/null) || return 1
  [ "$state" = "false" ] || return 1
  docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true || return 1
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null)
  printf '%s' "$health"
}

usage() {
  cat >&2 <<EOF
Usage: $0 list
       $0 status
       $0 pause <stack> [stack...]
       $0 resume

Subcommands:
  list     print the full per-stack pause-safety classification, with reasons.
  status   show the recorded pause inventory and each container's real state.
  pause    pause the named stacks. The autoheal gate is paused first and is
           recorded so that resume puts it back last. Refuses to run while the
           cold-run protocol is active.
  resume   unpause every recorded container in strict REVERSE order, verifying
           each one answers (docker ps health + one real probe request) before
           moving to the next.

Pause-safe stacks (the default-deny allowlist):
$(for s in $(all_stacks); do
    v=$(verdict_of SAFE "$s" 2>/dev/null || verdict_of UNIT "$s" 2>/dev/null || echo NEVER)
    [ "$v" = NEVER ] || printf '  %-34s %s\n' "$s" "$v"
  done)

Examples:
  $0 list
  $0 pause honeypot-elasticpot honeypot-multipot
  $0 status
  $0 resume

Everything else is refused. See docs/OPERATIONS.md ("Pausing decoys to free
host CPU") for the full table and the reasoning.
EOF
  exit 2
}

# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------
cmd_list() {
  local v s c p r
  while IFS='|' read -r v s c p r; do
    printf '%-6s %s\n' "$v" "$s"
    printf '       containers: %s\n' "$c"
    [ "$p" = "-" ] || printf '       probe:      %s (against %s)\n' "$p" "$PROBE_HOST"
    printf '       reason:     %s\n' "$r"
    printf '\n'
  done < <(printf '%s\n' "$CLASSIFICATION")
  printf '%d stacks classified. Only SAFE and UNIT are accepted by `pause`; the\n' "$(all_stacks | wc -l)"
  printf 'other %d are refused by name, with the reason above.\n' \
    "$(printf '%s\n' "$CLASSIFICATION" | awk -F'|' '$1=="NEVER"' | wc -l)"
}

cmd_status() {
  if [ ! -s "$INVENTORY" ]; then
    log "no pause recorded (inventory $INVENTORY absent or empty)"
    return 0
  fi
  log "recorded pause order ($INVENTORY), $(wc -l <"$INVENTORY") containers:"
  local n=0 c paused h
  while read -r c; do
    n=$((n+1))
    paused=$(docker inspect -f '{{.State.Paused}}' "$c" 2>/dev/null || echo missing)
    h=$(container_healthy "$c" || true)
    printf '  %2d  %-34s paused=%-6s health=%s\n' "$n" "$c" "$paused" "${h:-unreachable}"
  done <"$INVENTORY"
  log "resume order is the REVERSE of the above."
}

cmd_pause() {
  [ $# -gt 0 ] || usage
  local stack v reason
  for stack in "$@"; do
    all_stacks | grep -qx -- "$stack" || die "unknown stack '$stack' -- run '$0 list'. Typing a name that is not classified is exactly how the wrong decoy gets paused."
    v=$(verdict_of SAFE "$stack" 2>/dev/null || verdict_of UNIT "$stack" 2>/dev/null || echo NEVER)
    if [ "$v" = NEVER ]; then
      reason=$(reason_of NEVER "$stack" 2>/dev/null)
      case "$stack" in
        ghidra|unsloth|rex86-eval)
          die "refusing to pause stack '$stack' (contains a GPU/training/eval leg). $reason" ;;
      esac
      die "refusing to pause stack '$stack': verdict NEVER. $reason"
    fi
  done

  # Interlock 3: the cold-run protocol owns this host while it is running.
  if cold=$(cold_run_active); then
    die "cold-run protocol is active (matched '$cold'). Stop-workers-during-cold-run is governed by STOP_WORKERS=1 + the restore trap in sweep_extra.sh and is unchanged by this script -- pausing on top of it would create a second source of truth for which workers are down. Wait for the cold run to finish, or stop it, then pause."
  fi

  command -v docker >/dev/null 2>&1 || die "docker not on PATH"
  docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon"

  # Swarm stacks (#3590) are not paused here. Swarm sees a frozen task's
  # healthcheck time out, marks the task unhealthy and replaces it -- the same
  # silent un-pause autoheal causes. They are scaled to 0 through Arcane by
  # ops/swarm/stackctl.py pause, which also frees their RAM.
  for stack in "$@"; do
    if docker service ls -q --filter "label=com.docker.stack.namespace=$stack" 2>/dev/null | grep -q .; then
      die "stack '$stack' runs on Docker Swarm; pause it with: ops/swarm/stackctl.py pause $stack (scale to 0, see ops/swarm/README.md)"
    fi
  done

  [ ! -s "$INVENTORY" ] || die "a pause is already recorded in $INVENTORY -- resume it first (reverse order), or remove the file if you are certain nothing is paused."

  install -d -m 0755 "$PAUSE_DIR"
  : >"$INVENTORY"
  log "=== PAUSE START (issue #3135) ==="
  log "stacks: $*"
  log "note: pause frees CPU (the cgroup freezer), not RAM. See docs/OPERATIONS.md."

  # --- the autoheal gate, FIRST -------------------------------------------
  # Every decoy carries autoheal=true and autoheal restarts any container it
  # sees as unhealthy within ~30s. Left running, it silently unpauses
  # everything we are about to pause (measured 2026-09-27: 17s).
  if docker inspect "$AUTOHEAL_CONTAINER" >/dev/null 2>&1; then
    docker pause "$AUTOHEAL_CONTAINER" >/dev/null
    printf '%s\n' "$AUTOHEAL_CONTAINER" >>"$INVENTORY"
    log "GATE: paused $AUTOHEAL_CONTAINER (resumes LAST) -- without this, autoheal restarts every paused decoy within AUTOHEAL_INTERVAL"
  else
    warn "WARN: $AUTOHEAL_CONTAINER not found. Any pause-safe decoy that carries autoheal=true may be restarted within ~30s. Verify with '$0 status'."
  fi

  # --- the requested stacks -----------------------------------------------
  # UNIT stacks are recorded dependency-last so that resume (which reverses)
  # brings the dependent back first. Within a UNIT entry the order given is
  # the pause order and the resume order is its exact reverse.
  for stack in "$@"; do
    reason=$(reason_of SAFE "$stack" 2>/dev/null || reason_of UNIT "$stack" 2>/dev/null)
    log "pausing $stack -- $reason"
    local c
    for c in $(containers_of SAFE "$stack" 2>/dev/null || containers_of UNIT "$stack" 2>/dev/null | tr ',' ' '); do
      if ! docker inspect "$c" >/dev/null 2>&1; then
        warn "WARN: $c (in $stack) is not present on this host; skipping it and rolling the whole pause back"
        cmd_resume >/dev/null 2>&1 || true
        die "rolled back: $c is missing from $stack"
      fi
      docker pause "$c" >/dev/null
      printf '%s\n' "$c" >>"$INVENTORY"
      log "  paused $c"
    done
  done

  {
    printf 'pause_start_utc=%s\n' "$(date -u +%FT%TZ)"
    printf 'issue=%s\n' '#3135'
    printf 'stacks=%s\n' "$*"
    printf 'order=%s\n' "$(paste -sd, "$INVENTORY")"
  } >>"$RECORD"
  log "recorded $RECORD"
  log "=== PAUSE END: $(wc -l <"$INVENTORY") containers paused ==="
  log "resume with: $0 resume   (strict reverse order, verifies each)"
}

cmd_resume() {
  if [ ! -s "$INVENTORY" ]; then
    log "nothing recorded to resume ($INVENTORY absent or empty)"
    return 0
  fi
  command -v docker >/dev/null 2>&1 || die "docker not on PATH"

  # Reverse the inventory into a temp list; resume is strictly reverse order.
  tmp=$(mktemp); trap 'rm -f "$tmp"' RETURN
  tac "$INVENTORY" >"$tmp"

  log "=== RESUME START (issue #3135) -- reverse order ==="
  local total failed=0 c stack h
  total=$(wc -l <"$tmp")
  local n=0
  while read -r c; do
    n=$((n+1))
    if docker inspect "$c" >/dev/null 2>&1; then
      if [ "$(docker inspect -f '{{.State.Paused}}' "$c")" = "true" ]; then
        docker unpause "$c" >/dev/null
        log "[$n/$total] unpaused $c"
      else
        log "[$n/$total] $c was not paused; leaving it alone"
      fi
      # Health first. A just-unpaused container needs a beat to run its
      # healthcheck, and the autoheal gate is still shut at this point
      # precisely so it cannot restart it mid-verification.
      h=""
      local i
      for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        h=$(container_healthy "$c" || true)
        [ -z "$h" ] || [ "$h" = healthy ] || [ "$h" = none ] && break
        sleep 5
      done
      log "[$n/$total] $c health=${h:-unreachable}"
      [ "$h" = healthy ] || [ "$h" = none ] || { warn "WARN: $c did not return to healthy (got '${h:-unreachable}')"; failed=$((failed+1)); }
      if stack=$(stack_of_container "$c"); then
        if result=$(probe_stack "$stack"); then
          log "[$n/$total] $c probe $result"
        else
          warn "WARN: $c probe $result -- the decoy is NOT answering"
          failed=$((failed+1))
        fi
      else
        log "[$n/$total] $c has no per-stack probe (not a decoy); health check only"
      fi
    else
      warn "[$n/$total] WARN: $c is not present on this host; cannot verify"
      failed=$((failed+1))
    fi
  done <"$tmp"

  {
    printf 'resume_end_utc=%s\n' "$(date -u +%FT%TZ)"
    printf 'containers=%s\n' "$total"
    printf 'problems=%s\n' "$failed"
  } >>"$RECORD"

  log "=== RESUME END: $total containers, $failed problem(s) ==="
  if [ "$failed" -gt 0 ]; then
    warn "$failed container(s) did not verify. The record stays in $RECORD and $INVENTORY is kept for a retry. Do not treat this leg as clean until they answer."
    return 1
  fi
  rm -f "$INVENTORY"
  log "all containers verified; inventory cleared."
}

stack_of_container() { # reverse lookup: container -> stack
  local v s
  while IFS= read -r s; do
    for v in SAFE UNIT; do
      if [ "$v" = SAFE ]; then c_list=$(containers_of SAFE "$s" 2>/dev/null || true)
      else c_list=$(containers_of UNIT "$s" 2>/dev/null || true); fi
      case ",$c_list," in *",$1,"*) printf '%s' "$s"; return 0 ;; esac
    done
  done < <(all_stacks)
  return 1
}

[ $# -gt 0 ] || usage
action=$1; shift
case "$action" in
  list)   cmd_list ;;
  status) cmd_status ;;
  pause)  cmd_pause "$@" ;;
  resume) cmd_resume ;;
  -h|--help|help) usage ;;
  *) echo "unknown subcommand: $action" >&2; usage ;;
esac
