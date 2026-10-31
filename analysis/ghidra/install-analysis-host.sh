#!/usr/bin/env bash
# install-analysis-host.sh — stand up the Ghidra analysis backend on this host.
#
# Brings up three containers and wires the host-side worker to them:
#
#   ghidra       built from ./service in this directory -- official Ghidra
#                releases fetched checksum-verified at build time behind a
#                small REST wrapper, the decompiler behind /analyze (the
#                third-party packaging this replaced came off the stack
#                in #245; see docker-compose.ghidra.yml)
#   ollama       the local model that produces ai_triage (#103)
#   statictools  ssdeep/tlsh fuzzy hashing and lief structural parsing (#138)
#
# All three publish on 127.0.0.1 only. Between them they hold captured malware
# and every string, fuzzy hash and structural fact extracted from it, and the
# triage prompts are that text — so the model has to be on this host, and the
# worker refuses to talk to one that is not (see endpoint_is_local in
# worker/ghidra-worker.py).
#
# On a host running Dockge the compose file is deployed into a stack directory
# under /opt/stacks, the same place deploy.yml puts the honeypot stack, so the
# containers show up as a stack Dockge manages rather than as strays it can see
# but not touch. That directory is a deployment copy: edit the file in this
# repository and re-run this script, do not edit it there.
#
# Idempotent: safe to re-run after a pull, a model change, or a reboot. An
# existing /etc/default/honeypot-ghidra is never overwritten.
#
# Usage:
#   sudo analysis/ghidra/install-analysis-host.sh          # containers + worker
#   analysis/ghidra/install-analysis-host.sh --containers-only
#
# Options:
#   --containers-only  Bring up/refresh the containers and stop. Needs docker
#                      but not root, which is the half an operator in the
#                      docker group can run.
#   --host-files-only  The inverse of --containers-only: skip the Ghidra/
#                      Ollama/statictools containers entirely and only
#                      re-install the worker/systemd-unit half. Needs root.
#                      For CI to re-sync ghidra-worker.py and siblings on a
#                      routine deploy without also restarting the GPU
#                      containers every time (#1406).
#   --model NAME       Model to pull (default qwen3:14b, or GHIDRA_TRIAGE_MODEL
#                      from /etc/default/honeypot-ghidra if that file exists).
#   --no-gpu           Run the model on CPU even if an NVIDIA runtime is present.
#   --skip-pull        Do not pull the model. For a host that already has it.
#   --stack-dir PATH   Where to deploy the compose file. Defaults to
#                      /opt/stacks/ghidra when /opt/stacks exists, else the
#                      repository directory. Pass "" to run in place.
#   -h, --help         This text.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_file="$here/docker-compose.ghidra.yml"
gpu_file="$here/docker-compose.ghidra.gpu.yml"
env_file=/etc/default/honeypot-ghidra
target=/opt/honeypot-ghidra

CONTAINERS_ONLY=0
HOST_FILES_ONLY=0
USE_GPU=auto
SKIP_PULL=0
MODEL=""
# The compose project name is pinned in the file itself (`name: ghidra`,
# #1502) precisely so it can't drift with the directory holding the compose
# file -- it no longer has to be named "ghidra" for the volume names
# (ghidra_ollama_models etc.) to stay put.
STACK_DIR="$([ -d /opt/stacks ] && echo /opt/stacks/ghidra || true)"

while [ $# -gt 0 ]; do
  case "$1" in
    --containers-only) CONTAINERS_ONLY=1; shift ;;
    --host-files-only) HOST_FILES_ONLY=1; shift ;;
    --model) MODEL="${2:?--model needs a value}"; shift 2 ;;
    --no-gpu) USE_GPU=no; shift ;;
    --skip-pull) SKIP_PULL=1; shift ;;
    --stack-dir) STACK_DIR="${2?--stack-dir needs a value}"; shift 2 ;;
    # The header comment is the help text, printed up to the first line that
    # is not one - so editing the header cannot leave --help quoting code.
    -h|--help) awk 'NR>1 && !/^#/{exit} NR>1{sub(/^# ?/,""); print}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n== %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# The model name defaults to whatever the worker is already configured to use.
# A script that pulls qwen3:14b onto a host configured for something else leaves
# several GB on disk and triage still not working.
# Read it only if the file is there: under `set -e` with pipefail, sed's exit 2
# on a missing file kills the script inside the assignment, and 2>/dev/null
# hides even the reason. That is how this script first ran on a fresh host —
# silently, doing nothing, exiting 0 to its caller.
if [ -z "$MODEL" ] && [ -r "$env_file" ]; then
  MODEL="$(sed -n 's/^GHIDRA_TRIAGE_MODEL=//p' "$env_file" | tail -n1)"
  MODEL="${MODEL%\"}"; MODEL="${MODEL#\"}"   # tolerate a quoted value
fi
MODEL="${MODEL:-qwen3:14b}"

if [ "$HOST_FILES_ONLY" != 1 ]; then

# ── Preflight ────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "docker is required"
command -v curl >/dev/null 2>&1 || die "curl is required (the readiness checks use it)"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is required"
docker info >/dev/null 2>&1 ||
  die "cannot talk to the docker daemon (not running, or this user is not in the docker group)"

# Weights, the Ghidra image and a project directory. 20G is the point below
# which the pull will probably fail partway through, which is a worse way to
# find out than this.
avail="$(df -Pk /var/lib/docker 2>/dev/null || df -Pk /)"
avail="$(printf '%s\n' "$avail" | awk 'NR==2 {print int($4/1024/1024)}')"
[ "${avail:-0}" -ge 20 ] ||
  echo "warning: only ${avail}G free where docker stores images; the model pull needs several" >&2

if [ "$USE_GPU" = auto ]; then
  if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"nvidia"'; then
    USE_GPU=yes
  else
    USE_GPU=no
    echo "note: no nvidia container runtime; the model will run on CPU" >&2
  fi
fi

# ── Deploy the compose file ──────────────────────────────────────────────────
# Dockge lists a stack per directory under /opt/stacks and shells out to
# `docker compose` inside it with no -f, so the GPU settings have to reach it
# as compose.override.yml — the one extra file compose loads on its own. A
# stack whose card says "not managed by Dockge" is one whose start, stop and
# logs buttons do nothing, which is worth this copy.
if [ -n "$STACK_DIR" ]; then
  say "deploying the compose file to $STACK_DIR"
  mkdir -p "$STACK_DIR"
  cp "$compose_file" "$STACK_DIR/compose.yml"
  # Every service in this file defined with a build: instead of an image:
  # needs its build context present next to the copied compose file, or the
  # stack copy cannot build ("unable to prepare context: path not found" --
  # first caught deploying statictools, then again for ghidra after #793 gave
  # it a build context too, because this step only ever knew statictools'
  # name; see #2063). Derived, not enumerated, so a future build-context
  # service needs no edit here. `compose config` (no --profile) naturally
  # excludes profile-gated services like revdeck, whose context is a
  # manually-cloned repo (docs/analysis/ghidra/revdeck/README.md) that may
  # not exist on this host at all -- it must stay excluded, not mirrored.
  build_contexts="$(docker compose -f "$compose_file" config --format json 2>/dev/null |
    jq -r '.services[] | select(.build != null) | .build.context' 2>/dev/null || true)"
  if [ -z "$build_contexts" ]; then
    # jq or `compose config --format json` unavailable here -- fall back to
    # grepping the compose file's own build:/context: lines. Cruder: it
    # cannot see profiles, so it may also list revdeck's context, which then
    # gets skipped below the same way any other missing directory does.
    build_contexts="$(grep -E '^\s*(build|context):\s*\./' "$compose_file" |
      sed -E 's/^\s*(build|context):\s*//')"
  fi
  while IFS= read -r ctx; do
    [ -n "$ctx" ] || continue
    ctx_name="$(basename "$ctx")"
    ctx_src="$here/$ctx_name"
    if [ ! -d "$ctx_src" ]; then
      echo "  note: build context '$ctx_name' not present in $here, skipping (profile-gated service?)" >&2
      continue
    fi
    rm -rf "${STACK_DIR:?}/$ctx_name"
    cp -r "$ctx_src" "$STACK_DIR/$ctx_name"
  done <<< "$build_contexts"
  if [ "$USE_GPU" = yes ]; then
    cp "$gpu_file" "$STACK_DIR/compose.override.yml"
  else
    # Leaving a stale override behind would keep asking for a card that is no
    # longer wanted, and compose would load it without being asked.
    rm -f "$STACK_DIR/compose.override.yml"
  fi
  compose_file="$STACK_DIR/compose.yml"
  gpu_file="$STACK_DIR/compose.override.yml"
fi

files=(-f "$compose_file")
# if, not `[ ... ] && ...`: a trailing false test is itself the script's exit
# status under set -e, so the CPU path would quit here.
if [ "$USE_GPU" = yes ]; then
  files+=(-f "$gpu_file")
fi

# On a Dockge host $STACK_DIR (/opt/stacks/ghidra) is itself a symlink into
# /var/dockge/stacks, and buildx's filesystem-entitlements check treats a
# build context reached through one as "possibly insecure," refusing to build
# statictools without this. There is no untrusted party here to entitle
# against — this is the operator's own stack directory — so the check is
# switched off rather than granted piecemeal per invocation.
export BUILDX_BAKE_ENTITLEMENTS_FS=0

dc() { docker compose "${files[@]}" "$@"; }

# ── Containers ───────────────────────────────────────────────────────────────
say "starting ghidra, ollama and statictools (gpu=$USE_GPU)"
dc pull --quiet ghidra ollama
# statictools has no image: entry, only build: — `pull` on it fails rather
# than doing nothing, so it gets its own step.
dc build --quiet statictools
dc up -d ghidra ollama statictools

# `up -d` returns when the containers are started, not when the services inside
# them answer. Ghidra unpacks its own installation on first boot and takes a
# while; polling here means the verification below tests the service rather
# than the race.
say "waiting for the services to answer"
wait_for() {
  local service="$1" url="$2" tries=120
  while [ "$tries" -gt 0 ]; do
    if curl -sf -m 3 "$url" >/dev/null 2>&1; then
      echo "  $service is up"
      return 0
    fi
    tries=$((tries - 1))
    sleep 5
  done
  dc ps --format '{{.Name}}	{{.Status}}' >&2 || true
  die "$service did not answer at $url after 10 minutes"
}
wait_for ghidra http://127.0.0.1:9090/v1/health
wait_for ollama http://127.0.0.1:11434/api/tags
wait_for statictools http://127.0.0.1:9091/v1/health

if [ "$SKIP_PULL" = 0 ]; then
  say "pulling model $MODEL"
  # Pulls are resumable and skip layers already present, so re-running this is
  # cheap; checking first would only save the round trip.
  dc exec -T ollama ollama pull "$MODEL"

  # #1236: the dashboard's own semantic search reads LLM_EMBEDDING_MODEL
  # (default "nomic-embed-text:latest") in
  # arcane/home/honeypot-dashboard/backend-service/src/llm_search.rs and hits
  # this same ollama instance for embeddings -- a different kind of model (embedding,
  # not chat/completion) than $MODEL above, so it's pulled separately here
  # rather than folded into approved-models.json's chat-model qualification
  # manifest. Without this, semantic search 404'd with "model
  # \"nomic-embed-text:latest\" not found, try pulling it first" on any
  # host installed via this script until someone pulled it by hand.
  say "pulling embedding model nomic-embed-text:latest"
  dc exec -T ollama ollama pull nomic-embed-text:latest
fi
dc exec -T ollama ollama list

if [ "$CONTAINERS_ONLY" = 1 ]; then
  say "containers only - stopping here"
  echo "The worker half needs root:"
  echo "  sudo $0"
  exit 0
fi

fi # HOST_FILES_ONLY

# ── Host-side worker ─────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "installing the worker needs root; re-run with sudo, or pass --containers-only"

# #796: the worker's build_call_graph() shells out to `dot` (graphviz) to
# render the call graph SVG the dashboard's Ghidra detail page shows -- this
# step never existed anywhere in this script, so every install silently left
# the dashboard showing "no call graph was rendered" forever, with only the
# raw .dot file ever written. graphviz is a small, common package; installing
# it unconditionally here is cheaper than making it a flag.
say "installing graphviz (call-graph rendering)"
# Distro-aware since the homeserver moved to Rocky (#1609's rebuild): this was
# an unconditional apt-get, which is exit 127 on EL -- and under `set -e` that
# aborted this script *before* it installed the worker at all. The Ghidra
# containers then come up healthy while triage does nothing, which is #636's
# failure mode exactly: nothing errors, no analysis ever completes. Confirmed
# live on 2026-09-05, when install-homeserver.sh's ghidra-worker-install step
# failed with 127 on this line.
#
# Non-fatal: graphviz only affects call-graph SVG rendering (#796), and losing
# the whole worker install over a missing renderer is the trade that caused
# this bug.
if command -v apt-get >/dev/null 2>&1; then
  apt-get install -y graphviz || say "WARNING: graphviz install failed -- call graphs will not render"
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y graphviz || say "WARNING: graphviz install failed -- call graphs will not render"
else
  say "WARNING: no apt-get or dnf -- install graphviz by hand or call graphs will not render"
fi

say "installing the worker into $target"
install -d -m 0755 -o root -g root "$target" "$target/worker" "$target/models" "$target/report"
install -m 0755 -o root -g root "$here/worker/ghidra-worker.py" "$target/worker/ghidra-worker.py"
# gpu_queue.py is vendored (not shared by import across containers/hosts --
# see its own module docstring) into both ghidra-worker.py's deployment
# target here and llm-worker's container image separately.
install -m 0755 -o root -g root "$here/worker/gpu_queue.py" "$target/worker/gpu_queue.py"
install -m 0755 -o root -g root "$here/worker/gpu-queue-drain.py" "$target/worker/gpu-queue-drain.py"
# ghidra-worker.py's generate_report() imports this as a local sibling
# (report_dir = .../worker/../report), never a pip dependency -- found
# missing entirely on a live host (#498): every analysis completed with
# report_pdf: null and "ModuleNotFoundError: No module named
# 'generate_report'" in the worker log, because this install step never
# copied the report/ directory at all.
install -m 0755 -o root -g root "$here/report/generate_report.py" "$target/report/generate_report.py"
install -m 0755 -o root -g root "$here/models/model-governance.py" "$target/models/model-governance.py"
install -m 0755 -o root -g root "$here/models/model-status-adapter.py" "$target/models/model-status-adapter.py"
# #3334: the host-side runner for the llm-worker prompt-injection corpus. It
# lives next to the governance tools because that is where the approved pin it
# checks against already lives.
install -m 0755 -o root -g root "$here/models/run-llm-injection-suite.sh" "$target/models/run-llm-injection-suite.sh"
install -m 0644 -o root -g root \
  "$here/models/approved-models.json" "$target/models/approved-models.json"
# honeypot-llm-injection-suite.path watches this copy next to the manifest, so
# the pin-change leg fires whichever of the two moved. The runner still refuses
# a digest that disagrees with the manifest; installing it here is what makes
# that disagreement visible without a manual poll.
install -m 0644 -o root -g root \
  "$here/../../llm-worker/docker-compose.synthetic-canary.yml" \
  "$target/models/llm-worker-synthetic-canary.yml"
install -m 0644 -o root -g root \
  "$here/models/session-schema.json" "$target/models/session-schema.json"
install -m 0644 -o root -g root \
  "$here/../../docs/analysis/ghidra/models/approval-record.md" "$target/models/approval-record.md"
install -m 0644 -o root -g root "$here/../../docs/analysis/ghidra/models/README.md" "$target/models/README.md"
# The unit files point Documentation= at this, and it is the only description
# of the result format an operator on the host can read.
install -m 0644 -o root -g root "$here/../../docs/analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md" "$target/DASHBOARD_INTEGRATION_PLAN.md"

if [ ! -e "$env_file" ]; then
  install -m 0644 -o root -g root "$here/worker/honeypot-ghidra.default.example" "$env_file"
  echo "  wrote $env_file from the example"
else
  echo "  kept the existing $env_file (compare against worker/honeypot-ghidra.default.example)"
fi

# 0700: the request spool is a list of hashes the dashboard wants analysed and
# the results are full string dumps of live malware. Same posture as the
# sandbox spools.
install -d -m 0700 -o root -g root \
  /var/lib/honeypot-ghidra/requests/pending /var/lib/honeypot-ghidra/results

# Standalone Rev·Deck spool (#78), same posture as above. Created
# unconditionally, same as the Ghidra one -- REVDECK_API_BASE (empty by
# default) is what actually gates whether a request submitted here can
# succeed, not whether this directory exists.
install -d -m 0700 -o root -g root \
  /var/lib/honeypot-revdeck/requests/pending /var/lib/honeypot-revdeck/results

# #3334: injection-suite reports. Owner-only directory with owner-only files
# inside, same posture as the qualification reports the governance README asks
# operators to keep outside the repository. A report holds model verdicts and
# digests rather than captured data, but it is written by a unit that can reach
# the model, so it does not get looser than the spools beside it.
install -d -m 0700 -o root -g root /var/lib/honeypot-ghidra/injection-suite

for unit in honeypot-ghidra-worker.service honeypot-ghidra-worker.path \
            honeypot-gpu-queue-drain.service honeypot-gpu-queue-drain.timer; do
  install -m 0644 -o root -g root "$here/worker/$unit" "/etc/systemd/system/$unit"
done
for unit in honeypot-model-drift.service honeypot-model-drift.timer honeypot-model-status-adapter.service; do
  install -m 0644 -o root -g root "$here/models/$unit" "/etc/systemd/system/$unit"
done
# #3334: the template unit plus its two triggers. Installed unconditionally,
# like the units above -- the runner fails on a missing APIARY_REPO_DIR rather
# than reporting a pass it never measured, so an operator who has not pointed
# it at a checkout finds out from the journal instead of a silent no-op.
install -m 0644 -o root -g root \
  "$here/models/honeypot-llm-injection-suite.service" \
  "/etc/systemd/system/honeypot-llm-injection-suite@.service"
for unit in honeypot-llm-injection-suite.timer honeypot-llm-injection-suite.path; do
  install -m 0644 -o root -g root "$here/models/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl reset-failed honeypot-ghidra-worker.service honeypot-gpu-queue-drain.service 2>/dev/null || true
systemctl enable --now honeypot-ghidra-worker.path
systemctl enable --now honeypot-gpu-queue-drain.timer
systemctl enable --now honeypot-model-drift.timer
systemctl enable --now honeypot-llm-injection-suite.timer
systemctl enable --now honeypot-llm-injection-suite.path
systemctl enable --now honeypot-model-status-adapter.service
# The only long-running (Type=simple) unit installed here -- every other is a
# path/timer-triggered oneshot that naturally picks up a re-installed .py or
# .sh on its next invocation, with no running process to go stale.
# enable --now is a no-op on a re-run against an already-active unit, so a
# re-sync (#1406) that only overwrote the .py file would otherwise leave
# this one serving the old code from memory indefinitely.
systemctl restart honeypot-model-status-adapter.service

# ── Verify ───────────────────────────────────────────────────────────────────
# Against the running services, with the worker's own environment file, rather
# than trusting that the steps above added up. --selftest runs a real binary
# through /analyze and reports whether the model endpoint is reachable, local,
# and serving the configured model.
say "verifying"
set -a
# A host file, written above if it was absent, so there is nothing to follow.
# shellcheck source=/dev/null
. "$env_file"
set +a
python3 "$target/worker/ghidra-worker.py" --selftest || die "selftest failed - see above"
# Advisory by design: model unavailability or drift warns but must not stop
# deterministic Ghidra output, the session worker, or event ingestion.
python3 "$target/models/model-governance.py" check-runtime \
  --manifest "$target/models/approved-models.json" \
  --status-file /var/lib/honeypot-ghidra/model-status.json \
  --warn-only || true

say "done"
echo "The dashboard needs these in its .env to show the queue:"
echo "  GHIDRA_REQUEST_DIR=/ghidra-requests"
echo "  GHIDRA_RESULTS_DIR=/ghidra-results"
echo "Then bring up the mounted API in arcane/home/honeypot-dashboard/compose.yml,"
echo "which serves the queue to the dashboard (apiary-dashboard):"
echo "  docker compose up -d backend-service-mounted"
echo "(backend-service-mounted reuses apiary-backend:latest, which is built by"
echo "the sibling honeypot-dashboard-backend stack and never pushed to any registry.)"
systemctl --no-pager --plain is-active honeypot-ghidra-worker.path
