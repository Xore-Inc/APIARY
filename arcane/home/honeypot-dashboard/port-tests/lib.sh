#!/bin/bash
# Shared harness for the modernization-port smoke suite (#1608/#1610).
# Every script sources this. Requirements:
#   - an Elasticsearch tunnel or endpoint (default http://127.0.0.1:19200;
#     on the devbox: ssh -N -L 19200:172.16.1.16:9200 xore@$HOMESERVER_HOST)
#   - rust toolchain (cargo) and node 22+ / npm
# Overridables: ES_URL, BE_PORT.
set -u

PORT_TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="$(dirname "$PORT_TESTS_DIR")"
BACKEND_DIR="$DASHBOARD_DIR/backend-service"

ES_URL="${ES_URL:-http://127.0.0.1:19200}"
BE_PORT="${BE_PORT:-18081}"
BE_URL="http://127.0.0.1:$BE_PORT"

export PATH="$HOME/.cargo/bin:$PATH"

_BE_PID=""

require_es() {
  curl -sf --max-time 5 "$ES_URL" >/dev/null || {
    echo "FATAL: Elasticsearch not reachable at $ES_URL (start the tunnel?)" >&2
    exit 1
  }
}

start_backend() {
  ensure_ports_free
  # Extra env for worker-loop tests can be passed as arguments (VAR=val).
  # Defaults first, caller args last so they can override.
  # APIARY_ALLOW_UNAUTH_DEV=1 (#2183): this harness is exactly the sanctioned
  # dev case — a tokenless local boot that is meant to serve anything on
  # loopback. Without it the tier refuses to start with [E-SERVICE-TOKEN].
  (cd "$BACKEND_DIR" && env \
    ELASTICSEARCH_URL="$ES_URL" LISTEN_ADDR="127.0.0.1:$BE_PORT" \
    APIARY_ALLOW_UNAUTH_DEV=1 "$@" \
    cargo run -q >"${TMPDIR:-/tmp}/port-tests-backend.log" 2>&1) &
  _BE_PID=$!
  for _ in $(seq 1 60); do
    curl -sf "$BE_URL/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "FATAL: backend did not become healthy; log tail:" >&2
  tail -5 "${TMPDIR:-/tmp}/port-tests-backend.log" >&2
  exit 1
}

stop_all() {
  # The subshell PID isn't enough — cargo spawns children of its
  # own, and a survivor on the port makes the NEXT script silently test
  # a stale server. Kill by listening port, which is unambiguous.
  [ -n "$_BE_PID" ] && kill "$_BE_PID" 2>/dev/null
  fuser -k -TERM "$BE_PORT/tcp" 2>/dev/null
  wait 2>/dev/null
  sleep 1
}
trap stop_all EXIT

# Refuse to start over a survivor from a previous run.
ensure_ports_free() {
  if curl -sf --max-time 2 "$BE_URL/healthz" >/dev/null 2>&1; then
    echo "stale test server found on $BE_PORT — killing it" >&2
    fuser -k -TERM "$BE_PORT/tcp" 2>/dev/null
    sleep 2
  fi
}

PASS=0
FAIL=0
SKIPPED=0
_SKIP_LINES=""

# #2184: a conditionally-discovered key that comes up empty must not
# silently elide its detail checks — a fresh/partially-indexed ES would
# shrink coverage to zero while the summary stays green. announce + count
# every skipped family instead.
skip() { # skip <label> <kind>
  local label="$1" kind="$2"
  local line
  line="SKIP  $label (no $kind found)"
  echo "$line"
  _SKIP_LINES="${_SKIP_LINES:+${_SKIP_LINES}
}${line}"
  SKIPPED=$((SKIPPED + 1))
}

# Live-key discovery, tolerant to an empty or broken ES response (#2184):
# prints the first matching value, or '' when the index is empty, partially
# indexed, or returns unparseable JSON. '' then either substitutes into a URL
# whose own check fails loudly (unconditional sites) or trips an explicit
# `skip` (conditional sites) — it never surfaces as a python stack trace
# between PASS lines, and never as a silent coverage drop.
discover_key() { # discover_key <url> <python-expr over parsed d>
  curl -s --max-time 30 "$1" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
try:
    v = eval(sys.argv[1])
except Exception:
    v = ""
print(v if isinstance(v, str) else "")' "$2"
}

check() { # check <label> <command...>
  local label="$1"
  shift
  # #2214: a missing/empty command used to pass vacuously ("$@" with no
  # fields is a zero-exit no-op, so `check <label>` printed PASS for work
  # that never ran). A future edit that produces an empty command string
  # must name itself loudly here instead of silently converting real checks
  # into green ones — the counted FAIL keeps summary() red.
  if [ $# -eq 0 ] || [ -z "$1" ]; then
    echo "FAIL  $label (harness bug: check() invoked with an empty command — fix the caller)" >&2
    FAIL=$((FAIL + 1))
    return 1
  fi
  if "$@" >/dev/null 2>&1; then
    echo "PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $label" >&2
    FAIL=$((FAIL + 1))
  fi
}

check_http() { # check_http <label> <expected-code> <url>
  local label="$1" expected="$2" url="$3"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 90 "$url")
  if [ "$code" = "$expected" ]; then
    echo "PASS  $label ($code)"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $label (got $code, want $expected)" >&2
    FAIL=$((FAIL + 1))
  fi
}

check_json() { # check_json <label> <url> <python-expr over parsed d>
  local label="$1" url="$2" expr="$3"
  if curl -s --max-time 90 "$url" | python3 -c "import sys,json; d=json.load(sys.stdin); assert ($expr), 'assertion failed'" 2>/dev/null; then
    echo "PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $label ($expr)" >&2
    FAIL=$((FAIL + 1))
  fi
}

summary() {
  echo "----"
  echo "passed=$PASS failed=$FAIL skipped=$SKIPPED"
  if [ "$SKIPPED" -gt 0 ]; then
    # #2184: a green run over a sparse ES may have exercised only a fraction
    # of the detail surface. name every skipped family so nobody can read
    # "failed=0" as full parity. skips stay exit-zero by design; set
    # PORT_TESTS_MAX_SKIPS=N to turn an over-large skip count into a failure.
    echo "route families NOT exercised this run:"
    printf '%s\n' "$_SKIP_LINES" | sed 's/^/  /'
    if [ -n "${PORT_TESTS_MAX_SKIPS:-}" ] && [ "$SKIPPED" -gt "$PORT_TESTS_MAX_SKIPS" ]; then
      echo "FAIL  $SKIPPED skipped check(s) exceed PORT_TESTS_MAX_SKIPS=$PORT_TESTS_MAX_SKIPS (ES too empty to smoke?)" >&2
      return 1
    fi
  fi
  [ "$FAIL" -eq 0 ]
}
