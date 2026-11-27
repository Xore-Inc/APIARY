#!/usr/bin/env bash
# Tests for the honeypot-30d ILM policy analysis/elasticsearch-setup.sh
# installs (#585: without an explicit rollover action, ILM cannot delete a
# data stream's write index -- the delete phase gets permanently stuck at
# "wait-for-shard-history-leases" and the single backing index grows
# unbounded forever, so the stated 30-day retention did nothing at all).
#
# Runs a real Elasticsearch container and forces ILM's own periodic poll
# down to a few seconds so the full rollover-then-delete lifecycle can be
# observed end to end in well under a minute, with no manual _rollover call
# standing in for what ILM does automatically in production. Needs Docker
# and the ability to pull docker.elastic.co/elasticsearch; skips cleanly if
# either is unavailable, same convention as
# analysis/yara/tests/test_sync_yara.sh.
#
# Usage: analysis/tests/test_honeypot_ilm_rollover.sh
set -euo pipefail

ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:9.5.7@sha256:8aa3b18f6a26880f4c2fa1ffb37a48213e201b0b6a1a47412c66b1f5d533de91"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker is not installed"
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon is not reachable"
  exit 0
fi
if ! docker pull -q "$ES_IMAGE" >/dev/null 2>&1; then
  echo "SKIP: could not pull $ES_IMAGE (no network egress?)"
  exit 0
fi

src_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
container="es-ilm-rollover-test-$$"
port=$((19000 + (RANDOM % 900)))

cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# #2915: the `trap cleanup EXIT` above does not fire on SIGKILL (a runner
# OOM-kill -- and this container is Elasticsearch, so the runner is under
# memory pressure exactly when this leg runs -- a cancelled CI job escalating
# past SIGTERM, or a hard timeout). The container then survives, *running*,
# for the life of the runner. Unlike the Keycloak fixtures in scripts/, the
# port above is a fixed random draw rather than an ephemeral bind, so a
# survivor can also collide with a later run outright. Verified live on the
# homeserver 2026-09-04: one `es-ilm-rollover-test-<pid>` container had been up
# 13 hours with no owning run.
#
# Reap survivors of an earlier killed run, skipping anything younger than
# ${reap_min_age_s} so a *concurrent* run is never destroyed mid-flight --
# the fleet runs several self-hosted runners against one Docker daemon, which
# is what the `$$` in the name above is for.
reap_min_age_s="${APIARY_TEST_REAP_MIN_AGE_S:-3600}"
for stale_id in $(docker ps -aq --filter "name=^/es-ilm-rollover-test-" 2>/dev/null); do
  stale_created="$(docker inspect -f '{{.Created}}' "$stale_id" 2>/dev/null)" || continue
  stale_epoch="$(date -u -d "$stale_created" +%s 2>/dev/null)" || continue
  [ "$(( $(date -u +%s) - stale_epoch ))" -ge "$reap_min_age_s" ] || continue
  docker rm -fv "$stale_id" >/dev/null 2>&1 || true
done

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# Auto-creating an index (or a data stream's first backing index) makes the
# write block until that primary is active, and Elasticsearch gives up with
# a 503 unavailable_shards_exception after its own one-minute default. On
# the self-hosted runner several ES-backed legs of this matrix share a box,
# so allocation can genuinely take longer than that and the leg dies on a
# bare "curl: (22) ... error: 503" with the reason thrown away by -f.
#
# es_index widens the server-side wait and retries the whole request a few
# times, then prints the body it actually got so a real rejection (a
# mapping conflict, say) still reads as one instead of as a timeout.
es_index() {
  local path="$1" body="$2" attempt out code
  for attempt in 1 2 3; do
    out="$(curl -sS -w '\n%{http_code}' -X POST "$es_url/$path?timeout=120s" \
      -H 'Content-Type: application/json' -d "$body" 2>&1)"
    code="${out##*$'\n'}"
    case "$code" in
      2*) printf '%s' "${out%$'\n'*}"; return 0 ;;
      503) sleep $((attempt * 5)) ;;
      *) break ;;
    esac
  done
  echo "  last response (HTTP $code): ${out%$'\n'*}" >&2
  # A 503 here means the primary never became active. Which of the many
  # reasons that can happen is not guessable from the write's own error, so
  # ask the cluster directly rather than leaving the next reader to
  # hypothesise (2026-08-31: a 96%-full /var on the CI box was the trigger,
  # and it cost a morning to establish that from the bare curl exit alone).
  if [ "$code" = "503" ]; then
    echo "  --- cluster health ---" >&2
    curl -sS "$es_url/_cluster/health" >&2 || true
    echo >&2
    echo "  --- unassigned shards ---" >&2
    curl -sS "$es_url/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason" >&2 || true
    echo "  --- allocation explain ---" >&2
    curl -sS "$es_url/_cluster/allocation/explain?pretty" \
      -H 'Content-Type: application/json' \
      -d "{\"index\":\"${path%%/*}\",\"shard\":0,\"primary\":true}" >&2 || true
    echo >&2
    echo "  --- node disk as Elasticsearch sees it ---" >&2
    curl -sS "$es_url/_cat/allocation?v" >&2 || true
  fi
  return 1
}

# Disk-based allocation is off deliberately. This is a throwaway
# single-node cluster that indexes a handful of documents and is deleted
# on exit, but Elasticsearch still applies its watermarks against whatever
# filesystem backs /var/lib/docker on the host. When the CI box crossed
# the 95% flood stage the primary of every newly created index simply
# never became active, and the write died after its own two-minute wait:
#
#   unavailable_shards_exception: [.ds-honeypot-v2-test-...][0]
#   primary shard is not active Timeout: [2m]
#
# The host's free space is a real thing to watch, but it is not this
# test's subject and must not decide whether it passes.
docker run -d --name "$container" -p "127.0.0.1:${port}:9200" \
  -e discovery.type=single-node -e xpack.security.enabled=false \
  -e cluster.routing.allocation.disk.threshold_enabled=false \
  -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
  "$ES_IMAGE" >/dev/null

es_url="http://127.0.0.1:${port}"
# /_cluster/health answers 200 as soon as the HTTP layer is up, even while
# the cluster is still red and no shard can be allocated yet. Waiting on
# that alone let the first write race the recovery and come back 503
# (unavailable_shards_exception), which is how #585's and #565's legs
# turned flaky. wait_for_status=yellow makes the endpoint block until at
# least the primaries are assigned, so the first indexing request has
# somewhere to land.
ready=0
for _ in $(seq 1 40); do
  if curl -fsS "$es_url/_cluster/health?wait_for_status=yellow&timeout=3s" \
    >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 3
done
[ "$ready" -eq 1 ] || fail "Elasticsearch did not reach at least yellow at $es_url"

# ILM's default poll interval is 10 minutes -- far too slow for a test.
# Shortening it is the only way to observe a real, automatic (not manually
# forced) rollover-then-delete cycle in a reasonable test runtime.
curl -fsS -X PUT "$es_url/_cluster/settings" -H 'Content-Type: application/json' \
  --data-binary '{"transient":{"indices.lifecycle.poll_interval":"3s"}}' >/dev/null

# Extract the exact honeypot-30d policy body from elasticsearch-setup.sh,
# then substitute in fast rollover/delete ages for this test only -- stays
# in sync with the real policy's *shape* (still has a rollover action in
# the hot phase) automatically, without waiting real days for it to fire.
# Quote-style agnostic since #2193 moved the body to the loop's
# escaped-double-quote idiom (the single-quoted literal was itself the
# bug: it silently blocked ${retention_days} expansion).
setup="$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh"
policy_line=$(grep -n '_ilm/policy/honeypot-30d"' "$setup" | head -1 | cut -d: -f1)
[ -n "$policy_line" ] || fail "cannot locate the honeypot-30d PUT in elasticsearch-setup.sh"
policy_body=$(sed -n "$((policy_line + 2))p" "$setup" |
  sed -e 's/^ *--data-binary //' -e 's/ *>\/dev\/null$//' \
      -e 's/^"\(.*\)"$/\1/' -e 's/\\"/"/g')

case "$(printf '%s' "$policy_body" | grep -cF '${retention_days}')" in
  1)
    pass "honeypot-30d delete.min_age is wired to \${retention_days}, not hardcoded (#2193)"
    ;;
  *)
    fail "honeypot-30d min_age no longer derives from retention_days -- the #2193 hardcode crept back"
    ;;
esac

# Exercise the derivation without booting a second Elasticsearch: expand
# the knob textually through the REAL source line and check the resulting
# JSON deletes at the expected age both ways (unset default stays 30d --
# byte-equivalent to the pre-#2193 literal -- and a lowered knob shrinks
# the dominant stream along with everything else).
age_for() {
  printf '%s' "$policy_body" |
    awk -v repl="$1" '{ gsub(/\$\{retention_days\}/, repl); printf "%s", $0 }' |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["policy"]["phases"]["delete"]["min_age"])'
}
[ "$(age_for 30)" = "30d" ] || fail "default run must keep deleting at 30d (got $(age_for 30))"
pass "unset HONEYPOT_RETENTION_DAYS preserves today's exact 30d behavior"
[ "$(age_for 7)" = "7d" ] || fail "HONEYPOT_RETENTION_DAYS=7 must yield delete.min_age 7d (got $(age_for 7))"
pass "HONEYPOT_RETENTION_DAYS=7 propagates to honeypot-30d delete.min_age"

echo "$policy_body" | grep -q '"rollover"' ||
  fail "honeypot-30d policy has no rollover action -- this is exactly the #585 bug, still present"
pass "honeypot-30d policy's hot phase has a rollover action"

fast_body=$(echo "$policy_body" | python3 -c "
import json, sys
p = json.load(sys.stdin)
p['policy']['phases']['hot']['actions']['rollover'] = {'max_age': '5s'}
p['policy']['phases']['delete']['min_age'] = '5s'
print(json.dumps(p))
")
curl -fsS -X PUT "$es_url/_ilm/policy/honeypot-30d" -H 'Content-Type: application/json' \
  --data-binary "$fast_body" >/dev/null ||
  fail "Elasticsearch rejected the (fast-tuned) honeypot-30d policy"
pass "policy installs cleanly"

curl -fsS -X PUT "$es_url/_index_template/honeypot-events-v2" -H 'Content-Type: application/json' \
  --data-binary '{"index_patterns":["honeypot-v2-*"],"priority":500,"data_stream":{},"template":{"settings":{"index.lifecycle.name":"honeypot-30d","index.number_of_replicas":0}}}' >/dev/null ||
  fail "Elasticsearch rejected the honeypot-events-v2 data stream template"

resp="$(es_index honeypot-v2-test/_doc \
  '{"@timestamp":"2026-08-05T00:00:00Z","msg":"doc1"}')" ||
  fail "the data stream's first write never landed -- its backing index primary stayed unassigned"
first_index="$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['_index'])")"
pass "data stream created, first write landed in $first_index"

# Let ILM's own automatic poll do everything from here -- no manual
# _rollover call. This is the actual thing #585 found broken: without a
# rollover action, this loop would run forever with the index stuck at
# wait-for-shard-history-leases and never disappearing.
deleted=0
for _ in $(seq 1 20); do
  sleep 3
  if ! curl -fsS -o /dev/null "$es_url/$first_index" 2>/dev/null; then
    deleted=1
    break
  fi
done
[ "$deleted" -eq 1 ] ||
  fail "the original backing index ($first_index) was never deleted -- ILM's delete phase is still stuck, the #585 bug is not fixed"
pass "the original backing index was automatically rolled over and then deleted by ILM's own poll cycle -- no manual intervention"

status="$(curl -fsS "$es_url/_data_stream/honeypot-v2-test" | python3 -c "import json,sys; print(json.load(sys.stdin)['data_streams'][0]['status'])")"
[ "$status" = "GREEN" ] || fail "data stream status is $status after the delete, expected GREEN"
pass "data stream remains healthy (GREEN) after its original backing index was deleted"

es_index honeypot-v2-test/_doc \
  '{"@timestamp":"2026-08-05T00:10:00Z","msg":"still writable"}' >/dev/null ||
  fail "data stream stopped accepting writes after the delete"
pass "data stream still accepts writes after the delete"

echo
echo "all honeypot-30d ILM rollover tests passed"
