#!/usr/bin/env bash
# Tests for the dionaea-incidents-v1-* index template analysis/elasticsearch-setup.sh
# installs (#565: dionaea's log_incident records were reaching Elasticsearch
# only as an opaque `message` string).
#
# Runs a real Elasticsearch container -- the point of this test is proving
# heterogeneous data across incident origins does NOT cause a mapping
# rejection, which only a real mapping enforcement pass can confirm. Needs
# Docker and the ability to pull docker.elastic.co/elasticsearch; skips
# cleanly if either is unavailable, same convention as
# analysis/yara/tests/test_sync_yara.sh and
# analysis/tests/test_geoip_pipeline.sh.
#
# Usage: analysis/tests/test_dionaea_incidents_index.sh
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
container="es-dionaea-incidents-test-$$"
port=$((19000 + (RANDOM % 900)))
index="dionaea-incidents-v1-test-$$"

cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# #2915: the `trap cleanup EXIT` above does not fire on SIGKILL (a runner
# OOM-kill -- and this container is Elasticsearch, so the runner is under
# memory pressure exactly when this leg runs -- a cancelled CI job escalating
# past SIGTERM, or a hard timeout). The container then survives, *running*,
# for the life of the runner. Unlike the Keycloak fixtures in scripts/, the
# port above is a fixed random draw rather than an ephemeral bind, so a
# survivor can also collide with a later run outright. Verified live on the
# homeserver 2026-09-04: one `es-dionaea-incidents-test-<pid>` container had been up
# 13 hours with no owning run.
#
# Reap survivors of an earlier killed run, skipping anything younger than
# ${reap_min_age_s} so a *concurrent* run is never destroyed mid-flight --
# the fleet runs several self-hosted runners against one Docker daemon, which
# is what the `$$` in the name above is for.
reap_min_age_s="${APIARY_TEST_REAP_MIN_AGE_S:-3600}"
for stale_id in $(docker ps -aq --filter "name=^/es-dionaea-incidents-test-" 2>/dev/null); do
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

# The template references the delete-only daily-index policy -- register it
# so index creation doesn't warn/fail on a missing policy reference.
curl -fsS -X PUT "$es_url/_ilm/policy/dionaea-incidents-30d" \
  -H 'Content-Type: application/json' \
  --data-binary '{"policy":{"phases":{"hot":{"actions":{}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}' >/dev/null

# Extract exactly the dionaea-incidents template's JSON body between its PUT
# command's heredoc markers, same technique test_geoip_pipeline.sh uses --
# stays in sync with elasticsearch-setup.sh automatically.
start_line=$(grep -n '_index_template/dionaea-incidents"' "$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh" | head -1 | cut -d: -f1)
body_start=$((start_line + 3))
end_line=$(tail -n "+$body_start" "$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh" | grep -n '^JSON$' | head -1 | cut -d: -f1)
body_end=$((body_start + end_line - 2))
tmp="$(mktemp -d)"
sed -n "${body_start},${body_end}p" "$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh" > "$tmp/template.json"

python3 -c "import json; json.load(open('$tmp/template.json'))" ||
  fail "extracted template body is not valid JSON -- extraction line range needs updating"

curl -fsS -X PUT "$es_url/_index_template/dionaea-incidents" \
  -H 'Content-Type: application/json' \
  --data-binary "@$tmp/template.json" >/dev/null ||
  fail "Elasticsearch rejected the index template"
pass "index template installs cleanly"

policy_name=$(python3 -c "import json; print(json.load(open('$tmp/template.json'))['template']['settings']['index.lifecycle.name'])")
[ "$policy_name" = "dionaea-incidents-30d" ] ||
  fail "dionaea template uses $policy_name, want the non-rollover dionaea-incidents-30d policy"
pass "daily Dionaea indices use their dedicated non-rollover retention policy"

# #1375 migration regression: reproduce an already-existing daily index in
# the exact ERROR state from production, then exercise setup.sh's supported
# remove-then-apply policy switch. Directly overwriting index.lifecycle.name
# is deliberately not tested because Elasticsearch can retain the cached hot
# phase from the old policy in that unsupported sequence.
legacy_index="dionaea-incidents-v1-legacy-$$"
curl -fsS -X PUT "$es_url/_ilm/policy/honeypot-30d" \
  -H 'Content-Type: application/json' \
  --data-binary '{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"1d"}}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}' >/dev/null
curl -fsS -X PUT "$es_url/_cluster/settings" -H 'Content-Type: application/json' \
  --data-binary '{"transient":{"indices.lifecycle.poll_interval":"1s"}}' >/dev/null
curl -fsS -X PUT "$es_url/$legacy_index" -H 'Content-Type: application/json' \
  --data-binary '{"settings":{"index.lifecycle.name":"honeypot-30d"}}' >/dev/null

errored=0
for _ in $(seq 1 20); do
  step=$(curl -fsS "$es_url/$legacy_index/_ilm/explain" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['indices']['$legacy_index'].get('step', ''))")
  if [ "$step" = "ERROR" ]; then
    errored=1
    break
  fi
  sleep 1
done
[ "$errored" -eq 1 ] || fail "legacy rollover-managed Dionaea index did not reproduce the ERROR step"
pass "legacy daily index reproduces the missing-rollover-alias ERROR"

curl -fsS -X POST "$es_url/$legacy_index/_ilm/remove" >/dev/null
curl -fsS -X PUT "$es_url/$legacy_index/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.lifecycle.name":"dionaea-incidents-30d"}' >/dev/null

migrated=0
for _ in $(seq 1 20); do
  read -r policy step <<EOF
$(curl -fsS "$es_url/$legacy_index/_ilm/explain" | python3 -c "import json,sys; i=json.load(sys.stdin)['indices']['$legacy_index']; print(i.get('policy', ''), i.get('step', ''))")
EOF
  if [ "$policy" = "dionaea-incidents-30d" ] && [ "$step" != "ERROR" ]; then
    migrated=1
    break
  fi
  sleep 1
done
[ "$migrated" -eq 1 ] || fail "legacy Dionaea index did not leave ERROR under the delete-only policy"
pass "remove-then-apply migration clears the old ERROR and starts the delete-only policy"

# Two incidents from different origins reusing the same "port" key with
# incompatible value types (int vs string) -- exactly the scenario the
# previous raw-message design existed to avoid. Field/value shapes match
# real dionaea log_incident.py output: {timestamp, name, origin, data}.
es_index "$index/_doc" '{
  "timestamp":"2026-08-05T00:00:00","name":"dionaea","origin":"dionaea.download.complete",
  "data":{"url":"http://198.51.100.5/x.exe","shasum":"deadbeef","port":445}
}' >/dev/null || fail "indexing the first (int port) incident was rejected"

es_index "$index/_doc" '{
  "timestamp":"2026-08-05T00:01:00","name":"dionaea","origin":"dionaea.connection.link",
  "data":{"port":"not-a-number","connection":{"protocol":"smbd","remote_ip":"198.51.100.5"}}
}' >/dev/null || fail "indexing the second (string port) incident was rejected -- mapping conflict"
pass "two incidents with an incompatible-typed shared key (data.port: int vs string) both index without a mapping rejection"

curl -fsS -X POST "$es_url/$index/_refresh" >/dev/null

search() {
  curl -fsS -X GET "$es_url/$index/_search" -H 'Content-Type: application/json' --data-binary "$1" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['hits']['total']['value'])"
}

[ "$(search '{"query":{"exists":{"field":"data.url"}}}')" = "1" ] ||
  fail "data.url is not queryable through the flattened field"
pass "data.url is queryable"

[ "$(search '{"query":{"term":{"data.shasum":"deadbeef"}}}')" = "1" ] ||
  fail "data.shasum term query did not match"
pass "data.shasum is queryable"

[ "$(search '{"query":{"term":{"origin":"dionaea.connection.link"}}}')" = "1" ] ||
  fail "origin keyword filter did not match"
pass "origin is a filterable typed field"

echo
echo "all dionaea-incidents index tests passed"
