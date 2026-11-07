#!/usr/bin/env bash
# backfill-source-ip.sh -- operator script for #3560.
#
# Re-runs the geoip-honeypot ingest pipeline over the honeypot-v2 documents
# whose source.ip can now be promoted, so documents written before the
# promotion rules landed get the same source.ip / honeypot.fleet_peer /
# `source_ip_promoted` tag / source.geo / source.as that new documents get.
#
# Read docs/GEOIP-THREAT-INTEL.md ("source.ip promotion (#3560)") first.
# The new pipeline version must already be installed (re-run
# arcane/home/honeypot-init/analysis/elasticsearch-setup.sh) -- this script
# refuses to run if the live pipeline lacks the promotion marker.
#
# What it selects (same candidate order and fleet rules as
# backend-service/src/events.rs::attacker_ip / is_fleet_address):
#   A. source.ip is absent AND at least one of honeypot.src_ip,
#      honeypot.data.{connection,parent,child}.remote_ip holds a
#      non-fleet address.
#   B. source.ip is present but is a fleet address (the pipeline drops it).
# Documents whose only addresses are fleet ones are NOT selected: there is
# nothing to promote, and re-running them would only add honeypot.fleet_peer.
#
# Why `pipeline=geoip-honeypot` is passed explicitly: _update_by_query runs
# the index's default_pipeline anyway (also geoip-honeypot), and naming it
# makes that dependency visible and survives a template change. The pipeline
# is idempotent (a document that already has a public source.ip is left
# alone), so a re-run or an interrupted run is safe.
#
# Usage:
#   scripts/backfill-source-ip.sh --dry-run            # counts only (default)
#   scripts/backfill-source-ip.sh --run                # start, throttled, with progress
#
# Environment:
#   ES_URL               default http://localhost:9200
#   ES_EXEC              optional command prefix that runs curl somewhere with
#                        access to Elasticsearch, e.g.
#                        ES_EXEC="docker exec -i hp-elasticsearch"
#   HONEYPOT_SELF_IPS    comma-separated addresses of this deployment (same
#                        variable the backend uses); counted as fleet. Use the
#                        same value as the pipeline's ES_HOME_NET.
#   INDEX_PATTERN        default .ds-honeypot-v2-* (the backing indices)
#   REQUESTS_PER_SECOND  throttle for the update, default 500
#   SCROLL_SIZE          batch size, default 1000
#   SLICES               default 1 (raise only if the cluster is idle)
#   POLL_SECONDS         progress interval, default 15
set -euo pipefail

mode="dry-run"
case "${1:---dry-run}" in
  --dry-run) mode="dry-run" ;;
  --run) mode="run" ;;
  -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
  *) echo "usage: $0 [--dry-run|--run]" >&2; exit 2 ;;
esac

es_url="${ES_URL:-http://localhost:9200}"
index_pattern="${INDEX_PATTERN:-.ds-honeypot-v2-*}"
rps="${REQUESTS_PER_SECOND:-500}"
scroll_size="${SCROLL_SIZE:-1000}"
slices="${SLICES:-1}"
poll="${POLL_SECONDS:-15}"
self_ips="${HONEYPOT_SELF_IPS:-}"
# shellcheck disable=SC2206
es_exec=(${ES_EXEC:-})

if [ -z "$self_ips" ]; then
  echo "WARN: HONEYPOT_SELF_IPS is empty; this deployment's own public addresses" >&2
  echo "      will not be treated as fleet addresses (private ranges still are)." >&2
fi

es() {
  # es <METHOD> <PATH>   (JSON body on stdin)
  local method="$1" path="$2"
  "${es_exec[@]}" curl -fsS -X "$method" "$es_url$path" \
    -H Content-Type:application/json --data-binary @-
}

# Refuse to update with a pipeline that does not have the promotion yet.
require_new_pipeline() {
  if ! "${es_exec[@]}" curl -fsS "$es_url/_ingest/pipeline/geoip-honeypot" | grep -q 'source_ip_promoted'; then
    echo "ERROR: the live geoip-honeypot pipeline does not contain the #3560 promotion." >&2
    echo "       Re-run arcane/home/honeypot-init/analysis/elasticsearch-setup.sh first." >&2
    exit 1
  fi
}

# Build the selection queries with python3 so the fleet rules live in one place.
queries="$(SELF_IPS="$self_ips" python3 -I - <<'PY'
import json, os

self_ips = [x.strip() for x in os.environ.get("SELF_IPS", "").split(",") if x.strip()]

fleet_not = [  # must_not clauses on a keyword (flattened) candidate field
    {"prefix": {"F": "10."}}, {"prefix": {"F": "192.168."}},
    {"prefix": {"F": "169.254."}}, {"prefix": {"F": "127."}},
    # prefix only: regexp is not supported on keyed flattened fields.
    *[{"prefix": {"F": "172.%d." % n}} for n in range(16, 32)],
    *[{"prefix": {"F": p}} for p in ("fc", "fd", "FC", "FD", "fe8", "fe9", "fea", "feb",
                                    "FE8", "FE9", "FEA", "FEB")],
    {"terms": {"F": ["", "::1", "::", "0.0.0.0"] + self_ips}},
]
fields = [
    "honeypot.src_ip",
    "honeypot.data.connection.remote_ip",
    "honeypot.data.parent.remote_ip",
    "honeypot.data.child.remote_ip",
]

def candidate(field):
    def sub(c):
        (k, v), = c.items()
        (_, val), = v.items()
        return {k: {field: val}}
    return {"bool": {"filter": [{"exists": {"field": field}}],
                     "must_not": [sub(c) for c in fleet_not]}}

class_a = {"bool": {
    "must_not": [{"exists": {"field": "source.ip"}}],
    "should": [candidate(f) for f in fields],
    "minimum_should_match": 1}}
cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
         "127.0.0.0/8", "::1", "fc00::/7", "fe80::/10"] + self_ips
class_b = {"bool": {"should": [{"term": {"source.ip": c}} for c in cidrs],
                    "minimum_should_match": 1}}
print(json.dumps({"a": {"query": class_a}, "b": {"query": class_b},
                  "all": {"query": {"bool": {"should": [class_a, class_b],
                                              "minimum_should_match": 1}}}}))
PY
)"
q() { printf '%s' "$queries" | python3 -I -c "import json,sys;print(json.dumps(json.load(sys.stdin)['$1']))"; }

count() { q "$1" | es POST "/$index_pattern/_count?expand_wildcards=all" | python3 -I -c "import json,sys;print(json.load(sys.stdin)['count'])"; }

total="$("${es_exec[@]}" curl -fsS "$es_url/$index_pattern/_count?expand_wildcards=all" | python3 -I -c "import json,sys;print(json.load(sys.stdin)['count'])")"
n_a="$(count a)"; n_b="$(count b)"; n_all="$(count all)"
echo "index pattern                                   : $index_pattern"
echo "documents total                                 : $total"
echo "A) no source.ip, promotable honeypot.* address  : $n_a"
echo "B) source.ip present but a fleet address        : $n_b"
echo "would be updated (A or B)                       : $n_all"

if [ "$mode" = "dry-run" ]; then
  echo "dry run only; re-run with --run to start the update."
  exit 0
fi

if [ "$n_all" -eq 0 ]; then echo "nothing to do."; exit 0; fi
require_new_pipeline

echo "starting throttled _update_by_query (requests_per_second=$rps, scroll_size=$scroll_size, slices=$slices)"
task="$(q all | es POST "/$index_pattern/_update_by_query?expand_wildcards=all&pipeline=geoip-honeypot&conflicts=proceed&wait_for_completion=false&requests_per_second=$rps&scroll_size=$scroll_size&slices=$slices&refresh=false" \
  | python3 -I -c "import json,sys;print(json.load(sys.stdin)['task'])")"
echo "task: $task   (cancel with: POST /_tasks/$task/_cancel; re-throttle with: POST /_update_by_query/$task/_rethrottle?requests_per_second=N)"

while :; do
  resp="$("${es_exec[@]}" curl -fsS "$es_url/_tasks/$task")"
  line="$(printf '%s' "$resp" | python3 -I -c "
import json,sys
r=json.load(sys.stdin)
s=r.get('task',{}).get('status',{})
print(r.get('completed',False), s.get('updated',0), s.get('total',0), s.get('version_conflicts',0), s.get('noops',0))")"
  set -- $line
  echo "$(date -u +%H:%M:%SZ) updated=$2 of total=$3 version_conflicts=$4 noops=$5"
  [ "$1" = "True" ] && break
  sleep "$poll"
done
echo "done. Re-run with --dry-run: the A+B count should now be 0 (or only docs written meanwhile)."
