#!/usr/bin/env bash
# Tests for the geoip-honeypot ingest pipeline analysis/elasticsearch-setup.sh
# installs (#563: cowrie's url field wasn't promoted to ECS url.path the way
# other sensors' path field is).
#
# Runs a real Elasticsearch container and uses its _ingest/pipeline/_simulate
# API -- there is no standalone Painless interpreter to test the pipeline's
# script processors against, and this repo has no lighter-weight fixture for
# it. Needs Docker and the ability to pull docker.elastic.co/elasticsearch;
# skips cleanly if either is unavailable, same convention as
# analysis/yara/tests/test_sync_yara.sh skipping without a real yara(1).
#
# Usage: analysis/tests/test_geoip_pipeline.sh
set -euo pipefail

ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:9.5.2@sha256:9c1e1afc2bda921b35025e21c72ec6e392266995aa35ad6a47887363592718be"

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
container="es-pipeline-test-$$"
port=$((19000 + (RANDOM % 900)))
tmp="$(mktemp -d)"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# #2915: the `trap cleanup EXIT` above does not fire on SIGKILL (a runner
# OOM-kill -- and this container is Elasticsearch, so the runner is under
# memory pressure exactly when this leg runs -- a cancelled CI job escalating
# past SIGTERM, or a hard timeout). The container then survives, *running*,
# for the life of the runner. Unlike the Keycloak fixtures in scripts/, the
# port above is a fixed random draw rather than an ephemeral bind, so a
# survivor can also collide with a later run outright. Verified live on the
# homeserver 2026-09-04: one `es-pipeline-test-<pid>` container had been up
# 13 hours with no owning run.
#
# Reap survivors of an earlier killed run, skipping anything younger than
# ${reap_min_age_s} so a *concurrent* run is never destroyed mid-flight --
# the fleet runs several self-hosted runners against one Docker daemon, which
# is what the `$$` in the name above is for.
reap_min_age_s="${APIARY_TEST_REAP_MIN_AGE_S:-3600}"
for stale_id in $(docker ps -aq --filter "name=^/es-pipeline-test-" 2>/dev/null); do
  stale_created="$(docker inspect -f '{{.Created}}' "$stale_id" 2>/dev/null)" || continue
  stale_epoch="$(date -u -d "$stale_created" +%s 2>/dev/null)" || continue
  [ "$(( $(date -u +%s) - stale_epoch ))" -ge "$reap_min_age_s" ] || continue
  docker rm -fv "$stale_id" >/dev/null 2>&1 || true
done

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

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

# Extract exactly the geoip-honeypot pipeline's JSON body (the
# geoip_pipeline_body heredoc) rather than the whole file, so this stays in
# sync with elasticsearch-setup.sh automatically -- no copy of the pipeline
# definition to fall out of date here. Located by the heredoc's own open/
# close markers, not the PUT command -- #827 moved the actual curl call to
# after the heredoc (the body needs a placeholder substituted first, see
# below), so it's no longer adjacent to "<<'JSON'" the way earlier versions
# of this pipeline's install code had it.
start_line=$(grep -n "cat <<'JSON'" "$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh" | head -1 | cut -d: -f1)
body_start=$((start_line + 1))
end_line=$(tail -n "+$body_start" "$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh" | grep -n '^JSON$' | head -1 | cut -d: -f1)
body_end=$((body_start + end_line - 2))
sed -n "${body_start},${body_end}p" "$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh" > "$tmp/pipeline.json.tmpl"

# #827: the extracted body still has the literal __ES_HOME_NET_JSON__
# placeholder elasticsearch-setup.sh's own sed substitutes at install time --
# same real TEST-NET-2 convention as the rest of this file's fixtures below,
# not a real address, so this test's own "home_net" IS the address the
# simulate fixtures below deliberately trigger the swap against.
sed 's#__ES_HOME_NET_JSON__#["198.51.100.1"]#' "$tmp/pipeline.json.tmpl" > "$tmp/pipeline.json"

python3 -c "import json; json.load(open('$tmp/pipeline.json'))" ||
  fail "extracted pipeline body is not valid JSON -- extraction line range needs updating"

curl -fsS -X PUT "$es_url/_ingest/pipeline/geoip-honeypot" \
  -H 'Content-Type: application/json' \
  --data-binary "@$tmp/pipeline.json" >/dev/null ||
  fail "Elasticsearch rejected the pipeline definition"
pass "pipeline installs cleanly"

simulate() {
  # simulate <fixture-file> -> prints the resulting document's url.path (or empty)
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
print(doc.get('url', {}).get('path', ''))
"
}

cat > "$tmp/cowrie_url_only.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"eventid":"cowrie.session.file_download","url":"http://198.51.100.10/malware.sh","src_ip":"198.51.100.10"}}}]}
EOF
result="$(simulate "$tmp/cowrie_url_only.json")"
[ "$result" = "http://198.51.100.10/malware.sh" ] ||
  fail "cowrie's url field was not promoted to url.path (got: '$result')"
pass "cowrie's url field (no path) is promoted to url.path"

cat > "$tmp/path_only.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"http-honeypot","path":"/wp-login.php","src_ip":"198.51.100.20"}}}]}
EOF
result="$(simulate "$tmp/path_only.json")"
[ "$result" = "/wp-login.php" ] ||
  fail "an existing path-only sensor regressed (got: '$result')"
pass "an existing path-only sensor (http-honeypot) is unaffected"

cat > "$tmp/both_path_and_url.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"dionaea","path":"/uploads/x.exe","url":"http://should-not-win.example/decoy","src_ip":"198.51.100.30"}}}]}
EOF
result="$(simulate "$tmp/both_path_and_url.json")"
[ "$result" = "/uploads/x.exe" ] ||
  fail "path did not take precedence over url when a document sets both (got: '$result')"
pass "path takes precedence over url when a document sets both"

# #827: Suricata netflow logs both directions of one flow as separate
# records, source/destination reflecting literal packet direction not
# attacker/victim -- for the "reflected" direction (our own service
# answering back), source.ip is this host's own address, not the remote
# attacker's. This pipeline is installed above with home_net=198.51.100.1
# (this test's own fixture-only address, matching the TEST-NET-2 convention
# every other fixture here already uses).
simulate_flow() {
  # simulate_flow <fixture-file> -> prints "source.ip destination.ip destination.port"
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
src = doc.get('source', {}).get('ip', '')
dst = doc.get('destination', {})
print(f\"{src} {dst.get('ip', '')} {dst.get('port', '')}\")
"
}

# Normal direction: a real remote attacker (198.51.100.77) hitting our VNC
# honeypot (port 5900) -- source is already the remote party, nothing to
# swap. Confirms the fix doesn't disturb the overwhelming majority case.
cat > "$tmp/netflow_normal.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"netflow","src_ip":"198.51.100.77","src_port":51234,"dest_ip":"198.51.100.1","dest_port":5900,"proto":"TCP"}}}}]}
EOF
result="$(simulate_flow "$tmp/netflow_normal.json")"
[ "$result" = "198.51.100.77 198.51.100.1 5900" ] ||
  fail "normal-direction netflow regressed (got: '$result')"
pass "normal-direction netflow (remote -> us) is unaffected"

# Reflected direction: the same conversation's return leg, as Suricata
# actually logs it -- src_ip/src_port are OUR OWN service (5900), dest_ip/
# dest_port are the real remote attacker's ephemeral port. Without the
# #827 fix, source.ip would be our own address here -- exactly what showed
# up as the #1 "attack source" in the real dashboard before this fix.
cat > "$tmp/netflow_reflected.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"netflow","src_ip":"198.51.100.1","src_port":5900,"dest_ip":"198.51.100.77","dest_port":51234,"proto":"TCP"}}}}]}
EOF
result="$(simulate_flow "$tmp/netflow_reflected.json")"
[ "$result" = "198.51.100.77 198.51.100.1 5900" ] ||
  fail "reflected-direction netflow was not corrected (got: '$result', want the same real-attacker/our-own-service pair as the normal-direction case above)"
pass "reflected-direction netflow (us -> remote) is corrected to the real remote party"

# Neither side is home_net -- e.g. Suricata observing unrelated third-party
# traffic, or the swap condition genuinely doesn't apply. Falls back to
# positional (source, destination), same as every event type without this
# fix -- no false-positive swap.
cat > "$tmp/netflow_neither_homenet.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"netflow","src_ip":"203.0.113.5","src_port":443,"dest_ip":"198.51.100.77","dest_port":51234,"proto":"TCP"}}}}]}
EOF
result="$(simulate_flow "$tmp/netflow_neither_homenet.json")"
[ "$result" = "203.0.113.5 198.51.100.77 51234" ] ||
  fail "a flow with neither side in home_net was swapped when it shouldn't be (got: '$result')"
pass "a flow with neither side in home_net falls back to positional (no false-positive swap)"

# #1677: an "alert" event (unlike netflow) carries both packet-level
# src_ip/dest_ip (the specific packet that matched, whichever direction it
# travelled) and a flow object (always attacker-as-source regardless of
# packet direction). A signature that fires on the server's own response
# content (Suricata's own direction:"to_client") reports packet-level
# src_ip as OUR OWN address -- and since that address is a real routable
# IP, not a private/home_net range, the home_net-swap heuristic above
# never catches it, so source.ip ends up as our own service instead of
# the attacker. The fixture's addresses are deliberately NOT in this
# test's home_net (198.51.100.1) -- the whole point is that this case
# doesn't depend on home_net at all, it's caught by preferring flow.
cat > "$tmp/alert_to_client.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"alert","direction":"to_client","src_ip":"203.0.113.9","src_port":23,"dest_ip":"198.51.100.77","dest_port":55102,"proto":"TCP","flow":{"src_ip":"198.51.100.77","src_port":55102,"dest_ip":"203.0.113.9","dest_port":23}}}}}]}
EOF
result="$(simulate_flow "$tmp/alert_to_client.json")"
[ "$result" = "198.51.100.77 203.0.113.9 23" ] ||
  fail "a to_client alert's flow-level attribution was not preferred over its packet-level fields (got: '$result')"
pass "a to_client alert uses the flow's attacker-as-source, not the responding packet's own src_ip"

# #2978: beelzebub's `Init service` records write honeypot.port as a Go
# listen address (":8880"). It used to be copied verbatim into
# destination.port, which maps as `integer` -- so the value never reached
# the index, but stayed in _source, where ml-worker read it and int(":8880")
# crash-looped the worker. norm_port() must turn it into a real port number.
cat > "$tmp/beelzebub_listen_addr_port.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"beelzebub","msg":"Init service: Wordpress 6.0","port":":8880"}}}]}
EOF
result="$(simulate_flow "$tmp/beelzebub_listen_addr_port.json")"
[ "$result" = "  8880" ] ||
  fail "a Go listen-address honeypot.port was not normalised to a port number (got: '$result')"
pass "a Go listen-address honeypot.port (\":8880\") is normalised to 8880"

# The host-qualified forms Go also emits, including IPv6, must not have the
# host half swallow the port.
cat > "$tmp/beelzebub_host_qualified_port.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"beelzebub","port":"0.0.0.0:389","src_ip":"198.51.100.77"}}}]}
EOF
result="$(simulate_flow "$tmp/beelzebub_host_qualified_port.json")"
[ "$result" = "198.51.100.77  389" ] ||
  fail "a host-qualified honeypot.port was not normalised (got: '$result')"
pass "a host-qualified honeypot.port (\"0.0.0.0:389\") is normalised to 389"

cat > "$tmp/ipv6_listen_addr_port.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"beelzebub","port":"[::]:8880","src_ip":"198.51.100.77"}}}]}
EOF
result="$(simulate_flow "$tmp/ipv6_listen_addr_port.json")"
[ "$result" = "198.51.100.77  8880" ] ||
  fail "an IPv6 listen-address honeypot.port was not normalised (got: '$result')"
pass "an IPv6 listen-address honeypot.port (\"[::]:8880\") is normalised to 8880"

# Unparseable or out-of-range values write nothing at all, rather than
# planting a wrong number -- the caller treats them like an absent field.
cat > "$tmp/junk_port.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"beelzebub","port":"not-a-port","src_ip":"198.51.100.77"}}}]}
EOF
result="$(simulate_flow "$tmp/junk_port.json")"
[ "$result" = "198.51.100.77  " ] ||
  fail "an unparseable honeypot.port was not dropped (got: '$result')"
pass "an unparseable honeypot.port writes no destination.port at all"

cat > "$tmp/out_of_range_port.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"beelzebub","port":99999,"src_ip":"198.51.100.77"}}}]}
EOF
result="$(simulate_flow "$tmp/out_of_range_port.json")"
[ "$result" = "198.51.100.77  " ] ||
  fail "an out-of-range honeypot.port was not dropped (got: '$result')"
pass "an out-of-range honeypot.port writes no destination.port at all"

# A plain numeric port -- the overwhelmingly common case -- is unchanged.
cat > "$tmp/plain_numeric_port.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"http-honeypot","dst_port":8080,"src_ip":"198.51.100.77"}}}]}
EOF
result="$(simulate_flow "$tmp/plain_numeric_port.json")"
[ "$result" = "198.51.100.77  8080" ] ||
  fail "a plain numeric honeypot.dst_port regressed (got: '$result')"
pass "a plain numeric honeypot.dst_port is unaffected"

# Ordinary to_server alert: flow and packet-level fields already agree --
# confirms preferring flow doesn't change the overwhelmingly common case.
cat > "$tmp/alert_to_server.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"alert","direction":"to_server","src_ip":"198.51.100.77","src_port":55102,"dest_ip":"203.0.113.9","dest_port":23,"proto":"TCP","flow":{"src_ip":"198.51.100.77","src_port":55102,"dest_ip":"203.0.113.9","dest_port":23}}}}}]}
EOF
result="$(simulate_flow "$tmp/alert_to_server.json")"
[ "$result" = "198.51.100.77 203.0.113.9 23" ] ||
  fail "an ordinary to_server alert regressed (got: '$result')"
pass "an ordinary to_server alert (flow and packet already agree) is unaffected"

# #1677: dionaea_incident.json records (e.g. DoublePulsar) carry no
# top-level honeypot.src_ip at all -- the real signal is nested under
# honeypot.data.connection.remote_ip, which ip-enrichment-worker resolves
# in place but this pipeline never promoted to source.ip, so these events
# always rendered as "unattributed" regardless of enrichment succeeding.
cat > "$tmp/dionaea_incident.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"name":"dionaea","data":{"name":"DoublePulsar connection attempt","connection":{"local_ip":"172.16.10.2","remote_ip":"198.51.100.66","local_port":445,"remote_port":38514,"transport":"tcp"}}}}}]}
EOF
result="$(simulate_flow "$tmp/dionaea_incident.json")"
[ "$result" = "198.51.100.66  445" ] ||
  fail "dionaea_incident's nested remote_ip was not promoted to source.ip (got: '$result')"
pass "dionaea_incident's nested honeypot.data.connection.remote_ip is promoted to source.ip"

# #1677 defense-in-depth: several sensors' own Docker HEALTHCHECK dials
# 127.0.0.1 directly, and that self-connection can get logged with a
# meaningless loopback src_ip -- fixed at the source for the sensors this
# repo owns, but not every sensor's own binary is something this repo can
# patch (third-party C/Python images). Never let source.ip end up as a
# loopback address regardless of which branch above set it, so an
# unpatched or future sensor's self-probe can't leak into the dashboard
# looking like a real (if meaningless) attacker IP.
cat > "$tmp/loopback_src.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"sentrypeer","src_ip":"127.0.0.1"}}}]}
EOF
result="$(simulate_flow "$tmp/loopback_src.json")"
[ "$result" = "  " ] ||
  fail "a loopback source.ip was not scrubbed (got: '$result')"
pass "a loopback source.ip is scrubbed regardless of which sensor produced it"

simulate_hash() {
  # simulate_hash <fixture-file> -> prints file.hash.sha256 (or empty)
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
print(doc.get('file', {}).get('hash', {}).get('sha256', ''))
"
}

# #1240: cowrie.session.file_download's honeypot.shasum is a genuine
# captured-payload hash and must still reach file.hash.sha256 -- confirms
# the fix below doesn't regress the legitimate case.
cat > "$tmp/file_download_shasum.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"eventid":"cowrie.session.file_download","shasum":"deadbeefcafef00d0000000000000000000000000000000000000000000000","src_ip":"198.51.100.40"}}}]}
EOF
result="$(simulate_hash "$tmp/file_download_shasum.json")"
[ "$result" = "deadbeefcafef00d0000000000000000000000000000000000000000000000" ] ||
  fail "cowrie.session.file_download's shasum was not promoted to file.hash.sha256 (got: '$result')"
pass "cowrie.session.file_download's shasum is promoted to file.hash.sha256"

# #1240: cowrie.log.closed's honeypot.shasum is the TTY recording's own
# filename-derived session ID, not a captured file's hash -- confirmed live
# against real production data (51k+ documents carried a bogus
# file.hash.sha256 from this event type alone, vs. 2.9k genuine
# file_download hashes) that corrupted every payload-hash-keyed feature
# reading it (attacker-identity entity panels, correlation, dedup) with
# stale references that 404 when clicked.
cat > "$tmp/log_closed_shasum.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"eventid":"cowrie.log.closed","shasum":"1b160c2a72b76aa2b1e8cf1e2a2bca6dd2bd9d2de5df20f94577c138d6cc85b9","ttylog":"var/lib/cowrie/tty/1b160c2a72b76aa2b1e8cf1e2a2bca6dd2bd9d2de5df20f94577c138d6cc85b9","src_ip":"198.51.100.41"}}}]}
EOF
result="$(simulate_hash "$tmp/log_closed_shasum.json")"
[ -z "$result" ] ||
  fail "cowrie.log.closed's ttylog-derived shasum leaked into file.hash.sha256 (got: '$result', want empty)"
pass "cowrie.log.closed's shasum is not mistaken for a real payload hash"

# #1873/#1876: the fleet's own addresses must never become source.ip, and
# dionaea's nested peer must not be thrown away.
#
# This pipeline is installed above with home_net=["198.51.100.1"], so that
# address stands in for the tunnel peers and the WAN addresses the real
# deployment configures through ES_HOME_NET.
simulate_source_ip() {
  # simulate_source_ip <fixture-file> -> prints the resulting source.ip
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
print(doc.get('source', {}).get('ip', ''))
"
}

# A sensor behind the tunnel observes the tunnel peer as its client. Saying
# so in a field called source.ip states that our own relay attacked us.
cat > "$tmp/fleet_peer_source.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"hellpot","src_ip":"198.51.100.1","dst_ip":"172.16.10.3"}}}]}
EOF
result="$(simulate_source_ip "$tmp/fleet_peer_source.json")"
[ -z "$result" ] ||
  fail "a home_net address became source.ip (got: '$result', want empty so the event reads unattributed)"
pass "a home_net address never becomes source.ip"

# The guard must not swallow the addresses it exists to preserve.
cat > "$tmp/real_attacker_source.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"hellpot","src_ip":"198.51.100.77","dst_ip":"172.16.10.3"}}}]}
EOF
result="$(simulate_source_ip "$tmp/real_attacker_source.json")"
[ "$result" = "198.51.100.77" ] ||
  fail "a real attacker address was dropped by the home_net guard (got: '$result')"
pass "a real attacker address survives the home_net guard"

# dionaea emits two shapes. The flat one was always read; the raw one nests
# the peer, and only data.connection was handled -- a SIP session nests it
# under data.parent, so those events read as unattributed while the address
# sat in the same document.
cat > "$tmp/dionaea_parent_peer.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"name":"dionaea","data":{"parent":{"protocol":"SipSession","remote_ip":"198.51.100.88","remote_port":58459,"local_port":5060,"transport":"udp"}}}}}]}
EOF
result="$(simulate_source_ip "$tmp/dionaea_parent_peer.json")"
[ "$result" = "198.51.100.88" ] ||
  fail "dionaea's data.parent peer was not promoted to source.ip (got: '$result')"
pass "dionaea's data.parent peer becomes source.ip"

cat > "$tmp/dionaea_connection_peer.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"name":"dionaea","data":{"connection":{"protocol":"smbd","remote_ip":"198.51.100.99","local_port":445,"transport":"tcp"}}}}}]}
EOF
result="$(simulate_source_ip "$tmp/dionaea_connection_peer.json")"
[ "$result" = "198.51.100.99" ] ||
  fail "dionaea's data.connection peer regressed (got: '$result')"
pass "dionaea's data.connection peer still becomes source.ip"

# dionaea's own loopback health probe nests its address exactly like a real
# attacker does, so the nested path must go through the same guard.
cat > "$tmp/dionaea_probe_peer.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"name":"dionaea","data":{"connection":{"protocol":"smbd","remote_ip":"127.0.0.1","local_port":445,"transport":"tcp"}}}}}]}
EOF
result="$(simulate_source_ip "$tmp/dionaea_probe_peer.json")"
[ -z "$result" ] ||
  fail "a loopback nested peer became source.ip (got: '$result', want empty)"
pass "a loopback nested peer never becomes source.ip"

# home_net is exact-match configuration and cannot enumerate the container
# networks. Measured live: 172.16.10.x reaches source.ip too, so the guard
# matches shape as well as the configured list.
cat > "$tmp/docker_net_source.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"dionaea","src_ip":"172.16.10.3","dst_port":445}}}]}
JSON
result="$(simulate_source_ip "$tmp/docker_net_source.json")"
[ -z "$result" ] ||
  fail "a container-network address became source.ip (got: '$result', want empty)"
pass "a container-network address never becomes source.ip"

cat > "$tmp/rfc1918_source.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"cowrie","src_ip":"192.168.42.7"}}}]}
JSON
result="$(simulate_source_ip "$tmp/rfc1918_source.json")"
[ -z "$result" ] ||
  fail "a LAN address became source.ip (got: '$result', want empty)"
pass "a LAN address never becomes source.ip"

# 172.x is only private for 16-31. The guard must not swallow 172.32+.
cat > "$tmp/public_172_source.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"cowrie","src_ip":"172.32.5.9"}}}]}
JSON
result="$(simulate_source_ip "$tmp/public_172_source.json")"
[ "$result" = "172.32.5.9" ] ||
  fail "a public 172.32+ address was wrongly treated as private (got: '$result')"
pass "a public 172.32+ address survives the private-range guard"

cat > "$tmp/public_11_source.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"cowrie","src_ip":"11.9.9.9"}}}]}
JSON
result="$(simulate_source_ip "$tmp/public_11_source.json")"
[ "$result" = "11.9.9.9" ] ||
  fail "a public 11.x address was wrongly treated as private (got: '$result')"
pass "a public address starting 1 is not confused with 10.x"

# #1889: a honeypot event with a full 5-tuple must get a community_id, so
# it can join to Suricata's alert, Zeek's record and the #1783 flow pivot.
# Measured before this: 0 of 174,384 http-honeypot events in 7 days had one,
# because the branch promoted neither source.port nor network.transport.
simulate_community_id() {
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
net = doc.get('network', {})
src = doc.get('source', {})
dst = doc.get('destination', {})
print('%s|%s|%s|%s' % (net.get('community_id',''), src.get('port',''), dst.get('port',''), net.get('transport','')))
"
}

cat > "$tmp/http_full_tuple.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"http-honeypot","src_ip":"198.51.100.20","src_port":54321,"dst_ip":"198.51.100.1","dst_port":8080,"method":"POST","path":"/wp-login.php"}}}]}
JSON
result="$(simulate_community_id "$tmp/http_full_tuple.json")"
cid="${result%%|*}"
rest="${result#*|}"
[ -n "$cid" ] ||
  fail "a full 5-tuple produced no community_id (got fields: '$result')"
[ "$rest" = "54321|8080|tcp" ] ||
  fail "the tuple was not promoted correctly (got source.port|destination.port|transport = '$rest')"
pass "an http-honeypot event with a full tuple gets a community_id"

# The transport must be the transport, not the application protocol -- a
# community_id keyed on "smbd" or "HTTP" matches nothing anywhere.
cat > "$tmp/app_proto_not_transport.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"elasticpot","src_ip":"198.51.100.21","src_port":40000,"dst_port":9200,"proto":"HTTP"}}}]}
JSON
result="$(simulate_community_id "$tmp/app_proto_not_transport.json")"
transport="${result##*|}"
[ "$transport" != "http" ] ||
  fail "an application protocol was written into network.transport (got '$transport')"
pass "an application protocol is not mistaken for a transport"

# A real transport is taken.
cat > "$tmp/udp_tuple.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"dns-honeypot","src_ip":"198.51.100.22","src_port":33333,"dst_ip":"198.51.100.1","dst_port":53,"proto":"udp"}}}]}
JSON
result="$(simulate_community_id "$tmp/udp_tuple.json")"
[ "${result##*|}" = "udp" ] ||
  fail "udp was not promoted to network.transport (got '${result##*|}')"
[ -n "${result%%|*}" ] ||
  fail "a udp 5-tuple produced no community_id"
pass "a udp sensor event gets a community_id too"

# Absent is still absent: a relayed request reports no source port (the
# sensor omits it deliberately), and half a tuple must not produce a key.
cat > "$tmp/no_src_port.json" <<'JSON'
{"docs":[{"_source":{"honeypot":{"sensor":"http-honeypot","src_ip":"198.51.100.23","dst_port":8080,"method":"GET","path":"/"}}}]}
JSON
result="$(simulate_community_id "$tmp/no_src_port.json")"
[ -z "${result%%|*}" ] ||
  fail "a community_id was invented without a source port (got '${result%%|*}')"
pass "no source port means no community_id, rather than a wrong one"

# #3560: source.ip is promoted ONCE, at write time, from the same candidates
# and by the same rules as backend-service/src/events.rs::attacker_ip /
# is_fleet_address, so read-time and write-time agree and aggregations keyed on
# source.ip see the attacker. Candidate order: an existing non-fleet
# source.ip, honeypot.src_ip, then dionaea's data.connection / data.parent /
# data.child remote_ip -- the FIRST NON-FLEET one wins (a fleet src_ip must not
# shadow a public nested address). The fleet address that was passed over is
# kept in honeypot.fleet_peer; a promotion is tagged source_ip_promoted.
simulate_src() {
  # simulate_src <fixture-file> -> "source.ip|fleet_peer|tags|dest.port"
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
d = json.load(sys.stdin)['docs'][0]['doc']['_source']
print('|'.join([
    d.get('source', {}).get('ip', ''),
    d.get('honeypot', {}).get('fleet_peer', ''),
    # the test cluster has no GeoLite2 files; geoip adds its own _geoip_* tags
    ','.join(x for x in d.get('tags', []) if not x.startswith('_geoip')),
    str(d.get('destination', {}).get('port', '')),
]))
"
}
expect_src() {
  # expect_src <name> <document-json> <expected "ip|peer|tags|port">
  printf '{"docs":[{"_source":%s}]}' "$2" > "$tmp/src_case.json"
  got="$(simulate_src "$tmp/src_case.json")"
  [ "$got" = "$3" ] || fail "$1 (got '$got', want '$3')"
  pass "$1"
}

expect_src "cowrie with only honeypot.src_ip is promoted to source.ip and tagged" \
  '{"honeypot":{"sensor":"cowrie","src_ip":"203.0.113.10"}}' \
  "203.0.113.10||source_ip_promoted|"
expect_src "dionaea nested connection.remote_ip is promoted, with its local port" \
  '{"honeypot":{"sensor":"dionaea","data":{"connection":{"remote_ip":"203.0.113.11","local_port":5060,"transport":"udp"}}}}' \
  "203.0.113.11||source_ip_promoted|5060"
expect_src "a fleet src_ip does not shadow a public nested remote_ip; the peer is kept" \
  '{"honeypot":{"sensor":"dionaea","src_ip":"10.0.0.1","data":{"connection":{"remote_ip":"203.0.113.12","local_port":5060}}}}' \
  "203.0.113.12|10.0.0.1|source_ip_promoted|5060"
expect_src "a fleet connection.remote_ip does not shadow a public parent remote_ip" \
  '{"honeypot":{"sensor":"dionaea","data":{"connection":{"remote_ip":"10.0.0.1"},"parent":{"remote_ip":"203.0.113.13"}}}}' \
  "203.0.113.13|10.0.0.1|source_ip_promoted|"
expect_src "a tunnel-peer-only document stays without a source.ip, peer recorded" \
  '{"honeypot":{"sensor":"cowrie","src_ip":"10.0.0.1"}}' \
  "|10.0.0.1||"
expect_src "a private-only document is unchanged (no source.ip)" \
  '{"honeypot":{"sensor":"cowrie","src_ip":"192.168.1.5"}}' \
  "|192.168.1.5||"
expect_src "a fleet source.ip is dropped, not kept (loopback /8, like is_fleet_address)" \
  '{"honeypot":{"sensor":"cowrie","src_ip":"127.0.0.2"},"source":{"ip":"127.0.0.2"}}' \
  "|127.0.0.2||"
expect_src "an existing public source.ip is kept untouched and not re-tagged" \
  '{"honeypot":{"sensor":"cowrie","src_ip":"10.0.0.1"},"source":{"ip":"203.0.113.14"}}' \
  "203.0.113.14|||"
expect_src "IPv6 unique-local is fleet, a public IPv6 nested address wins" \
  '{"honeypot":{"sensor":"dionaea","src_ip":"fd12::1","data":{"parent":{"remote_ip":"2001:db8::1"}}}}' \
  "2001:db8::1|fd12::1|source_ip_promoted|"
expect_src "172.16/12 is fleet, 172.32.x is not" \
  '{"honeypot":{"sensor":"cowrie","src_ip":"172.31.0.9","data":{"connection":{"remote_ip":"172.32.0.9"}}}}' \
  "172.32.0.9|172.31.0.9|source_ip_promoted|"
expect_src "re-running on an already-promoted document is idempotent" \
  '{"honeypot":{"sensor":"cowrie","src_ip":"203.0.113.10"},"source":{"ip":"203.0.113.10"},"tags":["source_ip_promoted"]}' \
  "203.0.113.10||source_ip_promoted|"

echo
echo "all geoip-honeypot pipeline tests passed"
