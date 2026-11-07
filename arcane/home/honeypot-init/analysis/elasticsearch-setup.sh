#!/bin/sh
set -eu

es_url="${ELASTICSEARCH_URL:-http://elasticsearch:9200}"

until curl -fsS "$es_url/_cluster/health" >/dev/null; do
  sleep 2
done

curl -fsS -X PUT "$es_url/_snapshot/honeypot-fs" \
  -H 'Content-Type: application/json' \
  --data-binary '{"type":"fs","settings":{"location":"/snapshots","compress":true}}' >/dev/null

# #3283: the per-node shard ceiling stays at Elasticsearch's 1000 default, and
# is deliberately NOT pinned here. The 1000 default is what stopped every new
# index being created on 2026-09-21, dead-lettering all sensor ingest -- but the
# fix is that every shard family is bounded, not that the ceiling moves. Raising
# it in the repo hides the next unbounded family instead of failing it.
#
# tests/docs/test_3283_shard_budget.py projects the real steady state from the
# filebeat routing rules and the ILM min_ages (467 shards at 21d, 656 at 30d)
# and fails if that projection ever approaches 1000. If a future run ever needs
# more than 1000, the answer is a shorter retention window and fewer index
# families, not a larger ceiling. test_3283_fix.py asserts this file does not
# pin the ceiling, so the two tests cannot drift apart again.
# Bounded retention prevents a noisy internet-wide scan or IDS signature from
# filling the homeserver disk. Daily Filebeat names already provide rollover
# for suricata/portbridge/dead-letter/analysis-results (a fresh, plain
# date-named index each day -- see analysis/filebeat.yml's output.elasticsearch
# indices routing); ILM only has to delete the old ones once they age out.
# honeypot-30d is deliberately NOT in this loop -- see the #585 block below
# for why it needs a real rollover action instead of this delete-only shape.
#
# #261: every retention window in this stack (these ILM policies, the
# on-disk JSON retention in log-maintenance.sh/suricata-log-maintenance.sh/
# portbridge-log-maintenance.sh, and BISTREAMS_RETENTION_DAYS in
# dedupe-payloads.py) derives its default from this one operator-facing
# knob, T-Pot-style, instead of each hardcoding its own number. Ratios below
# match this stack's previous independent defaults (7d/30d, 60d/30d,
# 180d/30d) so a plain default deploy behaves exactly as before; an operator
# who sets HONEYPOT_RETENTION_DAYS scales every window at once.
#
# Policy *names* stay fixed (suricata-7d etc.) even though the actual
# min_age they enforce is now dynamic -- they are stable ILM policy
# identifiers referenced by index templates elsewhere in this file, not a
# literal claim about the configured duration. That holds for all FOURTEEN
# policies below, including honeypot-30d (#2193: its name predates the
# knob and other tooling references it by name only).
retention_days="${HONEYPOT_RETENTION_DAYS:-30}"
# #3283: zeek and zeek-proxy write one index per log type per MONTH
# (filebeat.yml), so their delete age is twice the retention window: a month's
# index is created on its first day, and deleting it at 30 days would drop the
# last weeks of that month early. zeek-60d / zeek-proxy-60d keep every record
# 30-60 days. zeek-30d / zeek-proxy-30d stay defined for the daily indices
# created before the switch (their lifecycle name is fixed at creation), so
# those still expire on the old schedule.
suricata_days=$(( retention_days * 7 / 30 ))
[ "$suricata_days" -ge 1 ] || suricata_days=1
for spec in "suricata-7d:${suricata_days}d" \
            "dead-letter-60d:$(( retention_days * 2 ))d" "portbridge-30d:${retention_days}d" \
            "dionaea-incidents-30d:${retention_days}d" \
            "traefik-30d:${retention_days}d" \
            "zeek-30d:${retention_days}d" "zeek-proxy-30d:${retention_days}d" "huginn-30d:${retention_days}d" \
            "zeek-60d:$(( retention_days * 2 ))d" "zeek-proxy-60d:$(( retention_days * 2 ))d" \
            "extracted-files-30d:${retention_days}d" \
            "dashboard-app-30d:${retention_days}d" \
            "analysis-results-180d:$(( retention_days * 6 ))d"; do
  name=${spec%%:*}
  age=${spec#*:}
  curl -fsS -X PUT "$es_url/_ilm/policy/$name" \
    -H 'Content-Type: application/json' \
    --data-binary "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{}},\"delete\":{\"min_age\":\"$age\",\"actions\":{\"delete\":{}}}}}}" >/dev/null
done

# #585: honeypot-30d is the one policy attached to a real ILM-managed data
# stream (honeypot-events-v2's own template below, "data_stream": {}) rather
# than a plain Filebeat date-named index -- confirmed live against a real
# Elasticsearch instance that without an explicit rollover action in the hot
# phase, ILM will not (structurally cannot) delete a data stream's write
# index, since a write index can only be removed after it has rolled over.
# With hot.actions empty (this policy's shape before this fix), the delete
# phase gets permanently stuck at "wait-for-shard-history-leases" and the
# single backing index grows unbounded forever -- the 30-day retention this
# policy is supposed to enforce did nothing at all. Daily rollover matches
# suricata-7d/portbridge-30d's own per-day cadence above (they get a new
# index each day from Filebeat's date-named pattern instead); 25gb is a
# secondary safety trigger so an unusually heavy single day still rolls
# rather than growing one shard past a healthy size.
# #2193: delete.min_age derives from retention_days like every other
# policy above -- this was the one ILM policy still hardcoding "30d",
# so an operator who shrank HONEYPOT_RETENTION_DAYS to reclaim disk saw
# every secondary family shrink while the dominant raw-events stream
# ignored the knob entirely. Body is assembled with escaped double quotes
# (same idiom as the loop) precisely because a single-quoted literal is
# what silently prevented ${retention_days} from ever expanding here.
# The #585 rollover mechanics and 25gb safety trigger are unchanged.
curl -fsS -X PUT "$es_url/_ilm/policy/honeypot-30d" \
  -H 'Content-Type: application/json' \
  --data-binary "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_age\":\"1d\",\"max_primary_shard_size\":\"25gb\"}}},\"delete\":{\"min_age\":\"${retention_days}d\",\"actions\":{\"delete\":{}}}}}}" >/dev/null

# #827: this stack's own address(es), so the Suricata block below can tell
# "the honeypot itself" apart from the actual remote party -- same real
# value(s) as vps/.env's SURICATA_HOME_NET and ml-worker/.env's ML_HOME_NET
# (each entered separately since this runs on a different host than
# either). NOT the same CIDR-list convention those two use, deliberately:
# bare comma-separated IPs, exact string match, no /32 or subnet syntax --
# the Painless script below checks List.contains(), and Painless has no
# convenient CIDR-containment primitive the way Python's ipaddress module
# does. Exact match is enough here: this stack's real home-net is always
# one or two fixed host addresses, never a range. Empty by default --
# unset means the swap below never triggers, which is the pre-#827
# behaviour (source/destination trusted positionally), still correct for
# every event type except Suricata netflow (see the pipeline comment).
#
# Builds a JSON array literal for the ingest script's "params" field --
# this whole pipeline body is a single-quoted heredoc (no shell expansion),
# so this is assembled separately and substituted in below rather than
# interpolated inline, keeping the giant Painless string free of shell
# quoting hazards.
# #1765: the VPS's own public address. Traefik logs the client side of a
# connection but never the address it accepted on, so the wire tuple needs
# this supplied. Set unconditionally -- it was originally assigned inside the
# ES_HOME_NET branch below, which left it unbound (and fatal under set -u)
# whenever ES_HOME_NET was not set. Empty is safe: the painless guard skips
# the whole wire block, so Traefik records carry no wire join key rather than
# a wrong one.
es_public_ip="${PUBLIC_IP:-}"

es_home_net_json="[]"
if [ -n "${ES_HOME_NET:-}" ]; then
  es_home_net_json=$(printf '%s' "$ES_HOME_NET" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -v '^$' | sed 's/.*/"&"/' | paste -sd, -)
  es_home_net_json="[$es_home_net_json]"
fi

# Geo enrichment is best-effort. Listener/startup events legitimately contain
# an empty source IP and must still be indexed rather than rejected.
#
# #1240: the script below only maps honeypot.shasum -> file.hash.sha256 for
# cowrie.session.file_download/file_upload, not unconditionally for every
# honeypot.shasum present. Confirmed live: cowrie.log.closed (a TTY session
# recording closing, no payload involved) also carries a honeypot.shasum
# field -- populated with the ttylog recording's own filename-derived
# session ID, not a captured file's hash -- and an unconditional mapping
# tagged 51k+ documents with a bogus file.hash.sha256 (vs. 2.9k genuine
# file_download hashes), corrupting every payload-hash-keyed feature that
# reads it (attacker-identity entity panels, correlation, dedup) with
# stale/wrong hash references that 404 when clicked.
# The pipeline body below is a single-quoted heredoc (no shell expansion --
# it contains its own literal ${...} sequences, e.g. the Log4Shell
# deobfuscation script further down, that an unquoted heredoc would mangle
# trying to expand as shell parameters). __ES_HOME_NET_JSON__ is a plain
# text placeholder substituted via sed afterward instead, so the dynamic
# home_net value never has to survive shell parameter expansion.
# One guard in the script below is not obvious and must not be "simplified":
# the Zeek branch derives source.ip from id.orig_h *only when*
# network.relay_ip is absent.
#
# zeek-proxy watches wg0, where id.orig_h is always the tunnel (10.8.0.1),
# so the attacker has to be resolved afterwards from portbridge's record of
# the same flow (see backend-service/src/zeek_proxy_attribution.rs). This
# pipeline is a default_pipeline, and a default_pipeline runs on _update as
# well as on index -- so without the guard it re-derives source.ip from
# id.orig_h immediately after the attribution writes the real attacker, and
# silently undoes it. The failure is invisible from the writer's side: the
# update returns "result":"updated" with a bumped _version, and only
# network.* survives, because nothing here touches those fields.
#
# #2978: every port a sensor writes into the honeypot.* namespace goes
# through norm_port() before it reaches ctx.source.port/ctx.destination.port.
# beelzebub's `Init service` records carry honeypot.port as a Go listen
# address (":8880", ":389"), which used to be copied verbatim; destination.port
# maps as `integer`, so Elasticsearch dropped the value from the index and no
# aggregation could see it, while the string stayed in `_source` -- where
# ml-worker reads it, and where a bare int(":8880") crash-looped the whole
# worker for five hours. norm_port takes the segment after the last colon
# (so "0.0.0.0:389" and "[::]:8880" work too), range-checks it, and yields
# null for anything unparseable, which the callers treat exactly like an
# absent field. Suricata/Zeek/portbridge/huginn ports are left alone: those
# namespaces are produced by typed emitters, not free-form sensor logs.
#
# #3560: source.ip is promoted ONCE, here at write time, so every
# source.ip-keyed view and aggregation sees the attacker. Candidates, in
# order: an existing source.ip, honeypot.src_ip, then dionaea's
# honeypot.data.{connection,parent,child}.remote_ip; the FIRST NON-FLEET one
# wins (a fleet src_ip never shadows a public nested address). This mirrors
# backend-service/src/events.rs attacker_ip / is_fleet_address exactly:
# loopback (127/8, ::1), unspecified, RFC1918, link-local (169.254/16,
# fe80::/10), unique-local (fc00::/7) and the deployment's own addresses
# (ES_HOME_NET here, HONEYPOT_SELF_IPS in the backend). The fleet address that
# was passed over (or the one dropped when nothing public exists) is kept in
# honeypot.fleet_peer, and a promotion adds the tag `source_ip_promoted`.
# The geoip processors below are keyed on the promoted source.ip, so they run
# on the promoted address. The pipeline is idempotent (an existing public
# source.ip is kept), which is what makes scripts/backfill-source-ip.sh safe
# to re-run. This PUT is idempotent: re-running the script installs the
# current definition over the old one.
geoip_pipeline_body="$(cat <<'JSON'
{
  "description": "Geo + ASN enrichment for Suricata and honeypot events (local GeoLite2 files)",
  "processors": [
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "params": {"home_net": __ES_HOME_NET_JSON__, "public_ip": "__ES_PUBLIC_IP__", "entrypoint_ports": {"web": 80, "websecure": 443, "traefik-oidc": 8081, "dashboard-oidc": 8082, "traefik-local": 8080}, "zeek_tcp_logs": ["ssl", "ssh", "http", "ftp", "rdp", "rfb", "ntlm", "ldap", "mysql", "smb_mapping", "smb_files", "smb_cmd", "ja4ssh", "smtp", "irc", "modbus", "modbus_detailed", "s7comm", "cotp"]},
        "source": "boolean is_fleet(String ip, def home) { if (ip == '') return false; if (ip == '::1' || ip == '::' || ip == '0.0.0.0' || ip.startsWith('127.')) return true; if (home.contains(ip)) return true; if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) return true; if (ip.startsWith('172.')) { int fdot = ip.indexOf('.', 4); if (fdot > 4) { try { int foct = Integer.parseInt(ip.substring(4, fdot)); if (foct >= 16 && foct <= 31) return true; } catch (Exception e) {} } return false; } int fc = ip.indexOf(':'); if (fc == 4) { String seg = ip.toLowerCase().substring(0, 4); if (seg.startsWith('fc') || seg.startsWith('fd') || seg.startsWith('fe8') || seg.startsWith('fe9') || seg.startsWith('fea') || seg.startsWith('feb')) return true; } return false; } def norm_port(def v) { if (v == null) return null; if (v instanceof Boolean) return null; if (v instanceof Number) { long np = ((Number)v).longValue(); return (np >= 0 && np <= 65535) ? (int)np : null; } String nt = v.toString().trim(); int nc = nt.lastIndexOf(':'); if (nc >= 0) nt = nt.substring(nc + 1).trim(); if (nt == '') return null; try { int npv = Integer.parseInt(nt); return (npv >= 0 && npv <= 65535) ? npv : null; } catch (Exception e) { return null; } } if (ctx.event == null) ctx.event = new HashMap(); if (ctx.source == null) ctx.source = new HashMap(); if (ctx.destination == null) ctx.destination = new HashMap(); if (ctx.network == null) ctx.network = new HashMap(); if (ctx.honeypot != null) { def h = ctx.honeypot; if (h.sensor != null) ctx.event.sensor = h.sensor; else if (h.eventid != null && h.eventid.toString().startsWith('cowrie.')) ctx.event.sensor = 'cowrie'; def srcs = new ArrayList(); srcs.add(ctx.source.ip); srcs.add(h.src_ip); def d1 = null; def d2 = null; def d3 = null; if (h.data instanceof Map) { d1 = h.data.connection; d2 = h.data.parent; d3 = h.data.child; } srcs.add(d1 instanceof Map ? d1.remote_ip : null); srcs.add(d2 instanceof Map ? d2.remote_ip : null); srcs.add(d3 instanceof Map ? d3.remote_ip : null); int pick = -1; int first = -1; String peer = null; for (int si = 0; si < srcs.size(); si++) { def sv = srcs.get(si); if (sv == null) continue; String ss = sv.toString(); if (ss == '') continue; if (first < 0) first = si; if (!is_fleet(ss, params.home_net)) { pick = si; break; } if (peer == null) peer = ss; } int use = pick >= 0 ? pick : first; if (use > 0) { ctx.source.ip = srcs.get(use).toString(); if (use == 2) { def cp = norm_port(d1.local_port); if (cp != null) ctx.destination.port = cp; if (d1.transport != null) ctx.network.protocol = d1.transport; } else if (use == 3) { def pp = norm_port(d2.local_port); if (pp != null) ctx.destination.port = pp; if (d2.transport != null) ctx.network.protocol = d2.transport; } else if (use == 4) { def dp = norm_port(d3.local_port); if (dp != null) ctx.destination.port = dp; } } if (peer != null) h.fleet_peer = peer; if (pick > 0) { if (ctx.tags == null) ctx.tags = new ArrayList(); if (ctx.tags instanceof List && !ctx.tags.contains('source_ip_promoted')) ctx.tags.add('source_ip_promoted'); } if (h.dst_ip != null && h.dst_ip != '') ctx.destination.ip = h.dst_ip; def hdp = norm_port(h.dst_port); if (hdp == null) hdp = norm_port(h.port); if (hdp != null) ctx.destination.port = hdp; def hsp = norm_port(h.src_port); if (hsp != null) ctx.source.port = hsp; if (h.transport != null) { String tr = h.transport.toString().toLowerCase(); if (tr == 'tcp' || tr == 'udp') ctx.network.transport = tr; } else if (h.proto != null) { String pr = h.proto.toString().toLowerCase(); if (pr == 'tcp' || pr == 'udp') ctx.network.transport = pr; } if (ctx.network.transport == null && h.method != null && h.path != null) ctx.network.transport = 'tcp'; if (h.proto != null) ctx.network.protocol = h.proto; else if (h.protocol != null) ctx.network.protocol = h.protocol; else if (h.data_type != null) ctx.network.protocol = h.data_type; if (h.username != null) { if (ctx.user == null) ctx.user = new HashMap(); ctx.user.name = h.username; } if (h.password != null) { if (ctx.user == null) ctx.user = new HashMap(); ctx.user.password = h.password; } if (h.command != null || h.input != null) { if (ctx.process == null) ctx.process = new HashMap(); ctx.process.command_line = h.command != null ? h.command : h.input; } if (h.path != null) { if (ctx.url == null) ctx.url = new HashMap(); ctx.url.path = h.path; } else if (h.url != null) { if (ctx.url == null) ctx.url = new HashMap(); ctx.url.path = h.url; } if (h.shasum != null && (h.eventid == 'cowrie.session.file_download' || h.eventid == 'cowrie.session.file_upload')) { if (ctx.file == null) ctx.file = new HashMap(); if (ctx.file.hash == null) ctx.file.hash = new HashMap(); ctx.file.hash.sha256 = h.shasum; } if (h.category != null) ctx.event.category = h.category; if (h.held_ms != null) ctx.held_ms = h.held_ms; } if (ctx.log != null && ctx.log.file != null && ctx.log.file.path != null) { String p = ctx.log.file.path; if (ctx.event.sensor == null && p.contains('/conpot')) { int a = p.indexOf('/conpot') + 1; int b = p.indexOf('/', a); if (b > a) { ctx.event.sensor = p.substring(a, b); } else { String base = p.substring(a); ctx.event.sensor = base.endsWith('.json') ? base.substring(0, base.length() - 5) : base; } } if (ctx.event.sensor == null && p.contains('/dionaea')) { ctx.event.sensor = 'dionaea'; } if (ctx.event.sensor != null && ctx.event.sensor.toString().startsWith('conpot')) { if (ctx.ot == null) ctx.ot = new HashMap(); ctx.ot.persona = ctx.event.sensor; } } if (ctx.suricata != null && ctx.suricata.eve != null) { def s = ctx.suricata.eve; ctx.event.sensor = 'suricata'; if (s.event_type != null) ctx.event.category = s.event_type; String sip; String dip; def dport; if (s.flow != null && s.flow.src_ip != null && s.flow.dest_ip != null) { sip = s.flow.src_ip; dip = s.flow.dest_ip; dport = s.flow.dest_port; } else { sip = s.src_ip; dip = s.dest_ip; dport = s.dest_port; if (sip != null && params.home_net.contains(sip) && dip != null && !params.home_net.contains(dip)) { String tmp = sip; sip = dip; dip = tmp; dport = s.src_port; } } if (sip != null) ctx.source.ip = sip; if (dip != null) ctx.destination.ip = dip; if (dport != null) ctx.destination.port = dport; if (s.proto != null) ctx.network.transport = s.proto.toString().toLowerCase(); if (s.community_id != null && s.community_id != '') ctx.network.community_id = s.community_id; } if (ctx.portbridge != null) { def pb = ctx.portbridge; ctx.event.sensor = 'portbridge'; ctx.event.category = pb.event != null ? pb.event.toString() : 'connect'; if (pb.src_ip != null && pb.src_ip != '') ctx.source.ip = pb.src_ip; if (pb.port != null) ctx.destination.port = pb.port; if (pb.proto != null) ctx.network.transport = pb.proto; if (pb.community_id != null && pb.community_id != '') ctx.network.community_id = pb.community_id; } if (ctx.traefik != null) { def t = ctx.traefik; ctx.event.sensor = 'traefik'; ctx.event.category = 'http_request'; if (t.ClientHost != null && t.ClientHost != '') ctx.source.ip = t.ClientHost; if (t.RequestPath != null) { if (ctx.url == null) ctx.url = new HashMap(); ctx.url.path = t.RequestPath; } if (t.RequestHost != null) { if (ctx.url == null) ctx.url = new HashMap(); ctx.url.domain = t.RequestHost; } if (t.RequestMethod != null) { if (ctx.http == null) ctx.http = new HashMap(); if (ctx.http.request == null) ctx.http.request = new HashMap(); ctx.http.request.method = t.RequestMethod; } if (t.DownstreamStatus != null) { if (ctx.http == null) ctx.http = new HashMap(); if (ctx.http.response == null) ctx.http.response = new HashMap(); ctx.http.response.status_code = t.DownstreamStatus; } if (t.RequestProtocol != null) ctx.network.protocol = t.RequestProtocol; if (t['request_User-Agent'] != null) { if (ctx.user_agent == null) ctx.user_agent = new HashMap(); ctx.user_agent.original = t['request_User-Agent']; } if (t.ClientAddr != null && params.public_ip != null && params.public_ip != '' && t.entryPointName != null && params.entrypoint_ports.containsKey(t.entryPointName)) { String ca = t.ClientAddr.toString(); int ci = ca.lastIndexOf(':'); if (ci > 0) { String wip = ca.substring(0, ci); String wport = ca.substring(ci + 1); try { t.wire_src_ip = wip; t.wire_src_port = Integer.parseInt(wport); t.wire_dst_ip = params.public_ip; t.wire_dst_port = params.entrypoint_ports.get(t.entryPointName); t.wire_transport = 'tcp'; } catch (Exception e) {} } } } if (ctx.zeek != null) { def z = ctx.zeek; ctx.event.sensor = (ctx.logset != null && ctx.logset == 'zeek-proxy') ? 'zeek-proxy' : 'zeek'; if (z['id.orig_h'] != null && ctx.network.relay_ip == null) ctx.source.ip = z['id.orig_h']; if (z['id.orig_p'] != null) { if (ctx.source == null) ctx.source = new HashMap(); ctx.source.port = z['id.orig_p']; } if (z['id.resp_h'] != null) ctx.destination.ip = z['id.resp_h']; if (z['id.resp_p'] != null) ctx.destination.port = z['id.resp_p']; if (z.proto != null) ctx.network.transport = z.proto; if (z.service != null) ctx.network.protocol = z.service; if (z.community_id != null && z.community_id != '') ctx.network.community_id = z.community_id; if (z.uid != null && z.uid != '') ctx.network.session_id = z.uid; if (z.orig_ip_bytes instanceof Number) ctx.source.bytes = z.orig_ip_bytes; else if (z.orig_bytes instanceof Number) ctx.source.bytes = z.orig_bytes; if (z.resp_ip_bytes instanceof Number) ctx.destination.bytes = z.resp_ip_bytes; else if (z.resp_bytes instanceof Number) ctx.destination.bytes = z.resp_bytes; if (z.orig_pkts instanceof Number) ctx.source.packets = z.orig_pkts; if (z.resp_pkts instanceof Number) ctx.destination.packets = z.resp_pkts; if (ctx.source.bytes != null || ctx.destination.bytes != null) { long sb = ctx.source.bytes == null ? 0L : ((Number)ctx.source.bytes).longValue(); long db = ctx.destination.bytes == null ? 0L : ((Number)ctx.destination.bytes).longValue(); ctx.network.bytes = sb + db; } if (ctx.source.packets != null || ctx.destination.packets != null) { long sp = ctx.source.packets == null ? 0L : ((Number)ctx.source.packets).longValue(); long dp = ctx.destination.packets == null ? 0L : ((Number)ctx.destination.packets).longValue(); ctx.network.packets = sp + dp; } if (ctx.event.category == null && ctx.log != null && ctx.log.file != null && ctx.log.file.path != null) { String zp = ctx.log.file.path; int zs = zp.lastIndexOf('/'); String zb = zs >= 0 ? zp.substring(zs + 1) : zp; int zd = zb.indexOf('.'); if (zd > 0) zb = zb.substring(0, zd); ctx.event.category = zb; } if (ctx.network.transport == null && ctx.event.category != null && params.zeek_tcp_logs.contains(ctx.event.category)) { ctx.network.transport = 'tcp'; } } if (ctx.huginn != null) { def hg = ctx.huginn; ctx.event.sensor = 'huginn'; if (hg.kind != null) ctx.event.category = hg.kind; String hsip = hg.src_ip; String hdip = hg.dst_ip; def hsport = hg.src_port; def hdport = hg.dst_port; if (hsip != null && params.home_net.contains(hsip) && hdip != null && !params.home_net.contains(hdip)) { String tmp = hsip; hsip = hdip; hdip = tmp; def tmpp = hsport; hsport = hdport; hdport = tmpp; } if (hsip != null && hsip != '') ctx.source.ip = hsip; if (hsport != null) ctx.source.port = hsport; if (hdip != null && hdip != '') ctx.destination.ip = hdip; if (hdport != null) ctx.destination.port = hdport; if (hg.proto != null) ctx.network.transport = hg.proto; if (hg.community_id != null && hg.community_id != '') ctx.network.community_id = hg.community_id; } if (ctx.source.ip != null) { String fsip = ctx.source.ip.toString(); if (is_fleet(fsip, params.home_net)) { if (ctx.honeypot != null && ctx.honeypot.fleet_peer == null && fsip != '') ctx.honeypot.fleet_peer = fsip; ctx.source.remove('ip'); } }"
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "description": "#1970: promote each sensor's correlation fingerprint into one typed (fingerprint.kind, fingerprint.value) envelope pair. Honeypot documents mirror dashboard-side pivots_from_source (backend-service/src/events.rs)'s exact precedence: honeypot.canonical_fingerprint first (carrying its canonical_fingerprint_kind, falling back to kind 'fingerprint' when the worker wrote one without the other), then hassh -> HASSH, fingerprint -> SSH pubkey, client -> client banner, user_agent -> User-Agent -- so a pre-promotion document classifies identically read-time vs ingest-side. Suricata TLS promotes ja4 over ja3.hash (same precedence charts.rs' TLS-fingerprint chart reads), JA3 falls back to the ja3.hash md5 rather than the ja3 string blob; suricata.eve.http.http_user_agent keeps the User-Agent kind alive on IDS HTTP records. portbridge.os becomes kind 'p0f OS'. Stripped or empty source values write NOTHING (no empty-string pollution) exactly like classify()'s absent-property degrade, and one document carries at most one fingerprint kind -- the same collapse semantics every consumer already assumed. Field shapes verified live before writing this (#1295/#1611 rule): honeypot.hassh is a bare md5 hex string, suricata.eve.tls.ja3 an OBJECT {string, hash}, ja4 a plain keyword-length string, portbridge.os a plain p0f label.",
        "source": "void put_fingerprint(def c, def k, def v) { if (c == null || k == null || v == null) { return; } String kd = k.toString(); String val = v.toString(); if (kd == '' || val == '') { return; } if (c.fingerprint == null) { c.fingerprint = new HashMap(); } c.fingerprint.kind = kd; c.fingerprint.value = val; } if (ctx.honeypot != null) { def h = ctx.honeypot; if (h.canonical_fingerprint != null && h.canonical_fingerprint.toString() != '') { if (h.canonical_fingerprint_kind != null && h.canonical_fingerprint_kind.toString() != '') { put_fingerprint(ctx, h.canonical_fingerprint_kind, h.canonical_fingerprint); } else { put_fingerprint(ctx, 'fingerprint', h.canonical_fingerprint); } } else if (h.hassh != null && h.hassh.toString() != '') { put_fingerprint(ctx, 'HASSH', h.hassh); } else if (h.fingerprint != null && h.fingerprint.toString() != '') { put_fingerprint(ctx, 'SSH pubkey', h.fingerprint); } else if (h.client != null && h.client.toString() != '') { put_fingerprint(ctx, 'client banner', h.client); } else if (h.user_agent != null && h.user_agent.toString() != '') { put_fingerprint(ctx, 'User-Agent', h.user_agent); } } if (ctx.suricata != null && ctx.suricata.eve != null) { def s = ctx.suricata.eve; if (s.tls != null) { if (s.tls.ja4 != null && s.tls.ja4.toString() != '') { put_fingerprint(ctx, 'JA4', s.tls.ja4); } else if (s.tls.ja3 != null && s.tls.ja3.hash != null && s.tls.ja3.hash.toString() != '') { put_fingerprint(ctx, 'JA3', s.tls.ja3.hash); } } else if (s.http != null && s.http.http_user_agent != null && s.http.http_user_agent.toString() != '') { put_fingerprint(ctx, 'User-Agent', s.http.http_user_agent); } } if (ctx.portbridge != null) { def pb = ctx.portbridge; if (pb.os != null && pb.os.toString() != '') { put_fingerprint(ctx, 'p0f OS', pb.os); } }"
      }
    },
    {
      "community_id": {
        "description": "#1765: Traefik's join key must describe the WIRE, not the logical client. source.ip is ClientHost -- the client Traefik resolved after applying forwardedHeaders trust -- which is the right attacker identity but is NOT what a passive sniffer saw when the request came through a proxy. The wire tuple built above uses ClientAddr (the address the connection was actually accepted from) against the VPS's own address and the entrypoint's port, so a Traefik request and huginn-sidecar's tls_client observation for the same TLS connection land on the same key. Runs before the generic processor below, which would otherwise fill this field from source.ip and produce a key matching nothing whenever the two differ -- exactly the Cloudflare case.",
        "source_ip": "traefik.wire_src_ip",
        "source_port": "traefik.wire_src_port",
        "destination_ip": "traefik.wire_dst_ip",
        "destination_port": "traefik.wire_dst_port",
        "transport": "traefik.wire_transport",
        "ignore_missing": true,
        "ignore_failure": true,
        "if": "ctx.traefik != null && ctx.traefik.wire_src_ip != null"
      }
    },
    {
      "community_id": {
        "description": "#1742: derive network.community_id for any record that has a 5-tuple but no key of its own -- Zeek's ~20 protocol logs (ssl, ssh, http, the ICSNPP ones) carry uid but only conn.log carries community_id, so without this a fingerprint in ssl.log needs two hops (session_id -> conn -> community_id) to reach Suricata, portbridge or huginn. Elasticsearch computes the same v1 hash natively, so this needs no Zeek scripting and cannot drift from the Go and Rust implementations. Seed 0 to match suricata.yaml. Runs after the script processor above, which is what populates source/destination/network.transport from the raw namespaces.",
        "ignore_missing": true,
        "ignore_failure": true,
        "if": "ctx.network == null || ctx.network.community_id == null"
      }
    },
    {
      "geoip": {
        "field": "suricata.eve.src_ip",
        "target_field": "source.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "suricata.eve.src_ip",
        "target_field": "source.as",
        "database_file": "GeoLite2-ASN.mmdb",
        "properties": ["asn", "organization_name"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "suricata.eve.dest_ip",
        "target_field": "destination.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "description": "#3560: keyed on the promoted source.ip (not honeypot.src_ip), so an attacker address promoted out of dionaea's nested remote_ip is geolocated too. Must stay after the first script processor, which does the promotion.",
        "field": "source.ip",
        "if": "ctx.honeypot != null",
        "target_field": "source.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "source.ip",
        "if": "ctx.honeypot != null",
        "target_field": "source.as",
        "database_file": "GeoLite2-ASN.mmdb",
        "properties": ["asn", "organization_name"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "portbridge.src_ip",
        "target_field": "source.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "portbridge.src_ip",
        "target_field": "source.as",
        "database_file": "GeoLite2-ASN.mmdb",
        "properties": ["asn", "organization_name"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "description": "#354: dionaea's captured-payload hash only exists inside dionaea_incident.json's raw message text -- that input is deliberately kept unparsed by filebeat (different incident origins reuse the same data keys with incompatible value types, and dynamically expanding them caused Elasticsearch mapping rejections; see filebeat.yml's dionaea-incidents-raw-v1 comment). Rather than parsing the whole heterogeneous document, this pulls out only a hash-shaped value by plain string scanning (no Painless regex, which is disabled by default) -- sha256/sha256hash preferred (64 hex chars), md5hash/md5 as the fallback dionaea actually emits today (32 hex chars). A trailing closing-quote check guards against matching a decoy substring or a truncated value.",
        "source": "if (ctx.message != null) { String msg = ctx.message; String key = null; int hashLen = 0; boolean isMd5 = false; if (msg.indexOf('\"sha256\"') >= 0) { key = '\"sha256\"'; hashLen = 64; } else if (msg.indexOf('\"sha256hash\"') >= 0) { key = '\"sha256hash\"'; hashLen = 64; } else if (msg.indexOf('\"md5hash\"') >= 0) { key = '\"md5hash\"'; hashLen = 32; isMd5 = true; } else if (msg.indexOf('\"md5\"') >= 0) { key = '\"md5\"'; hashLen = 32; isMd5 = true; } if (key != null) { int i = msg.indexOf(key) + key.length(); while (i < msg.length() && (msg.charAt(i) == (char)' ' || msg.charAt(i) == (char)':')) { i++; } if (i < msg.length() && msg.charAt(i) == (char)'\"') { i++; if (i + hashLen <= msg.length()) { String candidate = msg.substring(i, i + hashLen); boolean valid = true; for (int j = 0; j < candidate.length(); j++) { char c = candidate.charAt(j); if (!((c >= (char)'0' && c <= (char)'9') || (c >= (char)'a' && c <= (char)'f') || (c >= (char)'A' && c <= (char)'F'))) { valid = false; break; } } if (valid && i + hashLen < msg.length() && msg.charAt(i + hashLen) == (char)'\"') { if (ctx.file == null) ctx.file = new HashMap(); if (ctx.file.hash == null) ctx.file.hash = new HashMap(); if (isMd5) { ctx.file.hash.md5 = candidate.toLowerCase(); } else { ctx.file.hash.sha256 = candidate.toLowerCase(); } } } } } }"
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "source": "if (ctx.source != null && ctx.source.as != null && ctx.source.as.organization_name != null) { String o = ctx.source.as.organization_name.toLowerCase(); String t = 'network'; if (o.contains('censys') || o.contains('shadowserver') || o.contains('binaryedge') || o.contains('securitytrails') || o.contains('shodan')) t = 'scanner'; else if (o.contains('amazon') || o.contains('google cloud') || o.contains('microsoft') || o.contains('azure') || o.contains('digitalocean') || o.contains('oracle cloud') || o.contains('linode') || o.contains('vultr') || o.contains('cloudflare')) t = 'cloud'; else if (o.contains('hosting') || o.contains('server') || o.contains('datacenter') || o.contains('hetzner') || o.contains('ovh') || o.contains('leaseweb')) t = 'hosting'; ctx.source.as.type = t; }"
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "description": "#238/#416: flags JNDI/Log4Shell injection attempts across every sensor's captured free-text fields (concatenates every string value under honeypot.*, so this covers path/body/user_agent/headers/command/etc. uniformly without hardcoding field names per sensor -- automatically covers future sensors too). Deobfuscates Log4j lookup-based evasion first (nested lookup tricks like lower:j + ndi splitting the word jndi across sub-expressions, which a naive substring check for the literal jndi prefix would miss) -- ported from Log4Pot's deobfuscator.py (detection only, not its payloader.py, which actively downloads the attacker's LDAP/RMI callback payload; that outbound fetch is a distinct, larger decision out of scope here). depth is a hard recursion cap (25) and blob length is capped at 8192 chars -- both defend against a crafted pathological input causing runaway recursion/allocation on the ingest node, which the original Python implementation does not bound.",
        "source": "String deobfuscate(String expr, int depth) { if (depth > 25) { return expr; } if (expr.startsWith('${')) { int posEnd = expr.indexOf('}'); if (posEnd == -1) { return expr; } int posLookup = expr.indexOf('${', 2); if (posLookup != -1 && posLookup < posEnd) { return deobfuscate(expr.substring(0, posLookup) + deobfuscate(expr.substring(posLookup, posEnd + 1), depth + 1) + deobfuscate(expr.substring(posEnd + 1), depth + 1), depth + 1); } int posColon = expr.indexOf(':'); if (posColon == -1) { return expr; } String lookupType = expr.substring(2, posColon).toLowerCase(); int posValue = -1; int posValueRaw = expr.indexOf(':-'); if (posValueRaw != -1) { posValue = posValueRaw + 2; } if (lookupType.equals('jndi')) { return '${jndi' + expr.substring(6); } if (lookupType.equals('lower')) { return expr.substring(posColon + 1, posEnd).toLowerCase() + deobfuscate(expr.substring(posEnd + 1), depth + 1); } if (lookupType.equals('upper')) { return expr.substring(posColon + 1, posEnd).toUpperCase() + deobfuscate(expr.substring(posEnd + 1), depth + 1); } if (posValue != -1 && posValue < posEnd) { return expr.substring(posValue, posEnd) + deobfuscate(expr.substring(posEnd + 1), depth + 1); } return expr.substring(posColon + 1, posEnd) + deobfuscate(expr.substring(posEnd + 1), depth + 1); } int posExpr = expr.indexOf('${'); if (posExpr == -1) { return expr; } return expr.substring(0, posExpr) + deobfuscate(expr.substring(posExpr), depth + 1); } if (ctx.honeypot != null) { StringBuilder sb = new StringBuilder(); for (def v : ctx.honeypot.values()) { if (v instanceof String) { sb.append((String) v).append(' '); } } String blob = sb.toString(); if (blob.length() > 0 && blob.length() < 8192 && blob.indexOf('${') >= 0) { String result = deobfuscate(blob, 0); if (result.toLowerCase().indexOf('${jndi:') >= 0) { if (ctx.event == null) { ctx.event = new HashMap(); } ctx.event.log4shell = true; } } }"
      }
    }
  ]
}
JSON
)"
curl -fsS -X PUT "$es_url/_ingest/pipeline/geoip-honeypot" \
  -H 'Content-Type: application/json' \
  --data-binary "$(printf '%s' "$geoip_pipeline_body" \
      | sed "s#__ES_HOME_NET_JSON__#$es_home_net_json#" \
      | sed "s#__ES_PUBLIC_IP__#$es_public_ip#")" >/dev/null

echo

# Sensor formats are intentionally heterogeneous. Mapping the complete source
# object as `flattened` keeps every key/value searchable without allowing one
# sensor's value type to reject another sensor's event.
#
# ignore_above:32000 on the flattened `honeypot` field below (#1295/#1296):
# this template's own comment used to claim honeypot-v2-*'s per-sensor
# values were "short... never hit this" limit, unlike the analysis-results
# indices further down (which got ignore_above back on 2026-08-02, see that
# block's own comment). Found live (#1295) that claim is false: a real
# MSSQL CLR-assembly RCE attempt (CREATE ASSEMBLY ... FROM 0x<hex-encoded
# PE>) landed a multi-hundred-KB command string in honeypot.command, which
# Elasticsearch's flattened type rejected outright -- not just that one
# leaf, the *entire document* -- since flattened stores each leaf as a
# single Lucene keyword term (32766-byte hard limit) with no ignore_above
# set. Confirmed live: 66/66 documents in dead-letter-honeypot as of #1295
# trace to exactly this failure mode, 33 of them this field. ignore_above
# makes ES skip *indexing* (not storing) an overlong leaf instead -- still
# present and returned in _source/the document view, just not
# term-searchable past 32000 bytes -- so the document is never lost again.
#
# #1611 workstream F: user.password and top-level held_ms are new typed
# copies the geoip-honeypot pipeline above now writes alongside the
# existing user.name/process.command_line/url.path copies -- same "flattened
# leaf has no stats/range/wildcard support" problem, same fix (copy at
# ingest into a real typed field rather than migrate the flattened blob
# itself). held_ms backs a genuine ES range aggregation on the endlessh
# chart (charts.rs); user.password backs future prefix/wildcard credential
# hunting the way user.name already does. Only applies going forward --
# the pipeline can't rewrite documents already indexed, and the datastream
# rolls daily, so coverage is effectively immediate for new data.
# #1970: honeypot-v2-* gains the same typed fingerprint pair every other raw
# family maps below -- at ingest one document's correlation identity lands as
# top-level fingerprint.kind/fingerprint.value keywords (the promotion script
# in geoip-honeypot above mirrors events.rs pivots_from_source's precedence),
# so terms aggs stop depending on either a flattened leaf (honeypot.* has no
# stats/cardinality niceties) or the dashboard process running at all.
# ignore_above matches traefik-access' user_agent.original convention: a
# User-Agent value past 1024 bytes is attack junk, not an identity, and would
# otherwise be a rejected-document term-limit hazard (the #1295 failure mode).
curl -fsS -X PUT "$es_url/_index_template/honeypot-events-v2" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["honeypot-v2-*"],
  "priority": 500,
  "data_stream": {},
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "honeypot-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 2000,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "honeypot": { "type": "flattened", "ignore_above": 32000 },
        "sensor": { "type": "keyword" },
        "event_format": { "type": "keyword" },
        "logset": { "type": "keyword" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" }, "kind": { "type": "keyword" } } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
          "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
        } },
        "destination": { "properties": { "ip": { "type": "ip", "ignore_malformed": true }, "port": { "type": "integer", "ignore_malformed": true } } },
        "network": { "properties": { "transport": { "type": "keyword" }, "protocol": { "type": "keyword" }, "community_id": { "type": "keyword" } } },
        "fingerprint": { "properties": { "kind": { "type": "keyword" }, "value": { "type": "keyword", "ignore_above": 1024 } } },
        "user": { "properties": { "name": { "type": "keyword" }, "password": { "type": "keyword" } } },
        "process": { "properties": { "command_line": { "type": "wildcard" } } },
        "url": { "properties": { "path": { "type": "wildcard" } } },
        "file": { "properties": { "hash": { "properties": { "sha256": { "type": "keyword" }, "md5": { "type": "keyword" } } } } },
        "ot": { "properties": { "persona": { "type": "keyword" }, "protocol": { "type": "keyword" } } },
        "held_ms": { "type": "long", "ignore_malformed": true }
      }
    }
  }
}
JSON

# Suricata's protocol-specific daily indices can be high volume. Keep their
# mappings permissive but bounded, and retain seven days of raw IDS telemetry.
#
# #1970: JA3 (the ja3.hash md5, not the string blob) / JA4 from suricata.eve.tls.*
# and the HTTP User-Agent from suricata.eve.http.* are promoted to the typed
# fingerprint.kind/value pair at ingest (geoip-honeypot processor above) --
# today charts.rs reaches ja4 only through the accidental dynamic
# text+.keyword mapping (`suricata.eve.tls.ja4.keyword`), which no template ever
# declared. Same pair the honeypot and portbridge templates map, so one terms
# agg correlates fingerprints across all three raw families.
curl -fsS -X PUT "$es_url/_index_template/suricata-events" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["suricata-*"],
  "priority": 400,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "suricata-7d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 5000,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "10s"
    },
    "mappings": { "properties": {
      "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
      "source": { "properties": {
        "ip": { "type": "ip", "ignore_malformed": true },
        "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
        "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
      } },
      "destination": { "properties": {
        "ip": { "type": "ip", "ignore_malformed": true },
        "port": { "type": "integer", "ignore_malformed": true },
        "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } }
      } },
      "network": { "properties": { "transport": { "type": "keyword" }, "protocol": { "type": "keyword" }, "community_id": { "type": "keyword" } } },
      "fingerprint": { "properties": { "kind": { "type": "keyword" }, "value": { "type": "keyword", "ignore_above": 1024 } } }
    } }
  }
}
JSON

# #166: destination.geo.location was previously left to dynamic mapping here
# (unlike source.geo.location just above), so it came in as a plain
# {lat,lon} float object instead of geo_point on every live suricata-*
# index -- destination-side geo queries/map visualizations silently
# couldn't use it. A separate, untracked template ('suricata-field-limit',
# lower priority, never applied) had the correct destination.geo.location
# mapping and nothing else useful; folded that fix in here instead of
# keeping two templates for one setting. Existing indices keep their old
# dynamic mapping until suricata-7d ILM rolls them off; only new indices
# pick this up.

# #354: portbridge tunnel-connection records (real attacker IP, honeypot
# port, p0f OS guess), shipped to ES for the first time -- previously
# local-disk-only (dashboard/classify.go's buildViaMap). The geoip-honeypot
# pipeline's normalization script promotes portbridge.src_ip into the same
# source.ip / event.sensor ECS envelope honeypot-v2-* and suricata-* use, so
# a single query across honeypot-v2-*,suricata-*,portbridge-v2-* for one
# source.ip returns every correlated record for that IP in one pass -- no
# per-index-family join needed. Plain daily indices like suricata-events
# (not a data stream like honeypot-events-v2): portbridge's volume doesn't
# need rollover, and this keeps the simpler index-per-day model.
#
# #1970: the p0f OS guess is promoted at ingest into the typed fingerprint
# pair (kind 'p0f OS') -- fusion.rs' attacker-fusion table reads it from the
# flattened portbridge.* blob today, invisible to anything that does not
# re-parse per-sensor shapes. Same mapping block the honeypot and suricata
# templates carry.
curl -fsS -X PUT "$es_url/_index_template/portbridge-events" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["portbridge-v2-*"],
  "priority": 470,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "portbridge-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 200,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "portbridge": { "type": "flattened" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
          "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
        } },
        "destination": { "properties": { "port": { "type": "integer", "ignore_malformed": true } } },
        "network": { "properties": { "transport": { "type": "keyword" }, "community_id": { "type": "keyword" } } },
        "fingerprint": { "properties": { "kind": { "type": "keyword" }, "value": { "type": "keyword", "ignore_above": 1024 } } }
      }
    }
  }
}
JSON

# #1742/S5: Zeek and huginn-sidecar records. Both are kept -- they are not
# alternatives. Measured on the same web traffic, Zeek logged 4 ssl.log
# records where the sidecar produced 29 tls_client ones, because Zeek needs a
# completed handshake and stream reassembly while huginn-net fingerprints the
# ClientHello packet on its own. On scan traffic that never completes a
# handshake the packet-oriented view sees more; on traffic that does complete,
# Zeek carries far more per record. Neither is a superset, so both ship.
#
# Joining: network.community_id is the key across every sensor. Zeek writes it
# only on conn.log, so the community_id ingest processor below derives it for
# the protocol logs from the 5-tuple they already carry -- Elasticsearch
# computes the same v1 hash natively, which also means it cannot drift from
# the Go and Rust implementations. Verified against real data: four ssl.log
# records resolve to exactly the community_id Zeek computed for their own conn
# record.
#
# network.session_id (Zeek's uid) is still promoted and still useful -- it is
# what ties a file, a certificate or an ICS transaction back to its specific
# connection record, which community_id alone cannot do when one flow carries
# several.
#
# zeek-v1-* retention deliberately matches the pcap window rather than
# Suricata's shorter one. Zeek is the highest-volume producer here, but an
# investigation that has the packets and not the metadata -- or the reverse --
# is worse off than one missing both, because it can see that something
# happened and not what. Zeek metadata runs roughly 1-2 GB/day against pcap's
# ~13.8, so matching the window is cheap relative to what it protects.
curl -fsS -X PUT "$es_url/_index_template/zeek-events" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": [
    "zeek-v1-*",
    "zeek-proxy-v1-*"
  ],
  "priority": 470,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "zeek-60d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 500,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "zeek": {
          "type": "flattened"
        },
        "event": {
          "properties": {
            "sensor": {
              "type": "keyword"
            },
            "category": {
              "type": "keyword"
            }
          }
        },
        "source": {
          "properties": {
            "ip": {
              "type": "ip",
              "ignore_malformed": true
            },
            "port": {
              "type": "integer",
              "ignore_malformed": true
            },
            "geo": {
              "properties": {
                "location": {
                  "type": "geo_point"
                },
                "country_iso_code": {
                  "type": "keyword"
                },
                "city_name": {
                  "type": "keyword"
                }
              }
            },
            "as": {
              "properties": {
                "asn": {
                  "type": "long"
                },
                "organization_name": {
                  "type": "keyword"
                },
                "type": {
                  "type": "keyword"
                }
              }
            },
            "bytes": {
              "type": "long"
            },
            "packets": {
              "type": "long"
            }
          }
        },
        "destination": {
          "properties": {
            "ip": {
              "type": "ip",
              "ignore_malformed": true
            },
            "port": {
              "type": "integer",
              "ignore_malformed": true
            },
            "bytes": {
              "type": "long"
            },
            "packets": {
              "type": "long"
            }
          }
        },
        "network": {
          "properties": {
            "transport": {
              "type": "keyword"
            },
            "protocol": {
              "type": "keyword"
            },
            "community_id": {
              "type": "keyword"
            },
            "session_id": {
              "type": "keyword"
            },
            "bytes": {
              "type": "long"
            },
            "packets": {
              "type": "long"
            }
          }
        }
      }
    }
  }
}
JSON

# The decoy-side sensor (#1742 decision 8) reuses the Zeek mapping but gets its
# own template so it can carry its own ILM policy -- and so a query can tell
# the two vantage points apart. Higher priority than zeek-events, whose
# pattern also matches, because the more specific one must win.
# #3570: source.as.* (written by geoip-honeypot) must be mapped explicitly,
# as the zeek-events template does. Left to dynamic mapping, the geoip
# processor's string output became `text` in zeek-proxy-v1-conn-2026.10.01
# and any terms agg on source.as.type failed that shard. Applies to indices
# created after this template is PUT; existing ones are not touched.
curl -fsS -X PUT "$es_url/_index_template/zeek-proxy-events" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["zeek-proxy-v1-*"],
  "priority": 480,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "zeek-proxy-60d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 500,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "zeek": { "type": "flattened" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "port": { "type": "integer", "ignore_malformed": true },
          "geo": { "properties": {
            "location": { "type": "geo_point" },
            "country_iso_code": { "type": "keyword" },
            "city_name": { "type": "keyword" }
          } },
          "as": { "properties": {
            "asn": { "type": "long" },
            "organization_name": { "type": "keyword" },
            "type": { "type": "keyword" }
          } }
        } },
        "destination": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "port": { "type": "integer", "ignore_malformed": true }
        } },
        "network": { "properties": {
          "transport": { "type": "keyword" },
          "protocol": { "type": "keyword" },
          "community_id": { "type": "keyword" },
          "session_id": { "type": "keyword" },
          "relay_ip": { "type": "ip", "ignore_malformed": true },
          "community_id_attacker": { "type": "keyword" },
          "relay_unresolved": { "type": "boolean" }
        } }
      }
    }
  }
}
JSON

# #1738 decision 5: the bytes of wire-extracted files, not just their hashes.
#
# The ES store is the record and local disk is transient, so an artefact has
# to survive the VPS being wiped or rebuilt -- which disk-only storage does
# not. Bounded by the extraction policy's own 16 MB per-file cap, so this
# index cannot grow faster than that policy allows.
#
# Stated plainly because it is unusual: this puts attacker-controlled binaries
# inside the search cluster. They are stored as `binary`, which Elasticsearch
# accepts as base64 and does NOT index, analyse or make searchable -- the
# bytes are retrievable and nothing more, with doc_values off so they never
# enter the columnar store either. Nothing in the pipeline decompresses or
# executes them. The searchable half is the metadata beside them: hashes, mime
# type, size, and the connection this came from.
curl -fsS -X PUT "$es_url/_index_template/extracted-files" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["extracted-files-v1-*"],
  "priority": 470,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "extracted-files-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 100,
      "index.refresh_interval": "30s"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
        "file": { "properties": {
          "hash": { "properties": {
            "sha256": { "type": "keyword" },
            "md5": { "type": "keyword" },
            "sha1": { "type": "keyword" }
          } },
          "size": { "type": "long" },
          "mime_type": { "type": "keyword" },
          "source": { "type": "keyword" },
          "extracted_name": { "type": "keyword" },
          "bytes": { "type": "binary", "doc_values": false }
        } },
        "network": { "properties": {
          "community_id": { "type": "keyword" },
          "session_id": { "type": "keyword" },
          "transport": { "type": "keyword" }
        } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "port": { "type": "integer", "ignore_malformed": true },
          "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" } } },
          "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" } } }
        } },
        "destination": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "port": { "type": "integer", "ignore_malformed": true }
        } }
      }
    }
  }
}
JSON

curl -fsS -X PUT "$es_url/_index_template/huginn-events" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["huginn-v1-*"],
  "priority": 470,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "huginn-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 300,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "huginn": { "type": "flattened" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "port": { "type": "integer", "ignore_malformed": true },
          "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
          "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
        } },
        "destination": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "port": { "type": "integer", "ignore_malformed": true }
        } },
        "network": { "properties": { "transport": { "type": "keyword" }, "community_id": { "type": "keyword" } } }
      }
    }
  }
}
JSON

# #1739: Traefik access records. Traefik terminates TLS for the Host-routed
# decoys, so this is the only index that holds their requests in cleartext --
# no wire sensor can read them.
#
# ClientHost and ClientAddr are mapped separately and neither is promoted to
# source.ip by default. ClientAddr is the address Traefik actually accepted the
# connection from; ClientHost is what it resolved as the client after applying
# forwardedHeaders trust. Those differ exactly when a request came through a
# trusted proxy, and conflating them is how #1715 wrote a tunnel address into
# a recording's attacker IP. Keep both, decide downstream.
curl -fsS -X PUT "$es_url/_index_template/traefik-access" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["traefik-v1-*"],
  "priority": 470,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "traefik-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 300,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "traefik": { "type": "flattened" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
          "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
        } },
        "url": { "properties": { "path": { "type": "keyword" }, "domain": { "type": "keyword" } } },
        "http": { "properties": {
          "request": { "properties": { "method": { "type": "keyword" } } },
          "response": { "properties": { "status_code": { "type": "integer" } } }
        } },
        "user_agent": { "properties": { "original": { "type": "keyword", "ignore_above": 1024 } } },
        "network": { "properties": { "protocol": { "type": "keyword" }, "transport": { "type": "keyword" }, "community_id": { "type": "keyword" } } }
      }
    }
  }
}
JSON

# #1972 serving-tier app logs. The dashboard previously had no durable,
# searchable record of what its own HTTP tiers served -- backend-service
# logs vanished with each redeploy's json-file rotation (#1942's invisible
# auth failures were diagnosed from a container that no longer existed),
# so per-request lines now land on Elasticsearch via filebeat's
# dashboard-backend-app / dashboard-backend-mounted-app inputs.
#
# One template covers BOTH backend-service instances: they are the same
# image emitting the same nine fields; only the logset value distinguishes
# them at query time. Their records are pure request metadata -- method,
# path, status, duration, request.id -- plus service/level/event.category;
# nothing here is attacker-controlled beyond url.path, which is mapped as
# plain keyword exactly like traefik-access above (no analysis, capped by
# ignore_malformed on anything weird).
#
# Same index shape as every other family here: plain daily indices, not a
# data stream, delete-only ILM via dashboard-app-30d.
curl -fsS -X PUT "$es_url/_index_template/dashboard-backend-app" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["dashboard-backend-v1-*"],
  "priority": 468,
  "template": {
    "settings": {
      "index.lifecycle.name": "dashboard-app-30d",
      "index.number_of_replicas": 0,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "event": { "properties": { "category": { "type": "keyword" } } },
        "service": { "type": "keyword" },
        "level": { "type": "keyword" },
        "request.id": { "type": "keyword" },
        "http.request.method": { "type": "keyword" },
        "url.path": { "type": "keyword", "ignore_above": 1024 },
        "status_code": { "type": "integer" },
        "duration_ms": { "type": "long" }
      }
    }
  }
}
JSON

# The BFF tier's companion stream (filebeat input dashboard-bff-app): named
# outcomes, not per-request lines -- auth sign-in started/failed/completed
# and future recordNamedEvent call sites. reason carries the trimmed error
# string (#1942's diagnosis now possible months later); role is the closed
# set the auth layer assigns. Usernames are deliberately NOT among the
# emitted fields and therefore not in this mapping either (#1972's privacy
# note holds in both tiers' emitters).
curl -fsS -X PUT "$es_url/_index_template/dashboard-bff-app" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["dashboard-bff-v1-*"],
  "priority": 466,
  "template": {
    "settings": {
      "index.lifecycle.name": "dashboard-app-30d",
      "index.number_of_replicas": 0,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "event": { "properties": { "category": { "type": "keyword" }, "action": { "type": "keyword" } } },
        "service": { "type": "keyword" },
        "level": { "type": "keyword" },
        "reason": { "type": "keyword", "ignore_above": 256 },
        "role": { "type": "keyword" }
      }
    }
  }
}
JSON

# #565: dionaea's log_incident ihandler (dionaea_incident.json) -- every
# exploit/download/credential/lifecycle incident dionaea's core emits,
# across every enabled service (SMB/SIP/UPnP/TFTP/etc). Confirmed directly
# against upstream dionaea/lib/dionaea/python/dionaea/log_incident.py's
# handle_incident(): every record is exactly {timestamp, name, origin,
# data} -- the first three consistent across every incident, `data` not
# (different origins reuse the same keys with incompatible value types,
# the reason analysis/filebeat.yml previously left this whole stream as an
# opaque `message` string). Same flattened-for-heterogeneous-keys approach
# honeypot-events-v2's own `honeypot` field already uses, so `data` becomes
# queryable/aggregatable (data.url:*, data.shasum, ...) without a mapping
# explosion. Own index (not folded into honeypot-v2-*): a different record
# shape entirely (top-level origin/data, not the honeypot.* envelope every
# other sensor writes), and dashboard/classify.go's own dionaea-incident
# handler (~line 427) reads this file directly off disk, unaffected either
# way -- this is purely an additive ES-only path. Plain daily indices, not
# a data stream, same reasoning as portbridge-events above.
#
# ignore_above:32000 on `data` below (#1295/#1296): same fix, same reason
# as honeypot-events-v2's `honeypot` field above -- confirmed live 33 of
# the 66 dead-lettered documents #1295 found were this field rejecting an
# oversized dionaea incident value (SMB exploit payloads routinely carry a
# multi-KB+ embedded binary blob in `data`).
curl -fsS -X PUT "$es_url/_index_template/dionaea-incidents" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["dionaea-incidents-v1-*"],
  "priority": 465,
  "template": {
    "settings": {
      "index.lifecycle.name": "dionaea-incidents-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 200,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "timestamp": { "type": "date" },
        "name": { "type": "keyword" },
        "origin": { "type": "keyword" },
        "data": { "type": "flattened", "ignore_above": 32000 }
      }
    }
  }
}
JSON

# #378: Ghidra/sandbox/GitHub-analysis/workbench-run results, ingested by
# analysis/es-results-importer/importer.py (previously local-disk-only JSON
# files, per the issue's gap analysis). Each result document is heterogeneous
# and fairly deep (Ghidra alone has functions/capa/floss/lief/revdeck
# sub-objects), so -- same call as honeypot-events-v2's `honeypot` field --
# the full result is mapped `flattened` under a source-namespaced field
# rather than hand-mapping every nested key, and only the handful of fields
# actually needed for filtering/sorting/cross-index correlation are promoted
# to real types. file.hash.sha256 uses the same ECS field
# honeypot-events-v2 already populates from Dionaea's shasum, so a single
# query across honeypot-v2-*,ghidra-analysis-v1,sandbox-analysis-v1,
# github-analysis-v1 for one hash returns the raw capture event and every
# analysis result for that sample in one pass. 180d retention (not 30d like
# raw events): a completed analysis report is the valuable, expensive-to-
# regenerate artifact, not high-volume raw telemetry. Plain single indices,
# not data streams -- importer overwrites by deterministic _id (sha256, job
# id, or run id) rather than appending, so there is nothing to roll over.
#
# ignore_above on the flattened field: found live (2026-08-02) importing real
# sandbox results -- flattened stores each leaf value as a Lucene keyword
# term, and sandbox.stdout/runner_log routinely carry multi-KB dmesg/boot
# output past Lucene's 32766-byte term limit, which fails the *entire*
# document, not just that one leaf. This comment used to claim
# honeypot-events-v2's own `honeypot` field never needed the same guard
# ("short per-sensor values only, never hit this") -- found live (#1295,
# 2026-08-12) that was wrong: a real MSSQL CLR-assembly RCE attempt landed
# a multi-hundred-KB command string there, dead-lettering the whole
# document. `honeypot` and dionaea-incidents' `data` both got the same
# ignore_above:32000 guard added above/below once this was found.
# ignore_above makes ES skip indexing (not storing) an overlong leaf
# instead -- still present and returned in _source/the document view, just
# not term-searchable.
for spec in \
  "ghidra-analysis-v1:ghidra" \
  "sandbox-analysis-v1:sandbox" \
  "github-analysis-v1:github_analysis" \
  "workbench-runs-v1:workbench" \
  "cape-analysis-v1:cape" \
  "revdeck-analysis-v1:revdeck" \
  "yara-analysis-v1:yara"
do
  index_name=${spec%%:*}
  ns=${spec#*:}
  curl -fsS -X PUT "$es_url/_index_template/${index_name%-v1}" \
    -H 'Content-Type: application/json' \
    --data-binary "$(cat <<JSON
{
  "index_patterns": ["${index_name}"],
  "priority": 460,
  "template": {
    "settings": {
      "index.lifecycle.name": "analysis-results-180d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 500,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "30s"
    },
    "mappings": {
      "properties": {
        "${ns}": { "type": "flattened", "ignore_above": 32000 },
        "@timestamp": { "type": "date" },
        "event": { "properties": { "category": { "type": "keyword" } } },
        "file": { "properties": { "hash": { "properties": { "sha256": { "type": "keyword" } } } } },
        "exit_status": { "type": "keyword" },
        "risk_level": { "type": "keyword" },
        "risk_score": { "type": "integer", "ignore_malformed": true },
        "family": { "type": "keyword" },
        "platform": { "type": "keyword" }
      }
    }
  }
}
JSON
)" >/dev/null
done

# #638/#763: Ghidra per-sample report HTML + call-graph SVG, mirrored by
# es-results-importer's own binary sources (ghidra_report_html/
# ghidra_callgraph_svg, importer.py) -- the two binary artifacts
# dashboard/ghidra.go used to os.Open straight off GHIDRA_RESULTS_DIR.
# Shares ghidra-analysis-v1's own 180d ILM policy (analysis-results-180d)
# rather than cowrie-ttylog-v1's "no ILM, keep forever" posture just below:
# unlike a TTY recording (operator-significant evidence in its own right),
# a report/callgraph is purely a derived attachment to its ghidra-
# analysis-v1 result and is meaningless on its own once that result has
# aged out, so it should expire on the same schedule as the result it
# belongs to, not outlive it.
curl -fsS -X PUT "$es_url/_index_template/ghidra-report-artifacts" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["ghidra-report-artifacts-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.lifecycle.name": "analysis-results-180d",
      "index.number_of_replicas": 0,
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 50
    },
    "mappings": {
      "properties": {
        "sha256": { "type": "keyword" },
        "kind": { "type": "keyword" },
        "filename": { "type": "keyword" },
        "content_type": { "type": "keyword" },
        "size_bytes": { "type": "long" },
        "imported_at": { "type": "date" },
        "data_base64": { "type": "binary" }
      }
    }
  }
}' >/dev/null

# #638/#764: sandbox export artifacts (guest/host PCAP, diagnostics ZIP),
# mirrored by es-results-importer's own chunked binary sources -- the
# artifacts dashboard/sandbox.go used to os.Open straight off
# sandboxResultsDirs(). Chunked because a single document (even base64'd
# generously the way the smaller ghidra-report-artifacts-v1 above does)
# can't hold a 64MB PCAP -- one document per chunk instead, doc _id
# "<job>:<kind>:<chunk_index>". Same 180d ILM as sandbox-analysis-v1 (its
# own template a few dozen lines up) for the same reasoning as
# ghidra-report-artifacts-v1's own comment above: these are derived
# attachments to that result, meaningless once it's aged out, not
# standalone evidence.
curl -fsS -X PUT "$es_url/_index_template/sandbox-export-artifacts" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["sandbox-export-artifacts-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.lifecycle.name": "analysis-results-180d",
      "index.number_of_replicas": 0,
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 50
    },
    "mappings": {
      "properties": {
        "job": { "type": "keyword" },
        "kind": { "type": "keyword" },
        "filename": { "type": "keyword" },
        "content_type": { "type": "keyword" },
        "chunk_index": { "type": "integer" },
        "total_chunks": { "type": "integer" },
        "size_bytes": { "type": "long" },
        "imported_at": { "type": "date" },
        "data_base64": { "type": "binary" }
      }
    }
  }
}' >/dev/null

# #494: dashboard-owned operational alert-rule state (campaign detection,
# stale sensor feeds, activity spikes, ES pipeline health, OT command
# detection, YARA hits, sandbox failures -- ack/cooldown bookkeeping, not
# sensor telemetry). Written directly by the dashboard itself via
# doc-level PUT (dashboard/elastic.go's docGet/docIndex), not through the
# Python importer's flattened-namespace pattern the analysis-results
# indices above use -- the whole small, low-cardinality record is mapped at
# the top level. No ILM policy: this is bookkeeping an operator's
# acknowledgment should not silently expire out from under them, and the
# record count is bounded by how many distinct alert keys the stack
# produces (dozens, not millions), not by event volume.
curl -fsS -X PUT "$es_url/_index_template/dashboard-alert-state" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-alert-state-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s"
    },
    "mappings": {
      "properties": {
        "Key": { "type": "keyword" },
        "Message": { "type": "text" },
        "Link": { "type": "keyword" },
        "FirstSeen": { "type": "date" },
        "LastSeen": { "type": "date" },
        "LastNotified": { "type": "date" },
        "Count": { "type": "integer" },
        "Acknowledged": { "type": "boolean" }
      }
    }
  }
}' >/dev/null

# #1147: dashboard-owned "Report a problem" button submissions. Append-only
# (one fresh document per report, deterministic _id per problem_reports.go),
# so this is a plain index like dashboard-alert-state-v1 above rather than a
# CAS-updated singleton doc like dashboard-config-v1 below. Captured content
# (action trail, console errors, API bodies, DOM snapshot) is heterogeneous
# and can legitimately be large, so it stays `flattened` -- same reasoning
# workbench-runs-v1 already uses above -- while the handful of fields an
# admin actually filters/sorts by (status, submitted_by, submitted_at) are
# promoted to real types. No ILM: an open bug report should not silently
# expire, same posture as dashboard-alert-state-v1.
curl -fsS -X PUT "$es_url/_index_template/dashboard-problem-reports" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-problem-reports-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s",
      "index.mapping.total_fields.limit": 100
    },
    "mappings": {
      "properties": {
        "id": { "type": "keyword" },
        "submitted_at": { "type": "date" },
        "submitted_by": { "type": "keyword" },
        "submitted_by_name": { "type": "keyword" },
        "page": { "type": "keyword" },
        "status": { "type": "keyword" },
        "expected": { "type": "text" },
        "actual": { "type": "text" },
        "action_trail": { "type": "flattened", "ignore_above": 32000 },
        "console_errors": { "type": "flattened", "ignore_above": 32000 },
        "network_failures": { "type": "flattened", "ignore_above": 32000 },
        "api_calls": { "type": "flattened", "ignore_above": 32000 },
        "dom_snapshot": { "type": "text" },
        "user_agent": { "type": "keyword" }
      }
    }
  }
}' >/dev/null

# #787: dashboard-config-v1 / dashboard-users-v1 / dashboard-reports-
# definitions-v1 -- singleton documents (one fixed id per index: "config",
# "users", "definitions") replacing what used to be local files on the
# dashboard's shared /state volume. Each replica cached its local file in
# memory forever after loading it once at startup, so a setting/preference/
# report-definition change made through one replica was invisible to the
# other until it was restarted -- confirmed live, this 404'd /agent-campaigns
# on every other page load once an admin toggled a feature flag. Moved to
# Elasticsearch, the one backend both replicas already treat as shared
# source of truth (dashboard/settings_store_es.go). Writers use compare-and-
# swap (docGet's _seq_no/_primary_term, dashboard/elastic.go), same idiom as
# dashboard-alert-state-v1 above; readers poll every few seconds instead of
# caching forever.
#
# payload is "flattened", not field-by-field like dashboard-workbench-runs-v1
# below: every read of these three documents is docGet by the fixed
# singleton id, never _search, so there's no query use case field-level
# mapping would serve -- while dashboardConfig's schema (settingsSchemaVersion
# already at 4) and the open-ended user/report-definition arrays would make
# explicit field mapping pure maintenance overhead with real mapping-conflict
# risk across schema revisions, for zero query benefit.
for dashboard_settings_index in dashboard-config-v1 dashboard-users-v1 dashboard-reports-definitions-v1; do
  curl -fsS -X PUT "$es_url/_index_template/${dashboard_settings_index}" \
    -H 'Content-Type: application/json' \
    --data-binary '{
  "index_patterns": ["'"${dashboard_settings_index}"'"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s"
    },
    "mappings": {
      "properties": {
        "schema_version": { "type": "integer" },
        "revision": { "type": "long" },
        "updated": { "type": "date" },
        "payload": { "type": "flattened", "ignore_above": 32000 }
      }
    }
  }
}' >/dev/null
done

# Static-analysis cache (payload_analysis.go's staticAnalysisFor): the pure-
# function-of-bytes half of a payload's analysis (hashes, entropy, extracted
# strings/IOCs, static risk score) -- content-hash keyed and immutable once
# written (the same bytes always produce the same analysis), unlike
# dashboard-alert-state-v1's mutable ack/cooldown records above, so this
# needs no seq_no/if_match update path, only get-or-create. Bounded by
# docIndexMaxBytes (2MB, dashboard/elastic.go) at write time -- this holds a
# capped preview/string-extraction summary, never raw payload bytes.
curl -fsS -X PUT "$es_url/_index_template/dashboard-static-analysis" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-static-analysis-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "Fingerprint": { "type": "keyword" },
        "Analysis": {
          "properties": {
            "SHA256": { "type": "keyword" },
            "MD5": { "type": "keyword" },
            "SHA1": { "type": "keyword" },
            "MIME": { "type": "keyword" },
            "ScriptType": { "type": "keyword" },
            "StaticRiskLevel": { "type": "keyword" },
            "StaticRiskScore": { "type": "integer" },
            "EntropyValue": { "type": "float" },
            "PackedLikely": { "type": "boolean" },
            "Truncated": { "type": "boolean" }
          }
        }
      }
    }
  }
}' >/dev/null

# Payload inventory (#483, payloads_data.go's scanPayloads/indexPayloadInventory):
# Elasticsearch is now the sole source /payloads reads from -- no local
# disk-scan fallback (see payloadInventoryIndex's own comment in
# payloads_data.go). Documents are the same capturedFile shape scanPayloads
# has always built, keyed by hash; Preview is a hex-dump of a capped 512-byte
# head, never raw payload bytes, backstopped by docIndexMaxBytes at write
# time. Every dashboard instance's own periodic disk scan indexes into this
# same index, so mount-path differences between instances don't affect what
# any instance serves.
curl -fsS -X PUT "$es_url/_index_template/dashboard-payload-inventory" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-payload-inventory-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "Hash": { "type": "keyword" },
        "Size": { "type": "long" },
        "Mtime": { "type": "keyword" },
        "MIME": { "type": "keyword" },
        "Kind": { "type": "keyword" },
        "KindCode": { "type": "keyword" },
        "Platform": { "type": "keyword" },
        "Dynamic": { "type": "boolean" },
        "Sources": { "type": "keyword" },
        "Copies": { "type": "integer" },
        "PreviewTruncated": { "type": "boolean" }
      }
    }
  }
}' >/dev/null

# Generated PDF reports (#475, reports_es.go): metadata plus the base64-
# encoded PDF bytes itself, so any dashboard instance can serve a
# previously generated report regardless of which instance produced it --
# unlike the payload/static-analysis indices above, this one legitimately
# stores a real binary artifact (a dashboard-generated document, not raw
# captured malware), hence the larger per-document size expectation
# (docIndexSized's own generatedReportMaxBytes cap, not the blanket 2MB
# docIndexMaxBytes bookkeeping-record guard). No ILM: retention is enforced
# by application-level pruning (reportStore.maxGenerated) instead of age,
# since an operator may want to keep an old report much longer than a fixed
# window suggests.
curl -fsS -X PUT "$es_url/_index_template/dashboard-generated-reports" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-generated-reports-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s",
      "index.mapping.total_fields.limit": 50
    },
    "mappings": {
      "properties": {
        "id": { "type": "keyword" },
        "definition_id": { "type": "keyword" },
        "name": { "type": "text" },
        "template": { "type": "keyword" },
        "theme": { "type": "keyword" },
        "title": { "type": "text" },
        "size_bytes": { "type": "long" },
        "created_at": { "type": "date" },
        "origin": { "type": "keyword" },
        "pdf_base64": { "type": "binary" }
      }
    }
  }
}' >/dev/null

# Cowrie TTY session recordings (#638/#612, es-results-importer's
# cowrie_ttylog source): the dashboard must not read these off the
# `/logs/cowrie/tty` bind mount (#611) directly either, so the importer
# base64-encodes each file straight into its own document here, keyed by
# the filename cowrie itself already renames the file to on session close
# (its own sha256 content hash, ttylog.py's ttylog_inputhash) -- naturally
# idempotent, a re-import of the same file overwrites the same doc rather
# than duplicating it, and no id_fields lookup is needed the way the
# JSON-payload indices above need one. No ILM: these are content-addressed,
# immutable once written, and operator-significant evidence -- the same
# "keep, don't age out" treatment #611 gave the raw file (no retention
# handling in log-maintenance.sh, matching cowrie's own downloads/ dir).
curl -fsS -X PUT "$es_url/_index_template/cowrie-ttylog" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["cowrie-ttylog-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 50
    },
    "mappings": {
      "properties": {
        "shasum": { "type": "keyword" },
        "size_bytes": { "type": "long" },
        "imported_at": { "type": "date" },
        "ttylog_base64": { "type": "binary" }
      }
    }
  }
}' >/dev/null

# Payload Workbench runs (#405 follow-up, workbench_es.go): the run's own
# document ID IS its idempotency key (workbenchIdempotency's deterministic
# hash of payload+recipe+analyzer selection, prefixed "run_"), so a duplicate
# submission is detected by an ES op_type=create 409 rather than a directory
# scan -- correct across multiple dashboard instances, unlike the single-
# process mutex this replaced. Mutable after creation (children transition
# queued -> running -> completed as async analyzers report back), so updates
# go through docGet/docIndex with if_seq_no/if_primary_term CAS, not create-
# only. No ILM: retention is enforced by workbenchMaxRuns at submission time,
# not by age.
curl -fsS -X PUT "$es_url/_index_template/dashboard-workbench-runs" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-workbench-runs-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "schema_version": { "type": "integer" },
        "id": { "type": "keyword" },
        "payload_sha256": { "type": "keyword" },
        "payload_kind": { "type": "keyword" },
        "owner": { "type": "keyword" },
        "recipe_id": { "type": "keyword" },
        "recipe_revision": { "type": "integer" },
        "recipe_name": { "type": "keyword" },
        "idempotency_key": { "type": "keyword" },
        "state": { "type": "keyword" },
        "created_at": { "type": "date" },
        "updated_at": { "type": "date" },
        "children": {
          "properties": {
            "analyzer_id": { "type": "keyword" },
            "display_name": { "type": "keyword" },
            "state": { "type": "keyword" },
            "reason": { "type": "text" },
            "summary": { "type": "text" },
            "result_url": { "type": "keyword" },
            "created_at": { "type": "date" },
            "updated_at": { "type": "date" },
            "deadline": { "type": "date" },
            "queue_deadline": { "type": "date" },
            "attempts": { "type": "integer" },
            "retryable": { "type": "boolean" },
            "cancelable": { "type": "boolean" },
            "detonates": { "type": "boolean" },
            "gpu_consuming": { "type": "boolean" },
            "local_only": { "type": "boolean" },
            "stale": { "type": "boolean" }
          }
        }
      }
    }
  }
}' >/dev/null

# Payload Workbench recipes (#405 follow-up, workbench_es.go): each revision
# is its own immutable ES document keyed "<id>:<revision>" and written with
# op_type=create, so a genuine race on the same revision number conflicts
# instead of silently overwriting -- revisions are append-only, never
# mutated in place. No ILM: an operator's saved recipe should not silently
# expire.
curl -fsS -X PUT "$es_url/_index_template/dashboard-workbench-recipes" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-workbench-recipes-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "schema_version": { "type": "integer" },
        "id": { "type": "keyword" },
        "revision": { "type": "integer" },
        "name": { "type": "keyword" },
        "description": { "type": "text" },
        "owner": { "type": "keyword" },
        "scope": { "type": "keyword" },
        "created_at": { "type": "date" },
        "analyzers": {
          "properties": {
            "analyzer_id": { "type": "keyword" },
            "options": {
              "properties": {
                "timeout_seconds": { "type": "integer" },
                "max_queue_age_seconds": { "type": "integer" },
                "retry_limit": { "type": "integer" }
              }
            }
          }
        }
      }
    }
  }
}' >/dev/null

curl -fsS -X PUT "$es_url/_index_template/honeypot-dead-letter" \
  -H 'Content-Type: application/json' \
  --data-binary '{"index_patterns":["dead-letter-honeypot*"],"priority":450,"template":{"settings":{"index.lifecycle.name":"dead-letter-60d","index.number_of_replicas":0}}}' >/dev/null

# Adopt indices created before this policy was introduced. A missing wildcard
# is harmless on a fresh installation.
curl -fsS -X PUT "$es_url/suricata-*/_settings?allow_no_indices=true" \
  -H 'Content-Type: application/json' \
  -d '{"index.lifecycle.name":"suricata-7d"}' >/dev/null || true
curl -fsS -X PUT "$es_url/.ds-honeypot-v2-*/_settings?allow_no_indices=true&expand_wildcards=all" \
  -H 'Content-Type: application/json' \
  -d '{"index.lifecycle.name":"honeypot-30d"}' >/dev/null || true

# #1375: dionaea writes one plain date-suffixed index per day, so rollover is
# already performed by Filebeat's index name and there is no write alias for
# ILM to roll. These indices were previously attached to honeypot-30d (the
# rollover policy required by the honeypot-v2 data stream) and consequently
# entered ERROR at check-rollover-ready. Elasticsearch's supported policy
# switch sequence is remove first, then apply the new policy; assigning a new
# name directly can retain the old cached hot-phase definition and silently
# fail. Removing also clears the existing ERROR metadata, so the newly applied
# delete-only policy starts cleanly and no _ilm/retry of the invalid rollover
# step is needed. Inspect each current policy first: setup runs on every deploy,
# and removing/reapplying the already-correct policy each time would needlessly
# reset ILM execution metadata for healthy indices.
curl -fsS "$es_url/_cat/indices/dionaea-incidents-v1-*?h=index&allow_no_indices=true" 2>/dev/null |
  while IFS= read -r index; do
    [ -n "$index" ] || continue
    lifecycle=$(curl -fsS "$es_url/$index/_settings/index.lifecycle.name?flat_settings=true")
    case "$lifecycle" in
      *'"index.lifecycle.name":"dionaea-incidents-30d"'*) continue ;;
      *'"index.lifecycle.name":"honeypot-30d"'*)
        curl -fsS -X POST "$es_url/$index/_ilm/remove" >/dev/null ;;
    esac
    curl -fsS -X PUT "$es_url/$index/_settings" \
      -H 'Content-Type: application/json' \
      -d '{"index.lifecycle.name":"dionaea-incidents-30d"}' >/dev/null
  done

# This is intentionally a single-node analysis cluster. Replica shards cannot
# be allocated here and only make cluster health yellow; primaries retain data.
curl -fsS -X PUT "$es_url/_all/_settings?expand_wildcards=all" \
  -H 'Content-Type: application/json' \
  -d '{"index.number_of_replicas":0}' >/dev/null || true

# #787: the PUT above only reaches indices that already exist the moment this
# script runs. auth-events-worker-state, auth-failure-events, ml-anomalies,
# ml-worker-metrics, ml-worker-state, dashboard-intelligence-archive-v1, and
# dashboard-payload-bytes-v1 have no index template of their own (they're
# dynamically created on each producer's first write, which can happen well
# after this script's one-time pass) -- confirmed live, all seven picked up
# Elasticsearch's built-in default of 1 replica instead and sat permanently
# yellow on this single-node cluster. A lowest-priority catch-all template
# closes this for good: every other template above sets its own
# number_of_replicas explicitly and outranks this one on priority, so this
# only ever applies to an index nothing more specific already covers.
#
# #3343: the "EXCEPT arkime_sessions3-*/arkime_history_v1-*, explicitly
# excluded below" claim that used to stand here was simply false. Composable
# index templates have no exclusion syntax, so the "-arkime_..." entries this
# template carried matched nothing but literal index names -- the "*" really
# did match every arkime_sessions3-* index. The inert entries are gone, and so
# is any pretence that this catch-all leaves Arkime alone. It does not.
#
# That is not only a mapping wart, it is why Arkime could not be installed at
# all. Elasticsearch applies NO legacy template to an index once ANY
# composable template matches it (even a priority-1 catch-all like this one
# wins outright over a legacy template, which has no priority concept at all),
# and it refuses the reverse direction outright:
#
#   illegal_argument_exception: legacy template [arkime_sessions3_template] has
#   index patterns [arkime_sessions3-*] matching patterns from existing
#   composable templates [single-node-replica-default, ...] -- use composable
#   templates (/_index_template) instead
#
# `db.pl init` DELETEs and re-creates all three of Arkime's legacy templates,
# so against this catch-all it fails and exits 255, and Arkime ends up with no
# session indices at all while hp-arkime-capture and -viewer both look healthy.
#
# arkime-init now owns Arkime's mappings properly: it deletes this catch-all
# for the duration of db.pl, puts it straight back afterwards, and translates
# Arkime's own legacy templates into full composable equivalents at priority 11
# -- above this priority-1 one -- so the real field typing wins. See
# arkime/composable-templates.js. That is what replaced the
# arkime-sessions3-ip-fix fragment which used to stand below: it decided every
# sessions index alone (firstPacket long, no wordSplit analyzer, 1 replica) and
# left source.ip/destination.ip as text + .keyword, breaking session-detail
# lookups outright ("TypeError: Cannot create property 'keyword' on string" in
# Arkime's own viewer, since it assumes an object-typed IP field it can attach
# a .keyword accessor to).
#
# Waiting for Arkime's own legacy template before adding this catch-all is
# still worth doing -- it is the common case and needs no shadow/restore cycle
# at all -- but it is no longer load-bearing, since arkime-init now handles
# either order itself. It stays bounded and non-fatal: this script must not
# depend on arkime-init succeeding, or one Arkime failure would block every
# template here.
arkime_legacy_wait=60
while (( arkime_legacy_wait > 0 )); do
  if curl -fsS -o /dev/null "$es_url/_template/arkime_sessions3_template" 2>/dev/null; then
    echo "elasticsearch-setup: Arkime legacy template present, adding the composable catch-all"
    break
  fi
  sleep 2
  arkime_legacy_wait=$(( arkime_legacy_wait - 2 ))
done
if (( arkime_legacy_wait <= 0 )); then
  echo "elasticsearch-setup: Arkime legacy template did not appear within 60s --" \
       "adding the composable catch-all anyway (arkime-init may be disabled; if it" \
       "runs later it shadows this template and regenerates Arkime's own, so the" \
       "worst case is a needless shadow/restore cycle, not a failure -- #3343)"
fi

curl -fsS -X PUT "$es_url/_index_template/single-node-replica-default" \
  -H 'Content-Type: application/json' \
  --data-binary '{"index_patterns":["*"],"priority":1,"template":{"settings":{"index.number_of_replicas":0}}}' >/dev/null

# #3283: arkime_sessions3-*'s retention is NOT here, with the other twelve
# policies, and that placement is the fix rather than an omission. This
# script's own catch-all cannot reach that family: since #3343 its pattern is
# a bare "*", so it really does match arkime_sessions3-* -- what keeps it off
# that family is that the composable template arkime-init generates for it
# outranks this one on priority, and composable templates replace rather than
# merge, so nothing set here would survive to govern an index. The generated
# template is also what creates those indices. An index template naming an
# ILM policy that does not exist yet fails index creation outright. This job
# and arkime-init are independent one-shots that race -- the wait above exists
# because of exactly that -- and arkime-capture waits only on arkime-init.done,
# so a policy created here could not be relied on to exist before the first
# sessions index is created. composable-templates.js therefore installs
# arkime-sessions-30d immediately before the template that names it, and
# adopts the indices already on disk in the same run. One definition, one
# owner, an ordering that cannot lose.

echo
echo "elasticsearch-setup: GeoIP, retention policies, and event templates installed"
