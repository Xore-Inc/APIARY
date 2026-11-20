#!/bin/sh
set -eu

kibana="${KIBANA_URL:-http://10.8.0.2:19601}"
header='kbn-xsrf: honeypot-setup'

until curl -fsS "$kibana/api/status" | grep -q '"level":"available"'; do sleep 5; done

data_view() {
  id=$1 title=$2 name=$3
  curl -fsS -X POST "$kibana/api/data_views/data_view" -H "$header" -H 'Content-Type: application/json' \
    -d "{\"data_view\":{\"id\":\"$id\",\"title\":\"$title\",\"name\":\"$name\",\"timeFieldName\":\"@timestamp\",\"allowNoIndex\":true},\"override\":true}" >/dev/null
}

data_view honeypot-events 'honeypot-v2-*' 'Honeypot normalized events'
data_view suricata-events 'suricata-*' 'Suricata all protocols'
data_view dead-letter-events 'dead-letter-honeypot*' 'Honeypot ingest errors'

put_object() {
  type=$1 id=$2 file=$3
  curl -fsS -X POST "$kibana/api/saved_objects/$type/$id?overwrite=true" -H "$header" -H 'Content-Type: application/json' --data-binary "@$file" >/dev/null
}

cat >/tmp/recent.json <<'JSON'
{"attributes":{"title":"Honeypot — enriched recent events","description":"All sensors with persona, site, asset, GeoIP, ASN, provider and OT context","columns":["event.sensor","honeypot.persona_id","honeypot.site_id","honeypot.asset_id","source.ip","source.geo.country_iso_code","source.geo.city_name","source.as.asn","source.as.organization_name","source.as.type","network.protocol","destination.port","user.name","process.command_line","url.path","file.hash.sha256","ot.persona"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"honeypot-events"}]}
JSON
put_object search hp-enriched-recent /tmp/recent.json

cat >/tmp/ot.json <<'JSON'
{"attributes":{"title":"Honeypot — industrial OT activity","description":"Conpot PLC, S7, IEC-104, Guardian and Kamstrup personas","columns":["event.sensor","honeypot.persona_id","honeypot.site_id","honeypot.asset_id","ot.persona","ot.protocol","source.ip","source.geo.country_iso_code","source.as.organization_name","destination.port","network.protocol","honeypot.data_type","honeypot.request"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"event.sensor: conpot* or ot.persona: *\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"honeypot-events"}]}
JSON
put_object search hp-ot-activity /tmp/ot.json

cat >/tmp/commands.json <<'JSON'
{"attributes":{"title":"Honeypot — executed commands and credentials","description":"Cowrie and multipot commands with session/source context, plus SSH client fingerprinting (hassh)","columns":["event.sensor","honeypot.persona_id","honeypot.asset_id","source.ip","source.as.organization_name","user.name","honeypot.password","process.command_line","honeypot.session","honeypot.hassh","network.protocol","destination.port"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"process.command_line: * or honeypot.input: * or honeypot.command: *\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"honeypot-events"}]}
JSON
put_object search hp-commands /tmp/commands.json

cat >/tmp/payloads.json <<'JSON'
{"attributes":{"title":"Honeypot — payloads and downloads","description":"Captured hashes, URLs and source attribution","columns":["event.sensor","honeypot.persona_id","honeypot.asset_id","source.ip","source.geo.country_iso_code","source.as.organization_name","file.hash.sha256","file.hash.md5","honeypot.shasum","honeypot.url","honeypot.destfile","honeypot.filename","destination.port"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"file.hash.sha256: * or honeypot.shasum: * or honeypot.md5hash: *\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"honeypot-events"}]}
JSON
put_object search hp-payloads /tmp/payloads.json

cat >/tmp/ids.json <<'JSON'
{"attributes":{"title":"Suricata — enriched alerts","description":"IDS alerts with GeoIP/ASN and flow context","columns":["source.ip","source.geo.country_iso_code","source.as.organization_name","source.as.type","destination.ip","destination.port","network.transport","suricata.eve.alert.severity","suricata.eve.alert.category","suricata.eve.alert.signature","suricata.eve.app_proto","suricata.eve.flow_id"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"suricata.eve.event_type: alert\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"suricata-events"}]}
JSON
put_object search hp-ids-alerts /tmp/ids.json

cat >/tmp/errors.json <<'JSON'
{"attributes":{"title":"Pipeline — rejected/dead-letter events","description":"Filebeat records rejected by Elasticsearch with the original document and cause","columns":["error.type","error.message","message"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dead-letter-events"}]}
JSON
put_object search hp-ingest-errors /tmp/errors.json

cat >/tmp/ot-control.json <<'JSON'
{"attributes":{"title":"OT - process and PLC state changes","description":"High-impact S7, Modbus and DNP3 write, operate, restart, start, stop, download and force activity","columns":["@timestamp","source.ip","source.geo.country_iso_code","source.as.organization_name","destination.port","network.protocol","suricata.eve.alert.signature","suricata.eve.alert.category","suricata.eve.alert.metadata.mitre_tactic_id","suricata.eve.alert.metadata.mitre_technique_id","suricata.eve.flow_id"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"suricata.eve.event_type: alert and suricata.eve.alert.signature: (\\\"*WRITE*\\\" or \\\"*OPERATE*\\\" or \\\"*RESTART*\\\" or \\\"*START*\\\" or \\\"*STOP*\\\" or \\\"*DOWNLOAD*\\\" or \\\"*FORCE*\\\")\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"suricata-events"}]}
JSON
put_object search hp-ot-control /tmp/ot-control.json

cat >/tmp/custom-ids.json <<'JSON'
{"attributes":{"title":"IDS - local honeypot rules","description":"Alerts produced by the local HONEYPOT rule set, including OT ATT&CK metadata","columns":["@timestamp","source.ip","source.geo.country_iso_code","source.as.organization_name","destination.port","network.protocol","suricata.eve.alert.signature_id","suricata.eve.alert.signature","suricata.eve.alert.category","suricata.eve.alert.severity","suricata.eve.alert.metadata.mitre_tactic_id","suricata.eve.alert.metadata.mitre_technique_id","suricata.eve.flow_id"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"suricata.eve.event_type: alert and suricata.eve.alert.signature: HONEYPOT-*\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"suricata-events"}]}
JSON
put_object search hp-custom-ids /tmp/custom-ids.json

cat >/tmp/progression.json <<'JSON'
{"attributes":{"title":"Investigation - attack progression","description":"Chronological sensor, credential, command and payload context; filter source.ip or session to pivot. Cross-reference IDS alerts for the same source.ip separately via the Suricata — enriched alerts search: alert data lives in a different index and does not join into this view.","columns":["@timestamp","event.sensor","honeypot.persona_id","honeypot.asset_id","source.ip","source.as.asn","source.as.organization_name","event.category","network.protocol","destination.port","user.name","process.command_line","url.path","file.hash.sha256","honeypot.session"],"sort":[["@timestamp","asc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"honeypot-events"}]}
JSON
put_object search hp-attack-progression /tmp/progression.json

cat >/tmp/dashboard.json <<'JSON'
{"attributes":{"title":"XORE Honeypot — enriched investigation","description":"Unified dashboard for honeypots, OT personas, commands, payloads, GeoIP/ASN, IDS alerts and pipeline errors","panelsJSON":"[{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":0,\"y\":0,\"w\":48,\"h\":18,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_0\"},{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":0,\"y\":18,\"w\":24,\"h\":16,\"i\":\"2\"},\"panelIndex\":\"2\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"},{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":24,\"y\":18,\"w\":24,\"h\":16,\"i\":\"3\"},\"panelIndex\":\"3\",\"embeddableConfig\":{},\"panelRefName\":\"panel_2\"},{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":0,\"y\":34,\"w\":24,\"h\":16,\"i\":\"4\"},\"panelIndex\":\"4\",\"embeddableConfig\":{},\"panelRefName\":\"panel_3\"},{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":24,\"y\":34,\"w\":24,\"h\":16,\"i\":\"5\"},\"panelIndex\":\"5\",\"embeddableConfig\":{},\"panelRefName\":\"panel_4\"},{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":0,\"y\":50,\"w\":48,\"h\":12,\"i\":\"6\"},\"panelIndex\":\"6\",\"embeddableConfig\":{},\"panelRefName\":\"panel_5\"}]","optionsJSON":"{\"useMargins\":true,\"syncColors\":false,\"syncCursor\":true,\"syncTooltips\":false,\"hidePanelTitles\":false}","timeRestore":true,"timeFrom":"now-24h","timeTo":"now","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"panel_0","type":"search","id":"hp-enriched-recent"},{"name":"panel_1","type":"search","id":"hp-ot-activity"},{"name":"panel_2","type":"search","id":"hp-commands"},{"name":"panel_3","type":"search","id":"hp-payloads"},{"name":"panel_4","type":"search","id":"hp-ids-alerts"},{"name":"panel_5","type":"search","id":"hp-ingest-errors"}]}
JSON
put_object dashboard xore-honeypot-enriched /tmp/dashboard.json

cat >/tmp/ot-dashboard.json <<'JSON'
{"attributes":{"title":"XORE OT - control activity and ATT&CK","description":"Focused S7, Modbus and DNP3 process-change investigation with local rule and chronological progression views","panelsJSON":"[{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":0,\"y\":0,\"w\":48,\"h\":18,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_0\"},{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":0,\"y\":18,\"w\":48,\"h\":18,\"i\":\"2\"},\"panelIndex\":\"2\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"},{\"version\":\"8.13.4\",\"type\":\"search\",\"gridData\":{\"x\":0,\"y\":36,\"w\":48,\"h\":20,\"i\":\"3\"},\"panelIndex\":\"3\",\"embeddableConfig\":{},\"panelRefName\":\"panel_2\"}]","optionsJSON":"{\"useMargins\":true,\"syncColors\":false,\"syncCursor\":true,\"syncTooltips\":false,\"hidePanelTitles\":false}","timeRestore":true,"timeFrom":"now-24h","timeTo":"now","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"panel_0","type":"search","id":"hp-ot-control"},{"name":"panel_1","type":"search","id":"hp-custom-ids"},{"name":"panel_2","type":"search","id":"hp-attack-progression"}]}
JSON
put_object dashboard xore-ot-investigation /tmp/ot-dashboard.json

curl -fsS -X POST "$kibana/api/kibana/settings" -H "$header" -H 'Content-Type: application/json' -d '{"changes":{"defaultIndex":"honeypot-events"}}' >/dev/null || true
echo "honeypot-kibana-setup: enriched data views, searches, and investigation dashboards installed"
