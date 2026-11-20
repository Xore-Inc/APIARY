#!/bin/sh
set -eu

# #264: T-Pot treats Kibana dashboards as versioned, recoverable artifacts
# (docker/tpotinit/dist/bin/backup_kibana_config.sh, a checked-in
# kibana_export.ndjson, explicit README export/import instructions). This
# repo's ELK setup (elasticsearch-setup.sh) never touched Kibana saved
# objects -- any dashboard an operator built lived only in Elasticsearch's
# .kibana index, with no recovery path on an ES reset/migration/upgrade.
#
# Usage: analysis/kibana-export.sh [output-file]
# Reachable over honeynet by default -- run from a container/host that can
# resolve "kibana", or set KIBANA_URL to an externally reachable address
# (e.g. http://<HP_BIND>:19601).

kibana_url="${KIBANA_URL:-http://10.8.0.2:19601}"
script_dir="$(cd "$(dirname -- "$0")" && pwd)"
output="${1:-$script_dir/objects/kibana_export.ndjson}"

mkdir -p "$(dirname -- "$output")"

# includeReferencesDeep pulls in every index-pattern/search a dashboard or
# visualization depends on, so importing this file elsewhere doesn't leave
# a dashboard pointing at references that were never exported alongside it.
curl -fsS -X POST "$kibana_url/api/saved_objects/_export" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  --data-binary '{"type":["index-pattern","search","visualization","dashboard","lens","map"],"includeReferencesDeep":true}' \
  -o "$output"

# The last line is a summary object ({"exportedCount":N,...}), not a saved
# object itself, and Kibana's export has no trailing newline after it -- a
# plain `wc -l` both undercounts by one and would call the summary line a
# saved object. Pull exportedCount out of that line instead of counting.
count=$(tail -n 1 -- "$output" | sed -n 's/.*"exportedCount":\([0-9]*\).*/\1/p')
echo "kibana-export: wrote ${count:-an unknown number of} saved object(s) to $output"
