#!/bin/sh
set -eu

# #264: import counterpart to kibana-export.sh -- see that script's header
# for why this exists. Restores (or seeds a fresh deploy with) the
# dashboards/visualizations/index-patterns an operator built in Kibana,
# same shape as T-Pot's own export/import pair.
#
# Usage: analysis/kibana-import.sh [input-file]
# overwrite=true replaces an existing saved object of the same id rather
# than erroring on it -- the expected case for "restore after a reset" or
# "reapply the baseline after an upgrade", not a one-time-only import.

kibana_url="${KIBANA_URL:-http://10.8.0.2:19601}"
script_dir="$(cd "$(dirname -- "$0")" && pwd)"
input="${1:-$script_dir/objects/kibana_export.ndjson}"

if [ ! -f "$input" ]; then
  echo "kibana-import: no such file: $input" >&2
  exit 1
fi

response=$(curl -fsS -X POST "$kibana_url/api/saved_objects/_import?overwrite=true" \
  -H 'kbn-xsrf: true' \
  --form "file=@$input;type=application/ndjson")

echo "$response"

case "$response" in
  *'"success":true'*)
    echo "kibana-import: imported $input successfully"
    ;;
  *)
    echo "kibana-import: import reported errors, see response above" >&2
    exit 1
    ;;
esac
