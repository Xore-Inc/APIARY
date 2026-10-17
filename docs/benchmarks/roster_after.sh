#!/usr/bin/env bash
# Run the after-benchmark roster (OrcaSAQ models)
# Invoke AFTER the current roster_run.py finishes.
set -euo pipefail

PLAN="$(dirname "$0")/roster_after.json"
ACTIVE=/tmp/roster_plan.json

if [ ! -f "$PLAN" ]; then
  echo "ERROR: $PLAN not found"
  exit 1
fi

# Check current run isn't still active
if pgrep -f '[r]oster_run.py' >/dev/null 2>&1; then
  echo "ERROR: roster_run.py is still running — wait for it to finish first"
  exit 1
fi

# Swap plan
cp "$PLAN" "$ACTIVE"

echo "=== Starting after-benchmark roster ==="
echo "  Models:"
jq -r '.shortlist[]?, .safetensors_import[]?' "$PLAN" | sed 's/^/    /'
echo ""

cd /home/xore
python3 -u roster_run.py