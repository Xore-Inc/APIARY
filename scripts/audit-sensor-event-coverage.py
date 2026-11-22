#!/usr/bin/env python3
"""Report sensors whose events reach Elasticsearch without a category.

#789 originally diffed every event-kind string a homegrown Go sensor could
emit against `dashboard/classify.go`'s per-sensor switch, to find kinds the
dashboard had no explicit case for. #1659 deleted that file along with the Go
dashboard, and #1665 asked whether the concern still applies.

It does — but nothing like a classifier exists any more, so the old method
cannot be ported. Sensors now write structured JSON straight through the
`geoip-honeypot` ingest pipeline, and that pipeline does not classify: it
copies `honeypot.category` through to `event.category` when the sensor
supplied one, and does nothing when it did not. There is no per-sensor case
table left to have a gap against.

So the question moves from "does the classifier handle this kind" to "does
this sensor label its events at all", and that can only be answered from the
data. `honeypot.category` is the field that matters: backend-service's
events.rs reads it (falling back to suricata's alert category) and
the dashboard (Xore-Inc/apiary-dashboard) renders and filters on it. `event.category` is set by the
pipeline but no consumer reads it, so it is reported separately and only as
context.

This is an operational audit, not a CI check. The old one could run offline
because it read Go source; this one needs a populated Elasticsearch, which CI
does not have. `.github/workflows/quality.yml`'s step was removed rather than
left disabled, with that reasoning recorded in #1665.

Elasticsearch has no host-published port (arcane/home/honeypot-elk/
compose.yml), so it is only reachable by name from inside the honeynet
network -- `curl http://localhost:9200` from the host has never worked.
Run this the way scripts/reset-logs.sh reaches ES, from a throwaway
container joined to that network:

    docker run --rm --network honeynet -v "$PWD/scripts:/s:ro" \
      python:3-alpine python /s/audit-sensor-event-coverage.py --since 7d --min-events 100

Env:
    ES_URL   Elasticsearch base URL (default: http://elasticsearch:9200)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200").rstrip("/")
INDEX = "honeypot-v2-*"


def search(body: dict) -> dict:
    request = urllib.request.Request(
        f"{ES_URL}/{INDEX}/_search",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"elasticsearch: {e.code} {e.read().decode(errors='replace')[:300]}")
    except OSError as e:
        sys.exit(f"elasticsearch unreachable at {ES_URL}: {e}")


def coverage(since: str) -> list[dict]:
    """Per sensor: how many events, and how many carry each category field."""
    result = search({
        "size": 0,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{since}"}}}],
            # #1677: self-generated healthcheck traffic is not a sensor
            # observation and must not dilute a sensor's coverage figure.
            # honeypot.* because the enrichment worker writes the marker into
            # the sensor's log line and Filebeat nests every sensor field there.
            "must_not": [{"term": {"honeypot.internal_probe": True}}],
        }},
        "aggs": {"sensors": {
            "terms": {"field": "event.sensor", "size": 100},
            "aggs": {
                "labelled": {"filter": {"exists": {"field": "honeypot.category"}}},
                "pipeline_labelled": {"filter": {"exists": {"field": "event.category"}}},
                "kinds": {"terms": {"field": "honeypot.category", "size": 8}},
            },
        }},
    })
    rows = []
    for bucket in result["aggregations"]["sensors"]["buckets"]:
        total = bucket["doc_count"]
        labelled = bucket["labelled"]["doc_count"]
        rows.append({
            "sensor": bucket["key"],
            "events": total,
            "labelled": labelled,
            "percent": (100 * labelled // total) if total else 0,
            "pipeline": bucket["pipeline_labelled"]["doc_count"],
            "kinds": [b["key"] for b in bucket["kinds"]["buckets"]],
        })
    return sorted(rows, key=lambda r: (r["percent"], -r["events"]))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--since", default="24h", help="lookback window (default: 24h)")
    parser.add_argument("--min-events", type=int, default=1,
                        help="ignore sensors with fewer events than this (default: 1)")
    parser.add_argument("--fail-under", type=int, default=None,
                        help="exit non-zero if any sensor's coverage is below this percent")
    args = parser.parse_args()

    rows = [r for r in coverage(args.since) if r["events"] >= args.min_events]
    if not rows:
        print(f"no sensor events in the last {args.since}")
        return 0

    total = sum(r["events"] for r in rows)
    labelled = sum(r["labelled"] for r in rows)
    print(f"honeypot.category coverage, last {args.since} "
          f"({len(rows)} sensors, {total:,} events)\n")
    print(f"  {'sensor':<24}{'events':>10}{'labelled':>10}{'cover':>7}   categories seen")
    for row in rows:
        kinds = ", ".join(row["kinds"][:4]) if row["kinds"] else "-"
        print(f"  {row['sensor']:<24}{row['events']:>10,}{row['labelled']:>10,}"
              f"{row['percent']:>6}%   {kinds[:44]}")
    print(f"\n  {'TOTAL':<24}{total:>10,}{labelled:>10,}"
          f"{(100 * labelled // total) if total else 0:>6}%")

    uncovered = [r for r in rows if r["percent"] == 0]
    if uncovered:
        print(f"\n{len(uncovered)} sensor(s) label nothing at all — every event of theirs shows")
        print("a blank category in the dashboard's events table and cannot be filtered by it:")
        for row in uncovered:
            print(f"  - {row['sensor']} ({row['events']:,} events)")

    # event.category is pipeline-derived and currently has no reader; surfaced
    # only so a future consumer does not assume it is populated.
    orphaned = [r for r in rows if r["pipeline"] != r["labelled"]]
    if orphaned:
        print("\nnote: event.category differs from honeypot.category on "
              f"{len(orphaned)} sensor(s); nothing reads event.category today.")

    if args.fail_under is not None:
        below = [r for r in rows if r["percent"] < args.fail_under]
        if below:
            print(f"\nFAIL: {len(below)} sensor(s) below {args.fail_under}% coverage")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
