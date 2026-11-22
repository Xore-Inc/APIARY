#!/usr/bin/env python3
"""Read-only end-to-end health gate for the backend and Elasticsearch ingestion.

One command for the tail end of RECOVERY.md / BACKUP-ESSENTIALS.md /
CGNAT-DEPLOYMENT.md: fetch the backend's source-health, judge it, print one
JSON verdict, exit nonzero when anything is wrong.

This used to scrape the retired Go dashboard's ``/api/stats`` (Sensors[].State,
ES.Sources[].Count, FilebeatState, YARA.Enabled) — a response shape deleted
with the Go service in #1659, so the gate could only ever fail. #2086 ports it
onto the Rust backend's ``/api/v1/source-health``. That used to be reached
through dashboard-next's ``/bff`` passthrough; dashboard-next left with
#3749, so the gate now asks the backend itself. The backend publishes no
port, so by default the request runs inside its container (``docker exec``
into ``--backend-container``, the same seam ``scripts/verify-deploy.sh`` uses
for /healthz). ``--backend-url`` points it at a reachable listener instead,
e.g. over the swarm overlay:

    Go api/stats                        /api/v1/source-health successor
    ----------------------------------  -----------------------------------
    Sensors[name].State == "waiting"    name absent from sensors[] (terms
                                        agg only buckets sensors that have
                                        logged at least once)
    ES.Sources[name].Count <= 0         sensors[name].documents <= 0
    (implicit) sensor gone quiet        sensors[name].state == "STALE" --
                                        rate-aware per #1931, so quiet-by-
                                        nature decoys are not failed for it
    ES.State not green/yellow           cluster_status not green/yellow
    FilebeatState != "healthy"          pipeline.state != "healthy"
    IngestState == "stale"              ingest.state == "stale"
    YARA disabled or errors             yara.enabled false, yara.errors > 0

The route requires the backend's service token: pass --token or export
DASHBOARD_SERVICE_TOKEN (the backend stack's .env name). With neither set the
request goes out unauthenticated and fails with 401 rather than pretending to
verify. On the docker-exec path the token reaches curl on stdin, never on a
command line.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

# Core decoys as they are actually named in event.sensor today. The old
# default list said "http" (never a sensor name — http-honeypot) and tanner
# (ten events ever; its snare/tanner pair is Traefik-served and all but
# silent, so requiring it would keep the gate permanently red).
DEFAULT_REQUIRE = "cowrie,dionaea,multipot,http-honeypot,conpot,suricata"

SOURCE_HEALTH_PATH = "/api/v1/source-health"


class HTTPStatusError(Exception):
    def __init__(self, code):
        super().__init__(f"HTTP {code}")
        self.code = code


def get(url, token):
    request = urllib.request.Request(url)
    if token:
        request.add_header("X-Service-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise HTTPStatusError(error.code) from error


def exec_curl_command(container):
    """argv for one source-health request inside the backend container.

    The port comes from the container's own LISTEN_ADDR (the image's
    HEALTHCHECK trick), and the header arrives on stdin as a curl config
    line, so the token is never in this argv or the container's.
    """
    script = (
        'curl -sS --max-time 30 -K - -w "\\n%{http_code}" '
        '"http://127.0.0.1:${LISTEN_ADDR##*:}' + SOURCE_HEALTH_PATH + '"'
    )
    return ["docker", "exec", "-i", container, "sh", "-c", script]


def parse_exec_output(stdout):
    """Split curl's body from the trailing status line written by -w."""
    body, _, code = stdout.rstrip("\n").rpartition("\n")
    if not code.isdigit():
        raise ValueError(f"no HTTP status in backend response: {stdout[-200:]!r}")
    if int(code) != 200:
        raise HTTPStatusError(int(code))
    return json.loads(body)


def get_via_exec(container, token):
    config = f'header = "X-Service-Token: {token}"\n' if token else ""
    result = subprocess.run(
        exec_curl_command(container), input=config, capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0 and not result.stdout:
        raise OSError(f"docker exec {container} failed: {result.stderr.strip()[-300:]}")
    return parse_exec_output(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--backend-container",
        default="hp-apiary-backend",
        help="backend container to query through docker exec (default: hp-apiary-backend)",
    )
    parser.add_argument(
        "--backend-url",
        default="",
        help="reachable backend base URL instead of docker exec, e.g. over the overlay",
    )
    parser.add_argument(
        "--require",
        default=DEFAULT_REQUIRE,
        help="comma-separated event.sensor names that must have fed recently",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SERVICE_TOKEN") or os.environ.get("DASHBOARD_SERVICE_TOKEN", ""),
        help="backend service token (default: $SERVICE_TOKEN or $DASHBOARD_SERVICE_TOKEN)",
    )
    args = parser.parse_args()

    failures = []
    try:
        if args.backend_url:
            health = get(args.backend_url.rstrip("/") + SOURCE_HEALTH_PATH, args.token)
        else:
            health = get_via_exec(args.backend_container, args.token)
    except HTTPStatusError as error:
        detail = f"source-health unreachable: HTTP {error.code}"
        if error.code == 401:
            detail += " (service token required: --token or $DASHBOARD_SERVICE_TOKEN)"
        print(json.dumps({"failures": [detail]}, indent=2))
        return 1
    except (urllib.error.URLError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"failures": [f"source-health unreachable: {error}"]}, indent=2))
        return 1

    sensors = {row["sensor"]: row for row in health.get("sensors", [])}
    for name in [value.strip() for value in args.require.split(",") if value.strip()]:
        if name not in sensors:
            failures.append(f"dashboard sensor has never logged: {name}")
            continue
        row = sensors[name]
        if row.get("documents", 0) <= 0:
            failures.append(f"dashboard sensor has no documents: {name}")
        elif row.get("state") == "STALE":
            failures.append(f"dashboard sensor feed stale: {name} (last {row.get('last_seen', '?')})")

    cluster_status = health.get("cluster_status")
    if cluster_status not in ("green", "yellow"):
        failures.append(f"Elasticsearch state: {cluster_status}")

    pipeline = health.get("pipeline", {})
    if pipeline.get("state") != "healthy":
        failures.append(f"Filebeat state: {pipeline.get('state')}")

    ingest = health.get("ingest", {})
    # delayed is the amber run-up, not a gate failure -- same verdict split
    # elastic.go made, and a just-restored stack legitimately spends time in it.
    if ingest.get("state") == "stale":
        failures.append(f"Elasticsearch ingestion stale: age {ingest.get('age_seconds')}s")

    yara = health.get("yara", {})
    if not yara.get("enabled") or yara.get("errors", 0):
        failures.append(f"YARA state: {yara}")

    print(
        json.dumps(
            {
                "events": health.get("total_documents"),
                "sensors": sensors,
                "elasticsearch": {
                    "cluster_status": cluster_status,
                    "ingest": ingest,
                    "dead_letters": health.get("dead_letters"),
                    "recent_dead_letters": health.get("recent_dead_letters"),
                },
                "filebeat": pipeline,
                "yara": yara,
                "failures": failures,
            },
            indent=2,
        )
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
