#!/usr/bin/env python3
"""Regression test for #3658.

docker-hygiene.sh (arcane/home/honeypot-utilities/analysis/) sent an
unfiltered POST /containers/prune 300 s after the hygiene container started
and weekly after that. A prune removes every stopped container, so any
compose service that was stopped at that moment -- paused for a benchmark
(#3135), crashed, or kept stopped as a rollback path -- was deleted.
`docker start` cannot bring back a deleted container and nothing recreated
it. On 2026-09-29 one pass deleted five stopped sensors (conpot,
conpot-iec104, dicompot, rdp-honeypot, api-honeypot), and they stayed gone
for 17 days.

The fix sends a "label!" filter on the compose project label. This test runs
the real script with stand-in curl and sleep on PATH and checks the request
it actually makes.
"""
import json
import os
import pathlib
import stat
import subprocess
import urllib.parse

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "arcane/home/honeypot-utilities/analysis/docker-hygiene.sh"

INTERVAL = "4242"

FAKE_CURL = """#!/bin/sh
for a in "$@"; do last="$a"; done
printf '%s\\n' "$last" >> "$CURL_LOG"
case "$last" in
  */containers/prune*) printf '{"ContainersDeleted":["aaaaaaaaaaaa"],"SpaceReclaimed":7}' ;;
  */images/prune*) printf '{"ImagesDeleted":[],"SpaceReclaimed":0}' ;;
esac
"""

# The start delay is 0; the first interval sleep after a pass ends the run.
FAKE_SLEEP = """#!/bin/sh
[ "$1" = "{interval}" ] && exit 3
exit 0
""".format(interval=INTERVAL)


def _write_exec(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _run_one_pass(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "curl", FAKE_CURL)
    _write_exec(bindir / "sleep", FAKE_SLEEP)
    log = tmp_path / "curl.log"
    env = dict(
        os.environ,
        PATH=f"{bindir}:{os.environ['PATH']}",
        CURL_LOG=str(log),
        HYGIENE_START_DELAY="0",
        HYGIENE_INTERVAL=INTERVAL,
        DOCKER_PROXY_URL="http://proxy.invalid:2375",
    )
    proc = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)
    return log.read_text().splitlines(), proc


def _filters(url):
    query = urllib.parse.urlparse(url).query
    values = urllib.parse.parse_qs(query).get("filters")
    assert values, f"no filters on {url}"
    return json.loads(values[0])


def test_container_prune_skips_compose_managed_containers(tmp_path):
    urls, proc = _run_one_pass(tmp_path)
    prunes = [u for u in urls if "/containers/prune" in u]
    assert len(prunes) == 1, (urls, proc.stderr)
    # Exactly one label! key: the daemon skips a container only when it
    # carries every label listed under label!, so a second key would narrow
    # the exclusion.
    assert _filters(prunes[0]) == {"label!": ["com.docker.compose.project"]}
    assert "1 removed, 7 bytes reclaimed" in proc.stderr


def test_image_prune_filter_is_unchanged(tmp_path):
    urls, _ = _run_one_pass(tmp_path)
    images = [u for u in urls if "/images/prune" in u]
    assert len(images) == 1, urls
    assert _filters(images[0]) == {"until": ["168h"], "dangling": ["true"]}
