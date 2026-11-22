#!/usr/bin/env python3
"""Regression tests for #3658 and #3841.

#3658: docker-hygiene.sh (arcane/home/honeypot-utilities/analysis/) sent an
unfiltered POST /containers/prune 300 s after the hygiene container started
and weekly after that. A prune removes every stopped container, so any
compose service that was stopped at that moment -- paused for a benchmark
(#3135), crashed, or kept stopped as a rollback path -- was deleted.
`docker start` cannot bring back a deleted container and nothing recreated
it. On 2026-09-29 one pass deleted five stopped sensors (conpot,
conpot-iec104, dicompot, rdp-honeypot, api-honeypot), and they stayed gone
for 17 days.

#3841: the benchmark Ollama container (`docker create`, no compose label) is
stopped between runs and the same pass removed it. The fix is an opt-out
label, apiary.hygiene=keep. The daemon's prune cannot express "skip the
compose label OR the keep label" (repeated label! values are ANDed, checked
against the daemon on 2026-11-21), so the script lists the stopped
containers and the two protected sets and deletes the difference.

These tests run the real script with a stand-in curl that behaves like the
daemon's /containers/json and DELETE /containers/{id}, and a stand-in sleep.
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

# Stand-in daemon: containers come from $FAKE_DAEMON (JSON list of
# {id, state, labels}). GET /containers/json honours all=, status= and label=
# filters (label filters are ANDed, like the daemon's). DELETE is logged and
# the container is dropped from the state. $FAKE_FAIL names a URL fragment
# whose request fails like `curl -f` on an HTTP error.
FAKE_CURL = """#!/usr/bin/env python3
import json, os, sys, urllib.parse
args = sys.argv[1:]
url = args[-1]
method = args[args.index("-X") + 1] if "-X" in args else "GET"
with open(os.environ["CURL_LOG"], "a") as f:
    f.write(method + " " + url + "\\n")
fail = os.environ.get("FAKE_FAIL")
if fail and fail in url:
    sys.exit(22)
state_path = os.environ["FAKE_DAEMON"]
state = json.load(open(state_path))
parsed = urllib.parse.urlparse(url)
if parsed.path == "/containers/json":
    q = urllib.parse.parse_qs(parsed.query)
    flt = json.loads(q["filters"][0]) if "filters" in q else {}
    out = []
    for c in state:
        if "status" in flt and c["state"] not in flt["status"]:
            continue
        ok = True
        for want in flt.get("label", []):
            k, _, v = want.partition("=")
            if k not in c["labels"] or (v and c["labels"][k] != v):
                ok = False
        if ok:
            out.append({"Id": c["id"], "Names": ["/" + c["id"][:4]], "State": c["state"],
                        "Labels": c["labels"],
                        "NetworkSettings": {"Networks": {"n": {"NetworkID": "f" * 64, "EndpointID": "e" * 64}}}})
    print(json.dumps(out, separators=(",", ":")))
elif parsed.path.startswith("/containers/") and method == "DELETE":
    cid = parsed.path.rsplit("/", 1)[1]
    json.dump([c for c in state if c["id"] != cid], open(state_path, "w"))
elif parsed.path == "/images/prune":
    print('{"ImagesDeleted":[],"SpaceReclaimed":0}')
"""

# The start delay is 0; the first interval sleep after a pass ends the run.
FAKE_SLEEP = """#!/bin/sh
[ "$1" = "{interval}" ] && exit 3
exit 0
""".format(interval=INTERVAL)


def _write_exec(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _cid(ch):
    return ch * 64


UNLABELLED = _cid("a")
KEEP = _cid("b")
COMPOSE = _cid("c")
BOTH = _cid("d")
RUNNING = _cid("e")
SCOPED = _cid("f")

KEEP_LABEL = "apiary.hygiene"
COMPOSE_LABEL = "com.docker.compose.project"

DAEMON = [
    {"id": UNLABELLED, "state": "exited", "labels": {}},
    {"id": KEEP, "state": "exited", "labels": {KEEP_LABEL: "keep"}},
    {"id": COMPOSE, "state": "exited", "labels": {COMPOSE_LABEL: "honeypot-elk"}},
    {"id": BOTH, "state": "created", "labels": {KEEP_LABEL: "keep", COMPOSE_LABEL: "x"}},
    {"id": RUNNING, "state": "running", "labels": {}},
    # carries the key but not the value "keep": not an opt-out
    {"id": SCOPED, "state": "exited", "labels": {KEEP_LABEL: "no"}},
]


def _run_one_pass(tmp_path, daemon=DAEMON, fail=None, scope=None):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "curl", FAKE_CURL)
    _write_exec(bindir / "sleep", FAKE_SLEEP)
    log = tmp_path / "curl.log"
    state = tmp_path / "daemon.json"
    state.write_text(json.dumps(daemon))
    env = dict(
        os.environ,
        PATH=f"{bindir}:{os.environ['PATH']}",
        CURL_LOG=str(log),
        FAKE_DAEMON=str(state),
        HYGIENE_START_DELAY="0",
        HYGIENE_INTERVAL=INTERVAL,
        DOCKER_PROXY_URL="http://proxy.invalid:2375",
    )
    if fail:
        env["FAKE_FAIL"] = fail
    if scope:
        env["HYGIENE_SCOPE_LABEL"] = scope
    proc = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)
    remaining = {c["id"] for c in json.loads(state.read_text())}
    return log.read_text().splitlines(), proc, remaining


def _filters(url):
    query = urllib.parse.urlparse(url).query
    values = urllib.parse.parse_qs(query).get("filters")
    assert values, f"no filters on {url}"
    return json.loads(values[0])


def test_never_uses_unscoped_container_prune(tmp_path):
    urls, proc, _ = _run_one_pass(tmp_path)
    assert not [u for u in urls if "/containers/prune" in u], urls


def test_only_unprotected_stopped_containers_are_removed(tmp_path):
    urls, proc, remaining = _run_one_pass(tmp_path)
    deleted = [u.split("/containers/")[1] for u in urls if u.startswith("DELETE ")]
    assert sorted(deleted) == sorted([UNLABELLED, SCOPED]), (urls, proc.stderr)
    # #3658: compose-managed stopped containers survive.
    assert COMPOSE in remaining
    # #3841: apiary.hygiene=keep survives, alone or together with a compose
    # label, and so does anything running.
    assert KEEP in remaining and BOTH in remaining and RUNNING in remaining
    assert "2 removed, 2 kept (apiary.hygiene=keep), 1 kept (compose-managed), 0 failed" in proc.stderr


def test_candidate_list_asks_for_stopped_states_only(tmp_path):
    urls, _, _ = _run_one_pass(tmp_path)
    lists = [u for u in urls if u.startswith("GET ")]
    assert _filters(lists[0]) == {"status": ["created", "exited", "dead"]}
    # The protected sets cover every state, so a container that started
    # after the candidate list was taken is still recognised.
    assert _filters(lists[1]) == {"label": ["apiary.hygiene=keep"]}
    assert _filters(lists[2]) == {"label": ["com.docker.compose.project"]}
    for u in lists:
        assert "all=1" in u


def test_failed_listing_skips_the_pass_without_removing_anything(tmp_path):
    for fragment in ("%22status%22", "apiary.hygiene%3Dkeep", "com.docker.compose.project%22%5D%7D"):
        sub = tmp_path / fragment[:6].strip("%")
        sub.mkdir()
        urls, proc, remaining = _run_one_pass(sub, fail=fragment)
        assert not [u for u in urls if u.startswith("DELETE ")], (fragment, urls)
        assert len(remaining) == len(DAEMON), fragment
        assert "skipping container pass" in proc.stderr, (fragment, proc.stderr)


def test_scope_label_narrows_the_candidates(tmp_path):
    daemon = [
        {"id": UNLABELLED, "state": "exited", "labels": {}},
        {"id": SCOPED, "state": "exited", "labels": {"t3841": "1"}},
    ]
    urls, _, remaining = _run_one_pass(tmp_path, daemon=daemon, scope="t3841=1")
    assert remaining == {UNLABELLED}
    assert _filters([u for u in urls if u.startswith("GET ")][0]) == {
        "status": ["created", "exited", "dead"],
        "label": ["t3841=1"],
    }


def test_image_prune_filter_is_unchanged(tmp_path):
    urls, _, _ = _run_one_pass(tmp_path)
    images = [u for u in urls if "/images/prune" in u]
    assert len(images) == 1, urls
    assert _filters(images[0]) == {"until": ["168h"], "dangling": ["true"]}
