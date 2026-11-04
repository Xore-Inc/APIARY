"""Shared GPU job queue -- ES-backed, stdlib-only.

Any worker that needs the shared GPU (ghidra-worker.py's AI triage today;
llm-worker's session/payload/report analysis is the natural next consumer)
checks headroom before calling Ollama. If there isn't enough, it enqueues a
job here instead of blocking or failing, and a small drainer picks queued
jobs back up once headroom frees. The dashboard reads/aborts queued jobs
through this same index -- no direct file access, matching the rest of the
dashboard's ES-only read path.

Deliberately stdlib-only (urllib + subprocess, no `elasticsearch` client, no
third-party deps) so this one file can be vendored as-is into any worker's
environment without adding a dependency -- ghidra-worker.py runs host-side
with nothing but the interpreter, and this needs to work there unchanged.
It is *vendored*, not imported across containers: see
analysis/ghidra/worker/gpu_queue.py (installed alongside ghidra-worker.py by
install-analysis-host.sh) and llm-worker/gpu_queue.py (copied in at build
time). Keep those in sync with this canonical copy -- a contract test in
each consumer's test suite asserts byte-for-byte equality, the same pattern
already used for TRIAGE_SYSTEM/TRIAGE_WORKFLOWS between ghidra-worker.py and
evaluate-models.py (see analysis/ghidra/worker/tests/test_ghidra_worker.py).

Every function here is a plain HTTP call to Elasticsearch or `nvidia-smi`;
none of it executes captured data or picks a model -- that decision stays
with the caller.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

QUEUE_INDEX = "gpu-job-queue"

# Elasticsearch has no port published to the host on purpose (every other
# consumer reaches it by Docker network alias, never from outside Docker) --
# but ghidra-worker.py is a bare host-level systemd service, not a
# container, and can't resolve `elasticsearch` directly. Detect that case
# (no /.dockerenv -- the standard, if informal, way to tell) and bridge
# through a throwaway container on the same network instead of asking every
# host-side caller to know this quirk itself.
_RUNNING_IN_CONTAINER = os.path.exists("/.dockerenv")

# Statuses: queued -> running -> (completed | failed | aborted).
#
# Crash ownership for the running state (#2075): a drainer that dies between
# update_status("running") and any terminal write -- host reboot, OOM kill,
# power loss mid-generation -- leaves the job "running" forever, because
# only queued jobs are ever picked up again and nothing read started_at.
# gpu-queue-drain.py's stale-running sweep therefore owns the
# running -> terminal transition for jobs that outrun their drainer: past
# the drain's staleness bound a job is requeued once (attempts < 2, via
# requeue() below -- which is also what gives increment_attempts() its
# reader), then failed with an honest error on any attempt after that.
#
# abort_requested is honoured in two places (#1698). gpu-queue-drain.py checks
# it once before it starts, and ghidra-worker.py checks it again between
# streamed chunks while the model is generating -- abandoning that stream is
# what frees the GPU, because ollama cancels the inference task when the
# client disconnects (verified against 0.32.13: `srv stop: cancel task`).
#
# Setting the flag on a job that has already finished is still a harmless
# no-op, which is why nothing here refuses based on status.


def _raw_request(es_host: str, method: str, path: str, data: bytes | None) -> tuple[int, bytes]:
    """Returns (http_status, body). Never raises on a non-2xx status -- the
    two call sites that care about a specific status (ensure_index's
    exists-check, get_job's 404) read it from the tuple instead of catching
    urllib.error.HTTPError, which the docker-bridge path below can't raise
    (curl doesn't) -- keeping one status-handling convention for both.
    """
    url = f"{es_host.rstrip('/')}{path}"
    # GPU_QUEUE_TRANSPORT=direct (#2077): force the plain-urllib branch below
    # even outside a container. The docker bridge further down can only reach
    # hosts on the `honeynet` network -- never the runner's own loopback --
    # so pointing GPU_QUEUE_ES_HOST at a test-local ES-shaped stub silently
    # failed enqueue and re-tested the enqueue-failure path instead. This is
    # the documented injection point that makes hermetic tests of
    # transport-reachable queue calls possible; production never sets it.
    if _RUNNING_IN_CONTAINER or os.environ.get("GPU_QUEUE_TRANSPORT") == "direct":
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
    # Host-side: bridge through a throwaway container on the same Docker
    # network `es_host` actually lives on (honeynet), the same way every
    # other host-side script in this repo talks to ES. `-X HEAD` combined
    # with `-w` hangs waiting for a body a HEAD response never sends --
    # curl's actual HEAD flag (`-I`) doesn't have that problem, confirmed
    # live; every other verb goes through `-X` as normal.
    cmd = ["docker", "run", "--rm", "--network", "honeynet", "curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777", "-s"]
    if method == "HEAD":
        cmd += ["-I", "-o", "/dev/null", "-w", "%{http_code}"]
    else:
        cmd += ["-o", "-", "-w", "\n%{http_code}", "-X", method]
        if data is not None:
            cmd += ["-H", "Content-Type: application/json", "-d", data.decode()]
    cmd.append(url)
    completed = subprocess.run(cmd, capture_output=True, timeout=20, check=True)
    if method == "HEAD":
        return int(completed.stdout.strip()), b""
    body, _, status = completed.stdout.rpartition(b"\n")
    return int(status), body


def _request(es_host: str, method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    status, raw = _raw_request(es_host, method, path, data)
    if status >= 400:
        # hdrs/ fp are None: this exception is raised to be caught and read
        # for .code/.read() only, never to render a response.
        raise urllib.error.HTTPError(
            path, status, raw.decode(errors="replace"), None, None  # type: ignore[arg-type]
        )
    return json.loads(raw)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ensure_index(es_host: str) -> None:
    """Idempotent -- safe to call on every worker startup, matching
    llm-worker/worker.py's own ensure_indices() pattern for its state index.
    """
    status, _ = _raw_request(es_host, "HEAD", f"/{QUEUE_INDEX}", None)
    if status == 200:
        return  # already exists
    mapping = {
        "mappings": {
            "properties": {
                "job_id": {"type": "keyword"},
                # #2226: these two are term-filtered by list_queue() as
                # "<field>.keyword" (the shape #1686 fixed them to), so the
                # explicit mapping must reproduce the dynamic one -- "text"
                # with a ".keyword" multi-field, exactly what dynamic
                # mapping generates for any unmapped string. Mapping them
                # plain "keyword" (as this used to) creates an index on
                # which no ".keyword" path exists at all: ES silently
                # matches nothing for term queries against an unmapped
                # field, and a fresh deployment's drainer starves forever
                # with zero log output. Old dynamically-mapped indexes keep
                # working either way because the declared shape now matches
                # what they already have.
                "job_type": {"type": "text",
                             "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "ref": {"type": "keyword"},
                "model": {"type": "keyword"},
                "estimated_vram_mib": {"type": "long"},
                "status": {"type": "text",
                           "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "requested_at": {"type": "date"},
                "started_at": {"type": "date"},
                "finished_at": {"type": "date"},
                "abort_requested": {"type": "boolean"},
                "error": {"type": "text"},
                "attempts": {"type": "short"},
                # Job-type-specific data a drainer needs to actually run the
                # job later (e.g. ghidra-triage's evidence text). Not
                # indexed as structured fields -- shape varies by job_type
                # and nothing queries into it, only fetches the whole doc.
                "payload": {"type": "object", "enabled": False},
            }
        }
    }
    _request(es_host, "PUT", f"/{QUEUE_INDEX}", mapping)


def nvidia_free_mib() -> int | None:
    try:
        completed = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        return int(completed.stdout.splitlines()[0].strip())
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None


def has_headroom(needed_mib: int, safety_margin_mib: int = 1024) -> bool:
    """True if nvidia-smi reports enough free VRAM, or if telemetry is
    unavailable. Fails open on missing telemetry deliberately: a host with
    no GPU (or nvidia-smi not installed) should not have every GPU-bound
    call blocked forever by a probe that can never succeed -- Ollama's own
    request will fail normally in that case, same as before this existed.
    """
    free = nvidia_free_mib()
    if free is None:
        return True
    return free >= needed_mib + safety_margin_mib


def enqueue(
    es_host: str, job_type: str, ref: str, model: str, estimated_vram_mib: int,
    payload: dict[str, Any] | None = None,
) -> str:
    job_id = str(uuid.uuid4())
    doc = {
        "job_id": job_id,
        "job_type": job_type,
        "ref": ref,
        "model": model,
        "estimated_vram_mib": estimated_vram_mib,
        "status": "queued",
        "requested_at": _now(),
        "started_at": None,
        "finished_at": None,
        "abort_requested": False,
        "error": None,
        "attempts": 0,
        "payload": payload or {},
    }
    _request(es_host, "PUT", f"/{QUEUE_INDEX}/_doc/{job_id}?refresh=true", doc)
    return job_id


def list_queue(es_host: str, status: str | None = None, job_type: str | None = None, size: int = 100) -> list[dict]:
    # .keyword: these term filters filter on the keyword form of
    # status/job_type, and they own half of a two-sided contract whose other
    # half is the mapping those fields actually have:
    #
    #   * Indexes created before ensure_index() ever declared a mapping got
    #     ES's dynamic mapping for unmapped strings -- type "text"
    #     (analyzed) plus an auto-generated ".keyword" sub-field.
    #   * Indexes created by ensure_index() (#2226) declare exactly that
    #     shape explicitly, because mapping these plain "keyword" created an
    #     index with NO ".keyword" path at all -- ES silently matches
    #     nothing for a term query against an unmapped field, so a fresh
    #     deployment drained nothing forever, invisibly.
    #
    # Why the bare field name is not good enough (why this targets ".keyword"
    # rather than dropping the suffix): a term query against the bare
    # analyzed field never matched job_type values containing a hyphen
    # ("ghidra-triage" tokenizes to "ghidra"/"triage", neither of which
    # equals the literal string) -- confirmed live: three ghidra-triage jobs
    # sat "queued" for up to 11 days, gpu-queue-drain.py silently found zero
    # matches on every single tick (main() only prints once it has a job in
    # hand, so that failure produced no log output at all). status values
    # happen to be single words with no analyzer-relevant punctuation, so
    # that filter accidentally worked -- not something to rely on, fixed the
    # same way for both.
    #
    # analysis/gpu-queue/test_gpu_queue.py cross-asserts this contract: every
    # field path queried below must resolve within ensure_index()'s own
    # mapping payload. If you rename or re-shape either side here, update the
    # test -- it exists precisely to catch creator and querier disagreeing
    # again.
    filters = []
    if status is not None:
        filters.append({"term": {"status.keyword": status}})
    if job_type is not None:
        filters.append({"term": {"job_type.keyword": job_type}})
    query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
    result = _request(es_host, "POST", f"/{QUEUE_INDEX}/_search", {
        "size": size, "sort": [{"requested_at": "asc"}], "query": query,
    })
    return [{**hit["_source"], "_id": hit["_id"]} for hit in result.get("hits", {}).get("hits", [])]


def get_job(es_host: str, job_id: str) -> dict | None:
    try:
        result = _request(es_host, "GET", f"/{QUEUE_INDEX}/_doc/{job_id}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return {**result["_source"], "_id": result["_id"]}


def update_status(es_host: str, job_id: str, status: str, error: str | None = None,
                  result: dict[str, Any] | None = None) -> None:
    """`result` (#2928): what a completed job produced when it has no file
    of its own to land in -- vault-rag's {"answer", "citations"} -- kept on
    the queue document so /api/v1/gpu-queue can show it."""
    doc: dict[str, Any] = {"status": status}
    if result is not None:
        doc["result"] = result
    if status == "running":
        doc["started_at"] = _now()
    if status in ("completed", "failed", "aborted"):
        doc["finished_at"] = _now()
    if error is not None:
        doc["error"] = error[:2000]
    _request(es_host, "POST", f"/{QUEUE_INDEX}/_update/{job_id}?refresh=true", {"doc": doc})


def increment_attempts(es_host: str, job_id: str) -> None:
    _request(es_host, "POST", f"/{QUEUE_INDEX}/_update/{job_id}?refresh=true", {
        "script": {"source": "ctx._source.attempts += 1", "lang": "painless"},
    })


def requeue(es_host: str, job_id: str) -> None:
    """Return an interrupted job to 'queued' after its drainer died
    mid-run (#2075): clears started_at -- the marker the stale-running
    sweep ages jobs by -- and deliberately leaves attempts alone, since
    increment_attempts() at pickup is what bounds how many times a
    chronically-dying job can be retried before the sweep fails it."""
    _request(es_host, "POST", f"/{QUEUE_INDEX}/_update/{job_id}?refresh=true", {
        "doc": {"status": "queued", "started_at": None},
    })


def request_abort(es_host: str, job_id: str) -> None:
    """Only has an effect while the job is still 'queued' -- see module
    docstring. Setting this on a running/finished job is harmless (the
    drainer only checks it before starting), just a no-op.
    """
    _request(es_host, "POST", f"/{QUEUE_INDEX}/_update/{job_id}?refresh=true", {
        "doc": {"abort_requested": True},
    })


def is_abort_requested(es_host: str, job_id: str) -> bool:
    job = get_job(es_host, job_id)
    return bool(job and job.get("abort_requested"))
