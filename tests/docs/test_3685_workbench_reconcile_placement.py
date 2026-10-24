#!/usr/bin/env python3
"""#3685: the workbench-reconcile loop runs in backend-worker (homeserver),
not in backend-service-mounted, and exactly one service carries it (#1628).

The sweep only reads the analyzer spools, so backend-worker must mount every
spool it reads read-only. A second consumer would race the same CAS updates
on dashboard-workbench-runs-v1.
"""
import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "arcane" / "home" / "honeypot-dashboard" / "compose.yml"

LOOP = "workbench-reconcile"
SPOOL_TARGETS = (
    "/sandbox-results",
    "/sandbox-requests",
    "/windows-sandbox-results",
    "/windows-sandbox-requests",
    "/ghosts-sandbox-results",
    "/ghosts-sandbox-requests",
    "/ghidra-results",
    "/ghidra-requests",
    "/revdeck-results",
    "/revdeck-requests",
)


def _service_block(name):
    text = COMPOSE.read_text(encoding="utf-8")
    match = re.search(rf"^  {re.escape(name)}:\n", text, re.M)
    assert match, f"service {name} not found"
    rest = text[match.end():]
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\n", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def _loops(block):
    for line in block.splitlines():
        if line.strip().startswith("#"):
            continue
        m = re.search(r"WORKER_LOOPS=([^\s\"']+)", line)
        if m:
            return [x for x in m.group(1).split(",") if x]
    return []


def test_loop_runs_in_backend_worker():
    assert LOOP in _loops(_service_block("backend-worker"))


def test_loop_not_in_mounted_api():
    assert LOOP not in _loops(_service_block("backend-service-mounted"))
    assert "WORKBENCH_RECONCILE_INTERVAL_SECONDS" not in "\n".join(
        l for l in _service_block("backend-service-mounted").splitlines()
        if not l.strip().startswith("#")
    )


def test_loop_wired_exactly_once_in_compose():
    text = COMPOSE.read_text(encoding="utf-8")
    count = 0
    for name in re.findall(r"^  ([A-Za-z0-9_-]+):\n", text, re.M):
        if LOOP in _loops(_service_block(name)):
            count += 1
    assert count == 1


def test_worker_spool_mounts_are_read_only():
    block = _service_block("backend-worker")
    for target in SPOOL_TARGETS:
        mounts = [l for l in block.splitlines() if l.strip().startswith("- /") and f":{target}" in l]
        assert mounts, f"backend-worker does not mount {target}"
        assert all(l.rstrip().endswith(":ro") for l in mounts), f"{target} must be :ro"


def test_worker_has_revdeck_env():
    block = _service_block("backend-worker")
    assert "REVDECK_REQUEST_DIR=" in block and "REVDECK_RESULTS_DIR=" in block
    assert "WORKBENCH_RECONCILE_INTERVAL_SECONDS" in block
