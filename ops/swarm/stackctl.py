#!/usr/bin/env python3
"""Swarm stacks under Arcane GitOps (#3590, epic #3587).

Runs on the admin workstation, like swarm-membership.sh: it needs the Arcane API
key (~/.config/apiary/arcane-api-key, never printed) and SSH to `homeserver`.
Every call goes through the Arcane API of the manager environment, so Arcane
stays the single deploy path; nothing here runs `docker stack deploy`.

  list                       repo stacks, their syncs, and what runs in the swarm
  ensure [STACK...]          one GitOps sync per swarm/stacks/<name>/stack.yml,
                             created or corrected idempotently. Creating a sync
                             makes Arcane deploy it at once, so ensure then waits
                             for convergence like deploy does.
  deploy STACK               run the stack's sync, then wait until every service
                             update is `completed` (exit 0), was rolled back by
                             swarm (exit 3), or failed or timed out (exit 1)
  status STACK               services, replicas and update state
  rollback STACK [-s SVC]    swarm rollback to each service's previous spec.
                             Git still holds the bad commit: revert it and deploy,
                             or the next sync re-applies it.
  pause STACK...             scale the stacks to 0 (#3135). Default deny: every
                             service needs apiary.pause=safe|unit. The sync's
                             autoSync is the gate (a sync redeploys the file's
                             replicas), switched off first and restored last.
  resume                     scale back in reverse order; verifies replicas and
                             the optional apiary.probe
  pause-status               what is recorded as paused
  secret create NAME_vN      read a value from stdin and create an immutable
                             swarm secret; refuses an existing name
  secret ls | secret rm NAME
  remove STACK --yes         delete the stack's sync and the stack (both; deleting
                             a sync alone leaves the stack running)

Arcane: --arcane-url or ARCANE_URL. Without either, an SSH forward to the
manager (homeserver -> 10.8.0.2:3552) is opened for the duration of the run.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
STACKS_DIR = "swarm/stacks"
STACK_FILES = ("stack.yml", "stack.yaml")
KEY_FILE = Path(os.environ.get("ARCANE_API_KEY_FILE", "~/.config/apiary/arcane-api-key")).expanduser()
STATE_DIR = Path(os.environ.get("APIARY_SWARM_STATE", "~/.local/state/apiary/swarm-pause")).expanduser()
TUNNEL_HOST = os.environ.get("ARCANE_TUNNEL_HOST", "homeserver")
TUNNEL_TARGET = os.environ.get("ARCANE_TUNNEL_TARGET", "10.8.0.2:3552")
# Same patterns as scripts/honeypot-pause.sh: the cold-run protocol owns the
# homeserver while one of these runs.
COLD_RUN_PATTERNS = ("sweep_extra.sh", "record_baseline.py", "round7_sweep.sh", "coldrun.sh", "round7_coldrun.sh")

DONE_STATES = {"completed"}
ROLLED_BACK_STATES = {"rollback_completed"}
STUCK_STATES = {"paused", "rollback_paused"}

EXIT_OK, EXIT_FAIL, EXIT_ROLLED_BACK = 0, 1, 3


class Abort(Exception):
    pass


class NotFound(Abort):
    pass


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


# ---------------------------------------------------------------------------
# Arcane API
# ---------------------------------------------------------------------------


class Arcane:
    def __init__(self, base: str, key: str, env: str = "0", opener: Callable | None = None):
        self.base = base.rstrip("/")
        self.key = key
        self.env = env
        self._open = opener or urllib.request.urlopen

    def call(self, method: str, path: str, body=None, timeout: int = 600):
        url = self.base + path.replace("{env}", self.env)
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-API-Key", self.key)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._open(req, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:400]
            if exc.code == 401:
                raise Abort("Arcane answered 401: the API key is not accepted. Get a fresh key; do not debug the header.")
            if exc.code == 404:
                raise NotFound(f"{method} {path} -> 404: {detail}")
            raise Abort(f"{method} {path} -> HTTP {exc.code}: {detail}")
        return json.loads(raw) if raw else {}

    def paged(self, path: str) -> list[dict]:
        out: list[dict] = []
        start = 0
        while True:
            sep = "&" if "?" in path else "?"
            page = self.call("GET", f"{path}{sep}limit=100&start={start}")
            rows = page.get("data") or []
            out += rows
            total = (page.get("pagination") or {}).get("totalItems")
            start += len(rows)
            if not rows or total is None or start >= total:
                return out

    # -- gitops --------------------------------------------------------------
    def syncs(self) -> list[dict]:
        return self.paged("/environments/{env}/gitops-syncs")

    def repositories(self) -> list[dict]:
        return self.paged("/customize/git-repositories")

    # -- swarm ---------------------------------------------------------------
    def stack_services(self, stack: str) -> list[dict]:
        try:
            return self.paged(f"/environments/{{env}}/swarm/stacks/{urllib.parse.quote(stack)}/services")
        except NotFound:
            return []  # the stack does not exist (yet)

    def service(self, sid: str) -> dict:
        return self.call("GET", f"/environments/{{env}}/swarm/services/{sid}").get("data") or {}

    def stacks(self) -> list[dict]:
        return self.paged("/environments/{env}/swarm/stacks")


def find_sync(api: Arcane, stack: str, syncs: list[dict] | None = None) -> dict | None:
    matches = [s for s in (syncs if syncs is not None else api.syncs())
               if s.get("targetType") == "swarm_stack" and s.get("projectName") == stack]
    if len(matches) > 1:
        raise Abort(f"{len(matches)} swarm_stack syncs deploy {stack!r}; delete the extra ones first: "
                    + ", ".join(s["id"] for s in matches))
    return matches[0] if matches else None


# ---------------------------------------------------------------------------
# repo layout
# ---------------------------------------------------------------------------


def repo_stacks(root: Path = REPO_ROOT) -> dict[str, str]:
    """stack name -> repo-relative compose path, from swarm/stacks/<name>/stack.yml."""
    out: dict[str, str] = {}
    base = root / STACKS_DIR
    if not base.is_dir():
        return out
    for d in sorted(p for p in base.iterdir() if p.is_dir()):
        for fname in STACK_FILES:
            if (d / fname).is_file():
                out[d.name] = f"{STACKS_DIR}/{d.name}/{fname}"
                break
    return out


@dataclass
class SyncPlan:
    stack: str
    action: str  # create | update | ok
    body: dict
    sync_id: str | None = None


def desired_sync(stack: str, compose_path: str, repository_id: str, branch: str) -> dict:
    # Manual by default, like every other Arcane sync in this fleet: merging to
    # main does not deploy; `deploy` does. autoSync also gates `pause`.
    return {
        "name": f"swarm-{stack}",
        "projectName": stack,
        "targetType": "swarm_stack",
        "mode": "deploy",
        "repositoryId": repository_id,
        "branch": branch,
        "composePath": compose_path,
        "autoSync": False,
        "syncInterval": 60,
        # Directory mode, like every other sync here. Required, not cosmetic: in
        # single-file mode Arcane v2.15.1 resolves `file:` configs against its
        # relative clone dir (GIT_WORK_DIR defaults to data/git) and compounds
        # the path. Directory mode deploys from the absolute stack-source copy
        # under /app/data/swarm/sources, which also shows the files in the UI.
        "syncDirectory": True,
    }


def plan_syncs(stacks: dict[str, str], existing: list[dict], repository_id: str, branch: str) -> list[SyncPlan]:
    plans = []
    for stack, path in stacks.items():
        want = desired_sync(stack, path, repository_id, branch)
        have = [s for s in existing if s.get("targetType") == "swarm_stack" and s.get("projectName") == stack]
        if len(have) > 1:
            raise Abort(f"{len(have)} swarm_stack syncs deploy {stack!r}; delete the extra ones first")
        if not have:
            plans.append(SyncPlan(stack, "create", want))
            continue
        cur = have[0]
        # autoSync is left alone on an existing sync: pause may hold it off.
        diff = {k: v for k, v in want.items() if k not in ("autoSync", "syncInterval", "mode") and cur.get(k) != v}
        plans.append(SyncPlan(stack, "update" if diff else "ok", diff, cur["id"]))
    return plans


def resolve_repository(api: Arcane, name: str) -> str:
    repos = api.repositories()
    hits = [r for r in repos if r.get("name") == name]
    if len(hits) != 1:
        raise Abort(f"Arcane git repository {name!r}: {len(hits)} match(es) among {[r.get('name') for r in repos]}")
    return hits[0]["id"]


# ---------------------------------------------------------------------------
# waiting for a rollout
# ---------------------------------------------------------------------------


def snapshot(api: Arcane, stack: str) -> dict[str, dict]:
    out = {}
    for s in api.stack_services(stack):
        detail = api.service(s["id"])
        out[s["id"]] = {
            "name": s.get("name"),
            "replicas": s.get("replicas"),
            "running": s.get("runningReplicas"),
            "mode": s.get("mode"),
            "version": ((detail.get("version") or {}).get("Index")),
            "update": detail.get("updateStatus") or {},
        }
    return out


def wait_rollout(api: Arcane, stack: str, before: dict[str, dict], timeout: int = 900, poll: float = 5,
                 grace: float = 20, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> int:
    """Wait until every service settled. Returns EXIT_OK / EXIT_ROLLED_BACK / EXIT_FAIL.

    A service whose spec version did not change is settled once its replicas
    run. A changed one is settled when swarm reports a terminal UpdateStatus
    for an update that started after `before`, or, for a spec change that
    starts no rolling update (labels only), after `grace` seconds with all
    replicas running.
    """
    t0 = clock()
    last = ""
    while True:
        now = snapshot(api, stack)
        verdicts = {}
        for sid, cur in now.items():
            prev = before.get(sid)
            upd = cur["update"]
            state = upd.get("State") or ""
            fresh = prev is None or upd.get("StartedAt") != prev["update"].get("StartedAt")
            replicas_ok = cur["mode"] != "replicated" or cur["running"] == cur["replicas"]
            if prev is None:  # created by this deploy: no rolling update yet
                if state in ROLLED_BACK_STATES:
                    verdicts[cur["name"]] = "rolled_back"
                elif state in STUCK_STATES:
                    verdicts[cur["name"]] = f"stuck:{state}:{upd.get('Message', '')}"
                elif state in DONE_STATES or not state:
                    verdicts[cur["name"]] = "ok" if replicas_ok else "converging"
                else:
                    verdicts[cur["name"]] = f"updating:{state}"
            elif cur["version"] == prev["version"]:
                verdicts[cur["name"]] = "ok" if replicas_ok else "converging"
            elif fresh and state in ROLLED_BACK_STATES:
                verdicts[cur["name"]] = "rolled_back"
            elif fresh and state in STUCK_STATES:
                verdicts[cur["name"]] = f"stuck:{state}:{upd.get('Message', '')}"
            elif fresh and state in DONE_STATES:
                verdicts[cur["name"]] = "ok" if replicas_ok else "converging"
            elif not fresh and replicas_ok and clock() - t0 >= grace:
                verdicts[cur["name"]] = "ok"  # spec change without a rolling update
            else:
                verdicts[cur["name"]] = f"updating:{state or 'pending'}"
        line = ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items()))
        if line != last:
            log(f"{stack}: {line}")
            last = line
        if verdicts and all(v in ("ok", "rolled_back") or v.startswith("stuck") for v in verdicts.values()):
            if any(v.startswith("stuck") for v in verdicts.values()):
                return EXIT_FAIL
            return EXIT_ROLLED_BACK if "rolled_back" in verdicts.values() else EXIT_OK
        if clock() - t0 > timeout:
            log(f"{stack}: timed out after {timeout}s")
            return EXIT_FAIL
        sleep(poll)


def run_sync(api: Arcane, sync_id: str) -> None:
    res = api.call("POST", f"/environments/{{env}}/gitops-syncs/{sync_id}/sync").get("data") or {}
    if not res.get("success"):
        raise Abort(f"sync failed: {res.get('message')} {res.get('error') or ''}".strip())
    log(f"sync: {res.get('message')}")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_list(api: Arcane, args) -> int:
    stacks = repo_stacks()
    syncs = [s for s in api.syncs() if s.get("targetType") == "swarm_stack"]
    live = {s.get("name"): s.get("services") for s in api.stacks()}
    names = sorted(set(stacks) | {s.get("projectName") for s in syncs} | set(live))
    print(f"{'stack':24} {'repo':5} {'sync':40} {'last':8} {'commit':9} services")
    for n in names:
        s = next((x for x in syncs if x.get("projectName") == n), None)
        print(f"{n:24} {'yes' if n in stacks else 'NO':5} "
              f"{(s or {}).get('id', '-'):40} {(s or {}).get('lastSyncStatus') or '-':8} "
              f"{((s or {}).get('lastSyncCommit') or '-')[:8]:9} {live.get(n, '-')}")
    return 0


def cmd_ensure(api: Arcane, args) -> int:
    stacks = repo_stacks()
    if args.stacks:
        missing = [s for s in args.stacks if s not in stacks]
        if missing:
            raise Abort(f"no swarm/stacks/<name>/stack.yml for: {', '.join(missing)}")
        stacks = {k: v for k, v in stacks.items() if k in args.stacks}
    if not stacks:
        log("no stacks under swarm/stacks/")
        return 0
    repo_id = resolve_repository(api, args.repository)
    rc = EXIT_OK
    for plan in plan_syncs(stacks, api.syncs(), repo_id, args.branch):
        if plan.action == "ok":
            log(f"{plan.stack}: sync {plan.sync_id} already matches")
            continue
        if args.dry_run:
            log(f"{plan.stack}: would {plan.action} {json.dumps(plan.body, sort_keys=True)}")
            continue
        if plan.action == "update":
            api.call("PUT", f"/environments/{{env}}/gitops-syncs/{plan.sync_id}", plan.body)
            log(f"{plan.stack}: sync {plan.sync_id} updated {sorted(plan.body)}; run `deploy {plan.stack}` to apply")
            continue
        log(f"{plan.stack}: creating sync (Arcane deploys it immediately)")
        created = api.call("POST", "/environments/{env}/gitops-syncs", plan.body).get("data") or {}
        log(f"{plan.stack}: sync {created.get('id')} status={created.get('lastSyncStatus')}")
        if created.get("lastSyncStatus") == "failed":
            log(f"{plan.stack}: initial deploy failed: {created.get('lastSyncError')}")
            rc = EXIT_FAIL
            continue
        rc = max(rc, wait_rollout(api, plan.stack, {}, timeout=args.timeout))
    return rc


def cmd_deploy(api: Arcane, args) -> int:
    sync = find_sync(api, args.stack)
    if not sync:
        raise Abort(f"no swarm_stack sync for {args.stack!r}; run `ensure {args.stack}` first")
    if args.stack in {e["stack"] for e in read_inventory()}:
        raise Abort(f"{args.stack} is recorded as paused; a deploy would restore its replicas. `resume` first.")
    before = snapshot(api, args.stack)
    run_sync(api, sync["id"])
    if args.no_wait:
        return EXIT_OK
    rc = wait_rollout(api, args.stack, before, timeout=args.timeout)
    if rc == EXIT_ROLLED_BACK:
        log(f"{args.stack}: swarm ROLLED BACK the update (failure_action: rollback). "
            "The previous spec is running; fix or revert the commit before the next deploy.")
    return rc


def cmd_status(api: Arcane, args) -> int:
    snap = snapshot(api, args.stack)
    if not snap:
        log(f"{args.stack}: no services in the swarm")
        return EXIT_FAIL
    for sid, s in sorted(snap.items(), key=lambda kv: kv[1]["name"]):
        u = s["update"]
        print(f"{s['name']:40} {s['mode']:10} {s['running']}/{s['replicas']} v{s['version']} "
              f"update={u.get('State') or '-'} {u.get('Message') or ''}")
    return 0


def cmd_rollback(api: Arcane, args) -> int:
    before = snapshot(api, args.stack)
    targets = [sid for sid, s in before.items() if not args.service or s["name"] in args.service]
    if not targets:
        raise Abort("no matching service")
    for sid in targets:
        api.call("POST", f"/environments/{{env}}/swarm/services/{sid}/rollback")
        log(f"rollback requested: {before[sid]['name']}")
    rc = wait_rollout(api, args.stack, before, timeout=args.timeout)
    log("Git still holds the rolled-back change. Revert it on main, then `deploy`.")
    # A manual rollback is a ServiceUpdate to PreviousSpec, so swarm reports it
    # as rollback_completed; for this command that is success.
    return EXIT_OK if rc in (EXIT_OK, EXIT_ROLLED_BACK) else rc


# -- pause / resume (#3135) ----------------------------------------------------

INVENTORY = "inventory.json"


def read_inventory() -> list[dict]:
    path = STATE_DIR / INVENTORY
    if not path.is_file():
        return []
    return json.loads(path.read_text()).get("entries", [])


def write_inventory(entries: list[dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_DIR / (INVENTORY + ".tmp")
    tmp.write_text(json.dumps({"issue": "#3135", "entries": entries}, indent=2) + "\n")
    tmp.replace(STATE_DIR / INVENTORY)


def append_record(line: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with (STATE_DIR / "record.log").open("a") as fh:
        fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {line}\n")


def ssh_run(host: str, script: str) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", host, script], capture_output=True, text=True, timeout=60)


def cold_run_active(runner: Callable = ssh_run) -> str | None:
    pattern = "|".join(COLD_RUN_PATTERNS)
    res = runner("homeserver", f"pgrep -af -- '{pattern}' | grep -v pgrep || true")
    out = res.stdout.strip()
    return out.splitlines()[0] if out else None


def pause_plan(services: list[dict]) -> list[dict]:
    """Default deny. Returns services in pause order, or raises."""
    if not services:
        raise Abort("stack has no services in the swarm")
    plan = []
    for s in services:
        labels = s.get("labels") or {}
        verdict = labels.get("apiary.pause")
        if verdict not in ("safe", "unit"):
            raise Abort(f"service {s.get('name')}: apiary.pause={verdict!r}; only safe/unit may be paused "
                        f"({labels.get('apiary.pause.reason', 'no reason given')})")
        if s.get("mode") != "replicated":
            raise Abort(f"service {s.get('name')}: mode {s.get('mode')} cannot be scaled to 0")
        plan.append(s)
    return sorted(plan, key=lambda s: (int((s.get("labels") or {}).get("apiary.pause.order", 0)), s.get("name")))


def wait_replicas(api: Arcane, stack: str, sid: str, want: int, timeout: int = 300, poll: float = 3,
                  sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> bool:
    t0 = clock()
    while clock() - t0 <= timeout:
        for s in api.stack_services(stack):
            if s["id"] == sid and s.get("runningReplicas") == want:
                return True
        sleep(poll)
    return False


def probe(spec: str, host: str, via: str, runner: Callable = ssh_run) -> tuple[bool, str]:
    if spec.startswith("tcp:"):
        port = int(spec[4:])
        res = runner(via, f"timeout 5 bash -c 'exec 3<>/dev/tcp/{host}/{port}'")
        return res.returncode == 0, f"tcp/{port} {'connected' if res.returncode == 0 else 'refused'}"
    port, _, path = spec[5:].partition("/")
    res = runner(via, f"curl -s -o /dev/null -m 8 -w '%{{http_code}}' http://{host}:{int(port)}/{path}")
    code = res.stdout.strip()
    return code == "200", f"http/{port}/{path} -> {code or 'no answer'}"


def cmd_pause(api: Arcane, args, runner: Callable = ssh_run) -> int:
    if read_inventory():
        raise Abort(f"a pause is already recorded in {STATE_DIR / INVENTORY}; `resume` it first")
    if (cold := cold_run_active(runner)):
        raise Abort(f"cold-run protocol is active on homeserver ({cold}); it owns STOP_WORKERS. Wait for it.")
    plans = {stack: pause_plan(api.stack_services(stack)) for stack in args.stacks}
    syncs = api.syncs()
    entries: list[dict] = []
    log("=== PAUSE (swarm, #3135): scale to 0; frees CPU and RAM (the tasks stop) ===")
    for stack in args.stacks:
        sync = find_sync(api, stack, syncs)
        gate = {"stack": stack, "kind": "gate", "sync": sync["id"] if sync else None,
                "autoSync": bool(sync and sync.get("autoSync"))}
        if gate["autoSync"]:
            api.call("PUT", f"/environments/{{env}}/gitops-syncs/{sync['id']}", {"autoSync": False})
            log(f"GATE: autoSync off for {sync['name']} (an auto-sync would redeploy the replicas)")
        entries.append(gate)
        write_inventory(entries)
        for s in plans[stack]:
            entry = {"stack": stack, "kind": "service", "id": s["id"], "name": s["name"],
                     "replicas": s.get("replicas"), "probe": (s.get("labels") or {}).get("apiary.probe")}
            api.call("POST", f"/environments/{{env}}/swarm/services/{s['id']}/scale", {"replicas": 0})
            entries.append(entry)
            write_inventory(entries)
            ok = wait_replicas(api, stack, s["id"], 0)
            log(f"  {s['name']}: {s.get('replicas')} -> 0 {'(stopped)' if ok else '(NOT confirmed stopped)'}")
    append_record(f"pause stacks={','.join(args.stacks)} entries={len(entries)}")
    log(f"recorded {STATE_DIR / INVENTORY}; resume with: stackctl.py resume")
    return EXIT_OK


def cmd_resume(api: Arcane, args, runner: Callable = ssh_run) -> int:
    entries = read_inventory()
    if not entries:
        log("nothing recorded")
        return EXIT_OK
    problems = 0
    log("=== RESUME (swarm, #3135): reverse order ===")
    for e in reversed(entries):
        if e["kind"] == "gate":
            if e.get("autoSync") and e.get("sync"):
                api.call("PUT", f"/environments/{{env}}/gitops-syncs/{e['sync']}", {"autoSync": True})
                log(f"GATE: autoSync restored for {e['stack']}")
            continue
        api.call("POST", f"/environments/{{env}}/swarm/services/{e['id']}/scale", {"replicas": e["replicas"]})
        if not wait_replicas(api, e["stack"], e["id"], e["replicas"], timeout=args.timeout):
            log(f"  {e['name']}: replicas did not reach {e['replicas']}")
            problems += 1
            continue
        line = f"  {e['name']}: 0 -> {e['replicas']} running"
        if e.get("probe"):
            ok, detail = probe(e["probe"], args.probe_host, args.probe_via, runner)
            line += f", probe {detail}"
            problems += 0 if ok else 1
        log(line)
    append_record(f"resume entries={len(entries)} problems={problems}")
    if problems:
        log(f"{problems} problem(s); inventory kept for a retry")
        return EXIT_FAIL
    (STATE_DIR / INVENTORY).unlink()
    log("all verified; inventory cleared")
    return EXIT_OK


def cmd_pause_status(api: Arcane, args) -> int:
    entries = read_inventory()
    if not entries:
        log("no pause recorded")
        return 0
    for e in entries:
        print(json.dumps(e, sort_keys=True))
    return 0


# -- secrets -------------------------------------------------------------------

def secret_list(api: Arcane) -> list[dict]:
    return api.call("GET", "/environments/{env}/swarm/secrets").get("data") or []


def cmd_secret(api: Arcane, args, stdin=None) -> int:
    if args.action == "ls":
        for s in secret_list(api):
            spec = s.get("spec") or {}
            print(f"{spec.get('Name'):40} {s.get('createdAt')} {json.dumps(spec.get('Labels') or {}, sort_keys=True)}")
        return 0
    if not args.name:
        raise Abort("secret NAME is required")
    m = re.match(r"^([a-z0-9][a-z0-9_.-]*)_v([0-9]+)$", args.name)
    if not m:
        raise Abort(f"secret name {args.name!r} must be <base>_vN")
    existing = {(s.get("spec") or {}).get("Name"): s for s in secret_list(api)}
    if args.action == "rm":
        if args.name not in existing:
            raise Abort(f"no secret {args.name}")
        api.call("DELETE", f"/environments/{{env}}/swarm/secrets/{existing[args.name]['id']}")
        log(f"removed {args.name}")
        return 0
    if args.name in existing:
        raise Abort(f"{args.name} exists; secrets are immutable. Create {m.group(1)}_v{int(m.group(2)) + 1} instead.")
    stdin = stdin or sys.stdin
    if stdin.isatty():
        value = getpass.getpass(f"value for {args.name}: ").encode()
    else:
        value = stdin.buffer.read() if hasattr(stdin, "buffer") else stdin.read().encode()
    if not value:
        raise Abort("empty secret value")
    spec = {"Name": args.name, "Data": base64.b64encode(value).decode(),
            "Labels": {"apiary.secret.base": m.group(1), "apiary.secret.version": m.group(2)}}
    api.call("POST", "/environments/{env}/swarm/secrets", {"spec": spec})
    log(f"created {args.name} ({len(value)} bytes); the value was not printed")
    return 0


def cmd_remove(api: Arcane, args) -> int:
    if not args.yes:
        raise Abort("remove deletes the stack's sync AND its services; pass --yes")
    sync = find_sync(api, args.stack)
    if sync:
        api.call("DELETE", f"/environments/{{env}}/gitops-syncs/{sync['id']}")
        log(f"deleted sync {sync['id']}")
    if any(s.get("name") == args.stack for s in api.stacks()):
        api.call("DELETE", f"/environments/{{env}}/swarm/stacks/{urllib.parse.quote(args.stack)}")
        log(f"removed stack {args.stack}")
    return 0


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------


def open_tunnel() -> tuple[str, subprocess.Popen]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        ["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-L", f"127.0.0.1:{port}:{TUNNEL_TARGET}", TUNNEL_HOST],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        if proc.poll() is not None:
            raise Abort(f"ssh forward to {TUNNEL_HOST} failed: {proc.stderr.read().decode()[:300]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return f"http://127.0.0.1:{port}/api", proc
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise Abort("ssh forward did not come up")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arcane-url", default=os.environ.get("ARCANE_URL"))
    ap.add_argument("--env", default=os.environ.get("ARCANE_ENV", "0"), help="Arcane environment of a swarm manager")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p = sub.add_parser("ensure")
    p.add_argument("stacks", nargs="*")
    p.add_argument("--branch", default="main")
    p.add_argument("--repository", default="apiary", help="Arcane git repository name")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--timeout", type=int, default=900)
    p = sub.add_parser("deploy")
    p.add_argument("stack")
    p.add_argument("--no-wait", action="store_true")
    p.add_argument("--timeout", type=int, default=900)
    p = sub.add_parser("status")
    p.add_argument("stack")
    p = sub.add_parser("rollback")
    p.add_argument("stack")
    p.add_argument("-s", "--service", action="append")
    p.add_argument("--timeout", type=int, default=600)
    p = sub.add_parser("pause")
    p.add_argument("stacks", nargs="+")
    p = sub.add_parser("resume")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--probe-host", default="10.8.0.2")
    p.add_argument("--probe-via", default="homeserver", help="SSH alias the probe runs from")
    sub.add_parser("pause-status")
    p = sub.add_parser("secret")
    p.add_argument("action", choices=["create", "ls", "rm"])
    p.add_argument("name", nargs="?")
    p = sub.add_parser("remove")
    p.add_argument("stack")
    p.add_argument("--yes", action="store_true")
    return ap


COMMANDS = {
    "list": cmd_list, "ensure": cmd_ensure, "deploy": cmd_deploy, "status": cmd_status,
    "rollback": cmd_rollback, "pause": cmd_pause, "resume": cmd_resume,
    "pause-status": cmd_pause_status, "secret": cmd_secret, "remove": cmd_remove,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tunnel = None
    try:
        if not KEY_FILE.is_file():
            raise Abort(f"Arcane API key file {KEY_FILE} is missing")
        key = KEY_FILE.read_text().strip()
        url = args.arcane_url
        if not url:
            url, tunnel = open_tunnel()
        return COMMANDS[args.cmd](Arcane(url, key, args.env), args)
    except Abort as exc:
        log(f"ABORT: {exc}")
        return EXIT_FAIL
    finally:
        if tunnel:
            tunnel.terminate()


if __name__ == "__main__":
    sys.exit(main())
