#!/usr/bin/env python3
"""Bring Compose containers on swarm overlays back after a dockerd restart (#3837).

dockerd restores containers with a restart policy before its swarm component is
up, so a Compose container whose networks include an attachable swarm overlay
fails that start ("could not find a network matching network mode ...") and
dockerd never retries it. This runs after docker.service and finishes that
restore, driven by one config file (ops/swarm/hosts/<host>-overlay-attach.txt):

  start   CONTAINER NETWORK            the overlay is in the container's own
                                       compose file (hp-tanner, hp-tftp-relay, ...)
  connect CONTAINER NETWORK [ALIAS...] attached after start by this tool, never
                                       written into compose (D2 apiary-es, #3582)
  anchor-image IMAGE                   local image for the throwaway attachment

Which containers it starts: a listed container that is not running, has restart
policy `always` or `unless-stopped`, and carries a State.Error, i.e. dockerd
tried to start it and failed. A container someone stopped on purpose has no
State.Error (a successful start clears it, a stop never sets it), so it stays
down: the hp-galah rollback, ghidra-ollama-1 while the benchmark has the GPU.

If a start still fails, each overlay of that container is materialized with a
throwaway `docker run --rm` anchor (the #3722 dance without a swarm service),
the start is retried and the anchors are removed. `--rm` means an anchor never
lingers as a stopped non-compose container (#3841).

`connect` lines are re-attached whenever the container runs without the network
(after start, after a Compose recreate) and detached again when the unit stops,
so the overlay endpoint is never part of the container's saved config when
dockerd restores it. Without that, the next restore would fail on it.

  run CONFIG                  service main: retry every 10 s for 15 min, then
                              every 5 min until stopped
  once CONFIG                 one pass with the same 15 min retry; exit 0 when
                              settled, 1 otherwise
  start CONFIG CONTAINER...   operator start of listed containers regardless of
                              State.Error (after maintenance; the live proof)
  detach CONFIG               disconnect every `connect` network (ExecStop)
  status CONFIG               one line per listed container
"""
from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

RESTORED_POLICIES = {"always", "unless-stopped"}
ANCHOR_LABEL = "apiary.overlay-anchor"
ANCHOR_PREFIX = "apiary-overlay-anchor-"
DEFAULT_ANCHOR_IMAGE = "busybox:1.38.0"
BOOT_WINDOW = 900
FAST_INTERVAL = 10
SLOW_INTERVAL = 300


@dataclass
class Target:
    name: str
    start_nets: list[str] = field(default_factory=list)
    connect: dict[str, list[str]] = field(default_factory=dict)  # network -> aliases

    @property
    def overlays(self) -> list[str]:
        return self.start_nets + [n for n in self.connect if n not in self.start_nets]


@dataclass
class Config:
    targets: dict[str, Target]
    anchor_image: str = DEFAULT_ANCHOR_IMAGE


def parse_config(text: str) -> Config:
    targets: dict[str, Target] = {}
    anchor = DEFAULT_ANCHOR_IMAGE
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].split()
        if not line:
            continue
        mode, args = line[0], line[1:]
        if mode == "anchor-image" and len(args) == 1:
            anchor = args[0]
            continue
        if mode not in ("start", "connect") or len(args) < 2 or (mode == "start" and len(args) != 2):
            raise ValueError(f"line {lineno}: expected 'start CONTAINER NETWORK', "
                             f"'connect CONTAINER NETWORK [ALIAS...]' or 'anchor-image IMAGE': {raw!r}")
        name, net, aliases = args[0], args[1], args[2:]
        t = targets.setdefault(name, Target(name))
        if net in t.start_nets or net in t.connect:
            raise ValueError(f"line {lineno}: {name} {net} listed twice")
        if mode == "start":
            t.start_nets.append(net)
        else:
            t.connect[net] = aliases
    return Config(targets, anchor)


class Docker:
    """Thin docker CLI wrapper; tests replace `run`."""

    def run(self, *args: str, timeout: int = 120) -> tuple[int, str, str]:
        try:
            p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, "", f"docker {args[0]} timed out after {timeout}s"
        return p.returncode, p.stdout, p.stderr

    def swarm_state(self) -> str:
        rc, out, _ = self.run("info", "--format", "{{.Swarm.LocalNodeState}}", timeout=60)
        return out.strip() if rc == 0 else "unreachable"

    def container(self, name: str) -> dict | None:
        rc, out, _ = self.run("container", "inspect", name, timeout=60)
        if rc != 0:
            return None
        info = json.loads(out)[0]
        return {
            "running": bool(info["State"].get("Running")),
            "status": info["State"].get("Status", ""),
            "error": info["State"].get("Error", "") or "",
            "policy": (info["HostConfig"].get("RestartPolicy") or {}).get("Name", "") or "no",
            "networks": sorted((info["NetworkSettings"].get("Networks") or {}).keys()),
            "compose": "com.docker.compose.project" in (info["Config"].get("Labels") or {}),
        }

    def network_exists(self, net: str) -> bool:
        return self.run("network", "inspect", "--format", "{{.Id}}", net, timeout=60)[0] == 0

    def stopped_compose_containers(self) -> list[str]:
        rc, out, _ = self.run("ps", "-a", "--filter", "label=com.docker.compose.project",
                              "--filter", "status=exited", "--filter", "status=created",
                              "--format", "{{.Names}}", timeout=60)
        return out.split() if rc == 0 else []


class Attacher:
    def __init__(self, cfg: Config, docker: Docker, log=print):
        self.cfg, self.docker, self._log = cfg, docker, log
        self._said: dict[str, str] = {}

    def log(self, msg: str) -> None:
        self._log(msg)
        sys.stdout.flush()

    def say_once(self, key: str, msg: str) -> None:
        """Log a state, but only when it changed (keeps the 5-minute loop quiet)."""
        if self._said.get(key) != msg:
            self._said[key] = msg
            self.log(msg)

    # -- anchors -----------------------------------------------------------
    def clear_anchors(self) -> None:
        rc, out, _ = self.docker.run("ps", "-aq", "--filter", f"label={ANCHOR_LABEL}", timeout=60)
        for cid in out.split() if rc == 0 else []:
            self.docker.run("rm", "-f", cid, timeout=60)

    def anchor(self, net: str) -> str | None:
        name = ANCHOR_PREFIX + net
        self.docker.run("rm", "-f", name, timeout=60)
        rc, _, err = self.docker.run(
            "run", "-d", "--rm", "--pull", "never", "--name", name, "--network", net,
            "--label", f"{ANCHOR_LABEL}=3837", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--log-driver", "none",
            self.cfg.anchor_image, "sleep", "600", timeout=180)
        if rc != 0:
            self.log(f"anchor {net}: {err.strip() or f'rc {rc}'}")
            return None
        self.log(f"anchor {net}: attached")
        return name

    # -- one container -----------------------------------------------------
    def start(self, t: Target) -> bool:
        rc, _, err = self.docker.run("start", t.name)
        if rc == 0:
            self.log(f"{t.name}: started")
            return True
        self.log(f"{t.name}: start failed ({err.strip()}); materializing {', '.join(t.overlays)}")
        anchors = [a for a in (self.anchor(n) for n in t.overlays) if a]
        try:
            rc, _, err = self.docker.run("start", t.name)
        finally:
            for a in anchors:
                self.docker.run("rm", "-f", a, timeout=60)
        if rc == 0:
            self.log(f"{t.name}: started after materializing")
            return True
        self.say_once(t.name, f"{t.name}: still not startable: {err.strip()}")
        return False

    def connect(self, t: Target, info: dict) -> bool:
        ok = True
        for net, aliases in t.connect.items():
            if net in info["networks"]:
                self.say_once(f"{t.name}/{net}", f"{t.name}: on {net}")
                continue
            if not self.docker.network_exists(net):
                self.say_once(f"{t.name}/{net}", f"{t.name}: {net} does not exist yet; not attaching")
                continue
            args = ["network", "connect"]
            for a in aliases:
                args += ["--alias", a]
            rc, _, err = self.docker.run(*args, net, t.name)
            if rc == 0:
                self._said.pop(f"{t.name}/{net}", None)
                self.log(f"{t.name}: connected to {net}" + (f" as {', '.join(aliases)}" if aliases else ""))
            else:
                ok = False
                self.say_once(f"{t.name}/{net}", f"{t.name}: connect {net} failed: {err.strip()}")
        return ok

    def reconcile_one(self, t: Target, forced: bool = False) -> bool:
        info = self.docker.container(t.name)
        if info is None:
            self.say_once(t.name, f"{t.name}: no such container; skipped")
            return True
        if not info["running"]:
            restore_failed = info["policy"] in RESTORED_POLICIES and info["error"]
            if not (forced or restore_failed):
                self.say_once(t.name, f"{t.name}: {info['status']} with no start error "
                                      f"(policy {info['policy']}); left down")
                return True
            if not forced:
                self.log(f"{t.name}: dockerd's start failed: {info['error']}")
            if not self.start(t):
                return False
            self._said.pop(t.name, None)
            info = self.docker.container(t.name) or info
        return self.connect(t, info) if t.connect else True

    # -- passes ------------------------------------------------------------
    def reconcile(self, forced: set[str] = frozenset()) -> bool:
        state = self.docker.swarm_state()
        if state != "active":
            self.say_once("swarm", f"swarm state {state!r}; waiting")
            return False
        self._said.pop("swarm", None)
        settled = True
        for t in self.cfg.targets.values():
            if forced and t.name not in forced:
                continue
            settled &= self.reconcile_one(t, t.name in forced)
        return settled

    def report_unlisted(self) -> None:
        for name in self.docker.stopped_compose_containers():
            if name in self.cfg.targets:
                continue
            info = self.docker.container(name)
            if info and info["policy"] in RESTORED_POLICIES and "network" in info["error"]:
                self.log(f"WARNING {name}: not listed but failed on a network: {info['error']} "
                         "(add it to the overlay-attach config)")

    def until_settled(self, window: int = BOOT_WINDOW, interval: int = FAST_INTERVAL,
                      forced: set[str] = frozenset(), sleep=time.sleep, clock=time.monotonic) -> bool:
        deadline = clock() + window
        while True:
            if self.reconcile(forced):
                return True
            if clock() >= deadline:
                return False
            sleep(interval)

    def detach(self) -> None:
        for t in self.cfg.targets.values():
            info = self.docker.container(t.name)
            for net in t.connect:
                if info and net in info["networks"]:
                    rc, _, err = self.docker.run("network", "disconnect", net, t.name, timeout=60)
                    self.log(f"{t.name}: disconnected from {net}" if rc == 0
                             else f"{t.name}: disconnect {net} failed: {err.strip()}")

    def status(self) -> list[str]:
        rows = []
        for t in self.cfg.targets.values():
            info = self.docker.container(t.name)
            if info is None:
                rows.append(f"{t.name}: missing")
                continue
            want = ",".join(t.start_nets + [f"+{n}" for n in t.connect])
            rows.append(f"{t.name}: {info['status']} policy={info['policy']} want={want} "
                        f"nets={','.join(info['networks'])} error={info['error'] or '-'}")
        return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["run", "once", "start", "detach", "status"])
    ap.add_argument("config", type=Path)
    ap.add_argument("containers", nargs="*")
    args = ap.parse_args(argv)
    cfg = parse_config(args.config.read_text())
    a = Attacher(cfg, Docker())

    def stop(signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)

    if args.command == "status":
        print("\n".join(a.status()))
        return 0
    if args.command == "detach":
        a.detach()
        return 0
    if args.command == "start":
        unknown = sorted(set(args.containers) - set(cfg.targets))
        if not args.containers or unknown:
            print(f"start needs listed containers; not in {args.config}: {unknown}", file=sys.stderr)
            return 2
        return 0 if a.until_settled(window=120, forced=set(args.containers)) else 1
    a.clear_anchors()
    settled = a.until_settled()
    a.report_unlisted()
    a.log("settled" if settled else f"not settled after {BOOT_WINDOW}s; retrying every {SLOW_INTERVAL}s")
    if args.command == "once":
        return 0 if settled else 1
    while True:
        time.sleep(SLOW_INTERVAL)
        a.reconcile()


if __name__ == "__main__":
    sys.exit(main())
