"""#3837: Compose containers on swarm overlays come back after a dockerd restart.

dockerd restores containers before its swarm part is up, so a Compose container
on an attachable overlay fails that start and is never retried.
ops/swarm/overlay-attach.py finishes the restore from one config file. These
tests run it against a fake docker, and tie the config to the compose files and
the unit to the boot-ordering rules from #3839.
"""
from __future__ import annotations

import configparser
import importlib.util
import json
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ops/swarm/overlay-attach.py"
CONFIG = ROOT / "ops/swarm/hosts/homeserver-overlay-attach.txt"
VPS_CONFIG = ROOT / "ops/swarm/hosts/vps-overlay-attach.txt"
UNIT = ROOT / "ops/swarm/apiary-overlay-attach.service"
README = ROOT / "ops/swarm/README.md"

spec = importlib.util.spec_from_file_location("overlay_attach", SCRIPT)
oa = importlib.util.module_from_spec(spec)
sys.modules["overlay_attach"] = oa  # dataclasses look the module up
spec.loader.exec_module(oa)

NETWORK_ERROR = "failed to set up container networking: could not find a network matching network mode {}"


class FakeDocker(oa.Docker):
    """Just enough dockerd: containers, overlays that are local or not, anchors."""

    def __init__(self, overlays: dict[str, bool], swarm: str = "active"):
        self.overlays = dict(overlays)  # name -> materialized on this node
        self.swarm = swarm
        self.containers: dict[str, dict] = {}
        self.anchors: dict[str, str] = {}  # anchor name -> network
        self.calls: list[tuple[str, ...]] = []
        self.anchor_fails = False

    def add(self, name, nets, running=False, error="", policy="unless-stopped", compose=True):
        self.containers[name] = dict(running=running, error=error, policy=policy,
                                     nets=list(nets), compose=compose)

    def run(self, *args, timeout=120):
        self.calls.append(args)
        cmd = args[0]
        if cmd == "info":
            return 0, self.swarm + "\n", ""
        if cmd == "container" and args[1] == "inspect":
            c = self.containers.get(args[2])
            if c is None:
                return 1, "[]", "No such container"
            labels = {"com.docker.compose.project": "p"} if c["compose"] else {}
            return 0, json.dumps([{
                "State": {"Running": c["running"], "Status": "running" if c["running"] else "exited",
                          "Error": c["error"]},
                "HostConfig": {"RestartPolicy": {"Name": c["policy"]}},
                "NetworkSettings": {"Networks": {n: {} for n in c["nets"]}},
                "Config": {"Labels": labels},
            }]), ""
        if cmd == "start":
            c = self.containers[args[1]]
            missing = [n for n in c["nets"] if n in self.overlays and not self.overlays[n]]
            if missing:
                c["error"] = NETWORK_ERROR.format(missing[0])
                return 1, "", "Error response from daemon: " + c["error"]
            c.update(running=True, error="")
            return 0, args[1] + "\n", ""
        if cmd == "run":
            net = args[args.index("--network") + 1]
            if self.anchor_fails or net not in self.overlays:
                return 125, "", f"network {net} not found"
            self.overlays[net] = True
            self.anchors[args[args.index("--name") + 1]] = net
            return 0, "cid\n", ""
        if cmd == "rm":
            self.anchors.pop(args[2], None)
            return 0, "", ""
        if cmd == "ps":
            if "-aq" in args:
                return 0, "\n".join(self.anchors), ""
            return 0, "\n".join(n for n, c in self.containers.items()
                                if c["compose"] and not c["running"]), ""
        if cmd == "network" and args[1] == "inspect":
            return (0, "id\n", "") if args[-1] in self.overlays else (1, "", "not found")
        if cmd == "network" and args[1] == "connect":
            net, name = args[-2], args[-1]
            if net not in self.overlays:
                return 1, "", "network not found"
            self.overlays[net] = True
            self.containers[name]["nets"].append(net)
            return 0, "", ""
        if cmd == "network" and args[1] == "disconnect":
            self.containers[args[3]]["nets"].remove(args[2])
            return 0, "", ""
        raise AssertionError(f"unexpected docker call {args}")


def attacher(cfg_text, docker):
    logs: list[str] = []
    return oa.Attacher(oa.parse_config(cfg_text), docker, log=logs.append), logs


CFG = """\
anchor-image busybox:1.38.0
start hp-tanner sensor-snare_decoy   # comment
start hp-galah galah-broker_front
start ghidra-ollama-1 galah-broker_back
connect hp-elasticsearch apiary-es elasticsearch
"""


class ConfigTest(unittest.TestCase):
    def test_parse(self):
        cfg = oa.parse_config(CFG)
        self.assertEqual(cfg.anchor_image, "busybox:1.38.0")
        self.assertEqual(cfg.targets["hp-tanner"].start_nets, ["sensor-snare_decoy"])
        self.assertEqual(cfg.targets["hp-elasticsearch"].connect, {"apiary-es": ["elasticsearch"]})

    def test_rejects_bad_lines(self):
        for bad in ("start hp-tanner", "start a b c", "attach a b", "connect a", "start a n\nstart a n"):
            with self.assertRaises(ValueError, msg=bad):
                oa.parse_config(bad)


class ReconcileTest(unittest.TestCase):
    def overlays(self, **local):
        base = {"sensor-snare_decoy": False, "galah-broker_front": False,
                "galah-broker_back": False, "apiary-es": False}
        base.update(local)
        return base

    def test_restore_failure_is_finished_and_stopped_containers_stay_down(self):
        d = FakeDocker(self.overlays(**{"sensor-snare_decoy": True}))
        d.add("hp-tanner", ["sensor-snare_decoy", "tanner_local"],
              error=NETWORK_ERROR.format("sensor-snare_decoy"))
        d.add("hp-galah", ["galah-broker_front"])            # docker stop: no Error
        d.add("ghidra-ollama-1", ["galah-broker_back"])      # stopped for the benchmark
        d.add("hp-elasticsearch", ["honeynet"], running=True)
        a, logs = attacher(CFG.replace("connect", "#"), d)
        self.assertTrue(a.reconcile())
        self.assertTrue(d.containers["hp-tanner"]["running"])
        self.assertFalse(d.containers["hp-galah"]["running"])
        self.assertFalse(d.containers["ghidra-ollama-1"]["running"])
        self.assertNotIn(("start", "hp-galah"), d.calls)
        self.assertNotIn(("start", "ghidra-ollama-1"), d.calls)

    def test_restart_policy_no_is_left_alone(self):
        d = FakeDocker(self.overlays())
        d.add("hp-tanner", ["sensor-snare_decoy"], error="boom", policy="no")
        a, _ = attacher("start hp-tanner sensor-snare_decoy", d)
        self.assertTrue(a.reconcile())
        self.assertNotIn(("start", "hp-tanner"), d.calls)

    def test_nonlocal_overlay_is_materialized_by_an_anchor_then_removed(self):
        d = FakeDocker(self.overlays())
        d.add("hp-galah", ["galah-broker_front"], error=NETWORK_ERROR.format("galah-broker_front"))
        a, logs = attacher("start hp-galah galah-broker_front", d)
        self.assertTrue(a.reconcile())
        self.assertTrue(d.containers["hp-galah"]["running"])
        run = next(c for c in d.calls if c[0] == "run")
        for flag in ("--rm", "--pull", "never", "--read-only", "busybox:1.38.0"):
            self.assertIn(flag, run)
        self.assertEqual(d.anchors, {}, "anchor must not outlive the start")

    def test_swarm_not_active_waits(self):
        d = FakeDocker(self.overlays(), swarm="pending")
        d.add("hp-tanner", ["sensor-snare_decoy"], error="x")
        a, _ = attacher("start hp-tanner sensor-snare_decoy", d)
        self.assertFalse(a.reconcile())
        self.assertNotIn(("start", "hp-tanner"), d.calls)

    def test_until_settled_retries_then_gives_up_quietly(self):
        d = FakeDocker(self.overlays())
        d.anchor_fails = True
        d.add("hp-tanner", ["sensor-snare_decoy"], error="x")
        a, logs = attacher("start hp-tanner sensor-snare_decoy", d)
        t = [0.0]
        ok = a.until_settled(window=30, interval=10, sleep=lambda s: t.__setitem__(0, t[0] + s),
                             clock=lambda: t[0])
        self.assertFalse(ok)
        self.assertEqual(sum(1 for c in d.calls if c == ("start", "hp-tanner")), 8)
        self.assertEqual(sum("still not startable" in l for l in logs), 1, logs)
        # Once the overlay appears (sensor task scheduled), the next pass succeeds.
        d.anchor_fails = False
        self.assertTrue(a.reconcile())

    def test_connect_attaches_with_alias_and_detach_removes_it(self):
        d = FakeDocker(self.overlays())
        d.add("hp-elasticsearch", ["honeynet"], running=True)
        a, _ = attacher("connect hp-elasticsearch apiary-es elasticsearch", d)
        self.assertTrue(a.reconcile())
        self.assertIn(("network", "connect", "--alias", "elasticsearch", "apiary-es", "hp-elasticsearch"), d.calls)
        n = len(d.calls)
        self.assertTrue(a.reconcile())  # idempotent
        self.assertFalse([c for c in d.calls[n:] if c[:2] == ("network", "connect")])
        a.detach()
        self.assertEqual(d.containers["hp-elasticsearch"]["nets"], ["honeynet"])

    def test_connect_waits_for_a_missing_network(self):
        d = FakeDocker({})
        d.add("hp-elasticsearch", ["honeynet"], running=True)
        a, _ = attacher("connect hp-elasticsearch apiary-es elasticsearch", d)
        self.assertTrue(a.reconcile())
        self.assertFalse([c for c in d.calls if c[:2] == ("network", "connect")])

    def test_detach_leaves_start_networks(self):
        d = FakeDocker(self.overlays(**{"sensor-snare_decoy": True}))
        d.add("hp-tanner", ["sensor-snare_decoy"], running=True)
        a, _ = attacher("start hp-tanner sensor-snare_decoy", d)
        a.detach()
        self.assertEqual(d.containers["hp-tanner"]["nets"], ["sensor-snare_decoy"])

    def test_forced_start_ignores_the_error_gate_for_named_containers_only(self):
        d = FakeDocker(self.overlays(**{"sensor-snare_decoy": True}))
        d.add("hp-tanner", ["sensor-snare_decoy"])
        d.add("hp-galah", ["galah-broker_front"])
        a, _ = attacher(CFG.replace("connect", "#"), d)
        self.assertTrue(a.reconcile(forced={"hp-tanner"}))
        self.assertTrue(d.containers["hp-tanner"]["running"])
        self.assertFalse(d.containers["hp-galah"]["running"])

    def test_running_without_its_overlay_is_an_error_not_a_repair(self):
        """2026-11-14 live: a start that failed after endpoint creation left the
        container's saved networks without its overlay; later starts succeed
        without it. Report it, keep the pass unsettled, never connect it blindly."""
        d = FakeDocker(self.overlays(**{"sensor-snare_decoy": True}))
        d.add("hp-tanner", ["tanner_local"], running=True)
        a, logs = attacher("start hp-tanner sensor-snare_decoy", d)
        self.assertFalse(a.reconcile())
        self.assertFalse(a.reconcile())
        self.assertEqual(sum("ERROR hp-tanner: running without sensor-snare_decoy" in l for l in logs), 1, logs)
        self.assertFalse([c for c in d.calls if c[:2] == ("network", "connect")])
        d.containers["hp-tanner"]["nets"].append("sensor-snare_decoy")  # recreated
        self.assertTrue(a.reconcile())

    def test_unlisted_network_failure_is_reported(self):
        d = FakeDocker(self.overlays())
        d.add("hp-new", ["edge-x_gw"], error=NETWORK_ERROR.format("edge-x_gw"))
        a, logs = attacher("start hp-tanner sensor-snare_decoy", d)
        a.report_unlisted()
        self.assertTrue(any("WARNING hp-new" in l for l in logs), logs)
        self.assertNotIn(("start", "hp-new"), d.calls)


def swarm_overlays() -> set[str]:
    """Every network a swarm stack defines, by its deployed name."""
    names = set()
    for stack in sorted((ROOT / "swarm/stacks").glob("*/stack.yml")):
        doc = yaml.safe_load(stack.read_text()) or {}
        for key, net in (doc.get("networks") or {}).items():
            net = net or {}
            if not net.get("external"):
                names.add(net.get("name") or f"{stack.parent.name}_{key}")
    return names


def compose_overlay_users(overlays: set[str]):
    """(compose file, container name or None, overlay) for every Compose service on one."""
    files = [p for p in ROOT.glob("**/*compose*.yml")
             if not any(part in {"swarm", "node_modules", ".git", "graphify-out"} for part in p.parts)]
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        nets = {k: (v or {}).get("name", k) for k, v in (doc.get("networks") or {}).items()
                if isinstance(v, dict) and v.get("external")}
        for svc_name, svc in (doc.get("services") or {}).items():
            svc_nets = (svc or {}).get("networks") or []
            keys = svc_nets if isinstance(svc_nets, list) else list(svc_nets)
            for key in keys:
                if nets.get(key) in overlays:
                    yield path.relative_to(ROOT), svc.get("container_name"), nets[key]


class RepoTest(unittest.TestCase):
    def setUp(self):
        self.cfg = oa.parse_config(CONFIG.read_text())
        self.vps = oa.parse_config(VPS_CONFIG.read_text())

    def test_every_compose_service_on_a_swarm_overlay_is_listed(self):
        """vps/ compose runs on the VPS; every other compose file on the homeserver."""
        found = list(compose_overlay_users(swarm_overlays()))
        self.assertTrue(found, "expected tanner, tftp-relay, galah, ghidra ollama and the VPS OIDC proxies")
        for path, container, net in found:
            cfg, cfg_path = (self.vps, VPS_CONFIG) if path.parts[0] == "vps" else (self.cfg, CONFIG)
            listed = {(n, x) for n, t in cfg.targets.items() for x in t.start_nets}
            if container:
                self.assertIn((container, net), listed, f"{path}: add 'start {container} {net}' to {cfg_path.name}")
            else:
                self.assertIn(net, {x for _, x in listed}, f"{path}: list the container on {net} in {cfg_path.name}")

    def test_listed_networks_are_swarm_overlays_or_d2(self):
        overlays = swarm_overlays() | {"apiary-es"}
        for t in [*self.cfg.targets.values(), *self.vps.targets.values()]:
            for net in t.overlays:
                self.assertIn(net, overlays, f"{t.name}: {net} is not a swarm stack overlay")

    def test_d2_line_is_the_documented_one_and_compose_stays_clean(self):
        d2 = [l for l in CONFIG.read_text().splitlines() if "apiary-es" in l and "connect" in l]
        self.assertEqual(d2, ["# connect hp-elasticsearch apiary-es elasticsearch"])
        cfg = oa.parse_config(d2[0].lstrip("# "))
        self.assertEqual(cfg.targets["hp-elasticsearch"].connect, {"apiary-es": ["elasticsearch"]})
        self.assertNotIn("apiary-es", (ROOT / "arcane/home/honeypot-elk/compose.yml").read_text())

    def test_anchor_image_is_pinned(self):
        for cfg in (self.cfg, self.vps):
            self.assertRegex(cfg.anchor_image, r"^[a-z0-9./-]+:[0-9][\w.-]*$")


class UnitTest(unittest.TestCase):
    def setUp(self):
        self.unit = configparser.ConfigParser(strict=False, interpolation=None)
        self.unit.optionxform = str
        self.unit.read_string(UNIT.read_text())

    def test_follows_docker_without_blocking_it(self):
        u, s = self.unit["Unit"], self.unit["Service"]
        self.assertEqual(u["After"], "docker.service")
        self.assertEqual(u["PartOf"], "docker.service")
        self.assertEqual(u["Requires"], "docker.service")
        self.assertEqual(self.unit["Install"]["WantedBy"], "docker.service")
        # #3742/#3839: no Before=, and nothing a boot target needs is ordered after it.
        self.assertNotIn("Before", u)
        self.assertNotIn("DefaultDependencies", u)
        self.assertEqual(s["Type"], "exec")
        self.assertIn("overlay-attach run /etc/apiary/overlay-attach.txt", s["ExecStart"])
        self.assertIn("overlay-attach detach", s["ExecStop"])

    def test_readme_install_matches(self):
        text = README.read_text()
        for line in ("ops/swarm/overlay-attach.py /usr/local/libexec/apiary-overlay-attach",
                     "ops/swarm/hosts/homeserver-overlay-attach.txt /etc/apiary/overlay-attach.txt",
                     "ops/swarm/apiary-overlay-attach.service /etc/systemd/system/"):
            self.assertIn(line, text)


if __name__ == "__main__":
    unittest.main()
