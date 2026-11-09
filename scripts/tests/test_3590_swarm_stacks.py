"""Swarm stacks under Arcane GitOps (#3590): the conventions lint and stackctl.

No Arcane, Docker or network: stackctl's API is replaced by an in-memory fake
that models what the live proof on 2026-10-11 showed (a sync restores the stack
file's replicas, update states, config labels).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:  # pragma: no cover - CI installs PyYAML
    HAVE_YAML = False


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


stackctl = load("stackctl_3590", "ops/swarm/stackctl.py")
lint = load("check_swarm_stacks_3590", "scripts/check-swarm-stacks.py") if HAVE_YAML else None

GOOD_SERVICE = """
    image: busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
    environment:
      APP_TOKEN_FILE: /run/secrets/app_token
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      placement:
        constraints: [node.labels.role == manager, node.labels.sensor == false]
      restart_policy: {condition: any}
      update_config: {failure_action: rollback, order: start-first, monitor: 30s}
      rollback_config: {failure_action: pause, order: start-first}
      labels:
        apiary.pause: safe
        apiary.pause.reason: test
"""


def good_stack(extra_service: str = "", top: str = "") -> str:
    return "services:\n  app:" + textwrap.indent(textwrap.dedent(GOOD_SERVICE), "    ") + extra_service + top


@unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
class LintTest(unittest.TestCase):
    def write(self, body: str, name: str = "demo", files: dict[str, str] | None = None) -> tuple[Path, Path]:
        tmp = Path(tempfile.mkdtemp())
        d = tmp / "swarm" / "stacks" / name
        d.mkdir(parents=True)
        (d / "stack.yml").write_text(body)
        for rel, content in (files or {}).items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(content)
        return tmp, d / "stack.yml"

    def errors(self, body: str, **kw) -> list[str]:
        root, path = self.write(body, **kw)
        return lint.check_file(path, root)

    def test_repo_tree_and_template_pass(self):
        self.assertEqual(lint.main(["--root", str(ROOT)]), 0)
        self.assertEqual(lint.check_file(ROOT / lint.TEMPLATE, ROOT, template=True), [])

    def test_good_stack_with_secret_and_config(self):
        top = textwrap.dedent("""
            secrets:
              app_token: {external: true, name: app_token_v3}
            configs:
              index: {external: true, name: index_v2, x-apiary-file: ./configs/index.html}
        """)
        self.assertEqual(self.errors(good_stack(top=top), files={"configs/index.html": "x"}), [])

    def assertFlags(self, body: str, needle: str, **kw):
        errs = self.errors(body, **kw)
        self.assertTrue(any(needle in e for e in errs), f"{needle!r} not in {errs}")

    def test_secret_must_be_external_and_versioned(self):
        self.assertFlags(good_stack(top="secrets:\n  s: {file: ./s.txt, name: s_v1}\n"), "must be `external: true`")
        self.assertFlags(good_stack(top="secrets:\n  s: {external: true, name: s}\n"), "versioned")

    def test_config_rules(self):
        self.assertFlags(good_stack(top="configs:\n  c: {name: c_v1, file: ./c.txt}\n"), "prune",
                         files={"c.txt": "x"})
        self.assertFlags(good_stack(top="configs:\n  c: {external: true, name: c_v1}\n"), "x-apiary-file")
        self.assertFlags(good_stack(top="configs:\n  c: {external: true, name: c_v1, x-apiary-file: ../../x}\n"),
                         "leaves the stack directory")
        self.assertFlags(good_stack(top="configs:\n  c: {external: true, name: c_v1, x-apiary-file: ./missing}\n"),
                         "does not exist")
        self.assertFlags(good_stack(top="configs:\n  c: {external: true, name: c, x-apiary-file: ./c}\n"),
                         "versioned", files={"c": "x"})

    def test_service_rules(self):
        body = good_stack()
        self.assertFlags(body.replace('    healthcheck:\n      test: ["CMD", "true"]\n', ""), "healthcheck")
        self.assertFlags(body + "    restart: unless-stopped\n", "restart")
        self.assertFlags(body.replace("apiary.pause.reason: test", "apiary.pause.reason: test\n        autoheal: 'true'"),
                         "autoheal")
        self.assertFlags(body.replace("failure_action: rollback", "failure_action: pause"), "must be `rollback`")
        self.assertFlags(body.replace("monitor: 30s", "delay: 1s"), "monitor")
        self.assertFlags(body.replace("{failure_action: pause, order: start-first}", "{order: start-first}"),
                         "rollback_config.failure_action")
        self.assertFlags(body.replace("apiary.pause: safe", "apiary.pause: maybe"), "safe|unit|never")
        self.assertFlags(body.replace("restart_policy: {condition: any}", "replicas: 1"), "restart_policy")
        self.assertFlags(body.replace("APP_TOKEN_FILE: /run/secrets/app_token", "DB_PASSWORD: hunter2"),
                         "use DB_PASSWORD_FILE")
        self.assertFlags(body.replace("deploy:\n", "deploy:\n      mode: global\n"), "global service")
        self.assertFlags(body.replace("apiary.pause.reason: test", "apiary.pause.reason: test\n        apiary.probe: udp:53"),
                         "apiary.probe")

    def test_homeserver_placement_is_explicit(self):
        # #3722: the homeserver is an Active node; placement, not availability,
        # keeps generic services off it.
        body = good_stack()
        no_sensor = body.replace("[node.labels.role == manager, node.labels.sensor == false]",
                                 "[node.labels.role == manager]")
        self.assertFlags(no_sensor, "placement must decide the homeserver")
        for pin in ("node.labels.sensor == true", "node.labels.gpu==true", "node.hostname == supermicro"):
            self.assertEqual(self.errors(no_sensor.replace("[node.labels.role == manager]",
                                                           f"[node.labels.role == manager, {pin}]")), [], pin)
        allowed = no_sensor.replace("apiary.pause.reason: test",
                                    "apiary.pause.reason: test\n        apiary.homeserver: allow")
        self.assertFlags(allowed, "apiary.homeserver.reason")
        self.assertEqual(self.errors(allowed + "        apiary.homeserver.reason: cross-host canary\n"), [])
        self.assertFlags(no_sensor.replace("apiary.pause.reason: test",
                                           "apiary.pause.reason: test\n        apiary.homeserver: 'yes'"),
                         "must be `allow`")

    def test_sensor_ports_host_mode_and_guarded(self):
        # #3593: a sensor publishes in host mode, and the LAN guard lists the port.
        body = good_stack().replace("node.labels.sensor == false", "node.labels.sensor == true")
        ingress = body + "    ports: ['25:25']\n"
        self.assertFlags(ingress, "mode: host")
        host = body + "    ports:\n      - {target: 25, published: 25, mode: host, protocol: tcp}\n"
        self.assertFlags(host, "homeserver-swarm-host-ports.txt")
        root, path = self.write(host)
        guard = root / "ops/firewall/hosts/homeserver-swarm-host-ports.txt"
        guard.parent.mkdir(parents=True)
        guard.write_text("# c\ntcp 25\n")
        self.assertEqual(lint.check_file(path, root), [])
        guard.write_text("udp 25\n")
        self.assertTrue(any("not in" in e for e in lint.check_file(path, root)))

    def test_gpu_reservation_rules(self):
        # #3594: one GPU as a swarm generic resource.
        body = good_stack().replace(
            "[node.labels.role == manager, node.labels.sensor == false]",
            "[node.labels.role == manager, node.labels.gpu == true]",
        ).replace("restart_policy: {condition: any}",
                  "restart_policy: {condition: any}\n      resources:\n        reservations:\n"
                  "          generic_resources:\n            - discrete_resource_spec: {kind: NVIDIA-GPU, value: 1}")
        self.assertFlags(body, "stop-first update_config")
        stop = body.replace("order: start-first", "order: stop-first")
        self.assertEqual(self.errors(stop), [])
        self.assertFlags(stop.replace("node.labels.gpu == true", "node.labels.sensor == true"),
                         "needs the constraint node.labels.gpu == true")
        devices = good_stack().replace(
            "restart_policy: {condition: any}",
            "restart_policy: {condition: any}\n      resources:\n        reservations:\n"
            "          devices: [{driver: nvidia, count: 1, capabilities: [gpu]}]")
        self.assertFlags(devices, "ignored by swarm")

    def test_overlay_subnet_pinned_in_pool(self):
        # #3763: overlays pin a /24 inside 10.200.0.0/16.
        net = "networks:\n  n:\n    driver: overlay\n"
        self.assertFlags(good_stack(top=net), "pin exactly one")
        for bad in ("10.0.1.0/24", "10.200.0.0/24", "10.200.8.0/23"):
            self.assertFlags(good_stack(top=net + f"    ipam: {{config: [{{subnet: {bad}}}]}}\n"), "must be a /24")
        ok = net + "    ipam: {config: [{subnet: 10.200.9.0/24}]}\n"
        self.assertEqual(self.errors(good_stack(top=ok)), [])
        self.assertEqual(self.errors(good_stack(top="networks:\n  x: {external: true, name: y}\n")), [])

    def test_overlay_subnets_unique_across_stacks(self):
        ok = "networks:\n  n:\n    driver: overlay\n    ipam: {config: [{subnet: 10.200.9.0/24}]}\n"
        root, _ = self.write(good_stack(top=ok), name="one")
        d = root / "swarm/stacks/two"
        d.mkdir(parents=True)
        (d / "stack.yml").write_text(good_stack(top=ok))
        self.assertEqual(lint.main(["--root", str(root)]), 1)

    def test_bad_stack_name(self):
        self.assertFlags(good_stack(), "not a valid stack name", name="Bad.Name")

    def test_glob_matches_image_lint(self):
        images = ROOT / "scripts" / "check-swarm-images.py"
        if not images.is_file():
            self.skipTest("#3597 image lint not on this tree yet")
        mod = load("check_swarm_images_3590", "scripts/check-swarm-images.py")
        self.assertEqual(tuple(mod.SWARM_STACK_GLOBS), tuple(lint.SWARM_STACK_GLOBS))
        self.assertEqual(tuple(stackctl.STACK_FILES), tuple(Path(g).name for g in lint.SWARM_STACK_GLOBS))


class PlanSyncsTest(unittest.TestCase):
    def test_create_ok_update_and_duplicates(self):
        stacks = {"probe": "swarm/stacks/probe/stack.yml"}
        plans = stackctl.plan_syncs(stacks, [], "repo", "main")
        self.assertEqual(plans[0].action, "create")
        body = plans[0].body
        self.assertEqual((body["targetType"], body["projectName"], body["name"]), ("swarm_stack", "probe", "swarm-probe"))
        self.assertIs(body["autoSync"], False)
        self.assertIs(body["syncDirectory"], True)

        existing = dict(body, id="s1", autoSync=True)  # autoSync held by a pause: left alone
        self.assertEqual(stackctl.plan_syncs(stacks, [existing], "repo", "main")[0].action, "ok")
        drift = dict(existing, branch="other", syncDirectory=False)
        plan = stackctl.plan_syncs(stacks, [drift], "repo", "main")[0]
        self.assertEqual((plan.action, plan.body, plan.sync_id), ("update", {"branch": "main", "syncDirectory": True}, "s1"))
        with self.assertRaises(stackctl.Abort):
            stackctl.plan_syncs(stacks, [existing, dict(existing, id="s2")], "repo", "main")

    def test_repo_stacks_reads_layout(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "swarm/stacks/a").mkdir(parents=True)
        (tmp / "swarm/stacks/a/stack.yml").write_text("services: {}\n")
        (tmp / "swarm/stacks/nofile").mkdir(parents=True)
        self.assertEqual(stackctl.repo_stacks(tmp), {"a": "swarm/stacks/a/stack.yml"})


class CommitRaceTest(unittest.TestCase):
    def test_deploy_reports_a_different_synced_commit_as_failure(self):
        sync = dict(id="s1", targetType="swarm_stack", projectName="probe", branch="main",
                    composePath="swarm/stacks/probe/stack.yml", lastSyncCommit="newer")
        api = FakeArcane({})
        api.syncs_rows = [sync]
        with mock.patch.object(stackctl, "fetch_ref", return_value="expected"), \
             mock.patch.object(stackctl, "push_configs", return_value=[]), \
             mock.patch.object(stackctl, "read_inventory", return_value=[]), \
             mock.patch.object(stackctl, "run_sync"), \
             mock.patch.object(stackctl, "wait_rollout", return_value=0), \
             mock.patch.object(stackctl, "log"):
            self.assertEqual(stackctl.cmd_deploy(api, argparse.Namespace(stack="probe", no_wait=False, timeout=30)), 1)

    def test_ensure_reports_a_different_initial_commit_as_failure(self):
        api = FakeArcane({})
        sync = dict(id="s1", targetType="swarm_stack", projectName="probe", lastSyncCommit="newer")
        with mock.patch.object(stackctl, "repo_stacks", return_value={"probe": "swarm/stacks/probe/stack.yml"}), \
             mock.patch.object(stackctl, "resolve_repository", return_value="repo"), \
             mock.patch.object(stackctl, "fetch_ref", return_value="expected"), \
             mock.patch.object(stackctl, "push_configs", return_value=[]), \
             mock.patch.object(stackctl, "find_sync", return_value=sync), \
             mock.patch.object(stackctl, "wait_rollout", return_value=0), \
             mock.patch.object(stackctl, "log"):
            args = argparse.Namespace(stacks=["probe"], repository="apiary", branch="main", dry_run=False, timeout=30)
            self.assertEqual(stackctl.cmd_ensure(api, args), 1)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, d):
        self.t += d


class FakeArcane:
    """Services keyed by id; `script` mutates state on every poll."""

    def __init__(self, services: dict[str, dict], script=None):
        self.services = services
        self.script = script or (lambda fake: None)
        self.calls: list[tuple] = []
        self.syncs_rows: list[dict] = []
        self.configs: list[dict] = []

    def stack_services(self, stack):
        self.script(self)
        return [dict(id=sid, name=s["name"], replicas=s["replicas"], runningReplicas=s["running"],
                     mode=s.get("mode", "replicated"), labels=s.get("labels", {}))
                for sid, s in self.services.items()]

    def service(self, sid):
        s = self.services[sid]
        return {"version": {"Index": s["version"]}, "updateStatus": s.get("update"),
                "spec": {"TaskTemplate": {"ContainerSpec": {"Configs": [{"ConfigName": c} for c in s.get("configs", [])]}}}}

    def syncs(self):
        return self.syncs_rows

    def call(self, method, path, body=None, timeout=600):
        self.calls.append((method, path, body))
        if method == "POST" and path.endswith("/scale"):
            sid = path.split("/")[-2]
            self.services[sid]["replicas"] = body["replicas"]
            self.services[sid]["running"] = body["replicas"]
        if method == "GET" and path.endswith("/swarm/configs"):
            return {"data": self.configs}
        if method == "POST" and path.endswith("/swarm/configs"):
            self.configs.append({"id": f"c{len(self.configs)}", "spec": body["spec"]})
        return {"data": {}}


def svc(name="probe_web", replicas=1, running=1, version=10, update=None, **kw):
    return dict(name=name, replicas=replicas, running=running, version=version, update=update, **kw)


class WaitRolloutTest(unittest.TestCase):
    def run_wait(self, before_services, after_services, script=None, **kw):
        api = FakeArcane(before_services)
        before = stackctl.snapshot(api, "probe")
        api.services = after_services
        api.script = script or (lambda f: None)
        clock = Clock()
        with mock.patch.object(stackctl, "log"):
            return stackctl.wait_rollout(api, "probe", before, sleep=clock.sleep, clock=clock, **kw)

    def test_new_stack_settles_when_running(self):
        api = FakeArcane({"a": svc(update=None)})
        clock = Clock()
        with mock.patch.object(stackctl, "log"):
            self.assertEqual(stackctl.wait_rollout(api, "probe", {}, sleep=clock.sleep, clock=clock), 0)

    def test_completed_update(self):
        old = {"State": "completed", "StartedAt": "t1"}
        rc = self.run_wait({"a": svc(update=old)}, {"a": svc(version=11, update={"State": "completed", "StartedAt": "t2"})})
        self.assertEqual(rc, stackctl.EXIT_OK)

    def test_old_completed_status_is_not_mistaken_for_the_new_update(self):
        old = {"State": "completed", "StartedAt": "t1"}
        steps = iter([{"State": "completed", "StartedAt": "t1"}] * 2 + [{"State": "rollback_completed", "StartedAt": "t2"}] * 20)

        def script(fake):
            fake.services["a"]["update"] = next(steps)
        rc = self.run_wait({"a": svc(update=old)}, {"a": svc(version=11, update=old)}, script=script, grace=60)
        self.assertEqual(rc, stackctl.EXIT_ROLLED_BACK)

    def test_rollback_paused_is_failure(self):
        rc = self.run_wait({"a": svc(update=None)},
                           {"a": svc(version=11, update={"State": "rollback_paused", "StartedAt": "t2", "Message": "x"})})
        self.assertEqual(rc, stackctl.EXIT_FAIL)

    def test_spec_change_without_rolling_update(self):
        # Seen live: a revert to the running spec bumps the version and clears UpdateStatus.
        rc = self.run_wait({"a": svc(update={"State": "rollback_completed", "StartedAt": "t1"})},
                           {"a": svc(version=11, update=None)}, grace=20)
        self.assertEqual(rc, stackctl.EXIT_OK)

    def test_timeout(self):
        rc = self.run_wait({"a": svc()}, {"a": svc(version=11, running=0, update={"State": "updating", "StartedAt": "t2"})},
                           timeout=30)
        self.assertEqual(rc, stackctl.EXIT_FAIL)


class PauseTest(unittest.TestCase):
    def setUp(self):
        self.state = Path(tempfile.mkdtemp())
        patcher = mock.patch.object(stackctl, "STATE_DIR", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("log",):
            p = mock.patch.object(stackctl, name)
            p.start()
            self.addCleanup(p.stop)
        self.no_cold = lambda host, script: mock.Mock(stdout="", returncode=0)

    def test_default_deny(self):
        with self.assertRaises(stackctl.Abort):
            stackctl.pause_plan([{"name": "a", "mode": "replicated", "labels": {"apiary.pause": "never"}}])
        with self.assertRaises(stackctl.Abort):
            stackctl.pause_plan([{"name": "a", "mode": "replicated", "labels": {}}])
        with self.assertRaises(stackctl.Abort):
            stackctl.pause_plan([{"name": "a", "mode": "global", "labels": {"apiary.pause": "safe"}}])
        with self.assertRaises(stackctl.Abort):
            stackctl.pause_plan([])
        order = stackctl.pause_plan([
            {"name": "b", "mode": "replicated", "labels": {"apiary.pause": "unit", "apiary.pause.order": "2"}},
            {"name": "a", "mode": "replicated", "labels": {"apiary.pause": "unit", "apiary.pause.order": "1"}},
        ])
        self.assertEqual([s["name"] for s in order], ["a", "b"])

    def test_pause_does_not_accept_a_disappeared_service_as_settled(self):
        entry = {"kind": "service", "stack": "probe", "id": "s1", "name": "probe_web"}
        with self.assertRaisesRegex(stackctl.Abort, "disappeared"):
            stackctl.settle_paused(FakeArcane({}), [entry], quiet=0)

    def fake(self, auto_sync=True, script=None):
        api = FakeArcane({"s1": svc(name="probe_web", replicas=2, running=2,
                                    labels={"apiary.pause": "safe", "apiary.probe": "tcp:8080"})}, script)
        api.syncs_rows = [{"id": "sync1", "name": "swarm-probe", "targetType": "swarm_stack",
                           "projectName": "probe", "autoSync": auto_sync}]
        return api

    def run_pause(self, api):
        clock = Clock()
        real = stackctl.settle_paused
        with mock.patch.object(stackctl, "settle_paused",
                               lambda a, e: real(a, e, sleep=clock.sleep, clock=clock)), \
             mock.patch.object(stackctl, "wait_replicas", lambda *a, **k: True):
            return stackctl.cmd_pause(api, mock.Mock(stacks=["probe"]), runner=self.no_cold)

    def test_pause_gate_and_resume_reverse(self):
        api = self.fake()
        self.assertEqual(self.run_pause(api), 0)
        self.assertEqual(api.services["s1"]["replicas"], 0)
        puts = [c for c in api.calls if c[0] == "PUT"]
        self.assertEqual(puts, [("PUT", "/environments/{env}/gitops-syncs/sync1", {"autoSync": False})])
        inv = stackctl.read_inventory()
        self.assertEqual([e["kind"] for e in inv], ["gate", "service"])
        self.assertEqual(inv[1]["replicas"], 2)

        api.calls.clear()
        probe = mock.Mock(return_value=mock.Mock(returncode=0, stdout=""))
        rc = stackctl.cmd_resume(api, mock.Mock(timeout=5, probe_host="10.8.0.2", probe_via="homeserver"), runner=probe)
        self.assertEqual(rc, 0)
        self.assertEqual(api.services["s1"]["replicas"], 2)
        # service first, gate last
        self.assertEqual([c[0] for c in api.calls], ["POST", "PUT"])
        self.assertEqual(api.calls[-1][2], {"autoSync": True})
        self.assertIn("/dev/tcp/10.8.0.2/8080", probe.call_args[0][1])
        self.assertEqual(stackctl.read_inventory(), [])

    def test_pause_reasserts_when_a_sync_restores_replicas(self):
        hits = {"n": 0}

        def sync_lands_late(fake):
            hits["n"] += 1
            if hits["n"] == 3:  # an in-flight sync deploys the file's replicas
                fake.services["s1"]["replicas"] = fake.services["s1"]["running"] = 2
        api = self.fake(auto_sync=False, script=sync_lands_late)
        self.assertEqual(self.run_pause(api), 0)
        scales = [c for c in api.calls if c[1].endswith("/scale")]
        self.assertEqual(len(scales), 2)
        self.assertEqual(api.services["s1"]["replicas"], 0)

    def test_refuses_second_pause_cold_run_and_deploy(self):
        api = self.fake()
        self.run_pause(api)
        with self.assertRaises(stackctl.Abort):
            self.run_pause(api)
        with self.assertRaises(stackctl.Abort):
            stackctl.cmd_deploy(api, mock.Mock(stack="probe"))
        (self.state / stackctl.INVENTORY).unlink()
        busy = lambda host, script: mock.Mock(stdout="123 bash coldrun.sh\n", returncode=0)
        with self.assertRaises(stackctl.Abort):
            stackctl.cmd_pause(api, mock.Mock(stacks=["probe"]), runner=busy)


class ConfigsTest(unittest.TestCase):
    STACK = textwrap.dedent("""
        services: {}
        configs:
          index: {external: true, name: probe_index_v3, x-apiary-file: ./configs/index.html}
          other: {external: true, name: other_v1}
    """).encode()

    def reader(self, files):
        return lambda commit, path: files[path]

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_push_creates_then_refuses_changed_content(self):
        files = {"swarm/stacks/probe/stack.yml": self.STACK, "swarm/stacks/probe/configs/index.html": b"v3\n"}
        api = FakeArcane({})
        with mock.patch.object(stackctl, "log"):
            out = stackctl.push_configs(api, "probe", "swarm/stacks/probe/stack.yml", "abc12345", self.reader(files))
        self.assertEqual(len(api.configs), 1)
        spec = api.configs[0]["spec"]
        self.assertEqual(spec["Name"], "probe_index_v3")
        self.assertEqual(base64.b64decode(spec["Data"]), b"v3\n")
        self.assertEqual(spec["Labels"]["apiary.config.sha256"], hashlib.sha256(b"v3\n").hexdigest())
        self.assertEqual((spec["Labels"]["apiary.stack"], spec["Labels"]["apiary.config.version"]), ("probe", "3"))
        self.assertIn("created", out[0])
        # same content again: no second create
        stackctl.push_configs(api, "probe", "swarm/stacks/probe/stack.yml", "abc12345", self.reader(files))
        self.assertEqual(len(api.configs), 1)
        files["swarm/stacks/probe/configs/index.html"] = b"edited\n"
        with self.assertRaisesRegex(stackctl.Abort, "probe_index_v4"):
            stackctl.push_configs(api, "probe", "swarm/stacks/probe/stack.yml", "abc12346", self.reader(files))

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_escaping_source_refused(self):
        files = {"swarm/stacks/probe/stack.yml":
                 b"configs:\n  c: {external: true, name: c_v1, x-apiary-file: ../../../etc/passwd}\n"}
        with self.assertRaises(stackctl.Abort):
            stackctl.stack_configs("swarm/stacks/probe/stack.yml", "abc", self.reader(files))

    def test_prune_keeps_in_use_rollback_target_and_newer(self):
        def cfg(v, stack="probe", base="probe_index"):
            return {"id": f"id{v}", "spec": {"Name": f"{base}_v{v}", "Labels": {
                "apiary.stack": stack, "apiary.config.base": base, "apiary.config.version": str(v)}}}
        configs = [cfg(v) for v in (2, 3, 5, 6, 7)] + [cfg(1, stack="other")] + [cfg(v, base="unused") for v in (1, 2, 3)]
        doomed = stackctl.prune_plan(configs, "probe", 2, in_use={"probe_index_v5"})
        self.assertEqual(sorted(c["spec"]["Name"] for c in doomed), ["probe_index_v2", "unused_v1"])
        doomed = stackctl.prune_plan(configs, "probe", 3, in_use={"probe_index_v5"})
        self.assertEqual(sorted(c["spec"]["Name"] for c in doomed), [])

    def test_prune_keeps_previous_spec_after_skipped_versions(self):
        api = FakeArcane({"s1": svc(configs=["index_v8"])})
        api.configs = [{"id": f"id{v}", "spec": {"Name": f"index_v{v}", "Labels": {
            "apiary.stack": "probe", "apiary.config.base": "index", "apiary.config.version": str(v)}}}
                       for v in (2, 3, 5, 6, 7, 8)]
        prior = json.dumps({"TaskTemplate": {"ContainerSpec": {"Configs": [{"ConfigName": "index_v5"}]}}})
        runner = lambda host, script: mock.Mock(returncode=0, stdout=prior, stderr="")
        with mock.patch.object(stackctl, "log"):
            self.assertEqual(stackctl.cmd_prune(api, argparse.Namespace(stack="probe", keep=2), runner=runner), 0)
        removed = [path.rsplit("/", 1)[-1] for method, path, _ in api.calls if method == "DELETE"]
        self.assertEqual(removed, ["id2"])
        api.calls.clear()
        broken = lambda host, script: mock.Mock(returncode=1, stdout="", stderr="manager unavailable")
        with self.assertRaisesRegex(stackctl.Abort, "manager unavailable"):
            stackctl.cmd_prune(api, argparse.Namespace(stack="probe", keep=2), runner=broken)
        self.assertFalse(any(method == "DELETE" for method, _, _ in api.calls))


class SecretTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(stackctl, "log")
        p.start()
        self.addCleanup(p.stop)

    def api(self, names=()):
        api = FakeArcane({})
        api.secret_rows = [{"id": n, "spec": {"Name": n}} for n in names]
        orig = api.call

        def call(method, path, body=None, timeout=600):
            if method == "GET" and path.endswith("/swarm/secrets"):
                return {"data": api.secret_rows}
            return orig(method, path, body, timeout)
        api.call = call
        return api

    def stdin(self, data: bytes):
        s = io.TextIOWrapper(io.BytesIO(data))
        s.isatty = lambda: False
        return s

    def test_create_versioned_from_stdin(self):
        api = self.api()
        stackctl.cmd_secret(api, argparse.Namespace(action="create", name="tok_v2"), stdin=self.stdin(b"s3cret"))
        method, path, body = api.calls[-1]
        self.assertEqual((method, path), ("POST", "/environments/{env}/swarm/secrets"))
        self.assertEqual(base64.b64decode(body["spec"]["Data"]), b"s3cret")
        self.assertEqual(body["spec"]["Labels"], {"apiary.secret.base": "tok", "apiary.secret.version": "2"})

    def test_refusals(self):
        with self.assertRaisesRegex(stackctl.Abort, "_vN"):
            stackctl.cmd_secret(self.api(), argparse.Namespace(action="create", name="tok"), stdin=self.stdin(b"x"))
        with self.assertRaisesRegex(stackctl.Abort, "tok_v3"):
            stackctl.cmd_secret(self.api(["tok_v2"]), argparse.Namespace(action="create", name="tok_v2"), stdin=self.stdin(b"x"))
        with self.assertRaisesRegex(stackctl.Abort, "empty"):
            stackctl.cmd_secret(self.api(), argparse.Namespace(action="create", name="tok_v1"), stdin=self.stdin(b""))


if __name__ == "__main__":
    unittest.main()
