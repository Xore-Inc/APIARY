"""Swarm phase 9 leg C (#3596): the valkey/redis stores as homeserver stacks.

Pins what each cutover and rollback relies on: the homeserver pin, dnsrr, a
single stop-first replica, an internal attachable overlay and no published
port (6379 is a decoy port portbridge forwards to 10.8.0.2), and, for each
Compose app that stays behind, the relay that keeps the store's old name on
the app's bridge plus the apiary-overlay-attach `start` line that brings the
relay up after a dockerd restart.
"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ATTACH = ROOT / "ops/swarm/hosts/homeserver-overlay-attach.txt"

try:
    import yaml
    HAVE_YAML = True
except ImportError:  # pragma: no cover - CI installs PyYAML
    HAVE_YAML = False


def load(rel: str) -> dict:
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


class StoreStackMixin:
    stack_name: str
    service: str

    def setUp(self) -> None:  # noqa: D401 - unittest hook
        self.stack = load(f"swarm/stacks/{self.stack_name}/stack.yml")
        self.svc = self.stack["services"][self.service]
        self.deploy = self.svc["deploy"]

    def test_pinned_single_stop_first_replica(self) -> None:
        d = self.deploy
        self.assertEqual(d["placement"]["constraints"], ["node.hostname == supermicro"])
        self.assertIn(d["replicas"], (0, 1))
        self.assertEqual(d["endpoint_mode"], "dnsrr")
        self.assertEqual(d["update_config"]["order"], "stop-first")
        self.assertEqual(d["rollback_config"]["order"], "stop-first")
        self.assertEqual(d["labels"]["apiary.pause"], self.pause)

    def test_no_port_and_internal_attachable_store_overlay(self) -> None:
        self.assertNotIn("ports", self.svc)
        self.assertEqual(self.svc["networks"], ["store"])
        net = self.stack["networks"]["store"]
        self.assertTrue(net["internal"])
        self.assertTrue(net["attachable"], "the Compose relay attaches to it")
        self.assertEqual(net["driver_opts"]["com.docker.network.driver.overlay.encrypt"], "true")

    def test_hardened(self) -> None:
        self.assertTrue(self.svc["read_only"])
        self.assertEqual(self.svc["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", self.svc["security_opt"])
        self.assertNotIn("tmpfs", self.svc, "short-syntax tmpfs is dropped by Arcane (#3888)")

    def test_relay_start_line(self) -> None:
        lines = ATTACH.read_text().splitlines()
        self.assertIn(f"start {self.relay_container} {self.stack_name}_store", lines)


@unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
class DashboardSessionsTest(StoreStackMixin, unittest.TestCase):
    stack_name = "dashboard-sessions"
    service = "valkey"
    pause = "never"  # apiary-dashboard is NEVER in honeypot-pause.sh
    # The relay lives in Xore-Inc/apiary-dashboard (compose.honeynet.yml).
    relay_container = "hp-apiary-dashboard-oidc-sessions-relay"

    def test_memory_only_on_a_long_syntax_tmpfs(self) -> None:
        cmd = self.svc["command"]
        self.assertEqual(cmd[cmd.index("--save") + 1], "")
        self.assertEqual(cmd[cmd.index("--appendonly") + 1], "no")
        (tmpfs,) = [v for v in self.svc["volumes"] if v["type"] == "tmpfs"]
        self.assertEqual(tmpfs["target"], "/data")
        self.assertEqual(tmpfs["tmpfs"]["mode"], 0o700)

    def test_old_session_overlay_is_gone(self) -> None:
        self.assertNotIn("session", self.stack["networks"])
        subnet = self.stack["networks"]["store"]["ipam"]["config"][0]["subnet"]
        self.assertEqual(subnet, "10.200.34.0/24")


class RelayMixin:
    """A Compose relay that keeps the store's old name on the app's bridge."""
    compose_rel: str
    relay_service: str
    bridge: str
    alias: str

    def relay(self) -> tuple[dict, dict]:
        doc = load(self.compose_rel)
        return doc, doc["services"][self.relay_service]

    def test_relay_keeps_the_store_name_and_forwards_over_the_overlay(self) -> None:
        doc, relay = self.relay()
        self.assertEqual(relay["container_name"], self.relay_container)
        self.assertEqual(relay["networks"][self.bridge]["aliases"], [self.alias])
        (overlay_key,) = [k for k in relay["networks"] if k != self.bridge]
        self.assertEqual(doc["networks"][overlay_key], {"name": f"{self.stack_name}_store", "external": True})
        self.assertIn(f"TCP4:{self.stack_name}_{self.service}:6379", " ".join(relay["command"]))
        self.assertTrue(relay["read_only"])
        self.assertEqual(relay["cap_drop"], ["ALL"])
        self.assertNotIn("ports", relay)

    def test_only_the_relay_joins_the_overlay(self) -> None:
        doc, _ = self.relay()
        overlay_keys = {k for k, v in doc["networks"].items()
                        if isinstance(v, dict) and v.get("name") == f"{self.stack_name}_store"}
        for name, svc in doc["services"].items():
            nets = svc.get("networks") or []
            if name != self.relay_service:
                self.assertFalse(overlay_keys & set(nets), f"{name} must not join the store overlay (#3837)")

    def test_compose_store_is_legacy_and_nothing_hard_depends_on_it(self) -> None:
        doc, _ = self.relay()
        store = doc["services"][self.compose_store]
        self.assertEqual(store.get("profiles"), ["legacy"])
        self.assertEqual(store["image"].split("@")[1], self.svc["image"].split("@")[1],
                         "same digest on both sides of the rollback")
        for name, svc in doc["services"].items():
            deps = svc.get("depends_on") or {}
            if isinstance(deps, list):
                self.assertNotIn(self.compose_store, deps, name)
            elif self.compose_store in deps:
                self.assertIs(deps[self.compose_store].get("required"), False, name)


@unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
class CanarytokensRedisTest(StoreStackMixin, RelayMixin, unittest.TestCase):
    stack_name = "canarytokens-redis"
    service = "redis"
    pause = "unit"  # honeypot-canarytokens pauses as a unit
    relay_container = "hp-canarytokens-redis-relay"
    compose_rel = "arcane/home/honeypot-canarytokens/compose.yml"
    relay_service = "canarytokens-redis-relay"
    compose_store = "canarytokens-redis"
    bridge = "canarytokens_net"
    alias = "canarytokens-redis"

    def test_reuses_the_compose_volume_with_the_same_persistence(self) -> None:
        self.assertEqual(self.stack["volumes"]["data"],
                         {"external": True, "name": "honeypot-canarytokens_canarytokens-redis-data"})
        self.assertEqual(self.svc["volumes"], [{"type": "volume", "source": "data", "target": "/data"}])
        doc, _ = self.relay()
        self.assertEqual(doc["volumes"]["canarytokens-redis-data"],
                         {"name": "honeypot-canarytokens_canarytokens-redis-data", "external": True})
        compose_cmd = doc["services"]["canarytokens-redis"]["command"].split()
        self.assertEqual(self.svc["command"], compose_cmd)
        self.assertEqual(self.svc["stop_grace_period"], "30s")

    def test_installer_skips_the_relay_without_the_stack(self) -> None:
        text = (ROOT / "scripts/install-homeserver.sh").read_text()
        self.assertIn("honeypot-canarytokens) store_service=canarytokens-redis_redis relay=canarytokens-redis-relay", text)


if __name__ == "__main__":
    unittest.main()
