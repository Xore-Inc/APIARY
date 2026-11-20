"""Swarm phase 9 leg A (#3596): the Kibana stack and its Compose rollback.

Pins what the cutover and the rollback rely on: the same image digest on both
sides, the homeserver pin, the guarded host-mode port with a non-internal
network, the file-based encryption key, the legacy profile on the Compose
twin, and the consumers that now reach Kibana on 10.8.0.2:19601.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

try:
    import yaml
    HAVE_YAML = True
except ImportError:  # pragma: no cover - CI installs PyYAML
    HAVE_YAML = False


def load(rel: str) -> dict:
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


@unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
class KibanaStackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = load("swarm/stacks/kibana/stack.yml")
        self.svc = self.stack["services"]["kibana"]
        self.compose = load("arcane/home/honeypot-elk/compose.yml")["services"]["kibana"]

    def test_same_image_digest_as_the_compose_rollback(self) -> None:
        self.assertEqual(self.svc["image"], self.compose["image"])
        self.assertRegex(self.svc["image"], r"@sha256:[0-9a-f]{64}$")

    def test_compose_twin_is_legacy_only(self) -> None:
        self.assertEqual(self.compose.get("profiles"), ["legacy"])
        self.assertEqual(self.compose["container_name"], "hp-kibana")

    def test_pinned_to_the_homeserver_stop_first(self) -> None:
        deploy = self.svc["deploy"]
        self.assertIn("node.hostname == supermicro", deploy["placement"]["constraints"])
        self.assertEqual(deploy["update_config"]["order"], "stop-first")
        self.assertEqual(deploy["rollback_config"]["order"], "stop-first")
        self.assertIn(deploy["replicas"], (0, 1))
        self.assertEqual(deploy["labels"]["apiary.pause"], "unit")

    def test_host_mode_port_guarded_and_publishable(self) -> None:
        ports = self.svc["ports"]
        self.assertEqual(ports, [{"target": 5601, "published": 19601, "protocol": "tcp", "mode": "host"}])
        guard = (ROOT / "ops/firewall/hosts/homeserver-swarm-host-ports.txt").read_text().split("\n")
        self.assertIn("tcp 19601", guard)
        wg = (ROOT / "ops/firewall/hosts/homeserver-wg-ports.txt").read_text()
        self.assertRegex(wg, r"(?m)^tcp 19601\b", "the VPS hub path must stay open for the edge socat")
        nets = self.stack["networks"]
        self.assertEqual(set(self.svc["networks"]), {"es", "front"})
        self.assertFalse(nets["front"].get("internal", False), "a host-mode port needs a non-internal network")
        self.assertEqual(nets["es"], {"external": True, "name": "apiary-es"})

    def test_encryption_key_from_the_swarm_secret(self) -> None:
        env = self.svc["environment"]
        self.assertNotIn("XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY", env)
        self.assertEqual(env["ELASTICSEARCH_HOSTS"], "http://elasticsearch:9200")
        wrapper = " ".join(self.svc["entrypoint"])
        self.assertIn('$$(< /run/secrets/kibana_encryption_key)', wrapper)
        self.assertIn("exec /bin/tini -- /usr/local/bin/kibana-docker", wrapper)
        self.assertEqual(self.stack["secrets"]["kibana_encryption_key"],
                         {"external": True, "name": "kibana_encryption_key_v1"})
        (sec,) = self.svc["secrets"]
        self.assertEqual((sec["target"], sec["uid"], sec["mode"]), ("kibana_encryption_key", "1000", 0o400))

    def test_healthcheck_on_api_status(self) -> None:
        test = self.svc["healthcheck"]["test"]
        self.assertIn("http://127.0.0.1:5601/api/status", test)
        self.assertEqual(self.svc["healthcheck"]["start_period"], "120s")

    def test_consumers_reach_the_hub_address(self) -> None:
        init = load("arcane/home/honeypot-init/compose.yml")["services"]["honeypot-kibana-setup"]
        self.assertIn("KIBANA_URL=http://10.8.0.2:19601", init["environment"])
        for rel in ("analysis/kibana-import.sh", "analysis/kibana-export.sh",
                    "arcane/home/honeypot-init/analysis/honeypot-kibana-setup.sh"):
            text = (ROOT / rel).read_text()
            self.assertNotIn("http://kibana:5601", text, rel)
            self.assertIn("http://10.8.0.2:19601", text, rel)

    def test_d2_connect_line_is_active(self) -> None:
        lines = (ROOT / "ops/swarm/hosts/homeserver-overlay-attach.txt").read_text().splitlines()
        self.assertIn("connect hp-elasticsearch apiary-es elasticsearch", lines)
        self.assertFalse(any(re.match(r"^\s*#\s*connect hp-elasticsearch", ln) for ln in lines))


if __name__ == "__main__":
    unittest.main()
