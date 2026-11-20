"""Swarm phase 9 leg D (#3596): Elasticsearch as a homeserver stack.

Pins what the cutover and the rollback rely on: the same digest as the
Compose rollback, the homeserver pin, one stop-first replica on the reused
volume, memlock and the 120 s grace, dnsrr on the D2 overlay with the
`elasticsearch` alias, never a published port (portbridge forwards the public
9200 to 10.8.0.2), and on the Compose side the legacy profile, the external
volume and the shim that keeps `elasticsearch` on both bridges.
"""
from __future__ import annotations

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
class ElasticsearchStackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = load("swarm/stacks/elasticsearch/stack.yml")
        self.svc = self.stack["services"]["es"]
        self.deploy = self.svc["deploy"]
        self.compose = load("arcane/home/honeypot-elk/compose.yml")
        self.legacy = self.compose["services"]["elasticsearch"]

    def test_same_image_and_environment_as_the_compose_rollback(self) -> None:
        self.assertEqual(self.svc["image"], self.legacy["image"])
        legacy_env = dict(e.split("=", 1) for e in self.legacy["environment"])
        self.assertEqual({k: str(v) for k, v in self.svc["environment"].items()}, legacy_env)

    def test_pinned_single_stop_first_replica(self) -> None:
        d = self.deploy
        self.assertEqual(d["placement"]["constraints"], ["node.hostname == supermicro"])
        self.assertIn(d["replicas"], (0, 1))
        self.assertEqual(d["endpoint_mode"], "dnsrr")
        self.assertEqual(d["update_config"]["order"], "stop-first")
        self.assertEqual(d["rollback_config"]["order"], "stop-first")
        self.assertEqual(d["rollback_config"]["failure_action"], "pause")
        self.assertEqual(d["labels"]["apiary.pause"], "never")  # honeypot-pause.sh NEVER
        self.assertEqual(d["resources"]["limits"], self.legacy["deploy"]["resources"]["limits"])

    def test_memlock_and_grace(self) -> None:
        self.assertEqual(self.svc["ulimits"]["memlock"], {"soft": -1, "hard": -1})
        self.assertEqual(self.svc["cap_drop"], ["ALL"])
        self.assertEqual(self.svc["cap_add"], ["IPC_LOCK"])
        self.assertEqual(self.svc["environment"]["bootstrap.memory_lock"], "true")
        self.assertEqual(self.svc["stop_grace_period"], "120s")
        self.assertEqual(self.svc["healthcheck"]["start_period"], "300s")

    def test_reused_volume_and_binds(self) -> None:
        self.assertEqual(self.stack["volumes"]["data"], {"external": True, "name": "honeypot-elk_es-data"})
        by_target = {v["target"]: v for v in self.svc["volumes"]}
        self.assertEqual(by_target["/usr/share/elasticsearch/data"]["source"], "data")
        self.assertTrue(by_target["/usr/share/elasticsearch/config/ingest-geoip"]["read_only"])
        self.assertEqual(by_target["/snapshots"]["source"], "/opt/stacks/apiary/state/elasticsearch-snapshots")
        legacy_binds = {v.split(":")[1] for v in self.legacy["volumes"]}
        self.assertEqual(set(by_target), legacy_binds)

    def test_d2_overlay_only_and_no_port(self) -> None:
        self.assertNotIn("ports", self.svc)
        self.assertEqual(self.svc["networks"], {"es": {"aliases": ["elasticsearch"]}})
        self.assertEqual(self.stack["networks"]["es"], {"external": True, "name": "apiary-es"})

    def test_compose_side(self) -> None:
        self.assertEqual(self.legacy["profiles"], ["legacy"])
        self.assertEqual(self.compose["volumes"]["es-data"], {"name": "honeypot-elk_es-data", "external": True})
        shim = self.compose["services"]["elasticsearch-shim"]
        self.assertNotIn("profiles", shim)
        self.assertNotIn("ports", shim)
        self.assertTrue(shim["read_only"])
        self.assertEqual(shim["cap_drop"], ["ALL"])
        self.assertEqual(shim["command"][1], "TCP4:elasticsearch_es:9200,connect-timeout=5")
        self.assertEqual(shim["networks"]["honeynet"]["aliases"], ["elasticsearch"])
        self.assertEqual(shim["networks"]["llm-data"]["aliases"], ["elasticsearch"])
        self.assertIn("es", shim["networks"])
        # Nothing in the project may hard-depend on the disabled legacy ES.
        for name, svc in self.compose["services"].items():
            dep = (svc.get("depends_on") or {}).get("elasticsearch")
            if dep and "legacy" not in (svc.get("profiles") or []):
                self.assertIs(dep.get("required"), False, name)

    def test_installer_never_names_the_legacy_es_next_to_the_stack(self) -> None:
        text = (ROOT / "scripts/install-homeserver.sh").read_text()
        body = text[text.index("step_start_elasticsearch_first() {"):]
        body = body[: body.index("\n}\n")]
        start = body.index("docker service inspect elasticsearch_es")
        stack_branch = body[start: body.index("    return\n", start)]
        self.assertIn("--wait --no-recreate elasticsearch-shim", stack_branch)
        self.assertNotIn("--no-recreate elasticsearch\n", stack_branch)


if __name__ == "__main__":
    unittest.main()
