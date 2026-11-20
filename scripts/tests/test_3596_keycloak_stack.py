"""Swarm phase 9 leg B (#3596): the Keycloak + Postgres stack and its Compose rollback.

Pins what the cutover and the rollback rely on: the same image digests and the
same PGDATA volume on both sides, the homeserver pin with stop-first updates
(one postmaster per data directory), dnsrr for Postgres, the guarded host-mode
port with a non-internal network, the public domain read from a file (never
literal in git), and the legacy profile on both Compose services.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
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
class KeycloakStackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = load("swarm/stacks/keycloak/stack.yml")
        self.pg = self.stack["services"]["postgres"]
        self.kc = self.stack["services"]["keycloak"]
        self.compose = load("arcane/home/honeypot-keycloak/compose.yml")

    def test_same_digests_as_the_compose_rollback(self) -> None:
        cs = self.compose["services"]
        self.assertEqual(self.pg["image"], cs["postgres"]["image"])
        self.assertEqual(self.kc["image"], cs["keycloak"]["image"])
        for img in (self.pg["image"], self.kc["image"]):
            self.assertRegex(img, r"@sha256:[0-9a-f]{64}$")
        self.assertEqual(self.pg["environment"]["PGDATA"], cs["postgres"]["environment"]["PGDATA"])

    def test_compose_twins_are_legacy_only_and_share_the_external_volume(self) -> None:
        cs = self.compose["services"]
        self.assertEqual(cs["postgres"].get("profiles"), ["legacy"])
        self.assertEqual(cs["keycloak"].get("profiles"), ["legacy"])
        self.assertEqual(cs["postgres"]["container_name"], "hp-keycloak-postgres")
        self.assertEqual(cs["keycloak"]["container_name"], "hp-keycloak")
        name = "honeypot-keycloak_keycloak-postgres"
        self.assertEqual(self.compose["volumes"]["keycloak-postgres"], {"external": True, "name": name})
        self.assertEqual(self.stack["volumes"]["pgdata"], {"external": True, "name": name})
        (vol,) = [v for v in self.pg["volumes"] if v["type"] == "volume"]
        self.assertEqual((vol["source"], vol["target"]), ("pgdata", "/var/lib/postgresql"))

    def test_pinned_stop_first_and_landed_at_zero_or_one(self) -> None:
        for svc in (self.pg, self.kc):
            deploy = svc["deploy"]
            self.assertIn("node.hostname == supermicro", deploy["placement"]["constraints"])
            self.assertEqual(deploy["update_config"]["order"], "stop-first")
            self.assertEqual(deploy["rollback_config"]["order"], "stop-first")
            self.assertIn(deploy["replicas"], (0, 1))
            self.assertEqual(deploy["labels"]["apiary.pause"], "never")
            self.assertEqual(svc["stop_grace_period"], "60s")
        # Keycloak never runs without its database.
        self.assertLessEqual(self.kc["deploy"]["replicas"], self.pg["deploy"]["replicas"])

    def test_postgres_dnsrr_internal_only_unpublished(self) -> None:
        self.assertEqual(self.pg["deploy"]["endpoint_mode"], "dnsrr")
        self.assertNotIn("ports", self.pg)
        self.assertEqual(self.pg["networks"], ["data"])
        self.assertTrue(self.stack["networks"]["data"]["internal"])
        self.assertEqual(self.kc["environment"]["KC_DB_URL_HOST"], "postgres")
        self.assertEqual(self.pg["cap_drop"], ["ALL"])
        self.assertEqual(set(self.pg["cap_add"]), {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"})

    def test_keycloak_host_port_guarded_and_publishable(self) -> None:
        self.assertEqual(self.kc["ports"], [{"target": 8080, "published": 18080, "protocol": "tcp", "mode": "host"}])
        guard = (ROOT / "ops/firewall/hosts/homeserver-swarm-host-ports.txt").read_text().split("\n")
        self.assertIn("tcp 18080", guard)
        wg = (ROOT / "ops/firewall/hosts/homeserver-wg-ports.txt").read_text()
        self.assertRegex(wg, r"(?m)^tcp 18080\b", "the VPS hub path must stay open for socat-hp-keycloak")
        self.assertEqual(set(self.kc["networks"]), {"data", "egress"})
        self.assertFalse(self.stack["networks"]["egress"].get("internal", False))
        # management port 9000 stays unpublished
        self.assertNotIn(9000, [p["target"] for p in self.kc["ports"]])

    def test_public_domain_from_a_file_never_literal(self) -> None:
        env = self.kc["environment"]
        self.assertNotIn("KC_HOSTNAME", env)
        self.assertNotIn("KEYCLOAK_PUBLIC_DOMAIN", env)
        script = self.kc["command"][0]
        self.assertIn("/run/secrets/keycloak/public-domain", script)
        self.assertIn('export KC_HOSTNAME="https://auth.$${KEYCLOAK_PUBLIC_DOMAIN}"', script)
        text = (ROOT / "swarm/stacks/keycloak/stack.yml").read_text()
        self.assertNotRegex(text, r"xore\.|honeypot\.example")

    def test_long_syntax_tmpfs_and_ro_binds(self) -> None:
        self.assertNotIn("tmpfs", self.kc)
        mounts = {m["target"]: m for m in self.kc["volumes"]}
        self.assertEqual(mounts["/tmp"]["type"], "tmpfs")
        self.assertEqual(mounts["/opt/keycloak/data/import"]["type"], "tmpfs")
        for target in ("/run/secrets/keycloak", "/opt/keycloak/themes/apiary", "/opt/keycloak/realm-template"):
            self.assertEqual(mounts[target]["type"], "bind")
            self.assertTrue(mounts[target]["read_only"], target)
            self.assertTrue(mounts[target]["source"].startswith("/var/dockge/stacks/honeypot-keycloak/"))

    def test_install_bootstraps_on_compose_without_a_stack(self) -> None:
        text = (ROOT / "scripts/install-homeserver.sh").read_text()
        self.assertIn('docker service inspect keycloak_postgres', text)
        self.assertIn("profile_args=(--profile legacy)", text)


@unittest.skipUnless(HAVE_YAML and shutil.which("bash"), "needs PyYAML and bash")
class KeycloakEntrypointTest(unittest.TestCase):
    """Runs the stack entrypoint with stand-ins for kc.sh and the mounts."""

    def run_entrypoint(self, domain: str | None) -> subprocess.CompletedProcess:
        stack = load("swarm/stacks/keycloak/stack.yml")
        script = stack["services"]["keycloak"]["command"][0].replace("$$", "$")
        tmp = Path(tempfile.mkdtemp())
        secrets = tmp / "secrets"
        secrets.mkdir()
        (secrets / "postgres-password").write_text("pw\n")
        if domain is not None:
            (secrets / "public-domain").write_text(domain)
        tpl = tmp / "tpl"
        tpl.mkdir()
        (tpl / "apiary-realm.json").write_text('{"redirect": "https://dash.example.invalid/cb"}\n')
        imp = tmp / "import"
        imp.mkdir()
        kc = tmp / "kc.sh"
        kc.write_text('#!/bin/bash\necho "KC_HOSTNAME=$KC_HOSTNAME"\necho "ARGS=$*"\n')
        kc.chmod(0o755)
        script = (script.replace("/run/secrets/keycloak", str(secrets))
                  .replace("/opt/keycloak/realm-template", str(tpl))
                  .replace("/opt/keycloak/data/import", str(imp))
                  .replace("/opt/keycloak/bin/kc.sh", str(kc)))
        r = subprocess.run(["bash", "-ec", script], capture_output=True, text=True, timeout=30)
        r.imported = (imp / "apiary-realm.json").read_text() if (imp / "apiary-realm.json").exists() else None
        return r

    def test_refuses_to_start_without_the_domain_file(self) -> None:
        r = self.run_entrypoint(None)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing to start", r.stderr)
        self.assertNotIn("ARGS=", r.stdout)

    def test_refuses_an_empty_or_invalid_domain(self) -> None:
        for bad in ("", "\n", "evil.example/x", "a b.example"):
            r = self.run_entrypoint(bad)
            self.assertNotEqual(r.returncode, 0, repr(bad))
            self.assertNotIn("ARGS=", r.stdout)

    def test_derives_hostname_and_renders_the_realm(self) -> None:
        r = self.run_entrypoint("corp.test\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("KC_HOSTNAME=https://auth.corp.test", r.stdout)
        self.assertIn("ARGS=start --import-realm", r.stdout)
        self.assertIn("https://dash.corp.test/cb", r.imported)
        self.assertFalse(re.search(r"example\.invalid", r.imported))


if __name__ == "__main__":
    unittest.main()
