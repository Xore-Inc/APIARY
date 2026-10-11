"""#3619: the VPS hub wg0.conf carries every spoke, not only homeserver.

install-vps.sh used to write wg0.conf with the homeserver peer alone, so a
VPS rebuild silently dropped precision (10.8.0.3), the VPS worker's swarm
path to the second manager. The hub's spokes now come from one list,
ops/swarm/hosts/hub-peers.txt, rendered by ops/swarm/vps-hub-peer.sh. These
tests render with fixture keys (never real ones) and check that the list
agrees with every other place that names a hub spoke.
"""
import base64
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RENDERER = ROOT / "ops/swarm/vps-hub-peer.sh"
PEERS = ROOT / "ops/swarm/hosts/hub-peers.txt"
INSTALLER = ROOT / "scripts/install-vps.sh"


def fixture_key(seed: int) -> str:
    """A well-formed WireGuard-length key that is obviously not a real one."""
    return base64.b64encode(bytes([seed]) * 32).decode()


HOME_PUB, HOME_PSK = fixture_key(1), fixture_key(2)
PREC_PUB, PREC_PSK = fixture_key(3), fixture_key(4)
PLACEHOLDER_PUB = fixture_key(9)


def hub_peers() -> dict[str, str]:
    out = {}
    for line in PEERS.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, addr = line.split()
            out[name] = addr
    return out


def parse_peers(conf: str) -> list[dict[str, str]]:
    """[Peer] sections of a wg config as {key: value}, '#' comment as 'name'."""
    peers = []
    for section in re.split(r"^(?=\[)", conf, flags=re.M):
        if not section.startswith("[Peer]"):
            continue
        peer: dict[str, str] = {}
        for line in section.splitlines()[1:]:
            line = line.strip()
            if line.startswith("#"):
                peer["name"] = line[1:].strip()
            elif "=" in line:
                key, value = line.split("=", 1)
                peer[key.strip()] = value.strip()
        peers.append(peer)
    return peers


class HubPeerRenderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.wg = self.dir / "wireguard"
        self.wg.mkdir()
        bindir = self.dir / "bin"
        bindir.mkdir()
        # Only the placeholder path calls wg; a fixed key keeps it deterministic.
        (bindir / "wg").write_text(f"#!/bin/sh\necho {PLACEHOLDER_PUB}\n")
        (bindir / "wg").chmod(0o755)
        self.env = dict(os.environ, APIARY_WG_DIR=str(self.wg),
                        PATH=f"{bindir}:{os.environ['PATH']}")

    def tearDown(self):
        self.tmp.cleanup()

    def write_keys(self, name, pub=None, psk=None):
        if pub:
            (self.wg / f"{name}.pub").write_text(pub + "\n")
        if psk:
            (self.wg / f"{name}.psk").write_text(psk + "\n")

    def render(self, *args, peers=PEERS):
        return subprocess.run(["sh", str(RENDERER), "render", str(peers), *args],
                              env=self.env, capture_output=True, text=True)

    def test_renders_every_spoke_from_host_key_files(self):
        self.write_keys("homeserver", HOME_PUB, HOME_PSK)
        self.write_keys("precision", PREC_PUB, PREC_PSK)
        res = self.render("10.8.0.2", "")
        self.assertEqual(res.returncode, 0, res.stderr)
        peers = parse_peers(res.stdout)
        self.assertEqual([p["name"] for p in peers], ["homeserver", "precision"])
        home, prec = peers
        self.assertEqual(home["PublicKey"], HOME_PUB)
        self.assertEqual(home["PresharedKey"], HOME_PSK)
        self.assertEqual(home["AllowedIPs"], "10.8.0.2/32")
        self.assertEqual(prec["PublicKey"], PREC_PUB)
        self.assertEqual(prec["PresharedKey"], PREC_PSK)
        self.assertEqual(prec["AllowedIPs"], "10.8.0.3/32")
        for peer in peers:
            # Spokes dial in from behind NAT; the hub learns them by roaming.
            self.assertNotIn("Endpoint", peer)
            self.assertEqual(peer["PersistentKeepalive"], "25")

    def test_installer_step_writes_both_peers(self):
        """The real step_wireguard_config, with wg/systemctl stubbed."""
        self.write_keys("precision", PREC_PUB, PREC_PSK)
        etc = self.dir / "etc"
        step = re.search(r"^step_wireguard_config\(\) \{.*?^\}\n", INSTALLER.read_text(),
                         flags=re.M | re.S).group(0).replace("/etc/wireguard", str(self.wg))
        script = f"""
set -uo pipefail
systemctl() {{ echo "systemctl $*" >> "{etc}/calls"; }}
wg() {{ echo "{PLACEHOLDER_PUB}"; }}
APIARY_HUB_PEER_SH={RENDERER}
APIARY_HUB_PEERS={PEERS}
VPS_WG_ADDRESS=10.8.0.1
VPS_WG_PRIVATE_KEY={fixture_key(7)}
HOME_WG_ADDRESS=10.8.0.2/24
HOME_WG_PUBLIC_KEY={HOME_PUB}
{step}
step_wireguard_config
"""
        etc.mkdir()
        res = subprocess.run(["bash", "-c", script], env=self.env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        conf = (self.wg / "wg0.conf").read_text()
        self.assertIn("Address = 10.8.0.1/24\n", conf)
        self.assertIn("ListenPort = 51820\n", conf)
        self.assertIn("MTU = 1280\n", conf)
        peers = parse_peers(conf)
        self.assertEqual({p["AllowedIPs"]: p["PublicKey"] for p in peers},
                         {"10.8.0.2/32": HOME_PUB, "10.8.0.3/32": PREC_PUB})
        self.assertEqual(peers[1]["PresharedKey"], PREC_PSK)
        self.assertNotIn("PresharedKey", peers[0])  # pushed later by install-homeserver.sh
        self.assertTrue(all("Endpoint" not in p for p in peers))
        self.assertEqual((self.wg / "wg0.conf").stat().st_mode & 0o777, 0o600)
        self.assertIn("systemctl restart wg-quick@wg0", (etc / "calls").read_text())

    def test_reinstall_keeps_keys_from_the_live_conf(self):
        """The current wg0.conf wins over stale key files (dead-man restores it)."""
        self.write_keys("precision", fixture_key(5), fixture_key(6))
        (self.wg / "wg0.conf").write_text(
            "[Interface]\nAddress = 10.8.0.1/24\nPrivateKey = x\n"
            f"[Peer]\n# homeserver\nPublicKey = {HOME_PUB}\nPresharedKey = {HOME_PSK}\n"
            "AllowedIPs = 10.8.0.2/32\nEndpoint = 192.0.2.1:51820\n"
            f"[Peer]\nPublicKey={PREC_PUB}\nPresharedKey ={PREC_PSK}\nAllowedIPs = 10.8.0.3/32\n")
        res = self.render("10.8.0.2", "")
        self.assertEqual(res.returncode, 0, res.stderr)
        peers = parse_peers(res.stdout)
        self.assertEqual([(p["PublicKey"], p["PresharedKey"], p["AllowedIPs"]) for p in peers],
                         [(HOME_PUB, HOME_PSK, "10.8.0.2/32"), (PREC_PUB, PREC_PSK, "10.8.0.3/32")])

    def test_missing_spoke_keys_are_loud_and_never_drop_home(self):
        res = self.render("10.8.0.2", "")
        self.assertEqual(res.returncode, 3)
        self.assertIn("hub peer precision (10.8.0.3) skipped", res.stderr)
        self.assertIn("placeholder", res.stderr)
        peers = parse_peers(res.stdout)
        self.assertEqual([(p["name"], p["PublicKey"]) for p in peers],
                         [("homeserver", PLACEHOLDER_PUB)])

    def test_home_address_must_be_in_the_list(self):
        res = self.render("10.8.0.9", HOME_PUB)
        self.assertEqual(res.returncode, 2)
        self.assertIn("10.8.0.9 is not in", res.stderr)

    def test_malformed_home_key_is_fatal(self):
        res = self.render("10.8.0.2", "<HOME_WG_PUBLIC_KEY>")
        self.assertEqual(res.returncode, 2)

    def test_bad_list_is_rejected(self):
        bad = self.dir / "peers.txt"
        bad.write_text("homeserver 10.8.0.2\nprecision 10.8.0.2\n")
        self.assertEqual(self.render(peers=bad).returncode, 2)


class HubPeerListAgreementTest(unittest.TestCase):
    """Every other place that names a hub spoke agrees with hub-peers.txt."""

    def test_list_is_homeserver_and_precision(self):
        self.assertEqual(hub_peers(), {"homeserver": "10.8.0.2", "precision": "10.8.0.3"})

    def test_vps_firewall_peers_match(self):
        env = (ROOT / "ops/firewall/hosts/vps.env").read_text()
        peers = re.search(r'^SWARM_PEERS="([^"]*)"', env, re.M).group(1).split()
        self.assertEqual(sorted(peers), sorted(f"{a}/32" for a in hub_peers().values()))

    def test_spoke_env_local_hub_matches(self):
        for name, addr in hub_peers().items():
            env = ROOT / f"ops/swarm/hosts/{name}.env"
            if env.exists():
                self.assertIn(f"LOCAL_HUB={addr}\n", env.read_text(), env)

    def test_precision_wg0_template_matches(self):
        text = (ROOT / "ops/swarm/hosts/precision-wg0.conf.example").read_text()
        self.assertIn(f"Address = {hub_peers()['precision']}/24", text)


if __name__ == "__main__":
    unittest.main()
