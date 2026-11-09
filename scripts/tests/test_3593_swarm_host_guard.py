"""#3593: home-swarm-host-guard.sh keeps swarm host-mode sensor ports off the LAN.

A swarm `mode: host` port binds every address of the node, unlike the Compose
sensors' `10.8.0.2:` bindings. The guard runs in DOCKER-USER and lets only
the VPS hub path open a listed port, and only for flows DNATed from a host
address (#3769). Run against a fake iptables that logs
its arguments.
"""
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "ops/firewall/home-swarm-host-guard.sh"
PORTS = ROOT / "ops/firewall/hosts/homeserver-swarm-host-ports.txt"

FAKE = textwrap.dedent(
    """\
    #!/bin/sh
    # -n -L CHAIN: the chain does not exist yet; -C: rule not present.
    [ "$2" = -n ] && [ "$3" = -L ] && exit 1
    [ "$2" = -C ] && exit 1
    printf '%s\\n' "$*" >> "$FAKE_LOG"
    """
)


class GuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        fake = self.dir / "iptables"
        fake.write_text(FAKE)
        fake.chmod(0o755)
        self.log = self.dir / "iptables.log"
        self.env = dict(os.environ, PATH=f"{self.dir}:{os.environ['PATH']}", FAKE_LOG=str(self.log))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_guard(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", str(GUARD), *args], env=self.env, capture_output=True, text=True)

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def test_apply_drops_listed_ports_except_the_hub_path(self) -> None:
        ports = self.dir / "ports.txt"
        ports.write_text("# comment\ntcp 25\nudp 69\n")
        r = self.run_guard("apply", str(ports))
        self.assertEqual(r.returncode, 0, r.stderr)
        log = self.calls()
        self.assertIn("-N APIARY-SWARM-HOST", log)
        self.assertIn("-A APIARY-SWARM-HOST -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN", log)
        self.assertIn("-A APIARY-SWARM-HOST -i wg0 -s 10.8.0.1/32 -m conntrack --ctorigdst 10.8.0.2 -j RETURN", log)
        for proto, port in (("tcp", 25), ("udp", 69)):
            self.assertIn(
                f"--ctstate NEW --ctproto {proto} --ctorigdstport {port} -m conntrack --ctstate DNAT -j DROP", log
            )
            self.assertIn(
                f"--ctstate NEW --ctproto {proto} --ctorigdstport {port} -m conntrack --ctstate DNAT -m limit", log
            )
        self.assertIn("-I DOCKER-USER 1 -j APIARY-SWARM-HOST", log)
        # The hub RETURN must come before any DROP.
        lines = log.splitlines()
        hub = next(i for i, l in enumerate(lines) if "-i wg0 -s 10.8.0.1/32" in l)
        first_drop = next(i for i, l in enumerate(lines) if l.endswith("-j DROP"))
        self.assertLess(hub, first_drop)

    def test_only_dnat_flows_are_dropped(self) -> None:
        """#3769: every LOG/DROP is scoped to DNATed flows, i.e. flows whose
        original destination was a host address. Container-to-container,
        container egress and routed VM traffic are never DNATed."""
        ports = self.dir / "ports.txt"
        ports.write_text("tcp 8080\ntcp 3389\n")
        self.assertEqual(self.run_guard("apply", str(ports)).returncode, 0)
        rules = [l for l in self.calls().splitlines() if l.endswith(("-j DROP", "--log-level 4"))]
        self.assertEqual(len(rules), 4)
        for rule in rules:
            self.assertIn("-m conntrack --ctstate DNAT", rule)
        # No rule drops on the port alone.
        self.assertNotRegex(self.calls(), r"--ctorigdstport \d+ -j DROP")

    def test_local_containers_may_reach_the_hub_address(self) -> None:
        ports = self.dir / "ports.txt"
        ports.write_text("tcp 18083\n")
        self.assertEqual(self.run_guard("apply", str(ports)).returncode, 0)
        lines = self.calls().splitlines()
        first_drop = next(i for i, l in enumerate(lines) if l.endswith("-j DROP"))
        for ifname in ("docker0", "docker_gwbridge", "br-+"):
            rule = f"-w -A APIARY-SWARM-HOST -i {ifname} -m conntrack --ctorigdst 10.8.0.2 -j RETURN"
            self.assertIn(rule, lines)
            self.assertLess(lines.index(rule), first_drop)
        # The LAN uplinks get no exemption.
        self.assertNotIn("-i eno1", self.calls())
        self.assertNotIn("-i ens9f0", self.calls())

    def test_local_ifs_override(self) -> None:
        ports = self.dir / "ports.txt"
        ports.write_text("tcp 25\n")
        self.env["LOCAL_IFS"] = "br-test"
        self.assertEqual(self.run_guard("apply", str(ports)).returncode, 0)
        self.assertIn("-i br-test -m conntrack --ctorigdst 10.8.0.2 -j RETURN", self.calls())
        self.assertNotIn("-i docker0", self.calls())

    def test_checksum_covers_the_rule_shape(self) -> None:
        """A rule-shape change with an unchanged port list must not look
        applied: the comment checksum differs from the port file's alone."""
        ports = self.dir / "ports.txt"
        ports.write_text("tcp 25\n")
        self.assertEqual(self.run_guard("apply", str(ports)).returncode, 0)
        file_only = subprocess.run(["sha256sum", str(ports)], capture_output=True, text=True).stdout[:12]
        comment = next(l for l in self.calls().splitlines() if "-m comment --comment" in l)
        self.assertNotIn(file_only, comment)

    def test_invalid_rows_change_nothing(self) -> None:
        for bad in ("sctp 25\n", "tcp 70000\n", "tcp 25 extra\n", "tcp x\n"):
            ports = self.dir / "bad.txt"
            ports.write_text(bad)
            r = self.run_guard("apply", str(ports))
            self.assertNotEqual(r.returncode, 0, bad)
        self.assertEqual(self.calls(), "")

    def test_repo_list_is_valid(self) -> None:
        r = self.run_guard("apply", str(PORTS))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_usage(self) -> None:
        self.assertEqual(self.run_guard().returncode, 2)
        self.assertEqual(self.run_guard("apply").returncode, 2)


if __name__ == "__main__":
    unittest.main()
