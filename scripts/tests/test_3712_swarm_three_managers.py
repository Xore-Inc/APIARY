"""#3712: the repo matches the three-manager swarm (VPS manager since 2026-10-19).

- Every host's swarm-plane env opens TCP 2377 (SWARM_MANAGER=1). A repo
  re-apply on the VPS with SWARM_MANAGER=0 would have dropped 2377 and cut
  the VPS out of raft.
- swarm-plane.sh only removes rules of the shapes it emits. On 2026-10-23 an
  apply on the homeserver deleted a hand-added Arcane accept from
  apiary-swarm, because every rule in that zone counted as its own.
- precision's fibre is ens1f1 (udev slot name), not enp4s0f1.
- swarm-membership.sh and the runbooks no longer say the VPS is never a
  manager, and the membership script has a lost-quorum path.

The firewall tests run the real converge logic against a fake firewall-cmd
that keeps the permanent rich rules of each zone in a file.
"""
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLANE = ROOT / "ops/firewall/swarm-plane.sh"
HOSTS = ROOT / "ops/firewall/hosts"
MEMBERSHIP = ROOT / "ops/swarm/swarm-membership.sh"

FAKE_FIREWALL_CMD = textwrap.dedent(
    r"""
    #!/usr/bin/env bash
    # Minimal firewall-cmd: permanent rich rules per zone in $FAKE_FW/<zone>.
    zone= action= rule= perm=0
    for a in "$@"; do
      case "$a" in
        --permanent) perm=1 ;;
        --zone=*) zone=${a#--zone=} ;;
        --list-rich-rules) action=list ;;
        --add-rich-rule=*) action=add; rule=${a#--add-rich-rule=} ;;
        --remove-rich-rule=*) action=remove; rule=${a#--remove-rich-rule=} ;;
      esac
    done
    f="$FAKE_FW/$zone"; touch "$f"
    echo "$perm $action $rule" >> "$FAKE_FW/calls.log"
    case "$action" in
      list) cat "$f" ;;
      add) [ "$perm" = 1 ] && { grep -qxF -- "$rule" "$f" || echo "$rule" >> "$f"; } ;;
      remove) [ "$perm" = 1 ] && { grep -vxF -- "$rule" "$f" > "$f.tmp"; mv "$f.tmp" "$f"; } ;;
    esac
    exit 0
    """
).lstrip()

ARCANE_RULE = 'rule family="ipv4" source address="10.8.0.0/24" port port="3552" protocol="tcp" accept'


def env_value(host: str, key: str) -> str:
    text = (HOSTS / f"{host}.env").read_text()
    m = re.search(rf"^{key}=\"?([^\"\n]*)\"?$", text, flags=re.M)
    assert m, f"{key} missing in {host}.env"
    return m.group(1)


class PlaneHarness:
    """Source swarm-plane.sh without its dispatcher and call its functions."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        fake = self.dir / "bin/firewall-cmd"
        fake.parent.mkdir()
        fake.write_text(FAKE_FIREWALL_CMD)
        fake.chmod(0o755)
        (self.dir / "fw").mkdir()
        body = PLANE.read_text()
        self.lib = self.dir / "lib.sh"
        self.lib.write_text(body[: body.index("\ncase \"${1:-}\" in")] + "\n")

    def run(self, host: str, snippet: str, zone_rules: dict[str, list[str]] | None = None) -> str:
        for zone, rules in (zone_rules or {}).items():
            (self.dir / "fw" / zone).write_text("".join(r + "\n" for r in rules))
        script = f'source "{self.lib}"; load_env "{HOSTS / (host + ".env")}"; {snippet}'
        env = dict(os.environ, PATH=f"{self.dir / 'bin'}:{os.environ['PATH']}", FAKE_FW=str(self.dir / "fw"))
        out = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True)
        return out.stdout

    def rules(self, zone: str) -> list[str]:
        return (self.dir / "fw" / zone).read_text().splitlines()

    def close(self) -> None:
        self.tmp.cleanup()


class EnvFilesTest(unittest.TestCase):
    def test_every_host_is_a_manager(self) -> None:
        for host in ("homeserver", "precision", "vps"):
            self.assertEqual(env_value(host, "SWARM_MANAGER"), "1", host)

    def test_precision_fibre_interface(self) -> None:
        ifaces = env_value("precision", "SWARM_IFACES").split()
        self.assertIn("ens1f1", ifaces)
        self.assertNotIn("ens1f0", ifaces, "the LAN uplink must never be in apiary-swarm")
        nm = (ROOT / "ops/swarm/hosts/precision.nm").read_text()
        self.assertIn("ens1f1 connection.zone apiary-swarm", nm)
        for path in ("ops/swarm/hosts/precision.nm", "ops/firewall/hosts/precision.env",
                     "ops/swarm/hosts/precision-multihome.conf", "ops/swarm/README.md"):
            # Comments may name the old interfaces; config and commands may not.
            text = "\n".join(l for l in (ROOT / path).read_text().splitlines()
                              if not l.lstrip().startswith("#"))
            self.assertNotRegex(text, r"enp4s0f[01]", path)


class SwarmPlaneOwnershipTest(unittest.TestCase):
    def setUp(self) -> None:
        self.h = PlaneHarness()

    def tearDown(self) -> None:
        self.h.close()

    def test_every_desired_rule_is_owned(self) -> None:
        # Otherwise a rule dropped from an env file would never be removed.
        for host in ("homeserver", "precision", "vps"):
            out = self.h.run(host, 'desired_swarm_rules | while IFS= read -r r; do '
                                   'owned_swarm_rule "$r" || echo "UNOWNED $r"; done')
            self.assertNotIn("UNOWNED", out, host)

    def test_vps_desired_rules_open_2377_to_both_peers(self) -> None:
        out = self.h.run("vps", "desired_swarm_rules")
        for peer in ("10.8.0.2/32", "10.8.0.3/32"):
            self.assertIn(f'source address="{peer}" port port="2377" protocol="tcp" accept', out)

    def test_apply_keeps_unmanaged_and_removes_stale_owned(self) -> None:
        stale = 'rule family="ipv4" source address="10.9.9.9/32" port port="2377" protocol="tcp" accept'
        foreign = 'rule family="ipv4" source address="10.8.0.1/32" port port="9100" protocol="tcp" accept'
        out = self.h.run(
            "homeserver",
            'converge_rules "$SWARM_ZONE" "$(desired_swarm_rules)" owned_swarm_rule',
            {"apiary-swarm": [ARCANE_RULE, stale, foreign]},
        )
        rules = self.h.rules("apiary-swarm")
        self.assertIn(ARCANE_RULE, rules)
        self.assertIn(foreign, rules)
        self.assertNotIn(stale, rules)
        self.assertIn(f"keep unmanaged {ARCANE_RULE}", out)
        self.assertIn(f"remove {stale}", out)
        desired = self.h.run("homeserver", "desired_swarm_rules").splitlines()
        self.assertEqual(sorted(rules), sorted(desired + [ARCANE_RULE, foreign]))

    def test_lan_zone_does_not_report_foreign_rules(self) -> None:
        foreign = 'rule family="ipv4" source address="103.21.244.0/22" port port="443" protocol="tcp" accept'
        out = self.h.run("vps", 'converge_rules public "$(desired_lan_rules)" owned_lan_rule',
                         {"public": [foreign]})
        self.assertIn(foreign, self.h.rules("public"))
        self.assertNotIn("unmanaged", out)

    def test_converged_zone_is_a_no_op(self) -> None:
        desired = self.h.run("vps", "desired_swarm_rules").splitlines()
        self.h.run("vps", 'converge_rules "$SWARM_ZONE" "$(desired_swarm_rules)" owned_swarm_rule',
                   {"apiary-swarm": desired})
        calls = (self.h.dir / "fw/calls.log").read_text().split("\n")
        self.assertFalse([c for c in calls if " add " in c or " remove " in c])

    def test_unmanaged_rules_lists_only_foreign(self) -> None:
        desired = self.h.run("homeserver", "desired_swarm_rules").splitlines()
        out = self.h.run("homeserver", 'unmanaged_rules "$SWARM_ZONE" owned_swarm_rule',
                         {"apiary-swarm": desired + [ARCANE_RULE]})
        self.assertEqual(out.splitlines(), [ARCANE_RULE])


class MembershipTest(unittest.TestCase):
    def test_script_and_runbooks(self) -> None:
        subprocess.run(["bash", "-n", str(MEMBERSHIP)], check=True)
        text = MEMBERSHIP.read_text()
        self.assertNotIn("never a manager", text)
        for cmd in ("restore-quorum)", "forget)", "join)"):
            self.assertIn(cmd, text)
        self.assertRegex(text, r"join vps manager 10\.8\.0\.2 10\.8\.0\.1")
        for doc in ("ops/swarm/README.md", "docs/SWARM-NETWORK.md"):
            body = (ROOT / doc).read_text()
            self.assertNotIn("Never promote the VPS", body, doc)
            self.assertIn("HOMESERVER-VAR-RECOVERY.md#12-swarm-quorum-recovery", body, doc)

    def test_usage_without_args(self) -> None:
        out = subprocess.run(["bash", str(MEMBERSHIP)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 2)
        self.assertIn("restore-quorum SURVIVOR --yes", out.stdout)


if __name__ == "__main__":
    unittest.main()
