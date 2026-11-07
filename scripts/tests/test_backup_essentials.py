#!/usr/bin/env python3
"""Offline tests for scripts/backup-essentials.sh (#3709).

Incident #3708 found an archive that silently lacked the installer answers
file and the dashboard operator state, reached only 2 of 3 destinations, and
was produced by an installed copy six weeks older than the checkout -- with
exit status 0 throughout. What is pinned here is that none of those can be
quiet again:

  * every REQUIRED item missing from the collected tree makes the run exit 1
    with an ERROR line naming it (the archive is still written);
  * a destination that cannot be written, or a USB path that is not a mounted
    filesystem, is a failed destination in the exit status -- and the
    unmounted path is never created or written to;
  * an installed copy whose sha256 stamp differs from the checkout (or has no
    stamp) logs a WARNING, and `--check` fails on it.

No network and no real hosts: `ssh`/`scp` are stubs on PATH that serve canned
tar streams for the homeserver and VPS collectors and run the trivial
follow-up commands locally. The fixtures hold placeholder bytes only.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "backup-essentials.sh"
INSTALLER = REPO_ROOT / "scripts" / "install-backup-essentials.sh"

# One entry per REQUIRED item: tree path inside the homeserver tar.
REQUIRED = {
    "installer answers file": "installer/etc_apiary_install-home.conf",
    "operator-state export": "es-operator-state/MANIFEST.txt",
    "Keycloak dump": "keycloak/keycloak.sql.gz",
    "stack .env files": "env/honeypot-dashboard.env",
    "WireGuard keys": "wireguard/wg0.conf",
}

FAKE_SSH = r"""#!/usr/bin/env bash
# Stub for ssh: last arg is the remote command, the one before it the host.
cmd=${@: -1}
case $cmd in
  true|'sudo -n true') exit 0 ;;
  'sudo bash -s') cat >/dev/null; cat "$FAKE_HS_TAR"; exit 0 ;;
  'bash -s')      cat >/dev/null; cat "$FAKE_VPS_TAR"; exit 0 ;;
  mountpoint*)    [ "${FAKE_SERVER_MOUNTED:-1}" = 1 ]; exit $? ;;
  *) exec bash -c "$cmd" ;;
esac
"""

FAKE_SCP = r"""#!/usr/bin/env bash
# Stub for scp: sources are local files, destination is host:dir.
args=()
for a in "$@"; do case $a in -*|BatchMode*|ConnectTimeout*|ServerAliveInterval*) ;; *) args+=("$a") ;; esac; done
dest=${args[-1]#*:}
unset 'args[-1]'
# skip the value words of -o options
files=()
for a in "${args[@]}"; do [ -f "$a" ] && files+=("$a"); done
cp -- "${files[@]}" "$dest/"
"""


def write_exec(path: pathlib.Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def make_tar(dest: pathlib.Path, root: pathlib.Path) -> None:
    with tarfile.open(dest, "w") as tf:
        for p in sorted(root.rglob("*")):
            tf.add(p, arcname=str(p.relative_to(root)), recursive=False)


class BackupEssentialsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="bkess-test."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        write_exec(self.bin / "ssh", FAKE_SSH)
        write_exec(self.bin / "scp", FAKE_SCP)
        self.vps_tar = self.tmp / "vps.tar"
        make_tar(self.vps_tar, self._tree("vps", {"env/vps.env": "PLACEHOLDER=1\n"}))

    def _tree(self, name: str, files: dict[str, str]) -> pathlib.Path:
        root = self.tmp / f"tree-{name}"
        shutil.rmtree(root, ignore_errors=True)
        for rel, body in files.items():
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)
        root.mkdir(exist_ok=True)
        return root

    def _hs_tar(self, omit: str | None = None) -> pathlib.Path:
        files = {rel: "placeholder\n" for rel in REQUIRED.values()}
        if omit:
            files.pop(REQUIRED[omit])
        out = self.tmp / "hs.tar"
        make_tar(out, self._tree("hs", files))
        return out

    def _run(self, *args: str, omit: str | None = None, script: pathlib.Path = SCRIPT,
             env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        self.dest = {
            "usb": self.tmp / "dest-usb",
            "disk": self.tmp / "dest-disk",
            "srv": self.tmp / "dest-srv" / "apiary-backups",
        }
        (self.tmp / "dest-srv").mkdir(exist_ok=True)
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "HOMESERVER_SSH": "fake-hs",
            "VPS_SSH": "fake-vps",
            "DEST_LOCAL_USB": str(self.dest["usb"]),
            "DEST_LOCAL_DISK": str(self.dest["disk"]),
            "DEST_SERVER_USB": str(self.dest["srv"]),
            "REPO_DIR": str(self.tmp / "no-checkout"),
            "BACKUP_ENCRYPT": "0",
            "FAKE_HS_TAR": str(self._hs_tar(omit)),
            "FAKE_VPS_TAR": str(self.vps_tar),
        }
        env.update(env_extra or {})
        return subprocess.run(["bash", str(script), *args], env=env, text=True,
                              capture_output=True, timeout=120)

    def _archives(self, d: pathlib.Path) -> list[pathlib.Path]:
        return sorted(d.glob("apiary-essentials-*.tar.gz")) if d.is_dir() else []

    # -- the happy path ------------------------------------------------------

    def test_complete_run_exits_zero_and_writes_all_three(self) -> None:
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("stored in 3 of 3 locations", r.stderr)
        for d in self.dest.values():
            self.assertEqual(len(self._archives(d)), 1, d)
        # the archive self-describes as complete
        arc = self._archives(self.dest["disk"])[0]
        with tarfile.open(arc) as tf:
            manifest = tf.extractfile("./MANIFEST.txt").read().decode()
        self.assertIn("status     complete", manifest)

    # -- required items ------------------------------------------------------

    def test_each_missing_required_item_fails_loudly(self) -> None:
        for item in REQUIRED:
            with self.subTest(item=item):
                r = self._run(omit=item)
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("ERROR: REQUIRED item missing", r.stderr)
                self.assertIn("archive is INCOMPLETE", r.stderr)
                # a partial archive is still written to every destination
                self.assertEqual(len(self._archives(self.dest["disk"])), 1)
                arc = self._archives(self.dest["disk"])[0]
                with tarfile.open(arc) as tf:
                    manifest = tf.extractfile("./MANIFEST.txt").read().decode()
                self.assertIn("INCOMPLETE", manifest)
                shutil.rmtree(self.dest["disk"])

    def test_dry_run_also_fails_on_missing_item(self) -> None:
        r = self._run("--dry-run", omit="operator-state export")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("es-operator-state", r.stderr)

    # -- destinations --------------------------------------------------------

    def test_unwritable_destination_is_a_failed_destination(self) -> None:
        blocker = self.tmp / "blocker"
        blocker.write_text("a file, so mkdir -p beneath it fails")
        r = self._run(env_extra={"DEST_LOCAL_DISK": str(blocker / "apiary-backups")})
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not writable", r.stderr)
        self.assertIn("1 destination(s) FAILED", r.stderr)
        self.assertIn("stored in 2 of 3 locations", r.stderr)
        # the other two still got the archive
        self.assertEqual(len(self._archives(self.dest["usb"])), 1)
        self.assertEqual(len(self._archives(self.dest["srv"])), 1)

    def test_unmounted_usb_path_is_failed_and_never_written(self) -> None:
        ghost = pathlib.Path("/run/media/bkess-test-nonexistent/apiary-backups")
        self.assertFalse(ghost.parent.exists())
        r = self._run(env_extra={"DEST_LOCAL_USB": str(ghost)})
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not on a mounted filesystem", r.stderr)
        self.assertFalse(ghost.parent.exists(), "mountpoint -q safety must keep the path uncreated")

    def test_unmounted_server_usb_is_failed(self) -> None:
        r = self._run(env_extra={"FAKE_SERVER_MOUNTED": "0"})
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("is not mounted on", r.stderr)
        self.assertEqual(self._archives(self.dest["srv"]), [])

    # -- stale installed copy ------------------------------------------------

    def _installed_copy(self, stamp: str | None) -> pathlib.Path:
        checkout = self.tmp / "no-checkout"
        (checkout / "scripts").mkdir(parents=True, exist_ok=True)
        shutil.copy(SCRIPT, checkout / "scripts" / "backup-essentials.sh")
        inst = self.tmp / "libexec" / "apiary-backup-essentials.sh"
        inst.parent.mkdir(exist_ok=True)
        shutil.copy(SCRIPT, inst)
        stamp_file = pathlib.Path(str(inst) + ".src-sha256")
        stamp_file.unlink(missing_ok=True)
        if stamp is not None:
            stamp_file.write_text(stamp + "\n")
        return inst

    def test_matching_stamp_is_quiet(self) -> None:
        sha = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
        r = self._run(script=self._installed_copy(sha))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("installed copy", r.stderr)

    def test_stale_stamp_warns(self) -> None:
        r = self._run(script=self._installed_copy("0" * 64))
        self.assertIn("is older than the checkout", r.stderr)
        self.assertIn("install-backup-essentials.sh", r.stderr)

    def test_missing_stamp_warns(self) -> None:
        r = self._run(script=self._installed_copy(None))
        self.assertIn("has no install stamp", r.stderr)

    def test_check_mode_fails_on_stale_copy(self) -> None:
        # --check needs a fresh archive somewhere; a normal run provides it
        # (the stale copy itself is exercised by the run below, not the first).
        self.assertEqual(self._run().returncode, 0)
        inst = self._installed_copy("0" * 64)
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "HOMESERVER_SSH": "fake-hs",
            "DEST_LOCAL_USB": str(self.dest["usb"]),
            "DEST_LOCAL_DISK": str(self.dest["disk"]),
            "DEST_SERVER_USB": str(self.dest["srv"]),
            "REPO_DIR": str(self.tmp / "no-checkout"),
        }
        r = subprocess.run(["bash", str(inst), "--check"], env=env, text=True,
                           capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("installed copy of this script is stale", r.stderr)

    # -- collector paths and installer stamp (static) ------------------------

    def test_collector_looks_where_the_installer_conf_really_lives(self) -> None:
        text = SCRIPT.read_text()
        for path in ("/etc/apiary/install-home.conf",
                     "/root/apiary-install/install-homeserver.conf",
                     "/home/*/install/install-homeserver.conf"):
            self.assertIn(path, text)

    def test_installer_writes_the_stamp_the_script_reads(self) -> None:
        text = INSTALLER.read_text()
        self.assertIn('"$libexec.src-sha256"', text)
        self.assertIn(".src-sha256", SCRIPT.read_text())


if __name__ == "__main__":
    unittest.main()
