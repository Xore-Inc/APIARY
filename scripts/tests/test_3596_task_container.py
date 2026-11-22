#!/usr/bin/env python3
"""Offline tests for the task-container resolver and its backup users (#3596).

Swarm phase 9 moves Keycloak's Postgres from the Compose container
hp-keycloak-postgres to the swarm service keycloak_postgres, whose container
is a task named keycloak_postgres.1.<id>. Both backup scripts used to
`docker exec hp-keycloak-postgres`; after the move that name is a stopped
rollback copy, and backup-honeypot.sh skipped the identity dump without a
word. Pinned here:

  * task_container prefers the swarm task, falls back to the Compose name,
    and refuses (non-zero) when neither or more than one runs;
  * backup-honeypot.sh dumps from the resolved container and exits 1, after
    writing the rest of its backup, when there is no dump or the dump lacks
    pg_dump's completion footer;
  * backup-essentials.sh ships the helper ahead of its homeserver collector
    and resolves the container there, never a fixed name;
  * the Keycloak restic scripts resolve the container the same way.

`docker` is a stub on PATH driven by env vars; no daemon is touched.
"""
from __future__ import annotations

import gzip
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
LIB = REPO_ROOT / "scripts" / "lib" / "task-container.sh"
BACKUP_HONEYPOT = REPO_ROOT / "analysis" / "backup-honeypot.sh"
BACKUP_ESSENTIALS = REPO_ROOT / "scripts" / "backup-essentials.sh"
KEYCLOAK_DIR = REPO_ROOT / "arcane" / "home" / "honeypot-keycloak" / "keycloak"

# FAKE_SWARM: names of running tasks of keycloak_postgres (space separated).
# FAKE_COMPOSE: names of running containers matching the Compose filter.
# FAKE_DUMP: file whose bytes `docker exec ... pg_dump` prints.
FAKE_DOCKER = r"""#!/bin/sh
case "$1" in
  ps)
    for a in "$@"; do
      case "$a" in
        label=com.docker.swarm.service.name=*) for n in $FAKE_SWARM; do echo "$n"; done; exit 0 ;;
        name=*) for n in $FAKE_COMPOSE; do echo "$n"; done; exit 0 ;;
      esac
    done
    exit 0 ;;
  exec)
    echo "$*" >> "$FAKE_LOG"
    cat "$FAKE_DUMP"; exit "${FAKE_DUMP_RC:-0}" ;;
  compose) exit 0 ;;
  volume) exit 1 ;;
  *) exit 0 ;;
esac
"""

DUMP_OK = "-- PostgreSQL database dump\nCREATE TABLE realm ();\n--\n-- PostgreSQL database dump complete\n--\n"
DUMP_TRUNCATED = "-- PostgreSQL database dump\nCREATE TABLE realm ();\n"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="taskctr-test."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        self.dump = self.tmp / "dump.sql"
        self.dump.write_text(DUMP_OK)
        self.log = self.tmp / "docker.log"

    def env(self, swarm: str = "", compose: str = "", **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "FAKE_SWARM": swarm,
            "FAKE_COMPOSE": compose,
            "FAKE_DUMP": str(self.dump),
            "FAKE_LOG": str(self.log),
        }
        env.update(extra)
        return env


class TaskContainerTest(Base):
    def resolve(self, **kw: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sh", "-c", f'. "{LIB}" && task_container keycloak_postgres hp-keycloak-postgres'],
            env=self.env(**kw), text=True, capture_output=True, timeout=30)

    def test_swarm_task_is_found(self) -> None:
        r = self.resolve(swarm="keycloak_postgres.1.abc")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "keycloak_postgres.1.abc")

    def test_compose_fallback_keeps_rollback_working(self) -> None:
        r = self.resolve(compose="hp-keycloak-postgres")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "hp-keycloak-postgres")

    def test_none_running_is_an_error(self) -> None:
        r = self.resolve()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "")
        self.assertIn("neither swarm service keycloak_postgres nor container hp-keycloak-postgres", r.stderr)

    def test_two_writers_are_refused(self) -> None:
        r = self.resolve(swarm="keycloak_postgres.1.abc", compose="hp-keycloak-postgres")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")
        self.assertIn("refusing to pick one", r.stderr)

    def test_two_tasks_are_refused(self) -> None:
        r = self.resolve(swarm="keycloak_postgres.1.abc keycloak_postgres.1.def")
        self.assertEqual(r.returncode, 2)

    def test_usage_error(self) -> None:
        r = subprocess.run(["sh", "-c", f'. "{LIB}" && task_container only-one'],
                           env=self.env(), text=True, capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 2)

    def test_posix_sh_and_dash_clean(self) -> None:
        for shell in ("sh", "dash"):
            if shutil.which(shell):
                subprocess.run([shell, "-n", str(LIB)], check=True)


class BackupHoneypotTest(Base):
    def run_backup(self, **kw: str) -> tuple[subprocess.CompletedProcess, pathlib.Path]:
        stack = self.tmp / "stack"
        (stack / "state").mkdir(parents=True, exist_ok=True)
        (stack / ".env").write_text("PLACEHOLDER=1\n")
        root = self.tmp / "backups"
        env = self.env(STACK_DIR=str(stack), BACKUP_ROOT=str(root), **kw)
        r = subprocess.run(["sh", str(BACKUP_HONEYPOT)], env=env, text=True,
                           capture_output=True, timeout=120)
        runs = sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []
        self.assertEqual(len(runs), 1, r.stderr)
        return r, runs[0]

    def test_dump_from_swarm_task(self) -> None:
        r, dest = self.run_backup(swarm="keycloak_postgres.1.abc", compose="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(gzip.decompress((dest / "keycloak.sql.gz").read_bytes()).decode(), DUMP_OK)
        self.assertIn("exec keycloak_postgres.1.abc pg_dump", self.log.read_text())
        self.assertIn("keycloak.sql.gz", (dest / "SHA256SUMS").read_text())

    def test_dump_from_compose_container(self) -> None:
        r, dest = self.run_backup(compose="hp-keycloak-postgres")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("exec hp-keycloak-postgres pg_dump", self.log.read_text())
        self.assertTrue((dest / "keycloak.sql.gz").is_file())

    def test_no_postgres_fails_loudly_but_keeps_the_rest(self) -> None:
        r, dest = self.run_backup()
        self.assertEqual(r.returncode, 1)
        self.assertIn("ERROR", r.stderr)
        self.assertIn("NO identity dump", r.stderr)
        self.assertFalse((dest / "keycloak.sql.gz").exists())
        self.assertTrue((dest / "stack-config-state.tar.gz").is_file())
        self.assertNotIn("keycloak", (dest / "SHA256SUMS").read_text())

    def test_two_postgres_fail_loudly(self) -> None:
        r, dest = self.run_backup(swarm="keycloak_postgres.1.abc", compose="hp-keycloak-postgres")
        self.assertEqual(r.returncode, 1)
        self.assertFalse((dest / "keycloak.sql.gz").exists())
        self.assertFalse(self.log.exists(), "no pg_dump may run when two Postgres are up")

    def test_truncated_dump_fails_loudly(self) -> None:
        self.dump.write_text(DUMP_TRUNCATED)
        r, dest = self.run_backup(compose="hp-keycloak-postgres")
        self.assertEqual(r.returncode, 1)
        self.assertFalse((dest / "keycloak.sql.gz").exists())
        self.assertFalse((dest / "keycloak.sql").exists())

    def test_missing_helper_fails_loudly(self) -> None:
        r, dest = self.run_backup(compose="hp-keycloak-postgres",
                                  TASK_CONTAINER_LIB=str(self.tmp / "nope.sh"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing", r.stderr)
        self.assertFalse((dest / "keycloak.sql.gz").exists())

    def test_no_fixed_container_name_left(self) -> None:
        text = BACKUP_HONEYPOT.read_text()
        self.assertNotIn("docker exec hp-keycloak-postgres", text)
        self.assertNotIn("docker inspect hp-keycloak-postgres", text)


FAKE_SSH_CAPTURE = r"""#!/usr/bin/env bash
cmd=${@: -1}
case $cmd in
  true|'sudo -n true') exit 0 ;;
  'sudo bash -s') cat > "$CAPTURE"; exit 1 ;;
  *) exit 1 ;;
esac
"""


class BackupEssentialsCollectorTest(Base):
    def capture(self, **extra: str) -> tuple[subprocess.CompletedProcess, pathlib.Path]:
        ssh = self.bin / "ssh"
        ssh.write_text(FAKE_SSH_CAPTURE)
        ssh.chmod(ssh.stat().st_mode | stat.S_IXUSR)
        cap = self.tmp / "remote.sh"
        env = self.env(CAPTURE=str(cap), BACKUP_ENCRYPT="0", REPO_DIR=str(self.tmp / "none"),
                       DEST_LOCAL_DISK=str(self.tmp / "d"), DEST_LOCAL_USB=str(self.tmp / "u"),
                       DEST_SERVER_USB=str(self.tmp / "s"), **extra)
        r = subprocess.run(["bash", str(BACKUP_ESSENTIALS), "--dry-run"], env=env, text=True,
                           capture_output=True, timeout=120)
        return r, cap

    def test_helper_is_prepended_and_used(self) -> None:
        _, cap = self.capture()
        remote = cap.read_text()
        self.assertTrue(remote.startswith(LIB.read_text()), "the helper must come first")
        self.assertLess(remote.index("task_container() {"), remote.index("set -euo pipefail"))
        self.assertIn("task_container keycloak_postgres hp-keycloak-postgres", remote)
        self.assertNotIn("docker exec hp-keycloak-postgres", remote)
        self.assertIn("PostgreSQL database dump complete", remote)
        subprocess.run(["bash", "-n", str(cap)], check=True)

    def test_missing_helper_stops_before_collecting(self) -> None:
        r, cap = self.capture(TASK_CONTAINER_LIB=str(self.tmp / "nope.sh"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("task-container helper not found", r.stderr)
        self.assertFalse(cap.exists())

    def test_installer_ships_the_helper(self) -> None:
        text = (REPO_ROOT / "scripts" / "install-backup-essentials.sh").read_text()
        self.assertIn('"$script_dir/lib/task-container.sh" /usr/local/libexec/apiary-task-container.sh', text)
        self.assertIn('"$(dirname -- "$SELF")/apiary-task-container.sh"', BACKUP_ESSENTIALS.read_text())


class KeycloakResticScriptsTest(unittest.TestCase):
    def test_scripts_resolve_the_container(self) -> None:
        for name in ("backup.sh", "restore.sh"):
            text = (KEYCLOAK_DIR / name).read_text()
            self.assertIn("task_container keycloak_postgres hp-keycloak-postgres", text, name)
            self.assertNotIn("exec -T postgres", text, name)
            subprocess.run(["bash", "-n", str(KEYCLOAK_DIR / name)], check=True)
        restore = (KEYCLOAK_DIR / "restore.sh").read_text()
        self.assertIn("docker service scale --detach=false keycloak_keycloak=0", restore)

    def test_lib_path_from_the_stack_directory(self) -> None:
        rel = KEYCLOAK_DIR / ".." / ".." / ".." / ".." / "scripts" / "lib" / "task-container.sh"
        self.assertEqual(rel.resolve(), LIB.resolve())


if __name__ == "__main__":
    unittest.main()
