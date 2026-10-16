#!/usr/bin/env python3
"""retired_projects() allowlists (#3361): on-demand eval stacks are not retired."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "compose-drift-watch.py"
_spec = importlib.util.spec_from_file_location("compose_drift_watch_retired", SCRIPT)
cdw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cdw)


class RetiredProjectsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _mk(self, name: str) -> None:
        d = self.root / name
        d.mkdir()
        (d / "compose.yml").write_text("services: {}\n")

    def test_live_dir_absent_from_manifest_is_retired(self) -> None:
        self._mk("some-old-stack")
        self.assertEqual(cdw.retired_projects(self.root, {"honeypot-elk"}), ["some-old-stack"])

    def test_manifest_member_is_not_retired(self) -> None:
        self._mk("honeypot-elk")
        self.assertEqual(cdw.retired_projects(self.root, {"honeypot-elk"}), [])

    def test_known_ondemand_stack_is_not_retired(self) -> None:
        # #3361: rex86-eval is deployed during an eval and absent from the
        # always-on manifest by design; it must not read as retired drift.
        self._mk("rex86-eval")
        self.assertEqual(cdw.retired_projects(self.root, {"honeypot-elk"}), [])

    def test_ondemand_allowlist_is_documented(self) -> None:
        # Same rule the file states for EXPECTED_ABSENT_WHILE: every entry
        # carries a reason, so no silent blanket suppression creeps in.
        self.assertIn("rex86-eval", cdw.KNOWN_ONDEMAND_STACKS)
        for name, reason in cdw.KNOWN_ONDEMAND_STACKS.items():
            self.assertTrue(reason.strip(), f"{name} needs a documented reason")

    def test_a_real_retirement_next_to_the_allowlist_still_alarms(self) -> None:
        self._mk("rex86-eval")
        self._mk("genuinely-retired")
        self.assertEqual(cdw.retired_projects(self.root, {"honeypot-elk"}), ["genuinely-retired"])

    def test_empty_unknown_stack_dir_is_skipped_not_a_crash(self) -> None:
        # #3651: /var/dockge/stacks/honeypot-stack/ exists but is empty on
        # the homeserver. stat() raises FileNotFoundError there; that must
        # read as "no compose file", not abort the whole sweep.
        (self.root / "honeypot-stack").mkdir()
        self.assertEqual(cdw.retired_projects(self.root, {"honeypot-elk"}), [])

    def test_unreadable_unknown_stack_dir_is_still_skipped(self) -> None:
        # #3440: EACCES must keep propagating from is_regular_file() as
        # PermissionError, and retired_projects() must keep treating it as
        # "couldn't check", never as "retired".
        locked = self.root / "locked-stack"
        locked.mkdir()
        (locked / "compose.yml").write_text("services: {}\n")
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o755)
        with self.assertRaises(PermissionError):
            cdw.is_regular_file(locked / "compose.yml")
        self.assertEqual(cdw.retired_projects(self.root, {"honeypot-elk"}), [])


if __name__ == "__main__":
    unittest.main()
