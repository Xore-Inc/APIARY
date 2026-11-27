"""Dependabot lockfile check: 0.x line moves are reported, patch and 1.x moves are not."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-dependabot-lockfiles.py"
_spec = importlib.util.spec_from_file_location("check_dependabot_lockfiles", SCRIPT)
cdl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cdl)


def cargo(*packages: tuple[str, str]) -> str:
    return "version = 4\n\n" + "".join(
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n\n' for name, version in packages
    )


class MinorLineTests(unittest.TestCase):
    def test_lines(self):
        self.assertEqual(cdl.minor_line("0.44.2"), "0.44")
        self.assertEqual(cdl.minor_line("v0.5.0"), "0.5")
        self.assertEqual(cdl.minor_line("0.9"), "0.9")
        self.assertEqual(cdl.minor_line("1.2.3"), "1")
        self.assertEqual(cdl.minor_line("weird"), "weird")


class MovedTests(unittest.TestCase):
    def test_zero_minor_move_is_reported(self):
        base = {"lopdf": {"0.44.0"}}
        head = {"lopdf": {"0.47.0"}}
        self.assertEqual(cdl.moved(base, head), ["lopdf 0.44.0 -> 0.47.0"])

    def test_zero_to_one_is_reported(self):
        self.assertEqual(cdl.moved({"x": {"0.9.1"}}, {"x": {"1.0.0"}}), ["x 0.9.1 -> 1.0.0"])

    def test_patch_inside_a_zero_line_passes(self):
        self.assertEqual(cdl.moved({"x": {"0.44.1"}}, {"x": {"0.44.2"}}), [])

    def test_stable_minor_move_passes(self):
        self.assertEqual(cdl.moved({"serde": {"1.0.1"}}, {"serde": {"1.4.0"}}), [])

    def test_second_zero_line_added_beside_the_old_one_is_reported(self):
        self.assertEqual(cdl.moved({"rand": {"0.8.5"}}, {"rand": {"0.8.5", "0.9.2"}}), ["rand 0.8.5 -> 0.8.5,0.9.2"])

    def test_one_side_only_is_not_a_move(self):
        self.assertEqual(cdl.moved({"gone": {"0.1.0"}}, {"new": {"0.2.0"}}), [])


class ParserTests(unittest.TestCase):
    def test_cargo_lock_with_two_versions(self):
        parsed = cdl.parse_cargo(cargo(("rand", "0.8.5"), ("rand", "0.9.2")))
        self.assertEqual(parsed, {"rand": {"0.8.5", "0.9.2"}})

    def test_pip_pins(self):
        text = "Pandas_X[extra]==0.44.0 ; python_version>'3'\n# comment\nrequests>=2\nlopdf==0.47.0\n"
        self.assertEqual(cdl.parse_pip(text), {"pandas-x": {"0.44.0"}, "lopdf": {"0.47.0"}})

    def test_go_sum_strips_go_mod_suffix(self):
        text = "example.com/a v0.5.1 h1:abc=\nexample.com/a v0.5.1/go.mod h1:def=\n"
        self.assertEqual(cdl.parse_go_sum(text), {"example.com/a": {"v0.5.1"}})


class GitRepoTests(unittest.TestCase):
    """End to end over a real repository: the same paths the workflow uses."""

    def git(self, cwd: str, *args: str) -> str:
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        return subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True, text=True, env=env).stdout.strip()

    def commit(self, cwd: str, files: dict[str, str], message: str) -> str:
        for name, text in files.items():
            Path(cwd, name).write_text(text, encoding="utf-8")
        self.git(cwd, "add", "-A")
        self.git(cwd, "commit", "-q", "-m", message)
        return self.git(cwd, "rev-parse", "HEAD")

    def test_transitive_zero_minor_move_in_cargo_lock_is_reported(self):
        with tempfile.TemporaryDirectory() as repo:
            self.git(repo, "init", "-q")
            base = self.commit(repo, {"Cargo.lock": cargo(("lopdf", "0.44.0"), ("serde", "1.0.1"))}, "base")
            head = self.commit(repo, {"Cargo.lock": cargo(("lopdf", "0.47.0"), ("serde", "1.0.2"))}, "head")
            self.assertEqual(cdl.lockfile_moves(base, head, cwd=repo), ["Cargo.lock: lopdf 0.44.0 -> 0.47.0"])

    def test_new_lockfile_and_unrelated_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as repo:
            self.git(repo, "init", "-q")
            base = self.commit(repo, {"README.md": "a"}, "base")
            head = self.commit(repo, {"README.md": "b", "requirements.txt": "lopdf==0.47.0\n"}, "head")
            self.assertEqual(cdl.lockfile_moves(base, head, cwd=repo), [])

    def test_unknown_commit_fails_closed(self):
        with tempfile.TemporaryDirectory() as repo:
            self.git(repo, "init", "-q")
            head = self.commit(repo, {"a": "a"}, "head")
            with self.assertRaises(cdl.LockfileError):
                cdl.lockfile_moves("0" * 40, head, cwd=repo)


if __name__ == "__main__":
    unittest.main()
