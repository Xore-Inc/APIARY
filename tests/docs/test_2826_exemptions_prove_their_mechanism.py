#!/usr/bin/env python3
"""Regression test for #2826's review finding: an EXEMPT reason that asserts a
mechanism must prove it.

#2826 moved /logs/hellpot, /logs/canarytokens/frontend and
/logs/canarytokens/switchboard out of KNOWN_UNCOVERED and into EXEMPT with
reasons stating, as fact, that log-maintenance.sh's copytruncate rotate() now
covers them -- and nothing checked that. Deleting both new `rotate` lines from
log-maintenance.sh left three exemptions asserting coverage that no longer
existed, and scripts/check-json-sink-retention-parity.py still exited 0. That
is the exact failure mode the script exists to end: a ledger entry is a place
to record coverage, never a place to declare it.

So EXEMPT values may now carry the mechanism as a checked key -- "rotates"
(paths the pruner's rotate() must name, attributed to the directory that
claims them) and "writer" (subtree + grep tokens, the same proof ROWS uses).
Pinned here:

1. the real tree passes (a guard that fails on everything guards nothing);
2. deleting the rotate lines the three exemptions name fails, naming them --
   the reviewer's own demonstration, run in reverse;
3. an exemption claiming a rotate line belonging to a different directory
   fails, so the claim cannot be satisfied by a neighbour's line.
(A fourth case pinned frontend-next's self-bounding BFF writer; it left with
that frontend in #3749.)
"""
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-json-sink-retention-parity.py"
STACKS = REPO_ROOT / "arcane" / "home"
MAINTENANCE = STACKS / "honeypot-utilities" / "analysis" / "log-maintenance.sh"

ROTATE_LINES = (
    "  rotate /logs/hellpot/HellPot.log\n",
    "  rotate /logs/canarytokens/frontend/frontend.log\n",
    "  rotate /logs/canarytokens/switchboard/switchboard.log\n",
)


def build_root(tmp_path: pathlib.Path, *, maintenance_text: str | None = None) -> pathlib.Path:
    """A throwaway repo root the checker resolves itself against.

    Same shape as tests/docs/test_2216_sink_guardrail_enumerates_mounts.py's
    helper: every real stack is symlinked in so the mount enumeration sees the
    true fleet, and only the file a case needs to change is materialised.
    """
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / SCRIPT.name)

    home = root / "arcane" / "home"
    home.mkdir(parents=True)
    for stack in sorted(STACKS.iterdir()):
        if not stack.is_dir():
            continue
        if stack.name == "honeypot-utilities" and maintenance_text is not None:
            local = home / stack.name
            (local / "analysis").mkdir(parents=True)
            (local / "analysis" / "log-maintenance.sh").write_text(maintenance_text)
            shutil.copy(stack / "compose.yml", local / "compose.yml")
        else:
            (home / stack.name).symlink_to(stack)

    return root


def run(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(root / "scripts" / SCRIPT.name)],
        capture_output=True, text=True, check=False,
    )


def test_the_real_tree_passes(tmp_path):
    result = run(build_root(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "all accounted for" in result.stdout


def test_deleting_the_rotate_lines_fails_the_exemptions_that_name_them(tmp_path):
    original = MAINTENANCE.read_text()
    stripped = original
    for line in ROTATE_LINES:
        assert line in stripped, f"{line.strip()!r} moved; update this test"
        stripped = stripped.replace(line, "")

    result = run(build_root(tmp_path, maintenance_text=stripped))

    assert result.returncode == 1, result.stdout
    assert result.stderr.count("exemption unproven") == 3, result.stderr
    for claimed in ("/logs/hellpot/HellPot.log",
                    "/logs/canarytokens/frontend/frontend.log",
                    "/logs/canarytokens/switchboard/switchboard.log"):
        assert claimed in result.stderr


def test_a_rotate_line_for_a_neighbouring_directory_does_not_satisfy_the_claim(tmp_path):
    # The rotate() equivalent of #2216's moved-glob case: the string is still
    # in the file, on a line that rotates something else entirely.
    original = MAINTENANCE.read_text()
    moved = original.replace(
        "  rotate /logs/hellpot/HellPot.log\n",
        "  rotate /logs/cowrie/HellPot.log\n",
    )
    assert "HellPot.log" in moved

    result = run(build_root(tmp_path, maintenance_text=moved))

    assert result.returncode == 1, result.stdout
    assert "exemption unproven" in result.stderr
    assert "/logs/hellpot" in result.stderr


