#!/usr/bin/env python3
"""Tests for scripts/check-label-taxonomy.py (#3216).

The guard exists because the 2026-09-17 label/census audit found Dependabot
naming three labels that did not exist (`github-actions`, `go`, `containers`)
and nothing in CI noticed: GitHub drops a nonexistent label silently, so every
Dependabot PR opened without them and no filter ever matched. A check that
cannot fail on that exact tree is worse than no check, because it is read as
coverage, so each rule is pinned here against a synthetic repo root -- the
script under test is the real one, pointed at a throwaway tree via
--repo-root, so no repository state is mutated and no copy of the logic is
under test.

Pinned here:

1. the real tree passes offline (a guard that fails on everything guards
   nothing);
2. dependabot.yml naming a label the ledger never adjudicated fails, naming
   the label and its ecosystem -- the 2026-09-17 defect verbatim;
3. a watcher declaring an undeclared label fails;
4. a ledger entry nothing references fails, so a label that stopped being
   automated cannot sit in the taxonomy as a stale claim;
5. --live reports a label that is absent from the real catalogue, and one
   whose description is empty (the `frontend` defect fixed in this change);
6. --live without a readable `gh` refuses with exit 2 rather than passing
   silently.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-label-taxonomy.py"


def origin_slug() -> str:
    """OWNER/REPO from the origin remote.

    Derived rather than hardcoded: a stale slug makes `gh label list` fail
    against a repository that does not exist, and the live test then skips
    while appearing to have verified the real catalogue.
    """
    remote = subprocess.run(
        ["git", "remote", "get-url", "origin"], cwd=REPO_ROOT, capture_output=True, text=True
    )
    slug = remote.stdout.strip()
    slug = slug.removesuffix(".git").split("github.com/")[-1].strip("/")
    if "/" not in slug:
        pytest.skip(f"cannot derive OWNER/REPO from origin remote: {remote.stdout!r}")
    return slug


REPO = origin_slug()

# Read the script's own page limit rather than mirroring it, so raising the
# limit in the guard cannot quietly turn this truncation test into a 1000-row
# page the stub never produces.
LIVE_PAGE = int(
    re.search(r"^LIVE_PAGE\s*=\s*(\d+)", SCRIPT.read_text(encoding="utf-8"), re.MULTILINE).group(1)
)

# The labels the real dependabot.yml applies, and the labels the real watchers
# own. A synthetic tree carrying exactly these is the "in sync" baseline every
# negative test perturbs -- and it must carry BOTH halves, or the five
# watcher-owned ledger entries read as stale and their failure lines mask the
# rule the test is actually about.
APPLIES = ["dependencies", "github-actions", "go", "containers", "python"]
WATCHES = {
    "ci-queue-watch.py": "ci-queue-stall",
    "disk-usage-watch.py": "disk-usage-alarm",
    "backup-staleness-watch.py": "backup-staleness-alarm",
    "compose-drift-watch.py": "compose-drift-alarm",
    "main-health-watch.py": "main-red-alarm",
}


def dependabot(labels: list[str]) -> str:
    body = "version: 2\nupdates:\n"
    for name in labels:
        body += (
            "  - package-ecosystem: npm\n"
            "    directory: /arcane/home/honeypot-dashboard/backend-service\n"
            f"    labels: [dependencies, {name}]\n"
        )
    return body


def build_tree(root: pathlib.Path, *, applies: list[str], watches: dict[str, str]) -> pathlib.Path:
    """Write a minimal repo root the guard can be pointed at."""
    (root / ".github").mkdir(parents=True, exist_ok=True)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "dependabot.yml").write_text(dependabot(applies))
    for script, label in watches.items():
        (root / "scripts" / script).write_text(
            f'#!/usr/bin/env python3\n"""watcher"""\n\nLABEL = "{label}"\n'
        )
    return root


def run(root: pathlib.Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(root), *extra],
        capture_output=True,
        text=True,
    )


def fake_gh(tmp_path: pathlib.Path, catalogue: dict[str, str] | None) -> pathlib.Path:
    """Put a stub `gh` first on PATH that reports `catalogue` as the labels."""
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    if catalogue is None:
        (bindir / "gh").write_text("#!/bin/sh\nexit 1\n")
    else:
        payload = tmp_path / "catalogue.json"
        payload.write_text(json.dumps([{"name": n, "description": d} for n, d in catalogue.items()]))
        (bindir / "gh").write_text(f'#!/bin/sh\ncat "{payload}"\n')
    (bindir / "gh").chmod(0o755)
    return bindir


def full_catalogue(overrides: dict[str, str | None] | None = None) -> dict[str, str]:
    """A catalogue where every ledger label exists and documents itself."""
    names = [
        "dependencies", "python", "go", "github-actions", "containers",
        "ci-queue-stall", "disk-usage-alarm", "backup-staleness-alarm",
        "compose-drift-alarm", "main-red-alarm",
    ]
    catalogue = {n: f"{n} description" for n in names}
    for name, description in (overrides or {}).items():
        if description is None:
            catalogue.pop(name, None)
        else:
            catalogue[name] = description
    return catalogue


# --- 1. the real tree passes ------------------------------------------------

def test_real_tree_passes_offline():
    proc = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "holds (offline)" in proc.stdout


def test_real_tree_passes_live():
    """The real catalogue must satisfy --live, if gh can be reached here."""
    if shutil.which("gh") is None:
        pytest.skip("gh not on PATH")
    probe = subprocess.run(
        [sys.executable, str(SCRIPT), "--live", "--repo", REPO], capture_output=True, text=True
    )
    if probe.returncode == 2:
        pytest.skip(f"gh label list unavailable here: {probe.stderr.strip()}")
    assert probe.returncode == 0, probe.stdout + probe.stderr


# --- 2. dependabot names a label nobody adjudicated -------------------------

def test_undeclared_dependabot_label_fails(tmp_path):
    """The 2026-09-17 defect: dependabot.yml names a label with no ledger row."""
    root = build_tree(tmp_path / "tree", applies=APPLIES + ["ghost-ecosystem-label"], watches=WATCHES)
    proc = run(root)
    assert proc.returncode == 1, proc.stdout
    assert "ghost-ecosystem-label" in proc.stdout
    assert "not in the" in proc.stdout
    assert "kind=applies" in proc.stdout, "failure should say how to resolve it"


def test_undeclared_label_names_its_ecosystem(tmp_path):
    root = build_tree(tmp_path / "tree", applies=APPLIES + ["unlisted"], watches=WATCHES)
    proc = run(root)
    assert proc.returncode == 1
    assert "unlisted" in proc.stdout
    assert "npm" in proc.stdout, "the failure should name the ecosystem that reached for it"


def test_undeclared_watcher_label_fails(tmp_path):
    root = build_tree(
        tmp_path / "tree", applies=APPLIES, watches={**WATCHES, "new-watch.py": "unlisted-alarm"}
    )
    proc = run(root)
    assert proc.returncode == 1, proc.stdout
    assert "unlisted-alarm" in proc.stdout
    assert "kind=creates" in proc.stdout


# --- 3. a ledger entry nothing references -----------------------------------

def test_stale_ledger_entry_fails(tmp_path):
    """A tree that stops automating a label must not leave it in the taxonomy."""
    root = build_tree(tmp_path / "tree", applies=["dependencies"], watches={})
    proc = run(root)
    assert proc.returncode == 1, proc.stdout
    assert "is declared but nothing in dependabot.yml" in proc.stdout
    assert "containers" in proc.stdout, "the unreferenced ledger entry should be named"


# --- 4. --live checks the catalogue, not just the ledger --------------------

def test_live_reports_label_absent_from_catalogue(tmp_path, monkeypatch):
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    bindir = fake_gh(tmp_path, full_catalogue({"containers": None}))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    proc = run(root, "--live", "--repo", REPO)
    assert proc.returncode == 1, proc.stdout
    assert "not in the live catalogue" in proc.stdout
    assert "containers" in proc.stdout
    assert "dropped on every PR" in proc.stdout, "an applies-label absence is the silent one"


def test_live_reports_empty_description(tmp_path, monkeypatch):
    """The `frontend` defect (since retired with #3749): present, but
    documenting nothing. Exercised on `python` now."""
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    bindir = fake_gh(tmp_path, full_catalogue({"python": ""}))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    proc = run(root, "--live", "--repo", REPO)
    assert proc.returncode == 1, proc.stdout
    assert "python" in proc.stdout
    assert "empty description" in proc.stdout


def test_live_separator_only_counts_creates_as_recoverable(tmp_path, monkeypatch):
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    bindir = fake_gh(tmp_path, full_catalogue({"main-red-alarm": None}))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    proc = run(root, "--live", "--repo", REPO)
    assert proc.returncode == 1, proc.stdout
    assert "recreated on next sweep" in proc.stdout


def test_live_passes_when_catalogue_is_complete(tmp_path, monkeypatch):
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    bindir = fake_gh(tmp_path, full_catalogue())
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    proc = run(root, "--live", "--repo", REPO)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "holds (live)" in proc.stdout


# --- 5. --live must refuse, not pass, when it cannot see the catalogue -----

def test_live_without_gh_refuses(tmp_path, monkeypatch):
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    (tmp_path / "empty-bin").mkdir(exist_ok=True)
    proc = run(root, "--live", "--repo", REPO)
    assert proc.returncode == 2, proc.stdout
    assert "cannot verify" in proc.stderr


def test_live_refuses_a_full_page_rather_than_calling_the_rest_deleted(tmp_path, monkeypatch):
    """A response that fills the page is truncated, not a catalogue without
    the other labels -- reporting those as deleted would be its own false
    alarm, and a scarier one."""
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    page = [{"name": f"label-{i}", "description": "d"} for i in range(LIVE_PAGE)]
    bindir = tmp_path / "bin"
    bindir.mkdir()
    payload = tmp_path / "page.json"
    payload.write_text(json.dumps(page))
    (bindir / "gh").write_text(f'#!/bin/sh\ncat "{payload}"\n')
    (bindir / "gh").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    proc = run(root, "--live", "--repo", REPO)
    assert proc.returncode == 2, proc.stdout
    assert "page limit" in proc.stderr


# --- 6. both YAML spellings of a label list are read -----------------------

def test_block_style_label_list_is_not_a_false_pass(tmp_path):
    """Reformatting `labels:` to a YAML block must not silently stop the
    labels being checked -- that is a false pass, the failure mode this whole
    guard exists to avoid."""
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    # Rewrite one ecosystem's list in block style, adding an undeclared label.
    path = root / ".github" / "dependabot.yml"
    text = path.read_text()
    text = text.replace(
        "    labels: [dependencies, python]\n",
        "    labels:\n      - dependencies\n      - python\n      - block-style-ghost\n",
    )
    path.write_text(text)
    proc = run(root)
    assert proc.returncode == 1, proc.stdout
    assert "block-style-ghost" in proc.stdout, "block-style label was not read at all"


def test_inline_labels_still_parsed(tmp_path):
    """The form the real file uses must keep working after block support."""
    root = build_tree(tmp_path / "tree", applies=APPLIES, watches=WATCHES)
    proc = run(root)
    assert proc.returncode == 0, proc.stdout
    assert "holds (offline)" in proc.stdout
