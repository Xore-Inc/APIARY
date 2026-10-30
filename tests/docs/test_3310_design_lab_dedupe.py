#!/usr/bin/env python3
"""Regression test for #3310: the design lab was tracked twice.

`main` carried two trees of the same 2026-08-17 design lab:

* `branding/design-lab/` -- 12 files. #1827 (f9575d6e) preserved it, #1935
  (450c32af) added `lab.mjs` / `lab.test.mjs`. This is the canonical tree:
  `branding/` is the visual spec, `pages.yml` builds and publishes it, and
  `quality.yml` runs `lab.test.mjs` out of it in both the self-hosted and the
  GitHub-hosted lane.
* `docs/design-lab/` -- 10 files, added incidentally by the #3182 a11y PR
  (526eaf5c). It was the #1763 snapshot and had drifted: neither `lab.mjs` nor
  `lab.test.mjs`, and the weaker of the two `safePath` guards in
  `playground/compare.html` (both copies added one; the canonical one
  whitelists the path character by character and keeps `|| '/'` at every
  call site, the other resolves against an origin and drops the fallback).

It was *not* a pure duplicate, which is the part worth pinning. The `docs/`
copy had been edited since: the 2026-09-27 markdown reconciliation (b2b230cd)
gave it the redaction notice and the `design-notes.md` staleness banner, and
it carried a redaction of one captured attacker IP (`85.14.245.122` to RFC 5737
`203.0.113.122`) that `branding/` never received. That content is folded into
the canonical tree here rather than dropped -- see
`test_the_redaction_that_existed_only_in_the_duplicate_survived`.

What this file prevents is the recurrence, not the original. Three of the
tests below are deliberately path-agnostic. `SENTINELS` are basenames that
exist nowhere in the repository except the design lab, so a second copy is
caught wherever it is planted -- `docs/design-lab/` again, `branding/docs/`, a
fresh `lab/` -- rather than only at the path this issue names. A gate that
asserted nothing about `docs/design-lab` would go green the moment the fork
came back one directory over, which is the failure mode #3182 was.

Deliberately NOT asserted: that anything under the lab holds a particular
address, or that the lab is byte-stable. It is a preserved record, the
redaction is documented in the files themselves, and the two trees never were
the same bytes.

Runs under `python -m pytest tests/docs/` (quality.yml), which installs only
pytest -- so the CodeQL assertion reads YAML as text, the same trade
`tests/docs/test_3331_fix.py` makes for a workflow.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SELF = pathlib.Path(__file__).resolve().relative_to(REPO_ROOT).as_posix()

CANONICAL = "branding/design-lab"
DUPLICATE = "docs/design-lab"

# The ten files the duplicate carried, relative to its own root. Written out
# rather than read from git history, so the record of what was dropped is part
# of the gate and a future reader can see it without a `git show`.
DROPPED_TREE_FILES = (
    "README.md",
    "contrast_scan.js",
    "design-notes.md",
    "gen_palettes.py",
    "palettes.css",
    "playground/compare.html",
    "playground/elements.html",
    "playground/index.html",
    "playground/layouts.html",
    "v5-picks-override.css",
)

# The two files that made branding/design-lab the canonical tree and are why
# the duplicate was the one to go: CI runs the second of them, and the first
# is the harness README documents.
CANONICAL_ONLY_FILES = ("lab.mjs", "lab.test.mjs")

# Basenames that exist in exactly one place in the repository: the design lab.
# Any second tree holding one of them is a second copy of the lab, whatever it
# is called or wherever it is mounted -- which is why these are basenames and
# not a path. All five sit at the root of the tree that holds them, so one
# level of dirname is the tree root.
SENTINELS = frozenset({
    "contrast_scan.js",
    "design-notes.md",
    "gen_palettes.py",
    "palettes.css",
    "v5-picks-override.css",
})


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True,
    )
    if result.returncode not in (0, 1):
        raise AssertionError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def _tracked(*pathspecs: str) -> list[str]:
    """Tracked paths, optionally narrowed. `-z` so nothing splits on a space."""
    args = ["ls-files", "-z", *pathspecs]
    return [path for path in _git(*args).split("\0") if path]


def _text(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")


def test_the_duplicate_tree_is_gone():
    """The fork itself: no tracked file, and nothing left on disk.

    Both halves on purpose. The tracked check is what a reviewer sees in the
    diff; the exists() check is what a stale symlink or an untracked leftover
    would pass, and an untracked leftover is exactly how a "deleted" tree
    comes back for the next person who commits `docs/ -rf`.
    """
    tracked = _tracked(DUPLICATE)
    assert not tracked, (
        f"{DUPLICATE}/ is tracked again ({len(tracked)} files: {tracked[:5]}). The "
        f"design lab has one home, {CANONICAL}/; a second tree is a dead fork "
        "someone will edit instead of the real one (#3310)."
    )
    assert not (REPO_ROOT / DUPLICATE).exists(), (
        f"{DUPLICATE}/ exists on disk. If it is untracked it will be picked up "
        "by the next `git add`, which is how this came back the first time (#3310)."
    )


def test_nothing_tracked_references_the_removed_path():
    """Zero remaining references. A deleted tree with live links is worse.

    `git grep` rather than a Python walk: it is binary-safe, so the scan does
    not have to decide what a `.pcap` is, and it reads the same tracked set the
    gate is about. This file is skipped because it necessarily spells the
    path in order to forbid it.
    """
    hits = [
        path for path in _git("grep", "-l", "-I", "-z", "--fixed-strings", DUPLICATE).split("\0")
        if path and path != SELF
    ]
    assert not hits, (
        f"{len(hits)} tracked file(s) still reference {DUPLICATE}: {hits}. Repoint "
        f"them at {CANONICAL}/ in the same commit that removes the tree (#3310)."
    )


def test_the_canonical_tree_still_holds_every_file_the_duplicate_had():
    """No content lost. Ten filenames, and the two only the canonical tree has.

    A deletion that quietly drops a file is indistinguishable from a dedupe
    until somebody needs the file, so the shape of the dropped tree is asserted
    rather than described in a commit message nobody reads back.
    """
    present = set(_tracked(f"{CANONICAL}/*"))
    missing = [name for name in DROPPED_TREE_FILES if f"{CANONICAL}/{name}" not in present]
    assert not missing, (
        f"{CANONICAL}/ is missing {missing}, which {DUPLICATE}/ carried. The "
        "duplicate is being removed, not its content (#3310)."
    )
    # The two files that made this tree canonical (lab.mjs, lab.test.mjs)
    # served variants through frontend-next and left with it in #3749; the
    # README records that. The duplicate must still not come back.
    readme = (REPO_ROOT / CANONICAL / "README.md").read_text(encoding="utf-8")
    assert "#3749" in readme, "the design-lab README no longer explains where lab.mjs went"


def test_the_redaction_that_existed_only_in_the_duplicate_survived():
    """The one way the two trees were not interchangeable, folded and pinned.

    `docs/design-lab/` had been maintained after the fact: the redaction
    notice, the review-snapshot banner, the one attacker IP replaced, and the
    colour-research section the canonical README had never received. Those are
    edits, not duplication, so the fold had to carry them. This test is the
    evidence that it did -- it is the assertion a plain `git rm -r` would
    have failed.
    """
    notes = _text(f"{CANONICAL}/design-notes.md")
    readme = _text(f"{CANONICAL}/README.md")

    assert "Public, redacted copy" in notes, (
        f"{CANONICAL}/design-notes.md lost the public-copy banner the duplicate "
        "carried. It is what stops a later reader restoring the real addresses "
        "the redaction removed (#3310)."
    )
    assert "#1628" in notes, (
        f"{CANONICAL}/design-notes.md lost the note that the Go dashboard these "
        "findings cite was deleted in #1628, so the findings are re-locatable "
        "before they are acted on (#3310)."
    )
    assert "Colour research" in readme, (
        f"{CANONICAL}/README.md lost the colour-research section only the "
        "duplicate carried. It is the account of where the palettes came from "
        "that `gen_palettes.py` is kept for (#3310)."
    )
    assert "documentation-range placeholders" in readme, (
        f"{CANONICAL}/README.md lost the redaction notice the duplicate "
        "carried, so a reader no longer knows the addresses here are "
        "deliberately placeholders (#3310)."
    )

    # The redaction itself, in the two files the duplicate redacted. Asserted
    # as an absence because that is the shape of the fix: the address is gone
    # from the tree that is now the published one, not merely moved.
    for rel in (f"{CANONICAL}/design-notes.md", f"{CANONICAL}/playground/elements.html"):
        assert "85.14.245." not in _text(rel), (
            f"{rel} carries the unredacted captured address the duplicate had "
            f"already replaced with 203.0.113.x. branding/ is what pages.yml "
            "publishes; the redaction has to live there (#3310)."
        )
    assert "203.0.113.122" in _text(f"{CANONICAL}/playground/elements.html"), (
        f"{CANONICAL}/playground/elements.html has neither the real address nor "
        "the placeholder the duplicate substituted. Check the redaction was "
        "applied here rather than the file reverted wholesale (#3310)."
    )


def test_codeql_path_ignore_names_the_tree_that_exists():
    """The exclusion moved with the tree; nothing new was excluded.

    `paths-ignore` carried `docs/design-lab` for a reason that is a property of
    the lab, not of the directory: `playground/compare.html` is a local-only
    harness whose CodeQL js/html findings are documentation noise. That
    reasoning is unchanged and the files are still there, so dropping the entry
    would break the CodeQL job and keeping the old path would exempt nothing
    while silently blessing a re-added duplicate.
    """
    config = _text(".github/codeql/codeql-config.yml")
    ignores = _codeql_path_ignores(config)
    assert CANONICAL in ignores, (
        f"{CANONICAL} is missing from .github/codeql/codeql-config.yml's "
        f"paths-ignore ({ignores}). The lab's local-only playground is what the "
        "entry is for, and it lives in the canonical tree now (#3310)."
    )
    assert DUPLICATE not in ignores, (
        f"{DUPLICATE} is still in paths-ignore. The path holds no tracked file, "
        "so the entry exempts nothing -- and if a duplicate is added back under "
        "it, CodeQL will skip the fork nobody is reading (#3310)."
    )


def test_exactly_one_design_lab_tree_is_tracked():
    """The recurrence gate, and the one that does not name a path.

    This is the assertion that outlasts #3310. It is checked over sentinel
    basenames rather than over `docs/design-lab`, so it fails for a copy at
    any location -- `docs/design-lab/`, `branding/docs/`, `lab/`, a branch
    merge that brings the old tree back under a new name.
    """
    roots = {
        str(pathlib.PurePosixPath(path).parent)
        for path in _tracked()
        if pathlib.PurePosixPath(path).name in SENTINELS
    }
    assert roots == {CANONICAL}, (
        f"design-lab sentinels ({', '.join(sorted(SENTINELS))}) are tracked under "
        f"{sorted(roots)}, not only under {CANONICAL}. The lab has one home; a "
        "second tree is a dead fork (#3310)."
    )


def _codeql_path_ignores(config: str) -> list[str]:
    """The `paths-ignore:` list items, read as text.

    quality.yml's tests/docs row installs only pytest, so this is a line
    reader rather than a YAML parse -- the same trade test_3331_fix.py makes
    for a workflow. Items are `  - path` lines under the key; blank lines and
    `#` comments between them are skipped, and the first line that is neither
    ends the block.
    """
    lines = config.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.rstrip() == "paths-ignore:"), None
    )
    assert start is not None, (
        ".github/codeql/codeql-config.yml has no `paths-ignore:` key; this gate's "
        "excerptor is stale and would pass vacuously (#3310)"
    )
    ignores = []
    for line in lines[start + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith("  - "):
            break
        # `stripped` is already at the dash, so the item is everything after
        # `- `. Slicing the unstripped line instead would eat three characters
        # of the first path component.
        ignores.append(stripped.removeprefix("- ").strip())
    assert ignores, (
        ".github/codeql/codeql-config.yml's paths-ignore parsed as empty; the "
        "excerptor is stale and the assertions above would pass vacuously (#3310)"
    )
    return ignores


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
