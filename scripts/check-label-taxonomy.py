#!/usr/bin/env python3
"""Fail when automation references a label the catalogue cannot honour (#3216).

The 2026-09-17 label/census audit found the catalogue had grown to 30 labels
with nothing checking that the ones automation touches actually work, and the
residue it could not settle unilaterally was exactly that gap: Dependabot's
config named three labels -- `github-actions`, `go`, `containers` -- that did
not exist, so every Dependabot PR silently dropped them. Nothing failed. The
taxonomy drifted for ten days between the audit naming it and an operator
creating them.

GitHub applies a label that exists and drops one that does not, so a
nonexistent label is invisible: the PR opens, the grouping works, the triage
filter never matches. That is why this is a check and not a review step.

Two kinds of automation touch labels, and only one of them needs the label to
pre-exist:

1. **applies** -- `.github/dependabot.yml` lists labels for Dependabot to put
   on the PRs it opens. The label must exist before the PR does, or it is
   dropped without a word. This is where the 2026-09-17 finding lived.
2. **creates** -- the alarm watchers (`scripts/*-watch.py`, `main-health-watch`)
   each own one label and run `gh label create` for it on demand, so absence
   self-heals on the next sweep. The audit reached the same conclusion for
   these: zero open usage does not make a watcher-created label obsolete.

The ledger below is the decision the audit left open, now recorded next to
the thing that depends on it -- every automation-referenced label, and which
of the two kinds it is. Offline it cross-checks that ledger against the
sources; with `--live` it also asks GitHub whether each label is really there
and really has a description.

The 24 human-applied topic labels (`enhancement`, `bug`, `ops`, ...) are
deliberately out of scope: nothing in the repo references them by name, so
there is no drift for this guard to catch, and claiming otherwise would make
it a style opinion.

Usage:
    python scripts/check-label-taxonomy.py          # offline, CI-safe
    python scripts/check-label-taxonomy.py --live   # also query GitHub
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Declared taxonomy. kind="applies" means the label must pre-exist for
# Dependabot to attach it; kind="creates" means a watcher recreates it on
# demand. `since` records when the audit's open question was settled.
LEDGER: dict[str, dict[str, str]] = {
    # --- applies: Dependabot puts these on the PRs it opens -----------------
    "dependencies": {"kind": "applies", "why": "every dependabot.yml entry carries it"},
    "python": {"kind": "applies", "why": "pip entries"},
    "go": {"kind": "applies", "why": "gomod entry; created 2026-09-27, closing #3216 decision 1"},
    "github-actions": {"kind": "applies", "why": "github-actions entry; created 2026-09-27, closing #3216 decision 1"},
    "containers": {"kind": "applies", "why": "both docker entries; created 2026-09-27, closing #3216 decision 1"},
    # "frontend" (the frontend-next npm entry) left with #3749.
    # --- creates: a watcher owns the label and recreates it on demand ---------
    "ci-queue-stall": {"kind": "creates", "why": "scripts/ci-queue-watch.py"},
    "disk-usage-alarm": {"kind": "creates", "why": "scripts/disk-usage-watch.py"},
    "backup-staleness-alarm": {"kind": "creates", "why": "scripts/backup-staleness-watch.py"},
    "compose-drift-alarm": {"kind": "creates", "why": "scripts/compose-drift-watch.py"},
    "main-red-alarm": {"kind": "creates", "why": "scripts/main-health-watch.py"},
}

DEPENDABOT = Path(".github") / "dependabot.yml"
WATCHER_GLOB = "*-watch.py"
WATCHER_LABELS = re.compile(r'^LABEL\s*=\s*"([^"]+)"', re.MULTILINE)
DEPENDABOT_LABELS = re.compile(r"labels:\s*\[([^\]]*)\]")
DEPENDABOT_LABELS_BLOCK = re.compile(r"^\s*labels:\s*$")
DEPENDABOT_BLOCK_ITEM = re.compile(r"^\s*-\s*(\S+)\s*$")

# A page that comes back full is a truncated answer, not a complete one.
LIVE_PAGE = 1000


def dependabot_applies(root: Path) -> dict[str, set[str]]:
    """Map each label named in dependabot.yml to the entries naming it.

    Per-ecosystem rather than a flat set, so a failure names which entry
    reached for a label that is not there.

    Both YAML spellings are read: the inline flow form the file uses today
    (`labels: [dependencies, go]`) and the block form (`labels:` then `- go`).
    Reading only the first would be a false pass, not a false alarm: someone
    reformatting to block style -- the way a YAML formatter or a human tidying
    a long label list would -- would have their labels stop being checked
    entirely, with no failure anywhere to notice.
    """
    path = root / DEPENDABOT
    if not path.is_file():
        return {}
    used: dict[str, set[str]] = {}
    current = "<unattributed>"
    lines = path.read_text(errors="replace").splitlines()
    for index, line in enumerate(lines):
        eco = re.match(r"\s*-\s*package-ecosystem:\s*(\S+)", line)
        if eco:
            current = eco.group(1)
        inline = DEPENDABOT_LABELS.search(line)
        if inline:
            for raw in inline.group(1).split(","):
                name = raw.strip().strip("\"'")
                if name:
                    used.setdefault(name, set()).add(current)
            continue
        if DEPENDABOT_LABELS_BLOCK.match(line):
            for follow in lines[index + 1 :]:
                item = DEPENDABOT_BLOCK_ITEM.match(follow)
                if item is None:
                    break
                used.setdefault(item.group(1).strip().strip("\"'"), set()).add(current)
    return used


def watcher_creates(root: Path) -> dict[str, set[str]]:
    """Map each watcher-owned LABEL constant to the scripts declaring it."""
    used: dict[str, set[str]] = {}
    for script in sorted((root / "scripts").glob(WATCHER_GLOB)):
        for name in WATCHER_LABELS.findall(script.read_text(errors="replace")):
            used.setdefault(name, set()).add(script.name)
    return used


def live_catalogue(repo: str) -> dict[str, str]:
    """Ask GitHub for the live catalogue as {name: description}.

    Empty dict when `gh` is unavailable or unauthenticated, so --live degrades
    to a clear refusal rather than a false pass. A response that fills the
    page is also treated as no answer: a truncated catalogue would report
    every label past the cut as deleted, which is a scarier and equally wrong
    reading of the same tree.
    """
    if shutil.which("gh") is None:
        return {}
    proc = subprocess.run(
        ["gh", "label", "list", "-R", repo, "--limit", str(LIVE_PAGE), "--json", "name,description"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"warning: gh label list failed, skipping live verification: {proc.stderr.strip()}", file=sys.stderr)
        return {}
    labels = json.loads(proc.stdout)
    if len(labels) >= LIVE_PAGE:
        print(
            f"warning: gh returned {len(labels)} labels, the page limit; treating as unreadable "
            f"rather than reporting the unlisted remainder as deleted",
            file=sys.stderr,
        )
        return {}
    return {l["name"]: (l.get("description") or "") for l in labels}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="tree to check (default: this repo)")
    parser.add_argument("--live", action="store_true", help="also verify labels exist on GitHub with a description")
    parser.add_argument("--repo", default="", help="OWNER/REPO for --live (default: the origin remote)")
    args = parser.parse_args()
    root: Path = args.repo_root

    applies = dependabot_applies(root)
    creates = watcher_creates(root)
    referenced = set(applies) | set(creates)
    failures: list[str] = []

    # 1. A label automation applies but the ledger never adjudicated. This is
    #    the 2026-09-17 defect verbatim: dependabot.yml grew an ecosystem
    #    entry, someone named a label in it, and nothing forced the question
    #    "does this label exist, and who creates it?" to be answered.
    for name, ecosystems in sorted(applies.items()):
        if name not in LEDGER:
            where = ", ".join(sorted(ecosystems))
            failures.append(
                f"{DEPENDABOT}: labels {name!r} (ecosystem: {where}) but it is not in the "
                f"check-label-taxonomy.py ledger; declare it kind=applies (must pre-exist) "
                f"or kind=creates (a watcher recreates it)"
            )

    # 2. A ledger entry nothing references. Either the label stopped being
    #    automated -- in which case its `why` is now a lie and the entry goes
    #    stale -- or the regex missed a reference, which is worse to find here.
    for name, entry in sorted(LEDGER.items()):
        if name not in referenced:
            failures.append(
                f"ledger: {name!r} is declared but nothing in dependabot.yml or a watcher references it; "
                f"drop the entry or fix the reference it was meant to cover"
            )

    # 3. A watcher declares a label the ledger does not know. Same class as 1,
    #    on the other side of the ledger.
    for name, scripts in sorted(creates.items()):
        if name not in LEDGER:
            where = ", ".join(sorted(scripts))
            failures.append(
                f"{where}: creates label {name!r} which is not in the ledger; declare it kind=creates"
            )

    # 4. Live: the catalogue must actually honour the ledger. A label can be
    #    correctly declared here and still be missing on GitHub, which is
    #    exactly how the 2026-09-17 finding survived an audit that never
    #    re-read the catalogue afterwards.
    if args.live:
        repo = args.repo
        if not repo:
            remote = subprocess.run(["git", "remote", "get-url", "origin"], cwd=root, capture_output=True, text=True)
            repo = (remote.stdout.strip().removesuffix(".git").split("github.com/")[-1])
        catalogue = live_catalogue(repo)
        if not catalogue:
            print("error: --live needs a readable gh label list; cannot verify", file=sys.stderr)
            return 2
        for name, entry in sorted(LEDGER.items()):
            if name not in catalogue:
                severity = "dropped on every PR" if entry["kind"] == "applies" else "recreated on next sweep"
                failures.append(f"{repo}: {name!r} is not in the live catalogue ({severity})")
            elif not catalogue[name].strip():
                failures.append(f"{repo}: {name!r} has an empty description; every other label documents itself")

    if failures:
        print(f"{len(failures)} label taxonomy failure(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    scope = "live" if args.live else "offline"
    print(f"label taxonomy holds ({scope}): {len(LEDGER)} automation labels, {len(referenced)} referenced, all declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
