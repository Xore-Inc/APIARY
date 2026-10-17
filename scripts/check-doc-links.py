#!/usr/bin/env python3
"""Every relative markdown link in the WHOLE tracked tree must resolve on disk.

check-doc-paths-exist.py (#2458) scans only README.md and docs/**, so the
component trees under arcane/**, analysis/**, sandbox/**, branding/** were
never link-checked -- the agent-intrusion-corpus README's dead
`../../docs/...` hop survived there. This is the whole-tree version: it walks
every git-tracked *.md and resolves every non-fenced relative link plus every
src=/href= reference.

Fenced code blocks are skipped: their paths belong to the reader's project
(a favicon family next to their page, a Go template route), not to this repo.
Semantic staleness ("this says 31 stacks, there are 37") still needs a reader.

Usage: scripts/check-doc-links.py [path ...]   (default: tracked *.md)
Exit:  0 clean, 1 broken links found, 2 bad usage.
"""
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

REPO = Path(__file__).resolve().parent.parent
# [text](target) but not ![img](target) — images are checked too, but the
# anchor-only and http cases are skipped, not failed.
LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)>\s]+)[^)]*\)")
# HTML src=/href= in the branding lockup and raw blocks.
HTML_REF = re.compile(r'(?:src|href)="([^"]+)"')
SKIP_SCHEMES = ("http://", "https://", "mailto:", "tel:", "data:", "#")


def tracked_markdown() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return [REPO / f for f in out.splitlines() if f.strip()]


def refs_in(path: Path) -> list[tuple[int, str]]:
    """(line_no, target) for every link-ish reference outside code fences.

    Fenced blocks are skipped on purpose: they hold copy-paste snippets whose
    relative paths (a favicon family next to the page, a Go template route) are
    correct in the reader's project, not in this repo.
    """
    found = []
    fence: str | None = None
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        stripped = line.lstrip()
        if fence:
            if stripped.startswith(fence):
                fence = None
            continue
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fence = stripped[:3]
            continue
        for m in LINK.finditer(line):
            found.append((n, m.group(1)))
        for m in HTML_REF.finditer(line):
            found.append((n, m.group(1)))
    return found


def resolve(doc: Path, target: str) -> Path | None:
    """Local path a target should exist at, or None if it isn't a local ref."""
    t = unquote(target.strip())
    if not t or t.startswith(SKIP_SCHEMES):
        return None
    # strip an anchor / query
    t = urlparse(t).path
    if not t:
        return None
    return (doc.parent / t).resolve()


def main(argv: list[str]) -> int:
    docs = [Path(a).resolve() for a in argv[1:]] or tracked_markdown()
    missing_docs = [d for d in docs if not d.exists()]
    if missing_docs:
        print("not found: " + ", ".join(str(d) for d in missing_docs), file=sys.stderr)
        return 2

    broken: list[str] = []
    checked = 0
    for doc in docs:
        if doc.name == Path(__file__).name:
            continue
        for line_no, target in refs_in(doc):
            dest = resolve(doc, target)
            if dest is None:
                continue
            checked += 1
            if not dest.exists():
                rel = doc.relative_to(REPO)
                broken.append(f"{rel}:{line_no} -> {target}")

    for b in broken:
        print(f"BROKEN {b}", file=sys.stderr)
    if broken:
        print(f"\n{len(broken)} broken of {checked} local refs in {len(docs)} files", file=sys.stderr)
        return 1
    print(f"OK — {checked} local refs in {len(docs)} files all resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
