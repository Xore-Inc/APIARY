#!/usr/bin/env python3
"""List every external base image this repo pulls -- from Dockerfiles and
from compose files -- for #2316's scheduled trivy scan
(image-security-scan.yml).

Dependabot's docker updater only proposes an update when the *tag* in a
FROM line changes -- confirmed against this repo's own PR history (every
digest-pinned docker-ecosystem Dependabot PR examined paired a digest change
with a tag/version-string change; none was a same-tag digest-only refresh).
A base image that gets rebuilt under the same tag (a security patch to
`alpine:3.24`, say) is invisible to it forever. Trivy scanning the resolved
image directly closes that gap regardless of whether a newer tag exists, and
regardless of whether the directory is in dependabot.yml's `directories:` at
all -- this walks the whole tree itself, so it also closes the 22-directory
coverage gap #2316 found in dependabot's docker section as a side effect.

Multi-stage builds are handled: a `FROM <name>` that refers to an `AS <name>`
declared earlier in the *same file* is a build-stage reference, not an
external image, and is excluded.

The virtual `scratch` base (and any `FROM ${ARG}` still carrying an
unexpanded build-arg) is excluded too: neither resolves to a pullable image,
and trivy FATALs the whole scan when handed one.

#2763: the walk above covers Dockerfiles only, so every image a compose
service *pulls* rather than builds went unscanned -- traefik and
oauth2-proxy among them, both internet-facing. compose_pulled_images()
walks every tracked compose file the same way, repo-wide off `git ls-tree`
rather than a fixed path list, and includes a service's `image:` only when
that service has no `build:` of its own and no `pull_policy: never`/`build`
-- a locally-built service's `image:` is just the tag its own build
produces, not something to pull and scan externally. Parsed with PyYAML,
not a regex: a regex over compose (anchors, multi-line values) would rot
the same way the coverage gap it closes did.

One directory is excluded from the compose walk: `**/honeyfs/**`. That is
cowrie's fake filesystem, served to attackers as bait -- its
`docker-compose.yml` under
`arcane/home/honeypot-cowrie/cowrie/honeyfs/opt/nexusai-inference/` names a
fictional internal registry (`registry.nexusai.local`) that was never meant
to resolve, on purpose. Nothing else in the repo is excluded by path:
vendored upstream compose/Dockerfiles (e.g. sandbox/ghosts/vendor/ghosts-src/)
are deliberately included, matching this workflow's own stated design for
the Dockerfile walk of scanning whatever a vendored file currently resolves
to rather than special-casing it out.

Separately from that path exclusion, an individual reference can be withheld
because no scanner can resolve it at all -- see UNSCANNABLE below, which
carries a written reason per entry. Those are reported on stderr so they
stay visible rather than silently vanishing.

Usage: python3 scripts/list-docker-base-images.py [--new-since REV]
Prints one deduplicated, scannable image reference per line, sorted, on
stdout; notes any withheld unscannable reference on stderr. With
--new-since REV (#3923) it prints only the refs the working tree pulls that
REV's tree did not: the refs a pull request adds or changes. Both trees go
through the same parser, so the set difference is exact.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$",
    re.IGNORECASE,
)

# Virtual/non-pullable bases that have no registry image to scan. `scratch`
# is Docker's reserved empty base; trivy aborts on it with a FATAL
# "unable to find the specified image \"scratch\"" that fails the whole scan
# job. It carries nothing to have a CVE, so dropping it is correct, not a
# coverage gap.
VIRTUAL_BASES = {"scratch"}

# Bait content served to attackers, not real infrastructure -- see module
# docstring. Matched against the git-relative path with forward slashes.
EXCLUDED_PATH_RE = re.compile(r"(^|/)honeyfs/")

# References that genuinely exist in the tree but that no scanner can ever
# resolve. Withheld from stdout and reported on stderr instead.
#
# Withholding one is not the same as excluding its file: the vendored tree
# stays in the walk (see module docstring), so any *other* image a vendored
# file names is still scanned. This is a per-reference list with a written
# reason precisely so a new unscannable reference has to be argued for here
# rather than quietly disappearing behind a path glob.
#
# It matters because the scan cannot distinguish "this image does not exist"
# from "this image has CRITICAL CVEs" -- both are a non-zero trivy exit. One
# unresolvable reference otherwise sits in the report permanently, labelled
# as a vulnerability finding, which trains the reader to ignore the report.
UNSCANNABLE: dict[str, str] = {
    "dustinupdyke/ghosts-client-universal": (
        "never published: the Docker Hub v2 API returns 404 for this "
        "repository (the same query for dustinupdyke/ghosts returns 200, so "
        "this is the image's absence, not an API failure). The vendored "
        "upstream compose names it, but nothing pulls it -- this repo builds "
        "that image itself from "
        "sandbox/ghosts/vendor/ghosts-src/Dockerfile-client-universal"
    ),
}


def is_scannable(ref: str) -> bool:
    """A base is scannable only if it resolves to a real pullable image.

    Excludes the virtual `scratch` base and any `FROM ${ARG}` whose ref still
    carries an unexpanded build-arg substitution -- trivy can pull neither,
    and both would FATAL the scan.
    """
    return ref.lower() not in VIRTUAL_BASES and "$" not in ref


def tracked_files(rev: str = "HEAD") -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", rev],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return out.splitlines()


def read_tracked(rel: str, rev: str | None) -> str | None:
    """A tracked file's text: the working tree when rev is None, else rev's blob.

    #3923: --new-since lists a second tree (the PR's merge-base) with the
    same parser, so both sides of the diff are read the same way and a
    re-spelling inside this script cannot show up as an "added" image.
    """
    try:
        if rev is None:
            return (REPO_ROOT / rel).read_text()
        return subprocess.run(
            ["git", "show", f"{rev}:{rel}"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, UnicodeDecodeError, subprocess.CalledProcessError):
        return None


def tracked_dockerfiles(paths: list[str]) -> list[str]:
    return [
        p for p in paths
        if re.search(r"(^|/)(Dockerfile|Containerfile)[^/]*$", p)
        and not EXCLUDED_PATH_RE.search(p)
    ]


def tracked_compose_files(paths: list[str]) -> list[str]:
    return [
        p for p in paths
        if re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", p, re.IGNORECASE)
        and not EXCLUDED_PATH_RE.search(p)
    ]


def images_in(text: str) -> set[str]:
    stage_names: set[str] = set()
    images: set[str] = set()
    for raw_line in text.splitlines():
        m = FROM_RE.match(raw_line)
        if not m:
            continue
        ref, alias = m.group(1), m.group(2)
        if ref not in stage_names and is_scannable(ref):
            images.add(ref)
        if alias:
            stage_names.add(alias)
    return images


def compose_pulled_images(text: str) -> set[str]:
    """Images a compose file *pulls*, i.e. excluding services it builds.

    Malformed or non-compose-shaped YAML is skipped rather than crashing the
    listing -- the walk is repo-wide and will meet files whose name matches
    the compose pattern without being compose documents.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return set()
    if not isinstance(doc, dict):
        return set()
    services = doc.get("services")
    if not isinstance(services, dict):
        return set()

    images: set[str] = set()
    for service in services.values():
        if not isinstance(service, dict):
            continue
        if "build" in service:
            continue
        if service.get("pull_policy") in ("never", "build"):
            continue
        image = service.get("image")
        if isinstance(image, str) and image.strip() and is_scannable(image.strip()):
            images.add(image.strip())
    return images


def collect_images(rev: str | None = None) -> set[str]:
    """Every base image the tree pulls: the working tree (rev None) or rev's."""
    paths = tracked_files("HEAD" if rev is None else rev)
    all_images: set[str] = set()
    for rel in tracked_dockerfiles(paths):
        text = read_tracked(rel, rev)
        if text is not None:
            all_images |= images_in(text)
    for rel in tracked_compose_files(paths):
        text = read_tracked(rel, rev)
        if text is not None:
            all_images |= compose_pulled_images(text)
    return all_images


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--new-since", metavar="REV",
        help="#3923: print only refs the working tree pulls that REV did not "
             "(the PR-scoped gate passes the PR's merge-base here)",
    )
    args = parser.parse_args(argv)

    all_images = collect_images()
    for image in sorted(all_images & UNSCANNABLE.keys()):
        print(f"not scannable: {image} -- {UNSCANNABLE[image]}", file=sys.stderr)

    selected = all_images - UNSCANNABLE.keys()
    if args.new_since:
        before = collect_images(args.new_since)
        print(
            f"--new-since {args.new_since}: {len(selected & before)} unchanged "
            f"ref(s) skipped, {len(selected - before)} added or changed",
            file=sys.stderr,
        )
        selected -= before

    for image in sorted(selected):
        print(image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
