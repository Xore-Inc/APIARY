#!/usr/bin/env python3
"""Regression test for #3501: the base-image CVE exemption set must not rot.

The gate in image-security-scan.yml now fails the build on a base image with
fixable CRITICAL/HIGH findings, consulting ACCEPTED_CVES through
allow_cve_findings(). That makes the exemption set an instrument with
consequences, and instruments rot silently. Two failure modes this file
exists to catch:

**A key that exempts nothing.** Every key must be a reference
list-docker-base-images.py actually emits. The earlier attempt at arming this
gate shipped 30 keys that matched no emitted ref at all -- keys written as
bare tags while main() prints digest-pinned refs, so the comparison never
fired. Every entry read as an exemption somebody had argued for while
covering no image. Deleting a Dockerfile, retiring a compose service, or
re-spelling a pin is the same failure with a smaller diff: the key survives,
covers nothing, and the gate quietly stops gating whatever replaces it. So
the check below is against what the script emits *right now*, not against a
frozen copy of what it used to emit.

**A match that is looser than it looks.** allow_cve_findings() is exact
membership. The tempting simplification is a prefix test, which would let a
`node:22` key also cover `node:22-alpine` and `node:220` -- silently widening
an exemption past the single image it was argued for. The negative cases
below pin that boundary so the "simplification" fails here rather than in
production.

Prose reasons are deliberately not asserted against. A reason's accuracy is a
matter for a scan and a human reading the diff; what a test can hold is the
structural invariant that a key is live, reasoned, and no broader than the ref
it names.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LIST_SCRIPT = REPO_ROOT / "scripts" / "list-docker-base-images.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("list_docker_base_images_3501", LIST_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def listing():
    return _load_script()


@pytest.fixture(scope="module")
def emitted():
    """The refs main() actually prints right now.

    Runs the script rather than reimplementing the walk, so this stays a
    check on the real emission contract instead of a second copy of it that
    can drift.
    """
    out = subprocess.run(
        [sys.executable, str(LIST_SCRIPT)],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


def test_every_key_is_a_reference_the_script_emits(listing, emitted):
    """No dead exemptions.

    Each entry stands for exactly one reference -- the tag, joined to the
    digest it was measured against -- and that reference must be one the
    script prints. A key that is not is an entry that exempts nothing, which
    is how the reverted attempt shipped 30 of them.
    """
    dead = sorted(
        ref for ref in (listing.accepted_ref(t) for t in listing.ACCEPTED_CVES)
        if ref not in emitted
    )
    assert not dead, (
        "ACCEPTED_CVES entries whose reference is not one "
        f"list-docker-base-images.py emits (dead exemptions): {dead}\n"
        "Either the image left the tree, or the key names a digest the tree "
        "no longer pins. A dead key exempts nothing while reading like an "
        "argued-for exemption."
    )


def test_every_emitted_ref_is_matched_by_at_most_one_key(listing, emitted):
    """No duplicate coverage.

    Two entries naming the same artifact would mean two reasons arguing for
    one exemption, which is how a set rots into something nobody can review.
    """
    refs = [listing.accepted_ref(t) for t in listing.ACCEPTED_CVES]
    dupes = sorted({r for r in refs if refs.count(r) > 1})
    assert not dupes, f"references covered more than once: {dupes}"


def test_keys_are_unique_and_reasoned(listing):
    """Every entry carries a non-empty reason.

    #3501's gate is only trustworthy if each exemption says why this repo
    cannot move the image. A blank reason would let an entry be added with
    the explanation as the thing someone forgot.
    """
    unreasoned = sorted(
        tag for tag, (_, reason) in listing.ACCEPTED_CVES.items() if not reason.strip()
    )
    assert not unreasoned, f"exemptions with an empty reason: {unreasoned}"


def test_digest_field_is_a_real_digest_or_absent(listing):
    """The digest field is a pin or an explicit None.

    A malformed digest would make the entry silently match nothing, which is
    the dead-key failure the first test above reports -- but there it reads
    as a tree-drift problem, when it is actually a typo in here.
    """
    for tag, (digest, _reason) in listing.ACCEPTED_CVES.items():
        assert digest is None or re.fullmatch(r"sha256:[0-9a-f]{64}", digest), (
            f"{tag} has a malformed digest {digest!r}"
        )


@pytest.mark.parametrize(
    "key_digest, ref, expected",
    [
        # A digest-keyed entry covers its own pinned artifact and nothing else.
        ("sha256:" + "a" * 64, "node:22@sha256:" + "a" * 64, True),
        ("sha256:" + "a" * 64, "node:22@sha256:" + "b" * 64, False),
        # The bare tag is not the artifact the reason was written against --
        # main() would have to emit it unpinned for that to match.
        ("sha256:" + "a" * 64, "node:22", False),
        # A neighbouring tag is never swept in, digest or no digest.
        ("sha256:" + "a" * 64, "node:22-alpine", False),
        ("sha256:" + "a" * 64, "node:220", False),
        ("sha256:" + "a" * 64, "python:3.12-slim", False),
        # A tag-keyed entry (the digest-is-None case) covers the bare tag.
        (None, "node:22", True),
        (None, "node:22-alpine", False),
        (None, "node:22@sha256:" + "a" * 64, False),
    ],
)
def test_matching_does_not_over_match(listing, key_digest, ref, expected):
    """The match is exact, so a neighbouring ref is never swept in.

    If this ever degrades to a prefix test, a `node:22` entry would also
    exempt `node:22-alpine` -- widening an exemption past the image it was
    argued for, which is the same class of defect as a dead key.
    """
    original = listing.ACCEPTED_CVES
    listing.ACCEPTED_CVES = {"node:22": (key_digest, "test reason")}
    try:
        assert listing.allow_cve_findings(ref) is expected
    finally:
        listing.ACCEPTED_CVES = original


def test_a_digest_bump_retires_the_exemption(listing):
    """The property the key rewrite bought, asserted directly.

    A Dependabot digest bump moves the digest in the Dockerfile and leaves
    the tag alone. The bumped artifact must fall back under the gate rather
    than inheriting a judgement recorded against the previous digest -- no
    human has to remember to revisit the exemption file when a pin moves.
    A bare-tag key would survive every bump forever, which is the opposite
    of what an exemption should do.
    """
    old = "node:22@sha256:" + "1" * 64
    bumped = "node:22@sha256:" + "2" * 64
    original = listing.ACCEPTED_CVES
    listing.ACCEPTED_CVES = {"node:22": ("sha256:" + "1" * 64, "test reason")}
    try:
        assert listing.allow_cve_findings(old) is True
        assert listing.allow_cve_findings(bumped) is False
    finally:
        listing.ACCEPTED_CVES = original