#!/usr/bin/env python3
"""Regression test for #2314: stale base-image digest pins.

golang:1.26-alpine was pinned at the 1.26.5 digest
(sha256:0178a641fbb4...) in six Dockerfiles; the moving `1.26-alpine` tag
had since rolled forward to 1.26.7 (sha256:28d89ee9cc0f...) -- two Go
patch cycles of stdlib fixes never made it into the shipped binaries.

The same sweep (docs/CONTAINER-UPDATES.md's "safe batch") also covers the
issue's "same-version digest refreshes" -- tag aliases that moved
underneath without a version change -- for python:3.14-slim,
python:3.11-slim, python:3.10-slim, python:3.12-slim, debian:bookworm-slim,
valkey/valkey:9.1.1-alpine3.24, postgres:18.6-bookworm and redis:7-alpine.

The conpot image was deliberately NOT bumped at the time: 24.04.1 existed,
but the six *_patch.py scripts hard-coded 24.04's Python site-packages
root and the build FileNotFoundErrored against it. #2619 has since lifted
that freeze -- the "restructured the package" premise turned out to be
wrong, the only real difference being the Python install root -- so the
version contract for the conpot pin now lives in
tests/docs/test_2619_fix.py, which asserts the bumped state. The conpot
tests kept below are the ones that hold whatever the pin is.

Two things the issue body got wrong, corrected here against the real repo
and a live registry query rather than trusted verbatim:

- Its per-file attribution for the python:3.10-slim and python:3.12-slim
  refreshes names honeyfs-implant/elasticpot/mailoney/tanner and
  cowrie/dicompot respectively -- but grepping the actual repo shows only
  tanner/tanner ever pinned the 3.10-slim digest, and only elasticpot (both
  stages) ever pinned the 3.12-slim one. honeyfs-implant is a Go/scratch
  build with no Python stage at all. Files are listed below as they truly
  are, not as the issue claimed.
- The issue was "registry-resolved 2026-08-26"; by the time of this fix
  (2026-08-29) python:*-slim had already rebuilt again upstream, so the
  four python digests the issue cites were themselves already stale. Per
  this repo's own docs/CONTAINER-UPDATES.md ("verify it directly, don't
  trust a secondary source"), all same-version pins were refreshed
  against a live `docker-content-digest` registry query, not copied from
  the issue text.

Three defects in the original version of this file, fixed here:

1. The repo-wide sweep used `Path.rglob` from the repo root, which
   descends into untracked sibling checkouts (`.orchestrator/worktrees/*`)
   and `node_modules`. Run from a developer checkout that has them it
   reported 162 offenders -- every one a file belonging to some other
   branch's worktree, none of them this repo's content. It only passed in
   CI by accident of a fresh clone having no such directories. The sweep
   now walks `git ls-files`, so it sees exactly the repo's tracked content
   wherever it runs.
2. The conpot freeze was asserted by string-searching the whole file for
   the literal "dtagdevsec/conpot:24.04.1" -- both too narrow (a bump to
   24.05, `latest`, or a silently dropped digest pin all sailed through)
   and too broad (it failed on a *comment* naming the tag, which is how
   the freeze was documented). Those assertions have since been removed
   rather than repaired: #2619 lifted the freeze, so pinning the image at
   24.04 became an assertion against the repo's actual contract. The
   parsed-fields approach they were rewritten into lives on in
   test_2619_fix.py, applied to the 24.04.1 pin.
3. Nothing tested the coupling that *causes* the freeze. The tests below
   now assert that every COPY'd patch script exists in the build context
   and that the RUN line executes each one -- version-agnostic couplings
   that outlived the freeze. The layout-root assertion that went with them
   moved to test_2619_fix.py, retargeted at the 3.12 root.
"""
import pathlib
import re
import shlex
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SELF_RELPATH = "tests/docs/test_2314_fix.py"

OLD_GOLANG_DIGEST = "sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2"
NEW_GOLANG_DIGEST = "sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c"

# Issue #2314's "real bump" section names exactly these six Dockerfiles
# for the golang:1.26-alpine bump.
GOLANG_DOCKERFILES = {
    "attacker-identity-worker": "arcane/home/honeypot-attacker-identity-worker/attacker-identity-worker/Dockerfile",
    "correlator-worker": "arcane/home/honeypot-correlator-worker/correlator-worker/Dockerfile",
    "payload-inventory-worker": "arcane/home/honeypot-payload-inventory-worker/payload-inventory-worker/Dockerfile",
    "beelzebub": "arcane/home/honeypot-beelzebub/beelzebub/Dockerfile",
    "canarytokens-adapter": "arcane/home/honeypot-canarytokens/canarytokens-adapter/Dockerfile",
    "canarytokens-http-router": "arcane/home/honeypot-canarytokens/canarytokens-http-router/Dockerfile",
}

# Same-version digest refreshes from the issue's second section -- files
# listed are every file in the repo that actually carried the stale pin
# (confirmed by grep), not the issue's own per-file claims where those
# didn't match reality.
SAME_VERSION_REFRESHES = {
    "python:3.14-slim": {
        "old": "sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc",
        "superseded": "sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5",
        "new": "sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151",
        "files": [
            "analysis/ghidra/statictools/Dockerfile",
            "arcane/home/honeypot-agent-intrusion-worker/analysis/agent-intrusion-corpus/Dockerfile",
            "arcane/home/honeypot-dashboard/analysis/es-results-importer/Dockerfile",
            "arcane/home/honeypot-dashboard/services-adapter/Dockerfile",
            "auth-events-worker/Dockerfile",
            "llm-worker/Dockerfile",
            "ml-worker/Dockerfile",
        ],
    },
    "python:3.11-slim": {
        "old": "sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff",
        "superseded": "sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6",
        "new": "sha256:6f31d6e9ba2b0a787a3f81c37b004155b87b9efa1b771182bd550c1615745be5",
        "files": [
            "arcane/home/honeypot-tanner/snare/Dockerfile",
            "arcane/home/honeypot-init/snare/Dockerfile",
            "arcane/home/honeypot-mailoney/mailoney/Dockerfile",
        ],
    },
    "python:3.10-slim": {
        "old": "sha256:63669fd2563fa90b0442fa7b568e66e3667755636cda086d7bcaaa895f66fe39",
        "superseded": "sha256:38758a82a44d1acb9bae3dd5f7d2a55452fb44a5ceca7c4589f360f2c4aa3d0c",
        "new": "sha256:c1aaf3d03e14944a039a1647e0b3f6f34c6bee517bac6ff380215ee099c4e808",
        "files": [
            "arcane/home/honeypot-tanner/tanner/tanner/Dockerfile",
        ],
    },
    "python:3.12-slim": {
        "old": "sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65",
        "superseded": "sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217",
        "new": "sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d",
        "files": [
            "arcane/home/honeypot-elasticpot/elasticpot/Dockerfile",
        ],
    },
    "debian:bookworm-slim": {
        "old": "sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241",
        "superseded": "sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
        "new": "sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251",
        "files": [
            "arcane/home/honeypot-cowrie/cowrie/Dockerfile",
            "arcane/home/honeypot-galah/galah/Dockerfile",
        ],
    },
    # Superseded by a real version bump: the session store moved to
    # 9.1.2-alpine3.24 upstream, so #2314's same-version refresh of the
    # 9.1.1 alias no longer describes the pin. What still matters -- and is
    # what this entry now guards -- is that neither of the two superseded
    # 9.1.1 digests can come back. `old` remains #2314's stale digest;
    # `superseded` is the refreshed 9.1.1 digest this bump replaced.
    "valkey/valkey:9.1.2-alpine3.24": {
        "old": "sha256:ee91f7a174ac4d6a6b0685b3a60e321f0a9dbbb691f9b0e285be2ba1d1be8328",
        "superseded": "sha256:de31910896150d5e754a07d57d227cfdde4e258ddd0d1aa4607f2d2f95843715",
        "superseded": "sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd",
        "new": "sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11",
        "files": [
            "arcane/home/honeypot-dashboard/compose.yml",
        ],
    },
    "postgres:18.6-bookworm": {
        "old": "sha256:7d2695c3aa88e792e8b3b233e7e4adb296a20412c6c0ca361e3edaaacfada108",
        "superseded": "sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af",
        "new": "sha256:3725f4e2499eef5134592b3b4ab79a543ed7f8e533b05b5b637af926630f6650",
        "files": [
            "arcane/home/honeypot-keycloak/compose.yml",
        ],
    },
    "redis:7-alpine": {
        "old": "sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2",
        "superseded": "sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf",
        "new": "sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499",
        "files": [
            "arcane/home/honeypot-tanner/tanner/redis/Dockerfile",
            "scripts/test-dashboard-oidc-chaos.sh",
            "scripts/test-dashboard-oidc-pkce-totp-login.sh",
        ],
    },
}

ALL_OLD_DIGESTS = {OLD_GOLANG_DIGEST} | {spec["old"] for spec in SAME_VERSION_REFRESHES.values()}

# --- conpot ---------------------------------------------------------------
#
# The image pin itself -- repository, tag and digest -- is asserted by
# tests/docs/test_2619_fix.py, which owns that contract since #2619 bumped
# 24.04 -> 24.04.1. What remains here are the Dockerfile/build-context
# couplings that hold at any pin.
CONPOT_DIR = "arcane/home/honeypot-conpot/conpot"
CONPOT_DOCKERFILE = f"{CONPOT_DIR}/Dockerfile"


# --- helpers --------------------------------------------------------------

def _tracked_files():
    """Repo-tracked paths, relative to REPO_ROOT.

    Deliberately not `rglob`: a developer checkout carries untracked
    sibling worktrees under `.orchestrator/` and a `node_modules/` tree,
    and walking the filesystem pulls other branches' copies of these very
    Dockerfiles into the result set.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
            capture_output=True, check=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
        pytest.skip(f"git ls-files unavailable: {exc}")
    return [p for p in out.split("\0") if p]


def _instruction_lines(text):
    """Dockerfile instructions with comments/blanks dropped and
    backslash continuations folded into one logical line."""
    logical, buf = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        logical.append((buf + line).strip())
        buf = ""
    if buf.strip():
        logical.append(buf.strip())
    return logical


def _conpot_dockerfile_text():
    return (REPO_ROOT / CONPOT_DOCKERFILE).read_text(encoding="utf-8")


def _copy_pairs(instructions):
    """(build-context source, in-image destination) for every COPY without
    --from. A multi-source COPY targets a directory, so each source lands
    under it by basename."""
    pairs = []
    for line in instructions:
        if not re.match(r"^COPY\s", line, re.IGNORECASE):
            continue
        tokens = shlex.split(line)[1:]
        if any(t.startswith("--from=") for t in tokens):
            continue
        tokens = [t for t in tokens if not t.startswith("--")]
        if len(tokens) < 2:
            continue
        *sources, dest = tokens
        for src in sources:
            if len(sources) > 1 or dest.endswith("/"):
                pairs.append((src, dest.rstrip("/") + "/" + src.rsplit("/", 1)[-1]))
            else:
                pairs.append((src, dest))
    return pairs


def _copy_sources(instructions):
    """Build-context-relative sources of every COPY without --from."""
    return [src for src, _ in _copy_pairs(instructions)]


# --- golang:1.26-alpine bump ---------------------------------------------

@pytest.mark.parametrize("name,relpath", sorted(GOLANG_DOCKERFILES.items()))
def test_golang_dockerfile_exists(name, relpath):
    assert (REPO_ROOT / relpath).exists(), f"{name}: not found at {relpath}"


@pytest.mark.parametrize("name,relpath", sorted(GOLANG_DOCKERFILES.items()))
def test_golang_dockerfile_no_longer_pins_1_26_5(name, relpath):
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    assert OLD_GOLANG_DIGEST not in text, (
        f"{name} ({relpath}) still pins golang:1.26-alpine at the stale "
        f"1.26.5 digest {OLD_GOLANG_DIGEST} -- #2314"
    )


@pytest.mark.parametrize("name,relpath", sorted(GOLANG_DOCKERFILES.items()))
def test_golang_dockerfile_pins_1_26_7(name, relpath):
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    assert f"golang:1.26-alpine@{NEW_GOLANG_DIGEST}" in text, (
        f"{name} ({relpath}) does not pin golang:1.26-alpine at the "
        f"refreshed 1.26.7 digest {NEW_GOLANG_DIGEST} -- #2314"
    )


def test_golang_pins_are_consistent_across_the_whole_repo():
    """Every tracked build file that pins golang:1.26-alpine must pin the
    same refreshed digest, and the set of such files must be exactly the
    six the issue names.

    The previous version of this test compared GOLANG_DOCKERFILES against
    a hardcoded literal in this same file, so it could only ever pass --
    it asserted nothing about the repo. This asks the repo instead, which
    catches both a seventh Dockerfile appearing with a stale pin and one
    of the six being renamed out from under the list.
    """
    pinned, wrong_digest = set(), []
    for relpath in _tracked_files():
        if relpath == SELF_RELPATH:
            continue
        path = REPO_ROOT / relpath
        if not path.is_file() or path.suffix in {".md", ".txt"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for ref in re.findall(r"golang:1\.26-alpine(?:@(sha256:[0-9a-f]{64}))?", text):
            pinned.add(relpath)
            if ref != NEW_GOLANG_DIGEST:
                wrong_digest.append(f"{relpath}: {ref or '<no digest pin>'}")
    assert not wrong_digest, (
        "golang:1.26-alpine references not pinned at the refreshed "
        f"{NEW_GOLANG_DIGEST} -- #2314:\n" + "\n".join(sorted(wrong_digest))
    )
    assert pinned == set(GOLANG_DOCKERFILES.values()), (
        "the set of files pinning golang:1.26-alpine drifted from the six "
        "#2314 names.\nunexpected: "
        f"{sorted(pinned - set(GOLANG_DOCKERFILES.values()))}\n"
        f"missing: {sorted(set(GOLANG_DOCKERFILES.values()) - pinned)}"
    )


# --- same-version digest refreshes ---------------------------------------

@pytest.mark.parametrize("image,spec", sorted(SAME_VERSION_REFRESHES.items()))
def test_same_version_refresh_applied(image, spec):
    for relpath in spec["files"]:
        path = REPO_ROOT / relpath
        assert path.exists(), f"{relpath}: not found ({image} refresh -- #2314)"
        text = path.read_text(encoding="utf-8")
        assert spec["old"] not in text, (
            f"{relpath} still pins {image} at the stale digest {spec['old']} -- #2314"
        )
        # An entry that has since been superseded by a real version bump also
        # names the digest that bump replaced; it must not come back either.
        if "superseded" in spec:
            assert spec["superseded"] not in text, (
                f"{relpath} pins {image} at {spec['superseded']}, the digest a later "
                f"version bump replaced -- #2314"
            )
        assert spec["new"] in text, (
            f"{relpath} does not pin {image} at the refreshed digest {spec['new']} -- #2314"
        )


def test_no_stale_digest_pins_remain_anywhere():
    """Acceptance criterion: 'no stale digest pins remain' -- sweep every
    tracked build file, not just the ones named above, since the issue's
    own per-file attribution for a couple of the same-version refreshes
    didn't match the real repo (see module docstring).

    Scoped to `git ls-files` on purpose. The filesystem walk this
    replaced descended into `.orchestrator/worktrees/*` and reported 162
    offenders on a developer checkout, all of them other branches' copies.
    """
    offenders = []
    for relpath in _tracked_files():
        if relpath == SELF_RELPATH:
            continue
        name = pathlib.PurePosixPath(relpath).name
        if not (name.startswith("Dockerfile")
                or name.endswith((".yml", ".yaml", ".sh"))):
            continue
        path = REPO_ROOT / relpath
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for old_digest in ALL_OLD_DIGESTS:
            if old_digest in text:
                offenders.append(f"{relpath}: {old_digest}")
    assert not offenders, "stale digest pins remain -- #2314:\n" + "\n".join(offenders)


# --- conpot: couplings that outlive the pin ------------------------------
#
# Three tests used to sit here asserting the #2314 freeze: that the FROM
# pinned 24.04 at a fixed digest, that no instruction named 24.04.1, and
# that every patch script hard-coded the 3.11 layout root. #2619 bumped
# the pin, so all three now assert the opposite of the repo's contract.
# They were not dropped on the floor -- their inverse lives in
# tests/docs/test_2619_fix.py, which pins 24.04.1 at its digest, bans the
# old pin from instructions, and requires the 3.12 root in all six
# scripts. What stays below is version-agnostic.

def test_conpot_copied_files_exist_in_the_build_context():
    """Every COPY source must exist. The 24.04.1 failure was a build-time
    missing path; a COPY naming a file that isn't there is the same class
    of breakage and equally invisible until a build runs.
    """
    instructions = _instruction_lines(_conpot_dockerfile_text())
    sources = _copy_sources(instructions)
    assert sources, f"{CONPOT_DOCKERFILE} has no COPY instructions to check"
    missing = [s for s in sources if not (REPO_ROOT / CONPOT_DIR / s).is_file()]
    assert not missing, (
        f"{CONPOT_DOCKERFILE} COPYs files absent from the build context "
        f"({CONPOT_DIR}/): {missing}"
    )


def test_conpot_run_executes_every_copied_patch_script():
    """Each *_patch.py brought into the image must actually be executed.

    A patch that is COPY'd but never invoked silently stops applying --
    the container still builds and starts, it just serves an unpatched
    persona. Nothing else in the suite would notice.

    Matched as an interpreter invocation of the script's in-image path,
    not as a bare filename: the same RUN line also `rm`s every patch
    afterwards, so a substring search for the name passes even when the
    `python3 ...` call for it has been deleted.
    """
    instructions = _instruction_lines(_conpot_dockerfile_text())
    patches = [(s, d) for s, d in _copy_pairs(instructions) if s.endswith("_patch.py")]
    assert patches, f"{CONPOT_DOCKERFILE} COPYs no *_patch.py scripts"
    run_text = " ".join(l for l in instructions if re.match(r"^RUN\s", l, re.IGNORECASE))
    never_run = [
        src for src, dest in patches
        if not re.search(rf"python[0-9.]*\s+{re.escape(dest)}(?:\s|$)", run_text)
    ]
    assert not never_run, (
        f"{CONPOT_DOCKERFILE} COPYs these patch scripts but never executes "
        f"them: {never_run}. Being COPY'd (and later rm'd) is not enough -- "
        f"an unexecuted patch leaves the honeypot serving conpot's stock "
        f"persona while the build stays green."
    )


def test_conpot_patch_scripts_on_disk_match_the_ones_copied():
    """The build context and the Dockerfile must not drift apart: a patch
    script added to the directory but never COPY'd is dead code that reads
    as active coverage."""
    instructions = _instruction_lines(_conpot_dockerfile_text())
    copied = {s for s in _copy_sources(instructions) if s.endswith("_patch.py")}
    on_disk = {p.name for p in (REPO_ROOT / CONPOT_DIR).glob("*_patch.py")}
    assert copied == on_disk, (
        f"patch scripts in {CONPOT_DIR}/ do not match those COPY'd by the "
        f"Dockerfile.\nnot COPY'd: {sorted(on_disk - copied)}\n"
        f"COPY'd but absent: {sorted(copied - on_disk)}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
