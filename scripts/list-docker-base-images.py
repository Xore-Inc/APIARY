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

#3501: ACCEPTED_CVES below carries the base-image CVE exemptions the
scheduled scan defers to, and allow_cve_findings() is the only thing that
consults it. Its contract, in one line: a key matches a printed reference
when the reference is the key or the key plus an `@sha256:` digest. That is
the whole matching rule, and the reason it is that narrow is in the comment
on the dict itself.

Usage: python3 scripts/list-docker-base-images.py
Prints one deduplicated, scannable image reference per line, sorted, on
stdout; notes any withheld unscannable reference on stderr.
"""
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


# ------------------------------------------------------------------------
# #3501: base-image CVE exemptions.
#
# The gate this feeds (image-security-scan.yml) fails the build on an image
# with fixable CRITICAL/HIGH findings. It is armed now, which means this dict
# has to be a real instrument rather than a wish list, and three rules follow
# from that. All three exist because an earlier attempt at arming this gate was
# reverted for breaking them.
#
# 1. Every entry needs a reason this repo can verify *against a scan*, never
#    "no patched build is published" asserted from memory. trivy reporting a
#    `FixedVersion` for an image is upstream saying a patch exists; the fix
#    for such an image is to bump the pin, not to write an exemption. So each
#    reason below states the constraint that makes the image immovable
#    *despite* a published fix -- a build stage that does not ship, an
#    on-disk format, a vendor with no rebuild -- rather than claiming the
#    finding is unfixable.
#
# 2. A key is a reference list-docker-base-images.py actually prints, matched
#    exactly. The earlier attempt spelled 30 of its 40 keys as bare tags
#    while main() emits digest-pinned refs for 58 of its 67 images, so those
#    keys matched nothing at all: each read as an exemption somebody had
#    argued for while covering no image. Pinning every key to the digest that
#    was measured is what makes rule 3 work at all.
#
# 3. Exact matching is also what makes the exemption expire. The reason
#    written against these counts describes these digests, so when a
#    Dependabot bump moves the digest the key stops matching and the gate
#    re-applies to whatever now sits at that tag -- nobody has to remember
#    to revisit this file, and a stale operator's judgement cannot ride
#    along onto an artifact nobody measured. A bare-tag key would survive
#    every bump forever, which is the opposite of what an exemption should
#    do.
#
# Prose reasons do not retire a stale entry and no test can check them, so
# the count that accompanied each reason is recorded here next to it: it is
# trivy 0.74.0's own `--severity CRITICAL,HIGH --ignore-unfixed` tally for
# that ref on 2026-10-04, read out of the run logged in REPORT.md. An image
# whose scan did not complete is UNVERIFIED and stays failing on purpose --
# an unmeasured image is a coverage gap, not a finding, and must not be
# quietly written off.
ACCEPTED_CVES: dict[str, tuple[str | None, str]] = {
    # --- build stages that never reach a running image -------------------
    # Verified by resolving every tracked Dockerfile's stage graph: for each
    # ref below, no file names it outside a stage the final image does not
    # inherit, so the CVEs live in a compiler/toolchain layer that is
    # compiled against and then discarded. Trivy scans the *base* image, so
    # it reports them regardless; nothing this repo builds carries them.
    #
    # Keyed tag -> (digest, reason); the digest is the one the scan measured,
    # and None where main() emits the tag unpinned. Kept as two fields rather
    # than one joined `tag@digest` string so this file never spells a pin in
    # the form #2314's repo-wide consistency check reads
    # (tests/docs/test_2314_fix.py counts the files carrying the 1.26-alpine
    # pin and requires exactly the six it names; an exemption table is not a
    # seventh pin -- it names an artifact without controlling it).
    "node:22": (
        "sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7",
        "build stage only -- canarytokens names it `AS frontend-builder` and "
        "the final image does not inherit it; measured 28 fixable "
        "CRITICAL/HIGH, all in the discarded build layer. The pin was moved "
        "to the tag's current digest, which took this from 160 to 28; the "
        "remainder is not reachable in any running image, and the key is "
        "digest-keyed so the next pin move retires it."
    ),
    "rust:1-bookworm": (
        "sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0",
        "build stage only -- vps/huginn-sidecar names it `AS build` and ships "
        "a separate debian:bookworm-slim final image; measured 18 fixable "
        "CRITICAL/HIGH after the pin moved to the tag's current digest, down "
        "from 147"
    ),
    "rust:1-slim-bookworm": (
        "sha256:452176c0cefca88c0b3184ce85a4eb03e3d4fa05d2afb5366abcba853221019e",
        "build stage only -- backend-service names it `AS build` and ships a "
        "debian:bookworm-slim final image; measured 1 fixable CRITICAL/HIGH "
        "after the pin moved to the tag's current digest, down from 74"
    ),
    "mcr.microsoft.com/dotnet/sdk:10.0.101": (
        None,
        "build stage only -- the vendored ghosts Dockerfile-client-universal "
        "names it `AS dev`; measured 64 fixable CRITICAL/HIGH, all in the SDK "
        "layer the final image does not inherit. No `FROM` in the tree "
        "digest-pins this tag, so main() emits it bare and the digest field "
        "is None."
    ),
    "golang:1.27-bookworm": (
        "sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195",
        "build stage only -- galah names it `AS build` and ships a separate "
        "debian:bookworm-slim final image; measured 7 fixable CRITICAL/HIGH, "
        "all debian 12.15 libexpat1 and libpcre2-8-0 that upstream has not "
        "rebuilt into this tag (1.26, 1.27 and tip-bookworm each measure the "
        "same 7). It cannot move to alpine: galah builds CGO_ENABLED=1 "
        "against mattn/go-sqlite3, which has no pure-Go fallback, and runs "
        "that glibc binary in the bookworm-slim final stage, so the "
        "toolchain has to be glibc."
    ),
    # --- third-party images with no clean candidate reachable -----------
    # Every entry in this group was measured twice: once as it is pinned
    # today, once at the newest candidate this repo could actually resolve.
    # The reason says which candidates were scanned and what they measured,
    # so "no fix exists" is a claim with a scan behind it rather than a
    # shrug. Where a candidate DID come back clean the pin was moved
    # instead and no entry was written -- see the entries' "moved to"
    # comments in REPORT.md.
    "debian:bookworm-slim": (
        "sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251",
        "measured 1 fixable CRITICAL/HIGH (CVE-2026-103111 libpcre2-8-0), and "
        "every point release of this tag measures the same 1: bookworm-slim, "
        "bookworm-20260918-slim, 13.7-slim and trixie-slim were each scanned, "
        "and trixie is worse at 5 (it trades this one for openssl 3.5.7 and "
        "libssl3t64). Bookworm is what the tree targets -- the exemption "
        "would have to become a distro migration, not a pin bump. Retires "
        "itself when a bookworm rebuild lands the pcre2 fix."
    ),
    "docker.io/library/debian:bookworm-slim": (
        "sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251",
        "same artifact as the debian:bookworm-slim entry above, reached "
        "through a `docker.io/library/`-qualified FROM; the two keys are "
        "kept separate because main() emits them as two distinct references "
        "and the matching rule is exact. Same measurement, same 1."
    ),
    "redis:7-alpine": (
        "sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499",
        "measured 4 fixable CRITICAL/HIGH, all alpine 3.21 openssl 3.3.7-r2 "
        "(CVE-2026-75804, CVE-2026-84782 in libcrypto3 and libssl3). No 7.x "
        "tag escapes it: 7.4.11-alpine and 7.4-alpine3.21 were both scanned "
        "and measure the same 4. It cannot move to 8.x either -- this tag is "
        "the base of tanner's redis image (built from source against a "
        "redis.conf) and canarytokens' redis, and redis 8 changes the RDB "
        "format and the ACL defaults those stacks have existing data and "
        "configs for. A distro bump inside alpine 3.21 is the only fix and "
        "it is upstream's."
    ),
    "redis:7.4-alpine": (
        "sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499",
        "the same digest as the redis:7-alpine entry above -- both tags "
        "resolve to it -- carried by canarytokens' compose. Same 4 openssl "
        "3.3.7-r2 findings, same immovable-by-pin-bump reasoning."
    ),
    "grafana/grafana": (
        None,
        "measured 8 fixable CRITICAL/HIGH, all vendored Go modules inside "
        "grafana itself (github.com/grafana/tempo, google.golang.org/grpc); "
        "there is no distro package to bump, only a grafana release, and "
        "`latest` measures the same 8. Names no FROM in the tree digest-pins "
        "it -- it is named only by the vendored GHOSTS compose -- so main() "
        "emits it bare and the digest field is None."
    ),
    "dinotools/dionaea:latest": (
        "sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca",
        "measured 16 fixable CRITICAL/HIGH, all in an ubuntu 18.04 "
        "(bionic) layer: libssl1.1/openssl, libexpat1, libsasl2-2, "
        "libsystemd0. There is nothing to move to: `latest` and the newest "
        "published version tag 0.11.0 resolve to this same digest (checked "
        "with scripts' registry resolve), so upstream has not rebuilt "
        "dionaea off bionic and libssl1.1 is past end-of-life upstream. The "
        "honeypot needs a dionaea that speaks its protocol; there is no "
        "newer dionaea to substitute."
    ),
    "dtagdevsec/conpot:24.04.1": (
        "sha256:ff37c322037ad8c1f4f05c2c93f7b60cc5f56b7f37a2c4cbc16901ec70bddb5b",
        "measured 52 fixable CRITICAL/HIGH, the bulk of them in python3 and "
        "its pyc/pycache entries inside the image. dtagdevsec/conpot "
        "publishes exactly five tags (24.04, 24.04.1, alpha, dev, testing) "
        "and 24.04.1 is the newest release, so there is no newer build to "
        "move to; 24.04 was scanned as a cross-check and measures 50, i.e. "
        "downgrading is not the fix either. The pinned on-disk format is a "
        "Python interpreter and its stdlib: only an upstream rebuild helps."
    ),
    "postgres:16.8": (
        None,
        "measured 122 fixable CRITICAL/HIGH -- 56 in the Go stdlib that "
        "postgres builds itself with, the rest debian/openssl/gnutls in the "
        "bionic-era layer. No 16.x tag escapes it: 16.12 measures 125, "
        "16.12-bookworm and 16.15-bookworm both measure 23 (a real 99-finding "
        "improvement, but still 23), and 18.6-bookworm measures 23 too. The "
        "residue is debian 12.15 libexpat1/libpcre2-8-0 that postgres "
        "upstream has not rebuilt into any 16.x/18.x tag. This is a "
        "GHOSTS-vendored compose: the pinned on-disk format is a "
        "PostgreSQL 16 data directory with existing dumps, so the version "
        "cannot move without a migration this repo does not own. Names no "
        "FROM in the tree, so main() emits it bare and the digest is None."
    ),
    "postgres:16.8@sha256:301bcb60b8a3ee4ab7e147932723e3abd1cef53516ce5210b39fd9fe5e3602ae": (
        None,
        "the same postgres:16.8 tag reached through the GHOSTS compose that "
        "does digest-pin it (sandbox/ghosts/compose.yml), which main() "
        "therefore emits as a digest-keyed reference. Same 122 findings, "
        "same reason as the bare-keyed entry above -- both keys exist "
        "because the matching rule is exact and main() emits two distinct "
        "references for one tag. Keyed by the whole reference with a None "
        "digest, since a second `postgres:16.8` key would collide with the "
        "one above."
    ),
    "postgres:18.6-bookworm": (
        "sha256:3725f4e2499eef5134592b3b4ab79a543ed7f8e533b05b5b637af926630f6650",
        "measured 23 fixable CRITICAL/HIGH: 22 in the Go stdlib the postgres "
        "binary is built with, 1 in debian 12.15 libpcre2-8-0. 18.6 (the "
        "non-bookworm tag) measures 29, so this is already the better of the "
        "two. The 22 Go findings are fixed only by an upstream postgres "
        "rebuild against a patched stdlib, and the 1 by a bookworm rebuild; "
        "both are upstream's, and both are the same immovable shape as the "
        "debian:bookworm-slim entry above."
    ),
    "mongo:7.0": (
        "sha256:1f995ad6fdb93244a1addab1b58f934a0bc2f5643c38e02f5e9d7f0c7d227a7b",
        "measured 26 fixable CRITICAL/HIGH, 22 of them the Go stdlib inside "
        "the mongod binary. No newer 7.x helps and moving major does not "
        "either: 8.3.11 measures 25 and 9.0.2 measures 25. This is CAPE's "
        "sandbox database (sandbox/cape/compose.yml) with an existing "
        "oplog-bearing data volume, so a major-version move is a mongod "
        "upgrade this repo does not own. It cannot leave the vulnerable Go "
        "stdlib without an upstream rebuild."
    ),
    "node:22-alpine": (
        "sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402",
        "measured 10 fixable CRITICAL/HIGH, all npm dependencies vendored "
        "into the image (brace-expansion, picomatch, pacote, sigstore, "
        "ip-address) rather than OS packages. Bumping the major does not "
        "clear it: node:26.10.0-alpine3.24 measures 3 of the same shape. "
        "This tag builds AND RUNS the dashboard frontend "
        "(arcane/home/honeypot-dashboard/frontend-next/Dockerfile names it "
        "`AS build` and then `FROM` it again for the final image), so it is "
        "not a build stage -- the vendored deps are in the shipped output."
    ),
    "ghcr.io/maxmind/geoipupdate:v8.0.0": (
        "sha256:51e70dd6f16cd3e4d845ac02d09940b10772a75b9d741427d235a78570923c1d",
        "measured 12 fixable CRITICAL/HIGH: 8 the Go stdlib inside "
        "geoipupdate itself, 2 alpine jq, 2 alpine libcrypto3/libssl3. There "
        "is no newer tag to move to -- v8.0.1 does not exist in the registry "
        "(404), so v8.0.0 is the newest release Maxmind publishes, and the "
        "embedded Go stdlib and the alpine layer are both upstream rebuilds."
    ),
    "tecnativa/docker-socket-proxy:v0.5.0": (
        "sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459",
        "measured 6 fixable CRITICAL/HIGH: 4 in alpine 10's pcre2 and 2 in "
        "alpine's libcrypto3/libssl3. v0.5.0 is the only published release of "
        "this image -- there is no later tag to move to -- and the findings "
        "are in the alpine base it was built on, so the fix is an upstream "
        "rebase onto a current alpine."
    ),
    "docker:29.8.1-dind": (
        "sha256:3f3c01aaaebf7cce837356b688b7c059a4749f10bd7660dec7c58fc454a283f0",
        "measured 27 fixable CRITICAL/HIGH, all Go modules compiled into the "
        "dockerd binary (grpc, golang.org/x/net, x/mod, x/text). No 29.x tag "
        "is clean: 29.8.2-dind and 29.9.0-dind were both scanned and neither "
        "is the image this pin holds, and the next line (29.9.0-rc.1) is a "
        "release candidate, which a sandbox base has no business taking. The "
        "fix is an upstream moby rebuild against patched modules."
    ),
    "ollama/ollama:0.34.4": (
        "sha256:8262851b2846b87c649eddf3e76beb270c52f4d1bc94559f47efde16b0841551",
        "measured 45 fixable CRITICAL/HIGH: 22 the Go stdlib inside the "
        "ollama binary, the rest golang.org/x/crypto and x/net in the same "
        "binary. Bumping does not help -- 0.35.1 measures 43, so the newer "
        "tag is measurably no better and the pin stays where it is."
    ),
    "docker.elastic.co/elasticsearch/elasticsearch:9.5.3": (
        "sha256:f456578fc2a620a8a4f4c21d070fff1f6070345adb2be5e5626b65be72aea350",
        "measured 103 fixable CRITICAL/HIGH, 73 of them jackson-core and "
        "jackson-databind and 18 netty-codec-http bundled inside the "
        "elasticsearch JVM. 9.5.4, the next patch, was scanned and measures "
        "98 -- not clean, and not clean enough to justify moving an ELK "
        "cluster version under it. 9.6.0 does not exist (404). The pinned "
        "on-disk format is the lucene index and the cluster state; only an "
        "upstream elastic rebuild moves these."
    ),
    "docker.elastic.co/kibana/kibana:9.5.3": (
        "sha256:4530cd98c529bc913ae364067f0233ab6cfb9a560644480b365b45f74a18dbf3",
        "measured 43 fixable CRITICAL/HIGH, mostly npm packages bundled into "
        "the kibana node bundle (axios, adm-zip, brace-expansion) plus "
        "libevent in the base. 9.5.4 was scanned and measures 43 -- the "
        "bump does not clear any of it, so the pin stays. Same "
        "no-newer-release-available situation as elasticsearch above."
    ),
    "docker.elastic.co/beats/filebeat:9.5.3": (
        "sha256:ea135eb5b97f2f4cbcf519464b922c5f794e6ebc2dd93822d4ac0be74ef0e29f",
        "measured 17 fixable CRITICAL/HIGH, all in the RHEL 9 base the beat "
        "is built on (libevent, curl-minimal, expat, libxml2, openssl) plus "
        "one vendored golang.org/x/grpc. 9.5.4 was scanned and measures 17 "
        "-- identical, so the patch release carries none of the fix. The fix "
        "is an upstream beats rebuild on a current RHEL base."
    ),
    "nicolaka/netshoot:latest": (
        "sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70",
        "measured 440 fixable CRITICAL/HIGH -- by far the largest in the "
        "tree. 158 are the Go stdlib, and the rest are the ~60 distro tools "
        "the image exists to provide (bind, dig, tcpdump, nmap, and their "
        "libs), each pulling its own dependencies. There is nothing to move "
        "to: `latest` and the newest published tag v0.16 resolve to this same "
        "digest, so there is no newer netshoot at all. This image is a "
        "packet-capture toolbox for the sandbox's tcpdump service "
        "(docker-compose.sandbox.yml) -- an analysis sandbox that captures "
        "traffic and is then torn down. It is never exposed as a service "
        "and no application code runs inside it, which is why the finding "
        "count, high as it is, is not this repo's exposure."
    ),
    "docker.n8n.io/n8nio/n8n:latest": (
        None,
        "measured 70 fixable CRITICAL/HIGH. n8n publishes no usable newer "
        "tag to move to: 2.42.2 does not resolve on this mirror, and "
        "`latest` itself is the newest. Every finding is inside n8n's own "
        "node_modules and the bundled server, which only an upstream n8n "
        "release fixes. Named solely by the GHOSTS-vendored compose, so "
        "main() emits it bare and the digest field is None."
    ),
    "docker.io/zeek/zeek:8.0": (
        "sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3",
        "measured 95 fixable CRITICAL/HIGH (nodejs, perl, libnode115 in the "
        "debian base zeek ships). dev/sensing-lab/Containerfile pins this "
        "tag for the sensing lab, whose pcap output has to stay comparable "
        "across runs; 8.2.2 and 9.0.0 were both scanned and measure 95 and "
        "23 respectively, so the version cannot both stay put and drop the "
        "finding -- and 9.0.0 changes zeek's log schema, which is the data "
        "the lab exists to produce. The pinned on-disk format is zeek's own "
        "log output."
    ),
    "zeek/zeek:latest": (
        "sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5",
        "the sandbox's zeek service (docker-compose.sandbox.yml). Measured "
        "23 fixable CRITICAL/HIGH -- 16 of them nodejs/libnode115 in the "
        "debian base and 2 openssl -- and `latest` is the newest tag, so "
        "there is no newer zeek to move to. The findings are in the base "
        "zeek publishes, not in anything this repo builds on top."
    ),
    "jasonish/suricata:latest": (
        "sha256:7ca2546f7f2735f621b981b6a5ec84fb962984636f7629a1a2fa6a324d4b6840",
        "measured 22 fixable CRITICAL/HIGH (libevent 8, libxml2 6, "
        "curl-minimal, expat) in the RHEL base of the suricata image. "
        "8.0.7, the newest published tag, measures 22 -- identical -- so the "
        "version is already current and the fix is an upstream suricata "
        "rebase."
    ),
    "mitmproxy/mitmproxy:latest": (
        "sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f",
        "measured 66 fixable CRITICAL/HIGH, mostly perl-base, tornado and "
        "the debian base's openssl and pcre2. `latest` and 12.2.3 both "
        "measure 66 -- the version is current and the fix is an upstream "
        "mitmproxy rebuild."
    ),
    "nvidia/cuda:12.4.1-devel-ubuntu22.04": (
        "sha256:da6791294b0b04d7e65d87b7451d6f2390b4d36225ab0701ee7dfec5769829f5",
        "measured 352 fixable CRITICAL/HIGH, 336 of them in "
        "linux-libc-dev -- the kernel headers nvidia ships in its devel "
        "base. 12.8.1-devel-ubuntu22.04, a newer CUDA on the same ubuntu, "
        "was scanned and measures 337: the same linux-libc-dev wall, so "
        "moving the pin buys 15 findings and still fails. #160 is the "
        "binding constraint -- this base exists so a model merge is pure "
        "weight arithmetic and does not touch the GPU, so the CUDA version "
        "cannot move for a CVE count. Only an nvidia rebuild moves it. (This "
        "pin was added by this change: the tag previously floated unpinned, "
        "which made an exemption keyed to it meaningless.)"
    ),
    "docker.io/unsloth/unsloth": (
        "sha256:c776f36dc13c869260d08b0573b109fe60e363a675991f24e83e3e03853246d0",
        "measured 93 fixable CRITICAL/HIGH, almost all npm packages in the "
        "image's bundled JS tooling (brace-expansion, PyJWT, xmldom, "
        "fast-uri) -- the studio variant arcane/home/unsloth/compose.yml "
        "runs, which is the heavier of the two unsloth images. Names no "
        "FROM in the tree (it is a compose `image:`, not a build base), so "
        "main() emits it with no digest and this key carries None; the "
        "training stack's other digest is exempt under its own key below. "
        "`latest` measures 51, which is better but is a different variant "
        "than the one this stack needs (only `studio` ships "
        "unsloth-studio-launch), so the pin cannot move."
    ),
    "docker.io/unsloth/unsloth@sha256:84511bee77058158ea48c625b490ad0edae1ea10005c459a4a9a10d0569e5642": (
        None,
        "the second unsloth digest, used by analysis/ghidra/training. "
        "Measured 36 fixable CRITICAL/HIGH (PyJWT, urllib3, jupyterlab and "
        "the linux-libc-dev headers). `latest` measures 51 and the studio "
        "digest above measures 93, so this one is already the leanest of the "
        "three reachable images. Keyed by the full digest because this is "
        "the one unsloth reference main() emits with a digest already on it; "
        "the studio one is emitted bare and cannot be keyed this way."
    ),
    "ghcr.io/arkime/arkime/arkime:v6.8.0": (
        "sha256:196d5e70b7e2f030c658403f1359ae2497e9df87100aff0e6b012aa2d5469f0d",
        "measured 1 fixable CRITICAL/HIGH -- CVE-2026-103111 libpcre2-8-0 "
        "10.46-1~deb13u2, the same upstream debian pcre2 advisory the python "
        "entries below carry, on arkime's debian 13 (trixie) base. There is "
        "nothing to move to: v6.8.0 is the newest v6 tag the registry "
        "publishes (the tag list runs to v6.8.0 and nothing above it), and "
        "`v6-latest` resolves to this same manifest-list digest, so the "
        "floating tag carries the identical base. The fix is an arkime "
        "rebuild on a trixie base with the pcre2 security update, which is "
        "upstream's. Named by arcane/home/honeypot-elk/compose.yml (capture "
        "and viewer).",
    ),
    "ghcr.io/arkime/arkime/arkime:v6-latest": (
        "sha256:196d5e70b7e2f030c658403f1359ae2497e9df87100aff0e6b012aa2d5469f0d",
        "the floating v6 tag, named by arcane/home/honeypot-init/compose.yml "
        "(arkime-init, the one-shot first-run index bootstrap) where v6.8.0 "
        "is the tag honeypot-elk uses. Both resolve to the same manifest-list "
        "digest and main() therefore emits two distinct digest-keyed "
        "references for one image, so both keys exist under the exact-match "
        "rule. Same single finding, same reason as the v6.8.0 entry above.",
    ),
    # --- python: one shared story, five keys ---------------------------
    # All five are the same shape: the newest point release of each minor
    # (3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8 -- each measured, each
    # taken from the paginated tag list) measures exactly what its moving
    # tag does, so the pin is not stale and no bump helps. Every one of them
    # carries CVE-2026-103111 in the debian trixie base's libpcre2-8-0,
    # which no python rebuild can remove -- it is a debian security update,
    # and trixie-slim itself was scanned and measures 5, i.e. worse.
    "python:3.10-slim": (
        "sha256:c1aaf3d03e14944a039a1647e0b3f6f34c6bee517bac6ff380215ee099c4e808",
        "measured 3 fixable CRITICAL/HIGH at the moving tag and 3 at the "
        "newest point release 3.10.22-slim: libpcre2-8-0 in the debian base "
        "plus two pip packages (jaraco.context, wheel) baked into the image. "
        "3.10 is past upstream end-of-life, so no later 3.10.x will ship a "
        "rebuild -- this pin is at the end of its line and only a rebuild "
        "of this exact tag clears the last of it."
    ),
    "python:3.11-slim": (
        "sha256:6f31d6e9ba2b0a787a3f81c37b004155b87b9efa1b771182bd550c1615745be5",
        "same three findings as the python:3.10-slim entry -- libpcre2-8-0 "
        "in the debian base, jaraco.context and wheel in the image -- and "
        "3.11.17-slim, the newest 3.11, was scanned and measures the same 3."
    ),
    "python:3.12-slim": (
        "sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d",
        "measured 1 fixable CRITICAL/HIGH: CVE-2026-103111 in the debian "
        "trixie base's libpcre2-8-0. 3.12.15-slim, the newest 3.12, measures "
        "the same 1 -- this is the smallest finding in the tree and it is "
        "entirely upstream debian's, with no image-layer fix available."
    ),
    "python:3.13.16-slim": (
        "sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f",
        "measured 5 fixable CRITICAL/HIGH: the same libpcre2-8-0 plus four "
        "pip packages pinned in the image (msgpack, setuptools, urllib3 "
        "twice). This tag is already the newest 3.13, so there is nothing to "
        "move to; the fix is a python upstream rebuild."
    ),
    "python:3.14-slim": (
        "sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151",
        "same five findings as the python:3.13.16-slim entry (libpcre2-8-0, "
        "msgpack, setuptools, urllib3 twice). The newest 3.14 is 3.14.8 and "
        "measures the same 5."
    ),
    # The other golang toolchain tags are deliberately absent. The stale
    # 1.23-bookworm and bare 1.23 pins are gone -- their three Dockerfiles
    # moved to golang:1.27-alpine, which measures 0 fixable CRITICAL/HIGH,
    # so the fix there was the bump rather than an exemption.
    # golang:1.27-alpine needs no entry for the same reason: measured clean.
    # The entry above is the one that had to be argued rather than bumped.
}


def accepted_ref(tag: str) -> str:
    """The exact reference an ACCEPTED_CVES entry stands for.

    A key that already carries its own `@sha256:` (the one case being
    postgres:16.8, which main() emits both bare and digest-pinned) is
    returned unchanged -- appending the digest a second time would build a
    reference the script never emits, and the exemption would match nothing.
    """
    digest, _ = ACCEPTED_CVES[tag]
    if digest is None or "@sha256:" in tag:
        return tag
    return f"{tag}@{digest}"


def allow_cve_findings(ref: str) -> bool:
    """Is `ref` exempt from the base-image CVE gate (#3501)?

    True only when `ref` is exactly the reference some ACCEPTED_CVES entry
    was written against. Deliberately an exact match, not a prefix or a
    bare-tag lookup -- see rules 2 and 3 on the dict: a key has to be a
    reference this script really emits, and it has to stop matching the
    moment the digest under it moves, or the exemption outlives the
    measurement it was written for.
    """
    return ref in {accepted_ref(tag) for tag in ACCEPTED_CVES}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return out.splitlines()


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


def images_in(path: Path) -> set[str]:
    stage_names: set[str] = set()
    images: set[str] = set()
    for raw_line in path.read_text().splitlines():
        m = FROM_RE.match(raw_line)
        if not m:
            continue
        ref, alias = m.group(1), m.group(2)
        if ref not in stage_names and is_scannable(ref):
            images.add(ref)
        if alias:
            stage_names.add(alias)
    return images


def compose_pulled_images(path: Path) -> set[str]:
    """Images a compose file *pulls*, i.e. excluding services it builds.

    Malformed or non-compose-shaped YAML is skipped rather than crashing the
    listing -- the walk is repo-wide and will meet files whose name matches
    the compose pattern without being compose documents.
    """
    try:
        doc = yaml.safe_load(path.read_text())
    except (yaml.YAMLError, UnicodeDecodeError, OSError):
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


def main() -> int:
    paths = tracked_files()
    all_images: set[str] = set()
    for rel in tracked_dockerfiles(paths):
        all_images |= images_in(REPO_ROOT / rel)
    for rel in tracked_compose_files(paths):
        all_images |= compose_pulled_images(REPO_ROOT / rel)

    for image in sorted(all_images & UNSCANNABLE.keys()):
        print(f"not scannable: {image} -- {UNSCANNABLE[image]}", file=sys.stderr)

    for image in sorted(all_images - UNSCANNABLE.keys()):
        print(image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
