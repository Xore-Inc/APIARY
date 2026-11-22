#!/usr/bin/env python3
"""List the 0.x dependency lines that a Dependabot update moves in a lockfile.

Dependabot labels a 0.x minor bump `version-update:semver-minor`, and
`updated-dependencies-json` names only direct dependencies. A transitive 0.x
move is invisible to that metadata: lopdf 0.44 -> 0.47 reached a PR in #3942
through Cargo.lock alone. Under semver a 0.x minor (or major) change is
breaking, so the auto-merge workflow holds any PR this script reports.

Compared, per file, when it exists on both sides of the diff:
- Cargo.lock: every [[package]] name and version (tomllib);
- requirements*.txt: exact `name==version` pins;
- go.sum: module versions (the /go.mod lines are the same versions).

A package is reported when its set of 0.x minor lines differs between base
and head, which covers 0.44 -> 0.47, 0.9 -> 1.0 and a second 0.x line being
added beside the old one. Patch moves within a line (0.44.1 -> 0.44.2) and
anything at 1.x and above are not reported. Packages present on only one side
are not reported either: a new or removed dependency is not a version move.

Usage:
  check-dependabot-lockfiles.py BASE_SHA HEAD_SHA
Run inside a checkout that holds both commits. Prints one line per moved
package and exits 0; exits 2 when git or a lockfile cannot be read, so the
caller fails closed instead of arming auto-merge on an unreadable lockfile.
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
import tomllib

LOCKFILE_GLOBS = ("Cargo.lock", "requirements*.txt", "go.sum")
PIP_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")
VERSION = re.compile(r"v?(\d+)(?:\.(\d+))?")


class LockfileError(Exception):
    pass


def git(*args: str, cwd: str | None = None) -> str:
    done = subprocess.run(["git", *args], capture_output=True, text=True, check=False, cwd=cwd)
    if done.returncode != 0:
        raise LockfileError(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout


def canon(name: str) -> str:
    return name.lower().replace("_", "-")


def parse_cargo(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for pkg in tomllib.loads(text).get("package", []):
        out.setdefault(pkg["name"], set()).add(pkg["version"])
    return out


def parse_pip(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for line in text.splitlines():
        if match := PIP_PIN.match(line):
            out.setdefault(canon(match.group(1)), set()).add(match.group(2))
    return out


def parse_go_sum(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        version = fields[1].removesuffix("/go.mod")
        out.setdefault(fields[0], set()).add(version)
    return out


def parser_for(path: str):
    name = path.rsplit("/", 1)[-1]
    if name == "Cargo.lock":
        return parse_cargo
    if fnmatch.fnmatch(name, "requirements*.txt"):
        return parse_pip
    if name == "go.sum":
        return parse_go_sum
    return None


def minor_line(version: str) -> str:
    """'0.44.2' -> '0.44'; 'v0.5.0' -> '0.5'; '1.2.3' -> '1'. Unparsable: itself."""
    match = VERSION.match(version)
    if not match:
        return version
    major, minor = match.group(1), match.group(2) or "0"
    return f"0.{minor}" if major == "0" else major


def moved(base: dict[str, set[str]], head: dict[str, set[str]]) -> list[str]:
    report = []
    for name in sorted(base.keys() & head.keys()):
        old = {minor_line(v) for v in base[name] if minor_line(v).startswith("0.")}
        new = {minor_line(v) for v in head[name] if minor_line(v).startswith("0.")}
        if old != new:
            report.append(f"{name} {','.join(sorted(base[name]))} -> {','.join(sorted(head[name]))}")
    return report


def lockfile_moves(base_sha: str, head_sha: str, cwd: str | None = None) -> list[str]:
    report = []
    for path in git("diff", "--name-only", base_sha, head_sha, cwd=cwd).splitlines():
        parse = parser_for(path)
        if parse is None:
            continue
        try:
            old = git("show", f"{base_sha}:{path}", cwd=cwd)
        except LockfileError:
            continue  # not in base: a new lockfile moves nothing that existed
        try:
            new = git("show", f"{head_sha}:{path}", cwd=cwd)
        except LockfileError:
            continue  # removed in head: not a version move
        try:
            report += [f"{path}: {item}" for item in moved(parse(old), parse(new))]
        except (tomllib.TOMLDecodeError, KeyError, ValueError) as exc:
            raise LockfileError(f"{path}: cannot parse: {exc}") from exc
    return report


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: check-dependabot-lockfiles.py BASE_SHA HEAD_SHA", file=sys.stderr)
        return 2
    try:
        report = lockfile_moves(*argv)
    except LockfileError as exc:
        print(f"check-dependabot-lockfiles: {exc}", file=sys.stderr)
        return 2
    for line in report:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
