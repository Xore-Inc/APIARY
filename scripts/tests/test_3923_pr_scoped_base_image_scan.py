#!/usr/bin/env python3
"""Regression test for #3923: the PR-scoped base-image gate.

On a pull request, image-security-scan.yml scans only what
`list-docker-base-images.py --new-since <merge-base>` prints: the refs the
PR's tree pulls that the merge-base tree did not. Upstream CVE drift on pins
a PR never touched then stops blocking unrelated PRs, while the full scan on
push to main and on the schedule still fails on it.

The listing decides what gets scanned, so it is what this file holds:

- a PR that changes no image ref lists nothing (the gate passes);
- an added FROM, an added compose `image:` and a re-pinned digest are listed
  (the gate scans them, and fails if they carry fixable findings);
- an unchanged or removed ref, and a compose service that builds, are not.

Each case runs the real script copied into a throwaway git repository, so
`REPO_ROOT`, `git ls-tree` and `git show` behave as they do in CI.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "list-docker-base-images.py"

D1 = "a" * 64
D2 = "b" * 64
ALPINE_OLD = f"alpine:3.24@sha256:{D1}"
ALPINE_NEW = f"alpine:3.24@sha256:{D2}"
DEBIAN = f"debian:trixie-slim@sha256:{D1}"
PYTHON = f"python:3.15-alpine@sha256:{D1}"
POSTGRES = f"postgres:18.7-bookworm@sha256:{D1}"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()


def write(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def commit(repo: Path, msg: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


def listing(repo: Path, *args: str) -> list[str]:
    out = subprocess.run(
        ["python3", "scripts/list-docker-base-images.py", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    """A repo whose base commit pulls alpine (Dockerfile) and debian (compose)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "test")
    (repo / "scripts").mkdir()
    shutil.copy(SCRIPT, repo / "scripts" / "list-docker-base-images.py")
    write(repo, "svc/Dockerfile", f"FROM {ALPINE_OLD} AS build\nFROM build\n")
    write(
        repo, "stack/compose.yml",
        f"services:\n  db:\n    image: {DEBIAN}\n  app:\n    build: .\n    image: local/app:dev\n",
    )
    base = commit(repo, "base")
    return repo, base


def test_full_listing_is_unscoped(repo):
    repo, _ = repo
    assert listing(repo) == sorted([ALPINE_OLD, DEBIAN])


def test_pr_that_changes_no_image_lists_nothing(repo):
    repo, base = repo
    write(repo, "README.md", "docs only\n")
    write(repo, "svc/Dockerfile", f"FROM {ALPINE_OLD} AS build\nRUN true\nFROM build\n")
    commit(repo, "no image change")
    assert listing(repo, "--new-since", base) == []


def test_added_from_and_compose_image_are_listed(repo):
    repo, base = repo
    write(repo, "other/Containerfile", f"FROM {PYTHON}\n")
    write(
        repo, "stack/compose.yml",
        f"services:\n  db:\n    image: {DEBIAN}\n  pg:\n    image: {POSTGRES}\n",
    )
    commit(repo, "add two images")
    assert listing(repo, "--new-since", base) == sorted([PYTHON, POSTGRES])


def test_repinned_digest_is_listed_and_old_one_is_not(repo):
    repo, base = repo
    write(repo, "svc/Dockerfile", f"FROM {ALPINE_NEW} AS build\nFROM build\n")
    commit(repo, "re-pin alpine")
    assert listing(repo, "--new-since", base) == [ALPINE_NEW]


def test_removed_image_is_not_listed(repo):
    repo, base = repo
    (repo / "stack" / "compose.yml").unlink()
    commit(repo, "drop compose")
    assert listing(repo, "--new-since", base) == []


def test_built_compose_service_is_never_listed(repo):
    repo, base = repo
    write(
        repo, "stack/compose.yml",
        f"services:\n  db:\n    image: {DEBIAN}\n  app2:\n    build: .\n    image: {PYTHON}\n",
    )
    commit(repo, "add a built service")
    assert listing(repo, "--new-since", base) == []


def test_ref_already_pulled_elsewhere_is_not_new(repo):
    """Moving a pin between files is not a new image: the tree pulled it before."""
    repo, base = repo
    write(repo, "elsewhere/Dockerfile", f"FROM {DEBIAN}\n")
    commit(repo, "same debian, new file")
    assert listing(repo, "--new-since", base) == []
