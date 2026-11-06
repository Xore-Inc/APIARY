#!/usr/bin/env python3
"""Regression test for #2137: frontend-next/public/static/theme.css is a
vendored mirror of Xore/theme's theme.css, and it had gone silently stale
-- two defect classes this project already diagnosed upstream (the #2120
literal-shadow clobber and a pre-AA-fix --accent-hover) were still
shipping in the vendored copy, and nothing in CI compared the vendored
asset against upstream, so drift was invisible.

#2471 (landed the day after this issue was filed) re-vendored theme.css to
Xore/theme@d74d519, which carries both fixes, and keyed the served
stylesheet URL by theme.lock's content hash. scripts/check-vendored-theme.sh
already hash-checks the vendored copy against theme.lock offline and, when
the network is reachable, byte-compares it against the pinned commit on
GitHub; quality.yml's vendored-theme / vendored-theme-cloud jobs already run
it on every push and pull_request. This test is the standing guard #2137
asked for at the pytest layer, independent of the shell script: it fails if
the vendored copy drifts from theme.lock, if either stale defect
reappears, or if the CI wiring that enforces this is weakened or removed.
"""
import hashlib
import pathlib
import re
import stat
import sys
import urllib.error
import urllib.request

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
# #3749: the vendored copy moved from frontend-next to branding/vendor.
VENDOR_DIR = REPO_ROOT / "branding" / "vendor" / "xore-theme"
LOCK = VENDOR_DIR / "theme.lock"
VENDORED = VENDOR_DIR / "theme.css"
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check-vendored-theme.sh"
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync-theme.sh"
QUALITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "quality.yml"

# The pre-fix value from Xore/theme's stateful contrast audit (#127/#128):
# ink-on-accent hover measured 4.08:1, below AA. Regenerated to #0e8672.
STALE_ACCENT_HOVER = "#0d7d6a"


def _read_lock():
    fields = {}
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip()
    return fields


def test_lock_file_declares_repository_commit_and_hash():
    fields = _read_lock()
    assert fields.get("repository"), "theme.lock must declare repository="
    assert re.fullmatch(r"[0-9a-f]{40}", fields.get("commit", "")), (
        "theme.lock commit= must be a full 40-hex-char git SHA "
        f"(got {fields.get('commit')!r})"
    )
    assert re.fullmatch(r"[0-9a-f]{64}", fields.get("sha256", "")), (
        "theme.lock sha256= must be a full sha256 hex digest "
        f"(got {fields.get('sha256')!r})"
    )


def test_vendored_file_matches_lock_hash():
    """Offline check mirroring scripts/check-vendored-theme.sh: the bytes
    on disk must match the hash recorded in theme.lock, or the lock was
    edited without re-copying the stylesheet (or vice versa)."""
    fields = _read_lock()
    actual = hashlib.sha256(VENDORED.read_bytes()).hexdigest()
    assert actual == fields["sha256"], (
        "public/static/theme.css does not match theme.lock's sha256 -- "
        "run scripts/sync-theme.sh to re-vendor"
    )


def test_literal_shadow_clobber_is_gone():
    """#2120: literal rgba() --shadow-raised/--shadow-dialog values clobber
    the var()-based per-theme elevation colors at equal specificity. The
    fix expresses them via light-dark()-driven --shadow-*-near/-far tokens
    instead, so light mode no longer renders hardcoded black shadows."""
    text = VENDORED.read_text(encoding="utf-8")
    assert not re.search(r"--shadow-raised:\s*0 1px 2px rgba\(", text), (
        "literal rgba() --shadow-raised is back -- this clobbers the "
        "var()-based per-theme elevation tokens (#2120)"
    )
    assert not re.search(r"--shadow-dialog:\s*0 2px 6px rgba\(", text), (
        "literal rgba() --shadow-dialog is back -- this clobbers the "
        "var()-based per-theme elevation tokens (#2120)"
    )
    assert "--shadow-raised: 0 1px 2px var(--shadow-raised-near)" in text, (
        "expected --shadow-raised to resolve through the var()-based "
        "--shadow-raised-near/-far tokens"
    )
    assert "--shadow-dialog: 0 2px 6px var(--shadow-dialog-near)" in text, (
        "expected --shadow-dialog to resolve through the var()-based "
        "--shadow-dialog-near/-far tokens"
    )


def test_accent_hover_is_not_the_pre_aa_fix_value():
    """Xore/theme #127/#128: the neon-theme --accent-hover measured
    4.08:1 ink-on-accent contrast, below AA, and was regenerated."""
    text = VENDORED.read_text(encoding="utf-8")
    assert STALE_ACCENT_HOVER not in text, (
        f"stale pre-AA-fix --accent-hover value {STALE_ACCENT_HOVER} is "
        "back -- Xore/theme #127/#128 regenerated it after it measured "
        "4.08:1 ink-on-accent, below AA"
    )


def test_check_vendored_theme_tooling_present_and_executable():
    assert CHECK_SCRIPT.exists(), f"{CHECK_SCRIPT} missing"
    assert SYNC_SCRIPT.exists(), f"{SYNC_SCRIPT} missing"
    for script in (CHECK_SCRIPT, SYNC_SCRIPT):
        mode = script.stat().st_mode
        assert mode & stat.S_IXUSR, f"{script} is not executable"


def test_ci_runs_the_vendored_theme_check_on_every_pull_request():
    """Guards against the CI wiring silently disappearing: quality.yml
    must (a) trigger on pull_request with no path filter that could let a
    PR skip the check, and (b) run check-vendored-theme.sh on both
    executor lanes (self-hosted and GitHub-hosted)."""
    text = QUALITY_WORKFLOW.read_text(encoding="utf-8")
    on_match = re.search(r"^on:\n(.*?)\n\S", text, re.DOTALL | re.MULTILINE)
    assert on_match, "could not find the on: trigger block in quality.yml"
    on_block = on_match.group(1)
    assert "pull_request:" in on_block, (
        "quality.yml must trigger on pull_request so the vendored-theme "
        "check runs on every PR"
    )
    # A paths: filter under pull_request could let a PR that only touches
    # theme.css skip CI entirely if scoped wrong -- exactly the kind of
    # invisible-drift gap #2137 is about.
    pr_section = on_block[on_block.index("pull_request:"):].split(
        "workflow_dispatch"
    )[0]
    assert "paths:" not in pr_section, (
        "quality.yml's pull_request trigger gained a paths: filter -- "
        "verify it can't skip a PR that only touches the vendored theme"
    )
    occurrences = text.count("run: scripts/check-vendored-theme.sh")
    assert occurrences >= 2, (
        "expected scripts/check-vendored-theme.sh to run on both the "
        "self-hosted and GitHub-hosted lanes (vendored-theme / "
        f"vendored-theme-cloud), found {occurrences} invocation(s)"
    )


def test_vendored_theme_byte_identical_to_pinned_upstream_commit():
    """Live check: fetch theme.css at the exact pinned commit from GitHub
    and compare byte-for-byte, exactly as check-vendored-theme.sh does in
    CI. Skips (does not fail) when the network is unreachable, matching
    that script's own offline degrade."""
    fields = _read_lock()
    repository = fields["repository"].rstrip("/")
    commit = fields["commit"]
    raw_url = (
        repository.replace(
            "https://github.com", "https://raw.githubusercontent.com"
        )
        + f"/{commit}/theme.css"
    )
    try:
        with urllib.request.urlopen(raw_url, timeout=30) as resp:
            upstream_bytes = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        pytest.skip(f"upstream unreachable: {exc}")
        return
    assert upstream_bytes == VENDORED.read_bytes(), (
        f"public/static/theme.css differs from Xore/theme@{commit[:7]} -- "
        "run scripts/sync-theme.sh to re-vendor"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
