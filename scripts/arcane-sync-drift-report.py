#!/usr/bin/env python3
"""Report how far each Arcane gitops-sync record has drifted from `main`
(#2858). `autoSync` is `false` on every one of the 37 registered syncs — a
deliberate decision (see docs/ARCANE-GIT-SYNC.md, "autoSync decision
(#2858)"), not an oversight -- but a manual-only model has no visibility of
its own: nothing previously reported how far behind a project had fallen
until someone noticed a missing feature weeks later (#2815/#2816/#2817, three
separate "a merged PR never reached the host" issues that turned out to share
this one cause).

This is read-only and on-demand -- it does not sync or redeploy anything, and
it is not wired into a scheduled workflow (that would need an Arcane
credential available to CI, which is a separate, not-yet-made decision; see
the doc section above). Run it by hand, or from a personal cron/timer that
already has the credential, whenever a drift check is wanted.

Usage:
  ARCANE_API_KEY=... scripts/arcane-sync-drift-report.py [--behind-days N] [--repo-root PATH]

Exits non-zero if any project is more than --behind-days (default 3) days
past its last successful sync, if a sync's own lastSyncStatus is "failed"
and the project is not in KNOWN_STRUCTURAL_FAILURES below, or if a record's
lastSyncAt is absent, null or unparseable. That last case is a failure and not
a printed `?`: a record with no readable lastSyncAt is precisely the shape a
never-synced project has (#2853), which is the condition this report exists to
surface -- passing it silently would let the worst case be the quietest one.

The `failed` exemption is what makes the exit code carry information:
`honeypot-init` reports `failed` on every deploy for a structural reason Arcane
never rewrites (#2854), so without it this script would exit non-zero on a
healthy fleet, every run, forever -- the same
permanently-red-and-therefore-ignored shape scripts/isolation-audit.sh's
tiering comment was written against.

What a clean run does and does not mean
---------------------------------------
`lastSyncStatus` is unreliable in *both* directions, so exit 0 means "no record
reports a failure, a stale timestamp or an unreadable one" -- it does **not**
mean the fleet is deployed:

  #2854  `failed` when the deploy in fact succeeded (a `restart: no` one-shot's
         clean exit(0) read as an abort). Handled here by the exemption above.
  #2910  `success` when nothing was recreated -- Arcane's 5-minute sync deadline
         elapses, the retry reports success, and the container is untouched.
         Nothing in this API response distinguishes that from a real deploy;
         only comparing container creation time against lastSyncAt can, which
         needs host access this script deliberately does not take.
  #2853  a project that has never synced at all, whose lastSyncAt is null.
         Failed rather than printed as `?`, per the paragraph above.

Judge a project by its containers before concluding it is deployed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ARCANE_URL = os.environ.get("ARCANE_URL", "http://10.8.0.2:3552")

# Projects whose `lastSyncStatus: failed` is structural and permanent, each with
# the reason recorded next to the name. Same shape as scripts/isolation-audit.sh's
# CAP_EXCEPTIONS, and for the same stated reason: a check that is red on every run
# regardless of fleet state carries no information and gets ignored, so the
# known-permanent cases are named, exempted, and still printed -- not silenced.
# Anything reporting `failed` that is NOT named here still fails the run.
KNOWN_STRUCTURAL_FAILURES = {
    "honeypot-init": (
        "#2854: Arcane reads a `restart: no` one-shot's clean exit(0) as a deploy "
        "failure and never rewrites the record, so this project reports `failed` on "
        "deploys that in fact completed. Deploy it with "
        "scripts/arcane-deploy-honeypot-init.sh --apply and judge it by its "
        "containers, not by this field."
    ),
}


def fail(msg: str) -> "None":
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(2)


def fetch_syncs(api_key: str) -> list[dict]:
    req = urllib.request.Request(
        f"{ARCANE_URL.rstrip('/')}/api/agents/0/gitops/syncs?limit=100",
        headers={"X-API-Key": api_key},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
    except Exception as exc:  # noqa: BLE001 -- reported as a hard failure either way
        fail(f"could not reach Arcane at {ARCANE_URL}: {exc}")
    recs = data.get("data", data) if isinstance(data, dict) else data
    if not isinstance(recs, list) or not recs:
        fail("Arcane returned zero gitops-sync records -- refusing to read this as a healthy fleet")
    return recs


def commits_behind(commit: str, repo_root: Path, fetched: bool) -> int | None:
    """None if the commit can't be resolved against this checkout's `main`
    (a shallow clone, or the sync record naming a commit this checkout
    hasn't fetched) -- reported as unknown, never silently as 0.

    Also None when the `git fetch` failed: a stale local `origin/main` still
    resolves, so `rev-list` would succeed and return a number that is too
    small. Unknown is the honest answer there; a confident wrong one is worse
    than none."""
    if not fetched:
        return None
    out = subprocess.run(
        ["git", "-C", str(repo_root), "rev-list", "--count", f"{commit}..origin/main"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    try:
        return int(out.stdout.strip())
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--behind-days", type=float, default=3.0)
    ap.add_argument("--repo-root", default=".")
    args = ap.parse_args()

    api_key = os.environ.get("ARCANE_API_KEY", "")
    if not api_key:
        fail("ARCANE_API_KEY is required")

    repo_root = Path(args.repo_root)
    fetch = subprocess.run(
        ["git", "-C", str(repo_root), "fetch", "origin", "main", "-q"],
        capture_output=True, text=True,
    )
    fetched = fetch.returncode == 0
    if not fetched:
        print(
            f"WARNING: git fetch origin main failed in {repo_root} "
            f"({fetch.stderr.strip() or 'no stderr'}); the 'behind' column is reported "
            "as unknown rather than measured against a stale origin/main.",
            file=sys.stderr,
        )

    recs = fetch_syncs(api_key)
    now = datetime.now(timezone.utc)

    rows = []
    # `.get(k, "")` is not enough: Arcane returns the key present-and-null for a
    # project that has never synced (#2853), and None does not sort against str.
    for r in sorted(recs, key=lambda r: r.get("lastSyncAt") or ""):
        name = r.get("name", "?")
        status = r.get("lastSyncStatus", "unknown")
        auto = r.get("autoSync", False)
        commit = r.get("lastSyncCommit", "") or ""
        last_sync_at = r.get("lastSyncAt") or ""
        try:
            age_days = (now - datetime.fromisoformat(last_sync_at.replace("Z", "+00:00"))).total_seconds() / 86400
        except (ValueError, TypeError):
            age_days = None
        behind = commits_behind(commit, repo_root, fetched) if commit else None
        rows.append({
            "name": name, "status": status, "autoSync": auto,
            "commit": commit[:10], "age_days": age_days, "behind": behind,
        })

    print(f"{'project':<36} {'autoSync':<9} {'status':<8} {'commit':<11} {'age(d)':>7} {'behind':>7}")
    stale = []
    failed = []
    exempt = []
    unreadable = []
    for row in rows:
        age_str = f"{row['age_days']:.1f}" if row["age_days"] is not None else "?"
        behind_str = str(row["behind"]) if row["behind"] is not None else "?"
        print(f"{row['name']:<36} {str(row['autoSync']):<9} {row['status']:<8} {row['commit']:<11} {age_str:>7} {behind_str:>7}")
        if row["status"] == "failed":
            if row["name"] in KNOWN_STRUCTURAL_FAILURES:
                exempt.append(row["name"])
            else:
                failed.append(row["name"])
        if row["age_days"] is None:
            unreadable.append(row["name"])
        elif row["age_days"] > args.behind_days:
            stale.append(row["name"])

    print()
    print(
        f"{len(rows)} sync record(s); {len(stale)} older than {args.behind_days}d; "
        f"{len(failed)} with lastSyncStatus=failed; {len(exempt)} structurally-failed and exempt; "
        f"{len(unreadable)} with no readable lastSyncAt"
    )
    if exempt:
        print()
        print("EXEMPT (lastSyncStatus=failed for a known structural reason -- does not fail this run):")
        for name in exempt:
            print(f"  {name}: {KNOWN_STRUCTURAL_FAILURES[name]}")
    if failed:
        print(f"FAILED: {', '.join(failed)}", file=sys.stderr)
    if stale:
        print(f"STALE (>{args.behind_days}d since last sync): {', '.join(stale)}", file=sys.stderr)
    if unreadable:
        print(
            "NO READABLE lastSyncAt (never synced, or a timestamp this script cannot "
            f"parse -- #2853): {', '.join(unreadable)}",
            file=sys.stderr,
        )

    return 1 if (stale or failed or unreadable) else 0


if __name__ == "__main__":
    sys.exit(main())
