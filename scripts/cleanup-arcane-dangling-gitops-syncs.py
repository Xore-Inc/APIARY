#!/usr/bin/env python3
"""Remove dangling Arcane gitops_syncs rows (#2577).

#2381 retired the `honeypot-wordpot` stack -- deleted `arcane/home/
honeypot-wordpot/` and dropped it from `arcane/manifests/home-production.json`
-- but the live Arcane store on the homeserver still carries the gitops sync
(and project) record #1502's migration created for it. That leaves the live
store at 38 `gitops_syncs` rows against the manifest's 37 entries; the extra
row's `composePath` points at a directory that no longer exists on `main`,
so a future sync attempt at it fails confusingly and it can block anyone
naming a new stack `honeypot-wordpot`.

This script diffs the live store's sync names against the manifest and
deletes whatever is dangling (destroying the sync's project too, per
docs/ARCANE-GIT-SYNC.md's "a destroyed project can leave a stale path/sync
binding" note -- deleting only the sync is not enough to free the path).
It is idempotent: a name already absent from the live store is left alone,
and running it with nothing dangling is a no-op.

    ARCANE_URL=http://10.8.0.2:3552 ARCANE_API_TOKEN=... \\
        scripts/cleanup-arcane-dangling-gitops-syncs.py [--apply]

Read-only by default; pass --apply to actually delete. This script only
talks to the live store when explicitly invoked against one -- it is never
run as part of CI or of the test in tests/scripts/test_cleanup_arcane_
dangling_gitops_syncs.py, which exercises the pure diff/plan logic offline
against a fixture instead of a real Arcane instance.
"""
import argparse
import json
import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "arcane" / "manifests" / "home-production.json"


def manifest_sync_names(manifest_path: pathlib.Path = MANIFEST_PATH) -> set:
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {e["syncName"] for e in entries}


def dangling_sync_names(live_syncs: list, manifest_names: set) -> set:
    """live_syncs: list of {"name": ..., "id": ..., "projectId": ...} as
    returned by GET /agents/0/gitops/syncs. Names present live but
    absent from the manifest are dangling and safe to remove.
    """
    return {s["name"] for s in live_syncs} - manifest_names


def plan_deletions(live_syncs: list, manifest_names: set) -> list:
    """Returns the live sync records (full dicts) that are dangling, i.e.
    the concrete deletion plan -- one entry per orphan row, each carrying
    the sync id and project id a real run would delete/destroy.
    """
    targets = dangling_sync_names(live_syncs, manifest_names)
    return [s for s in live_syncs if s["name"] in targets]


def _arcane_api(session, method: str, path: str, base_url: str):
    resp = session.request(method, f"{base_url.rstrip('/')}/api{path}")
    resp.raise_for_status()
    if resp.content:
        return resp.json()
    return {}


def _fetch_live_syncs(session, base_url: str) -> list:
    # #2549: this endpoint paginates at 20 by default.
    data = _arcane_api(session, "GET", "/agents/0/gitops/syncs?limit=100", base_url)
    return data.get("data", data if isinstance(data, list) else [])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="actually delete (default: dry-run)")
    args = parser.parse_args()

    base_url = os.environ.get("ARCANE_URL")
    token = os.environ.get("ARCANE_API_TOKEN")
    if not base_url or not token:
        print("ARCANE_URL and ARCANE_API_TOKEN must be set", file=sys.stderr)
        return 2

    import requests  # local import: only needed for the live-store path

    session = requests.Session()
    # Arcane v3 takes an API key only as X-API-Key (Bearer is for session JWTs).
    session.headers["X-API-Key"] = token
    session.headers["Content-Type"] = "application/json"

    manifest_names = manifest_sync_names()
    live_syncs = _fetch_live_syncs(session, base_url)
    plan = plan_deletions(live_syncs, manifest_names)

    if not plan:
        print(f"no dangling syncs ({len(live_syncs)} live rows == {len(manifest_names)} manifest entries)")
        return 0

    for sync in plan:
        label = f"{sync['name']} (sync {sync['id']}, project {sync.get('projectId', 'unknown')})"
        if not args.apply:
            print(f"WOULD DELETE: {label}")
            continue
        print(f"DELETE: {label}")
        _arcane_api(session, "DELETE", f"/agents/0/gitops/syncs/{sync['id']}", base_url)
        project_id = sync.get("projectId")
        if project_id:
            _arcane_api(session, "DELETE", f"/agents/0/projects/{project_id}", base_url)

    if not args.apply:
        print(f"\ndry-run: {len(plan)} dangling sync(s) would be removed (rerun with --apply)")
    else:
        print(f"\nremoved {len(plan)} dangling sync(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
