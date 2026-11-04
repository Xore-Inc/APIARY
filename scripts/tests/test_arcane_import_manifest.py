#!/usr/bin/env python3
"""install-homeserver.sh's Arcane import associates every manifest entry with
the repository its gitRepo names.

The standalone dashboard's entry (gitRepo apiary-dashboard) must be created
against Xore/apiary-dashboard on its own branch, never against Xore/APIARY:
the wrong association would materialize the monorepo into the stack
directory. Runs step_arcane_import_stacks from the real installer against the
real manifest, with Arcane's API stubbed and stack directories in a temp dir.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install-homeserver.sh"
MANIFEST = ROOT / "arcane" / "manifests" / "home-production.json"
APIARY_URL = "https://github.com/Xore/APIARY.git"
DASHBOARD_URL = "https://github.com/Xore/apiary-dashboard.git"


def function_source(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}\n", text, re.M | re.S)
    if match is None:
        raise AssertionError(f"{name}() not found in {INSTALLER}")
    return match.group(0)


# Stub of arcane_api: repositories live in $STATE/repos.json, every request is
# appended to $STATE/calls.jsonl, a sync reports success.
STUB = r"""
arcane_api() {
  local method="$1" path="$2" body="${3:-}"
  jq -nc --arg m "$method" --arg p "$path" --arg b "$body" \
    '{method:$m, path:$p, body:($b | if . == "" then null else fromjson end)}' >> "$STATE/calls.jsonl"
  case "$method $path" in
    "GET /customize/git-repositories")
      jq -c '{success:true, data:.}' "$STATE/repos.json" ;;
    "POST /customize/git-repositories")
      local id="repo-$(jq length "$STATE/repos.json")"
      jq -c --arg id "$id" --argjson r "$body" '. + [$r + {id:$id}]' "$STATE/repos.json" > "$STATE/repos.tmp"
      mv "$STATE/repos.tmp" "$STATE/repos.json"
      jq -nc --arg id "$id" '{success:true, data:{id:$id}}' ;;
    "POST /environments/0/gitops-syncs")
      echo '{"success":true,"data":{"lastSyncStatus":"success"}}' ;;
    *) echo "unexpected call: $method $path" >&2; return 1 ;;
  esac
}
"""


def run_import(existing_repos: list[dict]) -> tuple[subprocess.CompletedProcess, list[dict], list[dict]]:
    text = INSTALLER.read_text()
    functions = function_source(text, "arcane_repo_id") + function_source(text, "step_arcane_import_stacks")
    with tempfile.TemporaryDirectory() as temp:
        state = Path(temp)
        (state / "stacks").mkdir()
        (state / "repos.json").write_text(json.dumps(existing_repos))
        (state / "calls.jsonl").write_text("")
        script = "\n".join(
            [
                "set -euo pipefail",
                f'STATE="{state}"',
                f'ARCANE_STACKS_ROOT="{state}/stacks"',
                f'ARCANE_STACK_MANIFEST="{MANIFEST}"',
                f'GIT_REPO_URL="{APIARY_URL}"',
                'GIT_REF="production"',
                STUB,
                functions,
                "step_arcane_import_stacks",
            ]
        )
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        calls = [json.loads(line) for line in (state / "calls.jsonl").read_text().splitlines()]
        repos = json.loads((state / "repos.json").read_text())
    return proc, calls, repos


def syncs(calls: list[dict]) -> dict[str, dict]:
    return {c["body"]["name"]: c["body"] for c in calls if c["path"] == "/environments/0/gitops-syncs"}


class ArcaneImportManifestTest(unittest.TestCase):
    def test_manifest_lists_the_standalone_dashboard(self) -> None:
        entry = next(e for e in json.loads(MANIFEST.read_text()) if e["syncName"] == "apiary-dashboard")
        self.assertEqual(entry["gitRepo"], "apiary-dashboard")
        self.assertEqual(entry["branch"], "main")
        self.assertEqual(entry["dockerComposePath"], "arcane/home/apiary-dashboard/compose.yml")
        self.assertFalse(entry["autoSync"])

    def test_fresh_host_associates_dashboard_with_its_own_repository(self) -> None:
        proc, calls, repos = run_import([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        by_name = {r["name"]: r for r in repos}
        self.assertEqual(by_name["apiary"]["url"], APIARY_URL)
        self.assertEqual(by_name["apiary-dashboard"]["url"], DASHBOARD_URL)
        self.assertEqual(by_name["apiary-dashboard"]["authType"], "none")

        created = syncs(calls)
        dashboard = created["apiary-dashboard"]
        self.assertEqual(dashboard["repositoryId"], by_name["apiary-dashboard"]["id"])
        self.assertNotEqual(dashboard["repositoryId"], by_name["apiary"]["id"])
        self.assertEqual(dashboard["branch"], "main")
        self.assertEqual(dashboard["composePath"], "arcane/home/apiary-dashboard/compose.yml")

        # APIARY's own stacks are unchanged: its repository, the installer's ref.
        elk = created["honeypot-elk"]
        self.assertEqual(elk["repositoryId"], by_name["apiary"]["id"])
        self.assertEqual(elk["branch"], "production")

    def test_existing_registrations_are_reused_not_duplicated(self) -> None:
        existing = [
            {"id": "a", "name": "apiary", "url": APIARY_URL},
            {"id": "d", "name": "apiary-dashboard", "url": DASHBOARD_URL},
        ]
        proc, calls, repos = run_import(existing)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(repos), 2)
        self.assertFalse([c for c in calls if c["method"] == "POST" and c["path"] == "/customize/git-repositories"])
        self.assertEqual(syncs(calls)["apiary-dashboard"]["repositoryId"], "d")

    def test_registration_with_the_wrong_url_fails_closed(self) -> None:
        proc, calls, _ = run_import([{"id": "d", "name": "apiary-dashboard", "url": APIARY_URL}])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("expected " + DASHBOARD_URL, proc.stderr)
        self.assertEqual(syncs(calls), {})


if __name__ == "__main__":
    unittest.main()
