#!/usr/bin/env python3
"""Keep exactly one issue open while main's own gates are red (#3324).

On 2026-09-25 five dependabot merges left main's Rust backend red for about
seven hours (#3311) and nothing said so: Quality/Containers ran on the push,
failed, and a red push run is read by nobody. The other *-watch workflows
already follow the one-labeled-issue lifecycle for disk, backups and compose
drift; this is the same thing for main itself:

- A single open `main-red-alarm` issue at a time. The newest completed push
  run of each watched workflow on main decides the state; cancelled runs are
  skipped (a newer push superseded them, they say nothing about the code).
- Red: open the issue, or comment on it -- but only when the failing head
  commit changed since the last comment, so a sweep does not repeat itself.
  The report names the failing jobs, the first red and last green commit per
  workflow, and the commits in between (the suspects).
- Untested heads get tested: when main's head is older than an hour and a
  watched workflow never ran on it (merges made by github-actions start no
  push runs -- 2026-09-25's actual case), the watch dispatches that workflow
  on main; the next sweep judges the result like any other run.
- Green again: close the issue with the green run as evidence.
- Never reverts, never re-runs anything.

Usage: main-health-watch.py [--dry-run] [--before ISO8601]   (needs gh, GITHUB_REPOSITORY)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

LABEL = "main-red-alarm"
WORKFLOWS = ("quality.yml", "containers.yml")
MARKER = "<!-- main-red-head: {sha} -->"
MARKER_RE = re.compile(r"<!-- main-red-head: ([0-9a-f]{40}) -->")
HISTORY = 30  # push runs to look back through for the last green one
UNTESTED_AFTER = timedelta(hours=1)  # CI for a fresh head may simply still be queued


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        print(f"FAIL: gh {' '.join(args[:2])}: {out.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return out.stdout


def gh_json(*args: str):
    return json.loads(gh(*args) or "null")


def push_runs(repo: str, workflow: str, before: str | None = None) -> list[dict]:
    runs = gh_json(
        "run", "list", "-R", repo, "--workflow", workflow, "--branch", "main",
        "--status", "completed", "--limit", str(HISTORY * (4 if before else 2)),
        "--json", "databaseId,headSha,conclusion,url,createdAt,event",
    )
    # push runs, plus the workflow_dispatch runs this watch starts for heads
    # no push run ever tested (see untested_head).
    runs = [
        r for r in runs
        if r["event"] in ("push", "workflow_dispatch") and r["conclusion"] not in ("cancelled", "skipped")
    ]
    if before:  # replay: judge main as it stood at that moment
        runs = [r for r in runs if r["createdAt"] < before]
    return runs[:HISTORY]


def failed_jobs(repo: str, run_id: int) -> list[str]:
    jobs = gh_json("run", "view", str(run_id), "-R", repo, "--json", "jobs")["jobs"]
    return [j["name"] for j in jobs if j["conclusion"] in ("failure", "timed_out")]


def assess(repo: str, before: str | None = None) -> dict:
    """Per workflow: latest conclusion, and for a red one, the red streak."""
    state = {}
    for wf in WORKFLOWS:
        runs = push_runs(repo, wf, before)
        if not runs:
            continue
        latest = runs[0]
        entry = {"latest": latest, "red": latest["conclusion"] != "success"}
        if entry["red"]:
            green = next((r for r in runs if r["conclusion"] == "success"), None)
            streak = runs[: runs.index(green)] if green else runs
            entry.update(first_red=streak[-1], last_green=green, jobs=failed_jobs(repo, latest["databaseId"]))
        state[wf] = entry
    return state


def untested_head(repo: str, before: str | None = None) -> dict | None:
    """main's head commit if it is older than UNTESTED_AFTER and a watched
    workflow has no run for it at all -- not red, not queued: never started.

    That is what 2026-09-25 actually looked like (#3311): merges made by
    github-actions with GITHUB_TOKEN start no workflow runs, so five broken
    dependabot merges produced no red run to notice, only silence.
    """
    query = f"repos/{repo}/commits?sha=main&per_page=1" + (f"&until={before}" if before else "")
    [head] = gh_json("api", query)
    committed = datetime.fromisoformat(head["commit"]["committer"]["date"].replace("Z", "+00:00"))
    now = datetime.fromisoformat(before.replace("Z", "+00:00")) if before else datetime.now(timezone.utc)
    if now - committed < UNTESTED_AFTER:
        return None
    missing = [
        wf for wf in WORKFLOWS
        if not gh_json("run", "list", "-R", repo, "--workflow", wf, "--commit", head["sha"], "--json", "databaseId")
    ]
    if not missing:
        return None
    return {"headSha": head["sha"], "committed": head["commit"]["committer"]["date"],
            "subject": head["commit"]["message"].splitlines()[0][:100], "missing": missing}


def suspects(repo: str, last_green: dict | None, first_red: dict) -> list[str]:
    if not last_green:
        return []
    cmp = gh_json("api", f"repos/{repo}/compare/{last_green['headSha']}...{first_red['headSha']}")
    return [f"{c['sha'][:10]} {c['commit']['message'].splitlines()[0][:100]}" for c in cmp["commits"]][-15:]


def report(repo: str, state: dict) -> str:
    lines = ["`main`'s own gates are red. Found by `scripts/main-health-watch.py` (#3324); this issue closes itself when they are green again.", ""]
    for wf, e in state.items():
        if not e["red"]:
            lines.append(f"- **{wf}**: green ({e['latest']['url']})")
            continue
        lg = e["last_green"]
        lines += [
            f"- **{wf}**: {e['latest']['conclusion']} on `{e['latest']['headSha'][:10]}` ({e['latest']['url']})",
            f"  - failing jobs: {', '.join(e['jobs']) or '(none reported)'}",
            f"  - first red: `{e['first_red']['headSha'][:10]}` ({e['first_red']['createdAt']})",
            f"  - last green: `{lg['headSha'][:10]}` ({lg['createdAt']})" if lg else f"  - no green run in the last {HISTORY}",
        ]
        if sus := suspects(repo, lg, e["first_red"]):
            lines += ["  - commits since last green (suspects):", *[f"    - {s}" for s in sus]]
    head = max((e["latest"] for e in state.values() if e["red"]), key=lambda r: r["createdAt"])
    lines += ["", MARKER.format(sha=head["headSha"])]
    return "\n".join(lines)


def open_issue(repo: str) -> dict | None:
    found = gh_json("issue", "list", "-R", repo, "--label", LABEL, "--state", "open", "--json", "number,comments,body")
    return found[0] if found else None


def last_marker(issue: dict) -> str | None:
    texts = [issue["body"], *(c["body"] for c in issue["comments"])]
    for text in reversed(texts):
        if m := MARKER_RE.search(text or ""):
            return m.group(1)
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--before", metavar="ISO8601", help="replay: judge main as of this time (implies --dry-run)")
    args = parser.parse_args(argv)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not repo:
        print("FAIL: GITHUB_REPOSITORY must be set", file=sys.stderr)
        return 1

    if args.before:
        args.dry_run = True
    state = assess(repo, args.before)
    untested = untested_head(repo, args.before)
    if untested:
        # workflow_dispatch is the one event GITHUB_TOKEN may start runs with,
        # so test the head instead of alarming; the next sweep judges the runs.
        print(f"untested head {untested['headSha'][:10]} ({untested['subject']}): no run of {', '.join(untested['missing'])}")
        for wf in untested["missing"]:
            if args.dry_run:
                print(f"  dry run: would dispatch {wf} on main")
            else:
                gh("workflow", "run", wf, "-R", repo, "--ref", "main")
                print(f"  dispatched {wf} on main")
    red = any(e["red"] for e in state.values())
    issue = None if args.dry_run else open_issue(repo)

    if not red:
        print("main is green: " + ", ".join(f"{wf} {e['latest']['headSha'][:10]}" for wf, e in state.items()))
        if issue:
            evidence = "\n".join(f"- {wf}: green on `{e['latest']['headSha'][:10]}` ({e['latest']['url']})" for wf, e in state.items())
            gh("issue", "close", str(issue["number"]), "-R", repo, "--comment", f"`main` is green again.\n\n{evidence}")
            print(f"closed #{issue['number']}")
        return 0

    body = report(repo, state)
    if args.dry_run:
        print(body)
        return 0
    marker = MARKER_RE.search(body)
    if marker is None:
        print("main-health-watch: no existing marker in the report body", file=sys.stderr)
        return 1
    head = marker.group(1)
    subprocess.run(
        ["gh", "label", "create", LABEL, "-R", repo, "-d", "main's own Quality/Containers gates are red (scripts/main-health-watch.py)", "--color", "B60205"],
        capture_output=True, text=True,
    )
    if issue:
        if last_marker(issue) == head:
            print(f"#{issue['number']} already reports head {head[:10]}; nothing new")
            return 0
        gh("issue", "comment", str(issue["number"]), "-R", repo, "--body", body)
        print(f"updated #{issue['number']}")
    else:
        gh("issue", "create", "-R", repo, "--label", LABEL, "--label", "ops", "--label", "bug",
           "--title", "ci: main is red -- Quality/Containers failing on main (#3324 watch)", "--body", body)
        print("opened main-red-alarm issue")
    return 0


if __name__ == "__main__":
    sys.exit(main())
