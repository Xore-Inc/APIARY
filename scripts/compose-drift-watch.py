#!/usr/bin/env python3
"""Alarm when a compose-defined, always-on service has no container at all
while its project siblings are actually running (#2747).

2026-08-31: a `systemctl restart docker` (#2743) surfaced four services
across three Dockge/Arcane stacks (`honeypot-elk`'s elasticsearch and
kibana, `honeypot-keycloak`'s postgres, `ghosts`'s ghosts-postgres) that had
**no container at all** -- not even a stopped one -- while their dependent
app containers kept running against a backing store that did not exist.
None of the four had a `docker events` destroy/die entry in the recent
history checked, so `restart: unless-stopped` never got a chance to save
them: a container that was never created has nothing to restart. Elasticsearch
sat in this state long enough that its absence was the standing condition,
not a blip -- with no alarm anywhere. This is a dedicated fleet-wide sweep
for exactly that shape, in the spirit of `disk-usage-watch.py` (#2743) and
the runner-capacity report (#2744), following `ci-queue-watch.py`'s (#2499)
proven de-dup design rather than inventing a new one.

What counts as drift:

- A service is "expected to persist" if its resolved `restart` policy is
  anything other than `no`/unset. This is a structural signal, not a
  hardcoded exclusion list: `honeypot-init`'s six one-shot setup jobs
  (arkime-init, elasticsearch-setup, honeypot-kibana-setup, log-init,
  persona-apply, snare-clone) all declare `restart: no` and are legitimately
  expected to reach zero containers once they've run -- they resolve out of
  the "expected to persist" set on their own, with no special-casing of the
  project name. A profile-gated service not in the compose file's active
  profile set does not appear in `docker compose config` output at all, so
  it is never considered either.
- "No container at all" means zero containers in any state (`docker compose
  ps -a`), not "not currently running" -- a stopped-but-existing container
  is a different, already-visible problem (`docker ps -a` shows it).
- The alarm only fires when at least one *other* service in the same
  project has a container in the `running` state. This is the "while
  dependants run" half of the issue title: it is what makes a missing
  sidecar dangerous (something is actively serving traffic against a
  backing store that silently isn't there) rather than "the whole stack was
  never started," which is a different, self-evident condition.

Design mirrors ci-queue-watch.py's proven shape:
- A single open `compose-drift-alarm`-labeled issue at a time: a sweep that
  finds continued drift appends to it; a sweep that finds it resolved closes
  it with the recovery evidence.
- Refuses to read a broken scan as a healthy fleet: zero project directories
  found, or `docker compose config`/`ps` failing on *every* project, is
  fatal rather than silently reported as "nothing wrong." A single project's
  `config`/`ps` failure (e.g. a missing required env var) is reported
  separately as "could not resolve" and does not block the rest of the
  sweep or get silently swallowed.
- Runs directly on the host being swept (no separate SSH credential or
  network path to the thing being measured), same reasoning
  disk-usage-watch.py and ci-queue-watch.py both give for their own designs.

Usage (the .github/workflows/compose-drift-watch.yml cron runs the first
form, on the homeserver-backed self-hosted runner):
  scripts/compose-drift-watch.py [--dry-run] [--stacks-root /var/dockge/stacks]
  --dry-run prints the would-be action and exits (no issue writes).

#2855: this sweep originally only checked a live stack directory against
*itself* (does a service that should persist have a container). It never
asked the reverse question -- does this live directory's project still
exist anywhere in the repo at all? A stack fully retired from the repo
(its whole `arcane/home/<name>/` directory deleted, as #2469 did for
wordpot) is invisible to the original check: its live directory under
`/var/dockge/stacks/` still has a stale `compose.yml` copy from before
retirement, so it resolves and gets checked for *internal* drift like any
other project, but nothing ever flagged "this project doesn't exist in the
repo any more and is still running" -- confirmed live: `hp-wordpot` ran
healthy for weeks after #2469 with zero alarms from this sweep (#2814).
Fixed by cross-checking each live stack directory's name against
`arcane/manifests/home-production.json`'s `syncName` list -- the same
canonical source of truth `scripts/install-homeserver.sh` and this repo's
own docs already treat as authoritative for "which 37 stacks exist"
(`docs/ARCANE-GIT-SYNC.md`), rather than re-deriving a second list by
grepping `arcane/home/*` (which would also miss the manifest's six
self-contained, non-`arcane/home/`-nested entries: `auth-events-worker`,
`llm-worker`, `ml-worker`, `ghidra`, `ghosts`, `pihole`).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

LABEL = "compose-drift-alarm"
REPO = os.environ.get("GITHUB_REPOSITORY", "")
PERSISTENT_RESTART_POLICIES = {"unless-stopped", "always", "on-failure"}
# Relative to this script's own location, not the checkout root -- the
# same "fixed deployed path" caution #2764 gives for PRIVILEGED_HELPER
# below doesn't apply here (this file has no separate root-owned install
# location), but resolving relative to the script keeps this correct
# whether it's invoked from the repo root (the CI workflow's case) or from
# some other cwd.
MANIFEST_PATH = Path(__file__).resolve().parent.parent / "arcane" / "manifests" / "home-production.json"
# Live directories under the stacks root that are never in the manifest by
# design, not by omission -- confirmed against docs/ARCANE-GIT-SYNC.md and
# live inspection, not guessed:
#   - honeypot-arcane: "not in the manifest and never will be -- syncing
#     the thing that has to already be running before any sync can happen
#     is a bootstrap loop." Installer/deploy.yml-managed instead.
#   - apiary: Arcane's own internal git-repository clone (registered via
#     POST /customize/git-repositories), the source directory-sync reads
#     individual stacks' files from -- not a deployed project itself. It
#     happens to carry a top-level compose.yml (this repo's own), which is
#     what made it look like a stack directory to a naive glob.
KNOWN_NON_PROJECT_DIRS = {"honeypot-arcane", "apiary"}
# #3129: llm-worker is still a manifest entry with a persistent restart
# policy (not retired), but its single container has been deliberately kept
# down since #3023 -- it was issuing a competing /api/chat against the same
# Ollama instance the #1947 benchmark sweep needs cold, so the sweep owner
# gated it off until the benchmark run releases it. That is an operator
# decision, not the "torn down" shape retired_projects() (and #3040's Gate 1
# below) exist to tell apart from real drift. #3040's own scope asked for
# exactly this mechanism -- "Retired/intentionally-absent services need an
# explicit allowlist with a reason, the same shape isolation-audit.sh
# already uses for its known-gap WARN tier" -- so this is the allowlist that
# issue specified, keyed by project name so it only ever silences this
# specific, documented absence. Do not add a second entry here
# without an equally-documented operator decision: that is exactly the
# blanket "no sibling, don't alarm" rule #3040 removed.
EXPECTED_ABSENT_WHILE = {
    "llm-worker": "#3023 sweep-owner-gated for the #1947 benchmark run; stays down until the operator releases it",
}

# #3361: stacks that are version-controlled under arcane/home/<name>/ but
# deliberately NOT in the always-on production manifest -- they are brought up
# on demand for a benchmark/eval run and torn down after, so "deployed, not in
# the manifest" is their normal running state, not the retired-but-not-torn-down
# drift retired_projects() looks for. Keyed by name with the reason, same shape
# and same rule as EXPECTED_ABSENT_WHILE above: one documented entry per
# operator decision, never a blanket "no manifest entry, don't alarm".
KNOWN_ONDEMAND_STACKS = {
    "rex86-eval": "#847/#3345 on-demand REx86 evaluation stack; version-controlled at arcane/home/rex86-eval/ but run only during an eval and intentionally kept out of home-production.json",
}


def fail(msg: str) -> "None":
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


def is_regular_file(path: Path) -> bool:
    """`Path.is_file()` does NOT do this: it delegates to `os.path.isfile`,
    which swallows OSError and returns False. A 0700 root-owned stack dir is
    therefore indistinguishable from "no compose file here", so every
    caller's `except PermissionError` is dead code and the stacks this
    script exists to watch get silently dropped. stat() directly, so EACCES
    reaches the caller as PermissionError and the two-tier privileged
    fallback below can actually engage.

    The other side of that contract is absence: a missing path
    (FileNotFoundError) or a path whose parent is not a directory
    (NotADirectoryError) returns False. A stack dir with no compose file
    (#3651: the live honeypot-stack dir is empty) is "not a project", not
    a crash that aborts the whole sweep."""
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def project_dirs(stacks_root: Path) -> list[Path]:
    if not stacks_root.is_dir():
        fail(f"{stacks_root} is not a directory -- refusing to read an absent fleet as healthy")
    dirs = []
    for d in sorted(stacks_root.iterdir()):
        if not d.is_dir():
            continue
        try:
            has_compose = is_regular_file(d / "compose.yml")
        except PermissionError:
            # REVIEW-A/#3040: llm-worker, auth-events-worker and ml-worker
            # are 0700 root-owned -- stat() on a path inside them raises
            # rather than returning False. None of the three
            # actually uses "compose.yml" as its basename, so this is never
            # a false exclusion of a real match; manifest_extra_targets()
            # is what enumerates these, using the manifest's own basename.
            continue
        if has_compose:
            dirs.append(d)
    if not dirs:
        fail(f"no compose.yml found under {stacks_root} -- refusing to read this as a healthy fleet")
    return dirs


def manifest_entries() -> list[dict] | None:
    """The manifest's raw entry list. None (not an empty list) if the
    manifest can't be read -- callers must treat that as "can't check
    this", never as "the manifest lists nothing"."""
    try:
        entries = json.loads(MANIFEST_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(entries, list) or not entries:
        return None
    return [e for e in entries if isinstance(e, dict) and e.get("syncName")]


def manifest_project_names(entries: list[dict]) -> set[str]:
    """The canonical set of live stack names, from the manifest's own
    `syncName` field."""
    return {e["syncName"] for e in entries}


def retired_projects(stacks_root: Path, known_names: set[str]) -> list[str]:
    """Live stack directories (compose.yml present) whose name is not in
    the manifest at all -- a project retired from the repo (its whole
    arcane/home/<name>/ directory deleted) but never torn down on this
    host. Distinct from project_dirs()'s callers, which only care about
    resolvable projects; this one only cares about the name.

    Deliberately one-directional: it flags "live directory, no manifest
    entry" and NOT the reverse, "manifest entry, no live directory". The
    reverse looks non-empty but is benign -- as of 2026-09-03 four entries
    are in that state (auth-events-worker, ghidra, llm-worker, ml-worker)
    purely because their stack directories use `docker-compose.yml` rather
    than `compose.yml`, exactly as their manifest `dockerComposePath` says.
    Alarming on those would be four permanent false positives, which is the
    failure mode this whole check exists to avoid."""
    names = []
    for d in stacks_root.iterdir():
        if not d.is_dir():
            continue
        # Name check first, before ever touching the filesystem again:
        # llm-worker/auth-events-worker/ml-worker are all 0700 root-owned
        # AND all three are known manifest entries, so this short-circuits
        # before the is_file() below would otherwise crash (REVIEW-A).
        if d.name in known_names or d.name in KNOWN_NON_PROJECT_DIRS or d.name in KNOWN_ONDEMAND_STACKS:
            continue
        try:
            if not is_regular_file(d / "compose.yml"):
                continue
        except PermissionError:
            # An unreadable dir that ISN'T a known manifest name: can't
            # tell whether it's retired or just locked down. Retirement is
            # a checkable fact (name absent from the manifest); an EACCES
            # is "couldn't check", never "retired".
            continue
        names.append(d.name)
    return sorted(names)


# #3048: honeypot-arcane is excluded from the manifest-driven checks above
# by design (KNOWN_NON_PROJECT_DIRS's own comment), which means nothing
# checks its *content* against the repo at all. 2026-09-05: the running
# hp-arcane container was still on v2.9.0 while docker-compose.arcane.yml on
# main had already moved to v2.10.1 -- a silent version drift across a
# rebuild, caught only by a human diffing both files by hand. This is a
# narrow, single-field check for exactly that image line, not a generic
# raw-file diff: env-var interpolation and the optional GPU overlay
# (docker-compose.arcane.gpu.yml, merged in only on hosts with a working
# NVIDIA runtime) make a byte-for-byte diff noisy, but the image tag is the
# one field install-homeserver.sh's step_arcane_install and deploy.yml's
# "Synchronize honeypot-arcane" step both copy from once and never re-diff.
ARCANE_REPO_COMPOSE = Path(__file__).resolve().parent.parent / "docker-compose.arcane.yml"
ARCANE_IMAGE_RE = re.compile(r"(?m)^\s*image:\s*(ghcr\.io/getarcaneapp/\S+)$")


def arcane_image(text: str) -> str | None:
    match = ARCANE_IMAGE_RE.search(text)
    return match.group(1) if match else None


def arcane_image_drift(stacks_root: Path) -> str | None:
    """A finding string if the live honeypot-arcane compose.yml's image
    differs from the repo's, None if it matches or either side can't be
    read (unreadable is "not checked", never reported as clean)."""
    live_path = stacks_root / "honeypot-arcane" / "compose.yml"
    try:
        repo_image = arcane_image(ARCANE_REPO_COMPOSE.read_text())
        live_image = arcane_image(live_path.read_text())
    except OSError:
        return None
    if repo_image is None or live_image is None or repo_image == live_image:
        return None
    return (
        f"- `honeypot-arcane` — deployed image `{live_image}` does not match "
        f"`docker-compose.arcane.yml` on `main` (`{repo_image}`)"
    )


# #2764: fixed deployed path, not this checkout's sibling file -- the
# sudoers NOPASSWD grant (scripts/github-ci-runner/install-ci-runner.sh)
# matches this exact interpreter + script path, and a self-hosted runner's
# checkout directory is not guaranteed stable the way this root-owned
# install location is. scripts/compose-project-state.py is that same file's
# source of truth -- re-run install-ci-runner.sh after changing it.
PRIVILEGED_HELPER = "/opt/github-ci-runner-helpers/compose-project-state.py"


def _resolved_config(project: Path, compose_file: str = "compose.yml") -> dict | None:
    """Parsed `docker compose config --format json`, unprivileged. None on
    resolution failure. Shared by resolved_services() and resolved_limits()
    so both #3040's restart-policy check and #3028's resource-limit check
    read the same one compose resolution instead of two divergent ones."""
    try:
        out = subprocess.run(
            ["docker", "compose", "-f", compose_file, "config", "--format", "json"],
            cwd=project, capture_output=True, text=True,
        )
    except OSError:
        # REVIEW-A/#3040: a 0700 root-owned project dir (llm-worker,
        # auth-events-worker, ml-worker) fails the chdir behind cwd=project
        # before docker even runs, raising here instead of returning a
        # nonzero exit code. project_state() treats this exactly like any
        # other resolution failure and falls through to the privileged helper.
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return None


def resolved_services(project: Path, compose_file: str = "compose.yml") -> dict[str, str] | None:
    """service name -> resolved restart policy. None on resolution failure."""
    data = _resolved_config(project, compose_file)
    if data is None:
        return None
    return {
        name: (svc.get("restart") or "")
        for name, svc in data.get("services", {}).items()
    }


def resolved_limits(project: Path, compose_file: str = "compose.yml") -> dict[str, tuple] | None:
    """service name -> (cpus, memory) declared deploy.resources.limits,
    unprivileged. None on resolution failure -- distinct from an empty dict,
    which means "resolved fine, nothing declared"."""
    data = _resolved_config(project, compose_file)
    if data is None:
        return None
    limits = {}
    for name, svc in data.get("services", {}).items():
        declared = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        cpus, memory = declared.get("cpus"), declared.get("memory")
        if cpus is not None or memory is not None:
            limits[name] = (cpus, memory)
    return limits


def actual_containers(project: Path, compose_file: str = "compose.yml") -> list[dict] | None:
    """[{Service, State}, ...] for every container docker knows about
    (any state), belonging to this project. None on resolution failure."""
    try:
        out = subprocess.run(
            ["docker", "compose", "-f", compose_file, "ps", "-a", "--format", "json"],
            cwd=project, capture_output=True, text=True,
        )
    except OSError:
        # Same 0700-dir chdir failure as resolved_services() above.
        return None
    if out.returncode != 0:
        return None
    containers = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return containers


_warned_limits_schema_skew = False


def _warn_limits_schema_skew() -> None:
    global _warned_limits_schema_skew
    if _warned_limits_schema_skew:
        return
    _warned_limits_schema_skew = True
    print(
        "warning: deployed compose-project-state.py has no 'limits' field -- "
        "resource-limit drift checks against every privileged-fallback stack "
        "are silently reporting \"nothing declared\" instead of running; "
        "refresh /opt/github-ci-runner-helpers/compose-project-state.py from this branch",
        file=sys.stderr,
    )


def privileged_project_state(
    project: Path, compose_file: str = "compose.yml"
) -> tuple[dict[str, str], list[dict], dict[str, tuple]] | None:
    """Same answers as the unprivileged path, obtained through the narrow
    root-run helper -- now three of them: services, containers, and declared
    resource limits (REVIEW-A/#3028: resource_limit_findings() had no
    privileged fallback at all, so it could never fire on any .env-locked or
    0700 root-owned stack; measured live as "projects with declared limits:
    0"). One helper call, one place that can fail, for all three.

    #2764: a handful of stacks' .env files aren't readable by whichever
    unprivileged user runs this sweep (root/deploy-runner-owned, 600/640).
    `docker compose config` AND `docker compose ps` both fail on those with
    permission denied -- `ps` has to load the project too, so patching only
    the config half leaves the stack just as unresolved as before.

    The helper resolves everything as root but only ever prints
    {"services": {name: restart}, "containers": [{Service, State}],
    "limits": {name: {cpus, memory}}} -- never a secret value, an image, a
    label or a command line. Silently absent (not installed, or the
    sudoers grant isn't there) just means this fallback fails too and the
    project stays "unresolved", same as before #2764 -- this can never make
    a resolution failure look like a clean pass.
    """
    out = subprocess.run(
        ["sudo", "-n", "/usr/bin/python3", PRIVILEGED_HELPER, str(project), compose_file],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return None
    services = data.get("services")
    containers = data.get("containers")
    if not isinstance(services, dict) or not isinstance(containers, list):
        return None
    # REVIEW-A: a deployed helper that predates the "limits" field and one
    # that resolved cleanly with nothing declared both used to end up as
    # `{}` here, indistinguishable from each other -- "projects with
    # declared limits: 0" against the *entire* live fleet was silently read
    # as "nothing declared" instead of "helper is out of date". The key
    # being absent is schema skew (warn loudly, once); the key present with
    # an empty dict is a genuine, resolved "no limits declared".
    if "limits" not in data:
        _warn_limits_schema_skew()
        limits_raw = {}
    else:
        limits_raw = data.get("limits")
    limits = {
        name: (v.get("cpus"), v.get("memory"))
        for name, v in limits_raw.items() if isinstance(v, dict)
    } if isinstance(limits_raw, dict) else {}
    return services, containers, limits


def project_state(project: Path, compose_file: str = "compose.yml") -> tuple[dict[str, str], list[dict]] | None:
    """(resolved services, existing containers), or None if this project
    can't be resolved at all. Tries unprivileged first and only reaches for
    the root helper when either half fails -- so an ordinary run stays
    entirely unprivileged, and the .env-locked stacks resolve through
    exactly one sudo call instead of two half-fixes."""
    services = resolved_services(project, compose_file)
    containers = actual_containers(project, compose_file) if services is not None else None
    if services is not None and containers is not None:
        return services, containers
    result = privileged_project_state(project, compose_file)
    if result is None:
        return None
    services, containers, _limits = result
    return services, containers


def project_limits(project: Path, compose_file: str = "compose.yml") -> dict[str, tuple] | None:
    """service name -> (cpus, memory) declared limits, or None if this
    project can't be resolved at all. Same two-tier resolution as
    project_state(), for resource_limit_findings() (REVIEW-A/#3028)."""
    limits = resolved_limits(project, compose_file)
    if limits is not None:
        return limits
    result = privileged_project_state(project, compose_file)
    if result is None:
        return None
    _, _, limits = result
    return limits


def manifest_extra_targets(stacks_root: Path, entries: list[dict]) -> list[tuple[Path, str]]:
    """Every manifest-listed stack, by its own dockerComposePath basename --
    including compose.yml-named ones. project_dirs()'s glob only ever finds
    compose.yml AND only succeeds on dirs this user can read, so relying on
    it to cover every compose.yml-named entry silently dropped every
    manifest stack that is both compose.yml-named and unreadable
    unprivileged (REVIEW-A: 34 of 43 `/var/dockge/stacks` dirs are 0700
    root:root -- 31 of 38 manifest entries, including honeypot-elk and
    honeypot-keycloak, the exact stacks #2747 was filed about, were never
    swept at all). project_state()'s privileged fallback is what actually
    resolves an unreadable one; sweep()'s real-path dedup (below) folds this
    back together with project_dirs()'s own list so nothing doubles up.

    Live project dir is always stacks_root/<syncName> -- confirmed against
    every one of this manifest's 38 entries, regardless of where
    dockerComposePath's own directory prefix points in the *repo* (e.g.
    ghosts' dockerComposePath is sandbox/ghosts/compose.yml, but its live
    directory is stacks_root/ghosts like everything else). The compose
    filename is dockerComposePath's basename, the same value
    install-homeserver.sh and Arcane's own gitops-sync already treat as
    authoritative.

    A target whose file isn't actually there yet is skipped (not alarmed):
    the normal per-project "unresolved" path already covers real resolution
    failures, and this function should never manufacture a project that
    plainly doesn't exist on this host yet.
    """
    targets = []
    for entry in entries:
        name = entry.get("syncName")
        compose_path = entry.get("dockerComposePath")
        if not name or not compose_path:
            continue
        compose_file = Path(compose_path).name
        project = stacks_root / name
        try:
            exists = is_regular_file(project / compose_file)
        except PermissionError:
            # REVIEW-A/#3040: llm-worker, auth-events-worker, ml-worker are
            # 0700 root-owned. This basename came straight from the
            # manifest's own dockerComposePath, so an EACCES means "can't
            # peek, but the manifest says it's there" -- include it
            # optimistically. project_state()'s privileged sudo fallback is
            # what actually resolves it (or correctly reports "unresolved"
            # if the manifest turns out to be wrong).
            exists = True
        if exists:
            targets.append((project, compose_file))
    return targets


def stack_targets(stacks_root: Path, entries: list[dict]) -> list[tuple[Path, str]]:
    """Every (project dir, compose filename) this host's sweep resolves,
    deduped by real path. Shared by sweep() and resource_limit_findings()
    (REVIEW-A/#3028) so both walk the same universe of stacks instead of the
    latter being limited to project_dirs()'s unprivileged-readable minority.

    ghidra's compose.yml is a symlink to docker-compose.ghidra.yml (same
    file, confirmed live) -- project_dirs() finds it via the former,
    manifest_extra_targets() via the latter (its manifest basename), so
    without dedup it gets swept twice and can double-report findings
    (REVIEW-A non-blocking). Dedup on the resolved real path, not the
    (project, compose_file) pair.
    """
    targets = [(p, "compose.yml") for p in project_dirs(stacks_root)]
    targets += manifest_extra_targets(stacks_root, entries)

    seen: set[Path] = set()
    deduped = []
    for project, compose_file in targets:
        try:
            real = (project / compose_file).resolve()
        except OSError:
            real = project / compose_file
        if real in seen:
            continue
        seen.add(real)
        deduped.append((project, compose_file))
    return deduped


def sweep(stacks_root: Path, entries: list[dict], retired: set[str] | None) -> tuple[list[dict], list[str]]:
    """Returns (drift findings, project names that failed to resolve).

    `retired` is the same set retired_projects() computes: live directories
    with no manifest entry at all. It is the only thing #3040's rewritten
    Gate 1 below is allowed to treat as "this project not running is
    expected" -- everything else that resolves gets judged on its own
    missing services, sibling or no sibling. `retired=None` (as opposed to
    `set()`) means the manifest itself couldn't be read this sweep -- see
    Gate 1's own comment for why that has to degrade quiet, not loud
    (REVIEW-A's :502 finding).
    """
    findings: list[dict] = []
    unresolved: list[str] = []

    for project, compose_file in stack_targets(stacks_root, entries):
        name = project.name
        state = project_state(project, compose_file)
        if state is None:
            unresolved.append(name)
            continue
        services, containers = state

        has_any_container = {c["Service"] for c in containers}
        has_running_container = {
            c["Service"] for c in containers if c.get("State") == "running"
        }

        expected_persistent = {
            svc for svc, restart in services.items()
            if restart in PERSISTENT_RESTART_POLICIES
        }
        missing = expected_persistent - has_any_container
        if not missing:
            continue

        # #3129: an operator-gated deliberate absence, distinct from both
        # "retired" (no manifest entry at all) and ordinary drift. Checked
        # before the sibling logic below since llm-worker structurally never
        # has a sibling either way -- this is not a re-run of #3040's removed
        # blanket rule, it only matches the one named project in
        # EXPECTED_ABSENT_WHILE.
        if name in EXPECTED_ABSENT_WHILE:
            continue

        # #3040: the old rule suppressed *every* project with no sibling
        # currently running, on the theory that "the whole stack isn't
        # deployed" is self-evident and doesn't need an alarm. That's true
        # for a project that was actually torn down -- but it also made the
        # alarm structurally unreachable for any single-service project
        # (llm-worker has no sibling to ever be "running" in the first
        # place), which is exactly how hp-llm-worker sat with zero
        # containers for 11 hours with nothing watching (#3023). The only
        # legitimate "not deployed, don't alarm" case is a project that has
        # actually been retired from the repo (retired_projects()'s own
        # set) and whose whole stack is down -- anything else with a
        # missing expected-persistent service, sibling or not, is drift.
        siblings_running = has_running_container - missing
        if not siblings_running:
            if retired is None:
                # REVIEW-A/:502 -- manifest unreadable this sweep, so
                # "retired" can't be told apart from "not yet deployed".
                # Fall back to the pre-#3040 behavior (suppress every
                # project with no running sibling) rather than the
                # opposite mistake: treating an unreadable manifest as
                # "nothing is retired" mass-alarms every idle project
                # instead of none.
                continue
            if name in retired:
                continue

        for svc in sorted(missing):
            findings.append({
                "project": name,
                "service": svc,
                "siblings_running": sorted(siblings_running),
            })

    return findings, unresolved


# #3030/REVIEW-A: a raw FailingStreak *count* threshold is structurally
# unreachable behind hp-autoheal -- autoheal restarts a container as soon as
# Docker marks it unhealthy (this fleet's healthchecks near-universally use
# `retries: 3`, llm-worker included), which resets FailingStreak to 0.
# #3023 observed exactly FailingStreak=3, never higher. A single `docker
# inspect` snapshot can't fix this by reading further back either: verified
# live against hp-elasticsearch that `.State.Health.Log` is capped at 5
# entries and, at this fleet's 15-30s healthcheck intervals, spans well
# under two minutes -- nowhere near enough to answer "has this been going
# on for an hour". So this sweep tracks its own first-seen timestamp per
# container name in a small state file, persisted across the 30-minute
# cron's scheduled runs, cleared the moment a container's streak returns to
# 0 -- an actual duration, not a per-snapshot count.
FAILING_STREAK_DURATION_THRESHOLD_S = int(
    os.environ.get("FAILING_STREAK_DURATION_THRESHOLD_S", str(60 * 60))
)
# REVIEW-A/#3030: /tmp is sticky (mode-protected against other users
# deleting your files) but a file inside it is still owned by whichever of
# the four github-ci-runner{,-2,-3,-4} users happened to create it, at
# whatever mode that user's umask left it -- confirmed live at 0644 owned by
# a single user, EACCES for every other runner's write. install-ci-runner.sh
# provisions this dir mode 2775 root:compose-drift-ro (same group every
# runner user is already in for the privileged sudo helper) so any runner
# can create or update the file; _save_streak_state() below still chmods
# each write explicitly since the setgid bit only fixes new files' group
# ownership, not their permission bits.
FAILING_STREAK_STATE_FILE = Path(
    os.environ.get("FAILING_STREAK_STATE_FILE", "/var/lib/compose-drift-watch/failing-streak-state.json")
)


def _fmt_duration(seconds: int) -> str:
    hours = seconds / 3600
    return f"{hours:.1f}h" if hours >= 1 else f"{seconds // 60}m"


def _load_streak_state(state_file: Path) -> dict[str, float]:
    try:
        data = json.loads(state_file.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_streak_state(state_file: Path, state: dict[str, float]) -> None:
    try:
        state_file.write_text(json.dumps(state))
    except OSError as e:
        # Best-effort: a lost state file just means duration tracking
        # restarts from "now" on the next sweep, never a crash -- but say
        # so, since a silently-unwritable state dir (REVIEW-A: not deployed
        # on the live host) makes #3030's duration threshold silently dead
        # rather than merely degraded.
        print(f"warning: could not persist failing-streak state to {state_file}: {e}", file=sys.stderr)
        return
    try:
        # Explicit group-write: a runner user's umask (typically 022) would
        # otherwise leave the file 0644, unwritable by every *other* runner
        # user sharing the group -- exactly the live #3030 bug. The setgid
        # dir bit only controls which group owns a new file, not its mode.
        state_file.chmod(0o664)
    except OSError:
        pass


def failing_streak_findings(
    threshold_seconds: int, state_file: Path = FAILING_STREAK_STATE_FILE
) -> list[dict] | None:
    """Containers whose `.State.Health.FailingStreak` has been continuously
    nonzero for at least `threshold_seconds`, across the whole host -- not
    scoped to compose projects at all. See the module comment above for why
    this is duration-tracked across sweeps rather than read from a single
    snapshot.

    #3030: a different failure shape than sweep()'s "zero containers"
    check above -- a container that exists, is Up, and keeps failing its
    own healthcheck (GPU slot contention, a wedged dependency, ...) is
    never "missing", so it never shows up there. `restart: unless-stopped`
    doesn't help either when the container itself never exits; a human
    needs to be told the healthcheck is the thing that's actually failing.

    Returns None (not an empty list) if `docker ps`/`docker inspect` itself
    fails, so a broken docker daemon reads as "couldn't check this", never
    as "nothing is failing".
    """
    ps = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True)
    if ps.returncode != 0:
        return None
    ids = [i for i in ps.stdout.split() if i]
    state = _load_streak_state(state_file)
    if not ids:
        _save_streak_state(state_file, {})
        return []

    inspect = subprocess.run(["docker", "inspect", *ids], capture_output=True, text=True)
    if inspect.returncode != 0:
        return None
    try:
        records = json.loads(inspect.stdout)
    except json.JSONDecodeError:
        return None

    now = time.time()
    still_failing: dict[str, float] = {}
    findings = []
    for r in records:
        health = ((r.get("State") or {}).get("Health")) or {}
        streak = health.get("FailingStreak")
        if not isinstance(streak, int) or streak <= 0:
            continue
        name = (r.get("Name") or "").lstrip("/") or (r.get("Id") or "?")[:12]
        first_seen = state.get(name, now)
        still_failing[name] = first_seen
        duration = now - first_seen
        if duration >= threshold_seconds:
            findings.append({
                "name": name,
                "failing_streak": streak,
                "status": health.get("Status", ""),
                "unhealthy_for_seconds": int(duration),
            })
    _save_streak_state(state_file, still_failing)
    return findings


def _compose_memory_bytes(value) -> int | None:
    """`docker compose config --format json` already normalizes a
    `deploy.resources.limits.memory` value (however it was written in the
    compose file -- `2GB`, `512M`, ...) down to a plain byte count string
    (confirmed live: `memory: 2GB` in technitium's compose.yml resolves to
    `"2147483648"`). Anything else is a shape this hasn't been seen to
    produce -- returns None rather than guessing."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def resource_limit_findings(stacks_root: Path, entries: list[dict] | None = None) -> list[dict]:
    """[{project, service, container, field, repo, live}, ...] for every
    running container whose live `cpus`/`memory` limit (`docker inspect`
    `.HostConfig.NanoCpus`/`.Memory`) diverges from its own project's
    repo-declared `deploy.resources.limits` (#2972/#3028: three stacks' live
    limits had silently drifted to exactly half the repo's declared values,
    with nothing catching it until an unrelated PR's manual diff surfaced
    it).

    Scoped to `cpus`/`memory` only, not every compose field -- the #2972
    class this exists to catch, not the fully generalized "diff everything"
    check #3028 also floats. See CODE-A.md for why the fuller version is a
    separate, deliberately-not-attempted piece of work in this batch.

    Walks the same stack_targets() universe as sweep() and resolves each one
    through project_limits()/project_state()'s privileged fallback
    (REVIEW-A: previously unprivileged-only against project_dirs()'s 5
    readable dirs, so it could never fire against any .env-locked or 0700
    root-owned stack -- measured live as "projects with declared limits:
    0"). Additive and read-only, same shape as failing_streak_findings()
    above: a project this can't resolve at all is silently skipped, never
    reported as "no drift" -- this can undercount but never lies about a
    stack it never actually checked.
    """
    findings = []
    for project, compose_file in stack_targets(stacks_root, entries or []):
        repo_limits = project_limits(project, compose_file)
        if not repo_limits:
            continue

        state = project_state(project, compose_file)
        if state is None:
            continue
        _, containers = state
        for c in containers:
            service = c.get("Service", "")
            if service not in repo_limits or c.get("State") != "running":
                continue
            name = c.get("Name") or ""
            if not name:
                continue
            inspect = subprocess.run(
                ["docker", "inspect", name, "--format", "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}"],
                capture_output=True, text=True,
            )
            if inspect.returncode != 0:
                continue
            parts = inspect.stdout.split()
            if len(parts) != 2:
                continue
            live_nanocpus, live_memory = parts
            repo_cpus, repo_memory = repo_limits[service]
            if repo_cpus is not None:
                want = round(float(repo_cpus) * 1_000_000_000)
                if int(live_nanocpus) != want:
                    findings.append({
                        "project": project.name, "service": service, "container": name,
                        "field": "cpus", "repo": repo_cpus, "live": int(live_nanocpus) / 1_000_000_000,
                    })
            if repo_memory is not None:
                want_bytes = _compose_memory_bytes(repo_memory)
                if want_bytes is not None and int(live_memory) != want_bytes:
                    findings.append({
                        "project": project.name, "service": service, "container": name,
                        "field": "memory", "repo": want_bytes, "live": int(live_memory),
                    })
    return findings


def open_alarm_issue() -> str:
    out = gh(
        "issue", "list", "-R", REPO, "--state", "open",
        "--label", LABEL, "--json", "number", "--jq", ".[0].number // \"\"",
    ).strip()
    return out or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stacks-root", default="/var/dockge/stacks")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    stacks_root = Path(args.stacks_root)
    host = os.environ.get("RUNNER_NAME") or os.uname().nodename

    # Computed before sweep() (not after, as before #3040) -- the rewritten
    # Gate 1 inside sweep() needs `retired` to tell "torn down as expected"
    # apart from "structurally can never have a sibling", so it has to
    # exist before the loop that decides findings, not after.
    entries = manifest_entries()
    if entries is None:
        print(
            f"note: could not read {MANIFEST_PATH} -- skipping the "
            "retired-from-repo check and the non-compose.yml manifest "
            "stacks this sweep (not read as healthy, just not checked)",
            file=sys.stderr,
        )
        retired: set[str] | None = None
    else:
        retired = set(retired_projects(stacks_root, manifest_project_names(entries)))

    findings, unresolved = sweep(stacks_root, entries or [], retired)
    arcane_drift = arcane_image_drift(stacks_root)
    bad_streaks = failing_streak_findings(FAILING_STREAK_DURATION_THRESHOLD_S)
    if bad_streaks is None:
        print("note: could not run docker ps/inspect -- skipping the "
              "failing-healthcheck-streak check this sweep", file=sys.stderr)
        bad_streaks = []
    resource_drift = resource_limit_findings(stacks_root, entries or [])

    if unresolved:
        print(
            f"note: {len(unresolved)} project(s) could not be resolved and "
            f"were skipped (not read as healthy): {', '.join(unresolved)}",
            file=sys.stderr,
        )

    if not findings and not retired and not arcane_drift and not bad_streaks and not resource_drift:
        print(f"healthy on {host}: no always-on service is missing all its containers, "
              "no live stack directory is missing from the repo manifest, "
              "honeypot-arcane's deployed image matches the repo, no "
              "container has had a healthcheck failing streak for at least "
              f"{_fmt_duration(FAILING_STREAK_DURATION_THRESHOLD_S)}, and no "
              "running container's cpus/memory limit diverges from its repo-declared value")
        if args.dry_run:
            return 0
        if not REPO:
            fail("GITHUB_REPOSITORY must be set")
        open_issue = open_alarm_issue()
        if open_issue:
            now = datetime.now(timezone.utc).strftime("%FT%TZ")
            gh(
                "issue", "close", open_issue, "-R", REPO,
                "--comment",
                f"Recovered as of {now}: sweep on {host} found no drifted "
                "service. Closing; the next sweep that finds drift reopens.",
            )
            print(f"closed compose-drift-alarm issue #{open_issue} (recovered)")
        return 0

    print(f"DRIFT: {len(findings)} service(s) missing all containers, "
          f"{len(retired or ())} live stack(s) retired from the repo, "
          f"{'1' if arcane_drift else '0'} honeypot-arcane image mismatch, "
          f"{len(bad_streaks)} container(s) over the failing-streak threshold, "
          f"{len(resource_drift)} container(s) with a resource-limit mismatch")
    lines = [
        (f"- `{f['project']}` / **{f['service']}** — zero containers "
         f"(running siblings: {', '.join(f['siblings_running'])})")
        if f['siblings_running'] else
        f"- `{f['project']}` / **{f['service']}** — zero containers, no siblings running either"
        for f in findings
    ]
    retired_lines = [f"- `{name}` — still deployed, no matching entry in the manifest" for name in sorted(retired or ())]
    streak_lines = [
        f"- `{s['name']}` — unhealthy for {_fmt_duration(s['unhealthy_for_seconds'])} "
        f"({s['failing_streak']} consecutive healthcheck failures, status: {s['status']})"
        for s in bad_streaks
    ]
    resource_lines = [
        f"- `{r['container']}` (`{r['project']}` / **{r['service']}**) — live `{r['field']}` "
        f"is {r['live']}, repo declares {r['repo']}"
        for r in resource_drift
    ]
    print("\n".join(lines + retired_lines + streak_lines + resource_lines + ([arcane_drift] if arcane_drift else [])))

    now = datetime.now(timezone.utc).strftime("%FT%TZ")
    body_sections = [
        f"Sweep at {now} on `{host}`: **{len(findings)}** compose-defined, "
        "always-on service(s) have no container at all (not even stopped), "
        f"**{len(retired or ())}** live stack(s) no longer exist in the repo "
        f"manifest, **{len(bad_streaks)}** container(s) have had a "
        "healthcheck failing streak continuously for at least "
        f"{_fmt_duration(FAILING_STREAK_DURATION_THRESHOLD_S)}, and "
        f"**{len(resource_drift)}** running container(s) have a cpus/memory "
        "limit that diverges from the repo's declared value.",
        "",
    ]
    if lines:
        body_sections += [
            "## Missing services",
            "",
            "Context: #2747 — this is exactly the shape that let a live "
            "Elasticsearch cluster and two other DB sidecars silently not "
            "exist while their dependent app containers ran regardless, "
            "with no alarm anywhere. #3040 extended this to also alarm on "
            "a single-service project with no sibling to compare against "
            "(the shape that let hp-llm-worker sit with zero containers "
            "for 11 hours, #3023) — a line above with \"no siblings "
            "running either\" is that case, not a false positive. Bring "
            "the missing service up against its **existing** data volume "
            "(`docker compose -f compose.yml up -d <service>`, run from the "
            "project directory) — never `docker volume prune`/`rm`, and "
            "never recreate a volume without first confirming it's actually "
            "empty. Check Arcane's gitops-sync history for the project "
            "around when this likely started.",
            "",
            *lines,
            "",
        ]
    if retired_lines:
        body_sections += [
            "## Retired from the repo, still deployed",
            "",
            "Context: #2855 — a stack whose `arcane/home/<name>/` directory "
            "(or manifest entry, for one of the six self-contained stacks) "
            "was removed from the repo, but never torn down on this host. "
            "Deleting the repo source does nothing to what is already "
            "deployed (`docs/ARCANE-GIT-SYNC.md`'s \"Retirement procedure\" "
            "section). Confirm the retirement was intentional, then stop "
            "and remove the live containers (`docker compose -f compose.yml "
            "down` in the stack's own directory) and delete the "
            "corresponding Arcane gitops-sync record and stack directory — "
            "never `docker volume prune`/`rm` as part of this.",
            "",
            *retired_lines,
            "",
        ]
    if arcane_drift:
        body_sections += [
            "## honeypot-arcane image mismatch",
            "",
            "Context: #3048 — honeypot-arcane is installer-/deploy.yml-managed "
            "by a one-time file copy, not an Arcane gitops-sync (syncing the "
            "thing that has to already be running before any sync can happen "
            "is a bootstrap loop), so nothing re-copies "
            "`docker-compose.arcane.yml` after the initial install unless "
            "deploy.yml's \"Synchronize honeypot-arcane\" step is actually "
            "run. Fix: run that step (`workflow_dispatch` on deploy.yml, "
            "target home) or re-run `scripts/install-homeserver.sh`'s "
            "`step_arcane_install`, then confirm `docker inspect hp-arcane "
            "--format '{{.Config.Image}}'` matches.",
            "",
            arcane_drift,
            "",
        ]
    if streak_lines:
        body_sections += [
            "## Healthcheck failing streak",
            "",
            f"Context: #3030 — a container that exists and is `Up` but keeps "
            "failing its own healthcheck (`FailingStreak` from `docker "
            "inspect`) continuously for at least "
            f"{_fmt_duration(FAILING_STREAK_DURATION_THRESHOLD_S)}. Tracked "
            "as a duration across sweeps, not a raw streak count — "
            "hp-autoheal restarts a container the moment Docker marks it "
            "unhealthy, which resets FailingStreak to 0 well before any "
            "fixed count threshold is reached (#3023 observed exactly "
            "FailingStreak=3, never higher). This is a distinct failure "
            "mode from the sections above: the container was never "
            "missing, so `restart:` policies never get a chance to help — "
            "the thing that's broken outlives a container restart (a "
            "wedged dependency, a resource the healthcheck needs that a "
            "plain restart doesn't free). Check `docker inspect <name> "
            "--format '{{json .State.Health}}'` for the actual probe "
            "failure before restarting anything.",
            "",
            *streak_lines,
            "",
        ]
    if resource_lines:
        body_sections += [
            "## Resource limit drift",
            "",
            "Context: #2972/#3028 — three stacks' live `deploy.resources.limits` "
            "had silently drifted to exactly half the repo's declared values, "
            "caught only by an unrelated PR's manual diff. Scoped to "
            "`cpus`/`memory` only, not every compose field (see CODE-A.md for "
            "why the fully generalized field-by-field diff #3028 also "
            "describes is a separate piece of work, not attempted here). "
            "Re-sync the project (Arcane gitops-sync or `docker compose -f "
            "compose.yml up -d --force-recreate <service>`) to bring the live "
            "limit back in line with the repo.",
            "",
            *resource_lines,
            "",
        ]
    if unresolved:
        body_sections.append(
            f"Also unresolved this sweep (skipped, not counted as "
            f"healthy): {', '.join(unresolved)}"
        )
    body = "\n".join(body_sections).strip() + "\n"

    if args.dry_run:
        print(f"--- dry run: would open/update {LABEL} issue with the body above")
        return 0
    if not REPO:
        fail("GITHUB_REPOSITORY must be set")

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(body)
        body_path = Path(fh.name)

    subprocess.run(
        ["gh", "label", "create", LABEL, "-R", REPO,
         "-d", "Compose-defined service missing all containers while a sibling runs (scripts/compose-drift-watch.py)",
         "--color", "D93F0B"],
        capture_output=True, text=True,
    )
    open_issue = open_alarm_issue()
    if open_issue:
        gh("issue", "comment", open_issue, "-R", REPO, "--body-file", str(body_path))
        print(f"appended to compose-drift-alarm issue #{open_issue}")
    else:
        title = (
            f"ops: {len(findings)} compose service(s) drifted out of existence, "
            f"{len(retired)} stack(s) retired from the repo but still deployed (#2747/#2855 watch)"
            if retired else
            f"ops: {len(findings)} compose service(s) drifted out of existence (#2747 watch)"
        )
        if arcane_drift:
            title += " + honeypot-arcane image mismatch (#3048 watch)"
        if bad_streaks:
            title += f" + {len(bad_streaks)} container(s) unhealthy for {_fmt_duration(FAILING_STREAK_DURATION_THRESHOLD_S)}+ (#3030 watch)"
        if resource_drift:
            title += f" + {len(resource_drift)} resource-limit mismatch(es) (#3028 watch)"
        gh(
            "issue", "create", "-R", REPO, "--title", title,
            "--label", LABEL, "--body-file", str(body_path),
        )
        print("opened compose-drift-alarm issue")
    body_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
