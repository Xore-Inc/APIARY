"""
Shared model-lifecycle helpers (#65): version retention and metadata,
used identically by IsoForestModel and LSTMAEModel so the "last N versions,
metadata sidecar per accepted version" contract is one implementation, not
two independently-maintained copies.

The acceptance gate itself (holdout evaluation, anomaly-rate comparison)
lives in each model class, not here -- what counts as a valid holdout split
and how to score it is model-specific; only what happens to a file on disk
after a version is accepted is shared.

See docs/ml-worker-plan.md §11 for the full design and the reasoning behind
each constant below.
"""
import glob
import json
import os
import re
import time

MAX_RETAINED_VERSIONS = 3

_VERSION_PATTERN_CACHE: "dict[str, re.Pattern]" = {}


def _version_pattern(prefix: str) -> "re.Pattern":
    return _VERSION_PATTERN_CACHE.setdefault(
        prefix, re.compile(re.escape(prefix) + r"_(\d+)\."))


def _live_target_version(model_dir: str, prefix: str) -> "int | None":
    """The timestamp embedded in whichever `{prefix}_{ts}.*` file the live
    `current_{prefix}.*` pointer names, or None if there is no pointer or
    it doesn't name a retained-looking file. realpath (not readlink)
    because `_symlink()` writes absolute targets while rollback.py may not,
    and because a pointer at a deleted file must still report its intended
    name -- pruning is exactly when protection matters most."""
    pattern = _version_pattern(prefix)
    links = glob.glob(os.path.join(model_dir, f"current_{prefix}.*"))
    if not links:
        return None
    m = pattern.search(os.path.basename(os.path.realpath(links[0])))
    return int(m.group(1)) if m else None


def staged_marker_path(model_dir: str, prefix: str) -> str:
    return os.path.join(model_dir, f"staged_rollback_{prefix}.txt")


def mark_staged(model_dir: str, prefix: str, ts: int) -> None:
    """Record an operator-staged rollback target on disk (#2230).

    Why a marker at all -- the live pointer can't serve as the durable
    record: _save() promotes through `current_{prefix}` BEFORE pruning, so
    from the very first post-staging accept onward the pointer names the
    freshly-accepted version, and a prune that exempts only
    pointer-targets reads normal state. The marker is written by
    rollback.py alongside its _symlink() swap; it persists (deliberately)
    until the operator stages something else, keeping the staged version's
    file prunable-proof across arbitrarily many accepted retrains."""
    try:
        with open(staged_marker_path(model_dir, prefix), "w") as f:
            f.write(str(ts))
    except OSError:
        pass


def read_staged_marker(model_dir: str, prefix: str) -> "int | None":
    """The ts recorded by mark_staged(), or None."""
    try:
        with open(staged_marker_path(model_dir, prefix)) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def unmark_staged(model_dir: str, prefix: str) -> None:
    try:
        os.remove(staged_marker_path(model_dir, prefix))
    except OSError:
        pass


def prune_old_versions(model_dir: str, prefix: str, keep: int = MAX_RETAINED_VERSIONS) -> None:
    """Delete every `{prefix}_{timestamp}.*` file in model_dir except the
    newest `keep` (by the timestamp embedded in the filename, not mtime --
    a restored/copied file's mtime is not trustworthy, the name ml-worker
    itself wrote is). Also deletes each pruned version's `.meta.json`
    sidecar, if present.

    Two exemptions, both #2230, both *in addition to* `keep` so retention
    stays honest about non-live history (at most `keep` deletable versions
    survive):

    - the version `current_{prefix}.*` points at RIGHT NOW, and
    - the version rollback.py last staged (read_staged_marker) -- the
      pointer alone can't express this, because promotion overwrites the
      pointer before prune runs, on the very first post-staging accept.

    Without these, "promotion keeps the newest" did hold, but a
    rollback.py repoint made the newest-renaming promise false in the
    other direction: the next accepted retrain's prune deleted the exact
    file group the operator had staged the live pointer onto, permanently
    (sidecar included), so re-running the identical rollback failed with
    "does not exist".
    """
    pattern = _version_pattern(prefix)
    versions: dict = {}
    for path in glob.glob(os.path.join(model_dir, f"{prefix}_*")):
        m = pattern.search(os.path.basename(path))
        if not m:
            continue
        versions.setdefault(int(m.group(1)), []).append(path)

    protected_ts = {_live_target_version(model_dir, prefix),
                    read_staged_marker(model_dir, prefix)} - {None}

    for ts in sorted(versions.keys(), reverse=True)[keep:]:
        if ts in protected_ts:
            continue
        for path in versions[ts]:
            try:
                os.remove(path)
            except OSError:
                pass


def staged_rollback_version(model_dir: str, prefix: str) -> "int | None":
    """Return the version the live `current_{prefix}.*` pointer names when
    that is NOT the newest retained `{prefix}_{ts}` version -- the
    fingerprint rollback.py leaves behind (#2230). None in every normal
    state (no models yet; or the pointer already names the newest accepted
    retrain). Callers about to promote through _save() use this to say out
    loud that they are overriding what an operator staged, instead of the
    old silent overwrite -- dashboards surface retrains, never symlink
    churn, so the warning here is the only place the voided staging is
    visible.

    Call it BEFORE writing the new version's files: after writing but
    before promotion, the new file IS the newest on disk and the previous
    pointer would be misread as a manual stage."""
    live = _live_target_version(model_dir, prefix)
    if live is None:
        return None
    pattern = _version_pattern(prefix)
    stored = [int(m.group(1))
              for path in glob.glob(os.path.join(model_dir, f"{prefix}_*"))
              if (m := pattern.search(os.path.basename(path)))]
    if stored and live != max(stored):
        return live
    return None


def write_version_metadata(model_dir: str, prefix: str, ts: int, meta: dict) -> None:
    """Write the evidence for one accepted version next to its model
    file(s) -- survives independent of Elasticsearch retention, so
    "why is this the active model" is answerable even if ml-worker-metrics
    has rolled over."""
    path = os.path.join(model_dir, f"{prefix}_{ts}.meta.json")
    try:
        with open(path, "w") as f:
            json.dump(meta, f, indent=2, default=str)
    except OSError:
        pass


def _symlink(target: str, link: str) -> None:
    """Atomically point `link` at `target` (#169). Writes a temporary
    symlink in the same directory, then os.replace()s it onto `link` --
    os.replace is an atomic rename on POSIX when source and destination
    share a filesystem (true here: both live directly under model_dir), so
    a process killed between these two calls can never observe `link`
    missing. It's either the previous target or the new one, never absent
    -- unlike the previous remove-then-symlink sequence, which had a window
    where `link` didn't exist at all.

    Lives here rather than in IsoForestModel since #2230: rollback.py --
    a deliberate stdlib-only standalone script -- performs the same kind
    of promotion when staging a rollback, and used to have its own
    remove-then-symlink copy of this exact bug. One implementation, not
    two independently-maintained copies (this module's stated contract).
    """
    directory = os.path.dirname(link) or "."
    temp_link = os.path.join(directory, f".{os.path.basename(link)}.tmp-{os.getpid()}-{time.time_ns()}")
    os.symlink(target, temp_link)
    os.replace(temp_link, link)
