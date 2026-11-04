#!/usr/bin/env python3
"""Fail CI when a JSON-emitting /logs directory lacks either retention half.

The #120 contract is two-sided: each JSON-emitting sensor self-rotates its
sink into generations with a digit-leading suffix, and
honeypot-utilities' log-maintenance.sh prunes those generations once they
age past the shared window. #2196 shipped because mailoney broke BOTH
halves at once -- its sink appended forever AND no pruner glob existed --
and nothing structural would have caught either omission; only a person
reading compose volumes next to pruner code next to vendored sensors
could connect them. This script is that connection, checked mechanically
on every push.

The ROWS ledger below is deliberately hand-written rather than inferred:
it documents WHERE each half lives for every rotating sink we know about,
so adding a sensor means adding one reviewable row, and forgetting either
half fails here naming exactly which half is missing. Two sides per row:

- "writer": where the rotation implementation itself lives, proven by a
  grep token in that subtree (a knob name or rotate() definition);
- "glob": the exact pruner find-line fragment log-maintenance.sh must
  carry for that directory.

The reverse check keeps the ledger honest too: every `find /logs/<dir>`
line in the pruner must be claimed by some row, so pruning coverage
cannot silently grow an unledgered entry (or lose one).

#2216 review: the two checks above only see the halves an author already
remembered to touch. A brand-new stack that bind-mounts a log directory,
appends a `.json` sink into it forever, adds no pruner line and no ROW
passed all of them, which is exactly the drift acceptance criterion 4 of
that issue asks this script to fail on. So there is a third check, and it
starts from the one artifact a new stack cannot omit and still reach disk:
its compose bind mount. Every `/opt/stacks/apiary/logs/<dir>` mount under
arcane/home/*/compose.yml must be accounted for by name -- as a ROWS
directory, an EXEMPT entry with a written reason, or a KNOWN_UNCOVERED
entry naming the issue that tracks it. Anything else fails.

Two supporting rules keep that enumeration from rotting:

- a `-name` glob is credited only to the `find` line for its OWN
  directory, so moving one onto a neighbouring line (leaving a directory
  unpruned while every glob string still appears somewhere in the file)
  fails instead of passing;
- a ROWS/EXEMPT/KNOWN_UNCOVERED entry for a directory nothing mounts any
  more is reported as stale, so a retired stack takes its ledger entry
  with it.

Usage: python scripts/check-json-sink-retention-parity.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAINTENANCE = ROOT / "arcane" / "home" / "honeypot-utilities" / "analysis" / "log-maintenance.sh"
STACKS = ROOT / "arcane" / "home"
SKIP_DIRS = {"vendor", "node_modules", "__pycache__"}

# #2921: a test file is evidence the implementation was ONCE correct, never
# evidence it is PRESENT -- DIONAEA_LOG_MAX_BYTES lives in both
# dionaea/log_rotation_patch.py and dionaea/tests/test_log_rotation_patch.py,
# so deleting the former and keeping the latter must not satisfy the proof.
_TEST_PATH_RE = re.compile(r"(?:^|/)tests?(?:/|$)")


def _is_test_path(rel_posix: str) -> bool:
    name = rel_posix.rsplit("/", 1)[-1]
    return bool(
        _TEST_PATH_RE.search(rel_posix)
        or name.endswith("_test.go")
        or (name.startswith("test_") and name.endswith(".py"))
    )


# `_tracked_cache is None` means "not computed yet" (what a caller sets to
# invalidate); _NO_GIT means "computed, and ROOT is not a git checkout".
_NO_GIT = object()
_tracked_cache: object = None


def _tracked_files() -> set[Path] | None:
    """Files `git` actually tracks under ROOT, or None if ROOT is not a
    git checkout.

    #2921: tree_contains() used to rglob the filesystem directly, which
    reads gitignored and untracked files too -- a stale __pycache__/*.pyc
    left over from running a row's tests carries its tokens as bytecode
    constants and satisfies the writer proof on its own, even with both the
    implementation and its tests deleted. A build artifact must never stand
    in for source.

    ROOT is not always a checkout, though: tests/docs/test_2216_* and
    test_2826_* assemble a throwaway root under tmp_path (real files for
    the one thing a case mutates, symlinks to the real stacks for the
    rest) and run this script out of it, and an exported tarball has the
    same shape. `git ls-files` answers 128 there, so tracking is reported
    as unavailable rather than raised, and tree_contains() reads the tree
    directly. Both #2921 paths stay closed in that mode: __pycache__ is in
    SKIP_DIRS and test paths are excluded by path, neither of which needs
    git.
    """
    global _tracked_cache
    if _tracked_cache is None:
        try:
            proc = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=ROOT, capture_output=True, check=False,
            )
        except OSError:  # no git binary at all
            _tracked_cache = _NO_GIT
        else:
            if proc.returncode != 0:
                _tracked_cache = _NO_GIT
            else:
                _tracked_cache = {
                    (ROOT / part.decode("utf-8", "replace"))
                    for part in proc.stdout.split(b"\0") if part
                }
    if _tracked_cache is _NO_GIT:
        return None
    return _tracked_cache  # type: ignore[return-value]

# Host side of every sensor log bind mount, and where the maintenance
# container sees it (honeypot-utilities/compose.yml mounts the whole parent).
LOGS_HOST_ROOT = "/opt/stacks/apiary/logs"
LOGS_CONTAINER_ROOT = "/logs"

# One row per self-rotating JSON directory under /logs.
# "writer" is (subtree to search, proof tokens); tokens are strings the
# rotation implementation cannot sensibly drop without stopping being one.
# http-honeypot's single binary serves both http.json and api.json (#120:
# see its persona_test.go) -- hence two rows sharing one writer.
ROWS: list[dict[str, Any]] = [
    {
        "dir": "/logs/cowrie",
        "globs": ["'cowrie.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-cowrie", ["CowrieDailyLogFile"]),
    },
    {
        "dir": "/logs/multipot",
        "globs": ["'multipot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-multipot/multipot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/http-honeypot",
        "globs": ["'http.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-http/http-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/api-honeypot",
        "globs": ["'api.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-http/http-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/enriched",
        "globs": ["'*.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dashboard/backend-service/src/ip_enrichment",
                   ["OUTPUT_MAX_BYTES"]),
    },
    {
        "dir": "/logs/dionaea",
        "globs": ["'dionaea.json.[0-9]*'", "'dionaea_incident.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dionaea/dionaea",
                   ["DIONAEA_LOG_MAX_BYTES"]),
    },
    {
        "dir": "/logs/mailoney",
        "globs": ["'mailoney.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-mailoney/mailoney",
                   ["MAILONEY_JSON_MAX_BYTES"]),
    },
    # #2323: the two zeek-proxy directories prune on the same two-sided
    # contract, but their writer half is Zeek's own rotation/extraction
    # (site scripts, not a Go knob), so the proof tokens are the redef /
    # hook that would have to disappear for the half to stop existing.
    {
        "dir": "/logs/zeek-proxy",
        "globs": ["'*.log'"],
        "writer": ("arcane/home/honeypot-elk/zeek-proxy",
                   ["Log::default_rotation_interval"]),
    },
    {
        "dir": "/logs/zeek-proxy-extract",
        "globs": ["'*.bin'"],
        "writer": ("arcane/home/honeypot-elk/zeek-proxy",
                   ["extract_filename"]),
    },
    # #2216: nine writers had neither half at all until this pass -- see
    # that issue for the fleet-wide audit. Each got the same self-rotator
    # multipot/http-honeypot already carry (LOG_MAX_BYTES + a rotate()
    # closing/renaming/reopening the sink), so the proof tokens match.
    {
        "dir": "/logs/rdp-honeypot",
        "globs": ["'rdp-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-rdp-honeypot/rdp-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/citrix-honeypot",
        "globs": ["'citrix-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-citrix-honeypot/citrix-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/sonicwall-sma-honeypot",
        "globs": ["'sonicwall-sma-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-sonicwall-sma/sonicwall-sma-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/dns-honeypot",
        "globs": ["'dns-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dns-honeypot/dns-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/cisco-asa-honeypot",
        "globs": ["'cisco-asa-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-cisco-asa-honeypot/cisco-asa-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/dicompot",
        "globs": ["'dicompot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dicompot/dicompot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/dnp3",
        "globs": ["'dnp3.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dnp3/dnp3-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/endlessh",
        "globs": ["'endlessh.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-endlessh/endlessh-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/canarytokens",
        "globs": ["'canarytokens.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-canarytokens/canarytokens-adapter",
                   ["LOG_MAX_BYTES", "func rotateLog()"]),
    },
    {
        "dir": "/logs/tftp-relay",
        "globs": ["'sessions.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dionaea/tftp-relay",
                   ["LOG_MAX_BYTES", "func (r *relay) rotateSessionLog()"]),
    },
    # #2892: conpot.json had neither half of the #120 contract -- only
    # conpot.log rotated. conpot/json_log_rotation_patch.py gives JsonLogger
    # the same close/rename/reopen self-rotation dionaea/mailoney already
    # have, applied at Docker build time against the vendored source (same
    # shape as persona_patch.py etc, see conpot/Dockerfile). All six conpot
    # personas share that one vendored tree, so one writer proof covers all
    # six directories -- each persona's conpot.json lives in its own
    # /logs/conpot* bind mount (compose.yml), hence six rows.
    {
        "dir": "/logs/conpot",
        "globs": ["'conpot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-conpot/conpot",
                   ["CONPOT_JSON_LOG_MAX_BYTES", "def _rotate(self)"]),
    },
    {
        "dir": "/logs/conpot-s7-1200",
        "globs": ["'conpot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-conpot/conpot",
                   ["CONPOT_JSON_LOG_MAX_BYTES", "def _rotate(self)"]),
    },
    {
        "dir": "/logs/conpot-s7-1500",
        "globs": ["'conpot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-conpot/conpot",
                   ["CONPOT_JSON_LOG_MAX_BYTES", "def _rotate(self)"]),
    },
    {
        "dir": "/logs/conpot-iec104",
        "globs": ["'conpot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-conpot/conpot",
                   ["CONPOT_JSON_LOG_MAX_BYTES", "def _rotate(self)"]),
    },
    {
        "dir": "/logs/conpot-guardian",
        "globs": ["'conpot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-conpot/conpot",
                   ["CONPOT_JSON_LOG_MAX_BYTES", "def _rotate(self)"]),
    },
    {
        "dir": "/logs/conpot-kamstrup",
        "globs": ["'conpot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-conpot/conpot",
                   ["CONPOT_JSON_LOG_MAX_BYTES", "def _rotate(self)"]),
    },
    # #2826: elasticpot self-rotates daily to elasticpot.json.<date>, but the
    # implementation is vendor-internal (baked into the pinned
    # dtagdevsec/elasticpot image, not built from source in this tree), so
    # there is no grep token to prove it from -- writer=None + writer_note
    # records how it was actually confirmed (live `ls` on the homeserver
    # showing daily-dated generations back to first deploy, per #2826's own
    # measurement table). Only the pruner half needed adding here.
    {
        "dir": "/logs/elasticpot",
        "globs": ["'elasticpot.json.[0-9]*'"],
        "writer": None,
        "writer_note": "vendor-internal daily logrotate, confirmed live "
                        "(elasticpot.json.<YYYY-MM-DD> generations present "
                        "back to 2026-08-15 on the homeserver, #2826)",
    },
    # #2892: event_log.json had neither half of the #120 contract --
    # internal/logger/logger.go's New() os.OpenFile()s it once and hands
    # the raw *os.File straight to cblog's EventLogger.SetOutput(), with no
    # size check and no rotation flag anywhere on galah's CLI.
    # galah/json_log_rotation_patch.py gives it the same close/rename/reopen
    # self-rotation dionaea/mailoney/conpot's own source patches use for
    # their sinks, inserted as a small io.Writer wrapper since Go has no
    # string-replace-a-method-body shape as convenient as those three
    # Python targets. Verified live: applying the patch against the actual
    # pinned upstream commit, `go build`ing the real cmd/galah binary, and
    # driving internal/logger.New()+LogEvent() through it directly all
    # succeeded, producing rotated event_log.json.<timestamp> generations
    # once GALAH_JSON_LOG_MAX_BYTES was exceeded.
    {
        "dir": "/logs/galah",
        "globs": ["'event_log.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-galah/galah",
                   ["GALAH_JSON_LOG_MAX_BYTES", "func (w *rotatingWriter) rotate()"]),
    },
    # #2892: beelzebub.json (core.yaml's logsPath) had neither half either --
    # internal/builder/builder.go's buildLogger() os.OpenFile()s it once and
    # hands the raw *os.File to logrus through io.MultiWriter, no size check,
    # no rotation knob in core.yaml's Logging block.
    # beelzebub/json_log_rotation_patch.py is galah's wrapper ported to that
    # call site, keeping Builder.logsFile (closed by Builder.Close()) pointed
    # at the live generation. Verified: patch applied to the real pinned
    # upstream commit, `go vet` + the Dockerfile's exact `go build` line
    # succeeded, and the extracted writer produced rotated
    # beelzebub.json.<timestamp> generations once BEELZEBUB_JSON_LOG_MAX_BYTES
    # was exceeded.
    {
        "dir": "/logs/beelzebub",
        "globs": ["'beelzebub.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-beelzebub/beelzebub",
                   ["BEELZEBUB_JSON_LOG_MAX_BYTES", "func (w *rotatingWriter) rotate()"]),
    },
    # #2892: sentrypeer.json, 94MB and growing, had neither half -- the
    # vendored C/Rust build's live writer (sentrypeer_rust::json_logger's
    # json_log_bad_actor_rs(), selected over the plain C writer because this
    # build's HAVE_RUST=1 leaves new_mode=true, and this image's CMD never
    # passes the -N flag that cli.rs wires to clear it) opened the
    # file fresh per call and never checked its size. Upstream itself ignores
    # SIGHUP (src/signal_handler.c) and has no reopen/logrotate knob at the
    # pinned SENTRYPEER_REF, so there was no config-only collapse available.
    # json_log_rotation_patch.py patches json_log_bad_actor_rs() to
    # close/rename/reopen once SENTRYPEER_JSON_LOG_MAX_BYTES is exceeded,
    # same digit-leading .<stamp>[.N] suffix as the rows above. Verified: a
    # standalone cargo crate built from the patch's own added functions
    # (chrono, already a sentrypeer_rust dependency) actually produced
    # rotated generations once the threshold was crossed.
    {
        "dir": "/logs/sentrypeer",
        "globs": ["'sentrypeer.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-sentrypeer/sentrypeer",
                   ["SENTRYPEER_JSON_LOG_MAX_BYTES", "fn rotate_json_log_if_needed("]),
    },
]

# Mounted log directories that are deliberately outside the two-sided
# contract. Each reason has to say what the directory actually holds and why
# nothing needs pruning it -- "it looked fine" is not a reason, and a wrong
# one here is how a sink hides in plain sight.
#
# #2826 review: prose alone is how a sink hides in plain sight the SECOND
# time. An exemption whose reason asserts a concrete mechanism ("rotate()
# covers it", "the writer self-bounds") was a claim nothing checked --
# deleting the rotate line left the ledger asserting coverage that no longer
# existed and the guardrail still green. So a value may be either a bare
# reason string (nothing mechanical to assert -- evidence corpora, VPS-written
# trees) or a dict carrying the mechanism as a checked key:
#
# - "rotates": the exact /logs/... paths log-maintenance.sh's copytruncate
#   rotate() must name, asserted per-path the way ROWS asserts "globs";
# - "writer": (subtree, [grep tokens]) proving a self-bounding writer, the
#   same proof shape ROWS uses for its own writer half.
EXEMPT: dict[str, str | dict[str, Any]] = {
    "/logs/cowrie/downloads":
        "attacker payload corpus, not an event sink -- files are content-"
        "addressed by hash and are the evidence the payload workers index; "
        "deleting them on a log schedule would delete the samples.",
    "/logs/cowrie/lib-cowrie":
        "cowrie's own state directory (userdb, fs pickle), not a log stream.",
    "/logs/cowrie/tty":
        "recorded TTY session casts, served by the dashboard's replay view; "
        "same evidence reasoning as downloads/.",
    "/logs/mailoney/mail":
        "captured .eml bodies, already pruned by their own retention line "
        "(MAILONEY_MAIL_RETENTION_DAYS, #2196 part 2) rather than a JSON glob.",
    "/logs/dashboard-backend":
        "backend-service's own durable JSONL sink (obs.rs). Self-bounded "
        "rather than pruned: audit::rotate_if_oversized keeps exactly one "
        "retired .1 generation and deletes the previous one, capping the "
        "directory at 2 x MAX_SINK_BYTES (<=50MiB) with nothing left to age "
        "out (#2468).",
    "/logs/dashboard-backend-mounted":
        "the same obs.rs sink under the honeypot-dashboard project's own "
        "mount name; identical self-bounding (#2468).",
    "/logs/dashboard-bff": {
        "reason":
            "the BFF tier's app.jsonl. #2826 ported obs.rs's "
            "rotate_if_oversized shape into obs.server.ts's rotateIfOversized "
            "(same 25MiB cap, one retired .1 generation, rename-not-truncate) "
            "-- self-bounded the same way /logs/dashboard-backend is, so it "
            "needs no pruner find line either.",
        "writer": ("arcane/home/honeypot-dashboard/frontend-next/src/lib/obs.server.ts",
                   ["async function rotateIfOversized(", "MAX_SINK_BYTES"]),
    },
    "/logs/canarytokens/frontend": {
        "reason":
            "vendored Canarytokens app's own frontend.log -- a plain text log, "
            "not a JSON sink, so it is rotated by log-maintenance.sh's "
            "copytruncate rotate() (added by #2826) rather than the "
            "find-glob/ROWS mechanism the JSON sinks above use; frontend/ is "
            "empty on the live host today so there is nothing to rotate yet, "
            "but the line is in place.",
        "rotates": ["/logs/canarytokens/frontend/frontend.log"],
    },
    "/logs/canarytokens/switchboard": {
        "reason":
            "vendored Canarytokens app's own switchboard.log, same "
            "copytruncate-rotate() treatment as frontend.log above (#2826). "
            "Bounded at MAX_LOG_BYTES (256MiB default) plus four gzipped "
            "generations, not rotated on a schedule: 1.7MB after ~3 weeks "
            "live, so the first rotation is a long way out.",
        "rotates": ["/logs/canarytokens/switchboard/switchboard.log"],
    },
    "/logs/hellpot": {
        "reason":
            "HellPot.log is a plain human-readable text log (not a JSON event "
            "sink), so #2826 gave it log-maintenance.sh's copytruncate rotate() "
            "the same way dionaea.log/cowrie.log/conpot.log already get it, "
            "rather than a find-glob/ROWS entry. Same caveat as switchboard "
            "above: the cap is 256MiB and the file is 11.4MB after ~18 days, "
            "so this bounds the directory rather than shrinking it today.",
        "rotates": ["/logs/hellpot/HellPot.log"],
    },
    "/logs/suricata":
        "written on the VPS, mounted read-only here for Filebeat. Its "
        "retention is vps/suricata-log-maintenance.sh's eve-*.json prune, "
        "which is where the writer is (#79/#113).",
    "/logs/suricata/pcap":
        "VPS-written pcap, read-only here; retention is the pcap sync "
        "window, not a JSON glob (#1737).",
    "/logs/arkime-raw":
        "Arkime's own pcap store (log.pcap.<epoch>), reclaimed by Arkime's "
        "freeSpaceG rather than by find -- deleting these behind its back "
        "would leave its session index pointing at nothing (#1737).",
    "/logs/zeek-extract":
        "legacy read-only mount kept for honeypot-payload-analysis; nothing "
        "in the fleet mounts it writable and it is empty on the live host -- "
        "carved files land in /logs/zeek-proxy-extract, which has its own "
        "row above (#2323).",
    "/logs/snare":
        "snare's runtime directory: a .cfg/.uuid/.pid plus a text snare.log "
        "and snare.err. No JSON event sink -- SNARE's events reach ES through "
        "tanner, not through this mount.",
    "/logs/tanner":
        "tanner.log/tanner.err text logs plus a static tanner_report.json "
        "the app writes once at startup; no appended event stream.",
}

# Mounted log directories that DO carry an unbounded or half-covered sink and
# are not fixed yet. This list is debt, not an exemption: it exists so the
# enumeration above can fail on a genuinely new stack today instead of
# waiting for the whole fleet to be clean first. Every entry names the issue
# that tracks it, and closing that issue means deleting the entry.
#
# #2892 closed this out: conpot (six rows), galah, beelzebub and finally
# sentrypeer all moved to ROWS above. sentrypeer was the last -- its build
# clones upstream SentryPeer C/Rust source at image-build time rather than
# vendoring interpreted source, and HAVE_RUST=1/new_mode=true in this build
# (confirmed against src/conf.c and tests/unit_tests/test_json_logger.c)
# means sentrypeer_rust::json_logger's json_log_bad_actor_rs() is the writer
# actually exercised, not src/json_logger.c. sentrypeer_rust/src/cli.rs's -N
# flag can clear new_mode back to false, but this image's CMD never passes
# -N -- and it would not matter if it did: under HAVE_RUST != 0,
# src/bad_actor.c compiles the C writer's call site out entirely (#else), so
# json_log_bad_actor_rs() is the only reachable JSON writer either way. That
# is what json_log_rotation_patch.py patches.
# Upstream itself (checked at the pinned SENTRYPEER_REF,
# 008be5ebb451467ca9c76763717bc75916e3fcac) ignores SIGHUP outright
# (src/signal_handler.c's signal(SIGHUP, SIG_IGN)) and has no reopen/logrotate
# knob anywhere, so the collapse-to-SIGHUP shortcut does not apply here.
KNOWN_UNCOVERED: dict[str, tuple[str, str]] = {}

# #2882: sinks that live in a named Docker volume rather than a
# /opt/stacks/apiary/logs/<dir> bind mount are architecturally invisible to
# mounted_log_dirs() above -- that enumeration only walks LOGS_HOST_ROOT
# mounts, and reporter-data:/data (arcane/home/honeypot-utilities/compose.yml)
# is a different mount entirely. Tracked here as its own checked entry
# instead of being silently uncovered the way audit.json was before this
# row existed: 5.99 GB over 25 days (~240 MB/day), no rotation, on a 128M-limited
# container -- found while auditing the same disk-pressure incident #2820
# tracks. Same writer-proof shape ROWS uses (a grep token the rotation
# implementation cannot sensibly drop without stopping being one).
VOLUME_SINKS: list[dict[str, Any]] = [
    {
        "name": "reporter-data/audit.json",
        "writer": ("arcane/home/honeypot-utilities/reporter",
                   ["rotatingWriter", "REPORTER_AUDIT_MAX_BYTES"]),
    },
]


def pruner_find_lines(text: str) -> dict[str, set[str]]:
    """Maps each `/logs/...` directory the pruner walks to the -name globs
    that line credits to IT, quotes stripped.

    Attribution is per line on purpose. Testing a glob against the whole
    file's text (as this script did before #2216's review) cannot tell
    `find /logs/tftp-relay -name 'sessions.json.[0-9]*'` from the same glob
    pasted onto /logs/dicompot's line, which leaves tftp-relay unpruned.
    """
    found: dict[str, set[str]] = {}
    for line in text.splitlines():
        match = re.search(r"\bfind\s+(/logs/\S+)", line)
        if not match:
            continue
        globs = {
            name.strip("'\"")
            for name in re.findall(r"-name\s+('[^']*'|\"[^\"]*\"|\S+)", line)
        }
        found.setdefault(match.group(1), set()).update(globs)
    return found


def rotate_targets(text: str) -> set[str]:
    """Every literal `/logs/...` file path log-maintenance.sh's copytruncate
    rotate() is called on.

    Only literal arguments are collected: the conpot loop's `rotate "$f"`
    resolves from a glob at runtime and cannot be attributed to a directory
    from source, so it is skipped rather than guessed at. That is the
    conservative direction -- an EXEMPT entry can only be proven by a path
    spelled out in the file, never by one this parser inferred.
    """
    return {
        match.group(1)
        for match in (
            re.search(r"^\s*rotate\s+(/logs/\S+)", line)
            for line in text.splitlines()
        )
        if match
    }


def exemption_reason(value: str | dict) -> str:
    """EXEMPT values are a bare reason string or a dict carrying that reason
    alongside the mechanism keys checked below."""
    return value if isinstance(value, str) else value.get("reason", "")


def mounted_log_dirs() -> dict[str, list[str]]:
    """Every `/opt/stacks/apiary/logs/<dir>` bind mount in the stacks, keyed
    by the container-side path the pruner would use, valued by where the
    mount is declared.

    The bare parent mount (`/opt/stacks/apiary/logs:/logs`, used by
    log-maintenance, Filebeat and ip-enrichment to see everything at once)
    names no individual sink and is skipped.
    """
    mount = re.compile(
        rf"^\s*-\s*[\"']?({re.escape(LOGS_HOST_ROOT)}(?:/[^:\"'\s]+)?)\s*:"
    )
    mounts: dict[str, list[str]] = {}
    for compose in sorted(STACKS.glob("*/compose.yml")):
        for number, line in enumerate(compose.read_text().splitlines(), 1):
            match = mount.match(line)
            if not match:
                continue
            host = match.group(1)
            if host == LOGS_HOST_ROOT:
                continue
            container = LOGS_CONTAINER_ROOT + host[len(LOGS_HOST_ROOT):]
            mounts.setdefault(container, []).append(
                f"{compose.relative_to(ROOT)}:{number}")
    return mounts


def tree_contains(rel_root: str, needle: str) -> bool:
    """True if some tracked, non-test file under rel_root contains needle.

    #2921: two things used to let a deleted implementation still pass. (1)
    A token that also appears verbatim in the row's own test file (common,
    since a test asserts on the constant it exercises) satisfied the proof
    with the implementation gone -- test paths are excluded now. (2) A
    stale __pycache__/*.pyc left over from a previous test run carries the
    token as a bytecode constant and is invisible to `git status` -- only
    files `git ls-files` actually tracks are read now, or, where ROOT is
    not a checkout to ask (see _tracked_files), only files SKIP_DIRS does
    not exclude.
    """
    base = ROOT / rel_root
    tracked = _tracked_files()
    if base.is_file():
        if tracked is not None and base not in tracked:
            return False
        if _is_test_path(base.relative_to(ROOT).as_posix()):
            return False
        return needle in base.read_text(encoding="utf-8", errors="replace")
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if SKIP_DIRS.intersection(path.parts):
            continue
        if tracked is not None and path not in tracked:
            continue
        rel_posix = path.relative_to(ROOT).as_posix()
        if _is_test_path(rel_posix):
            continue
        try:
            if needle in path.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def main() -> int:
    findings: list[str] = []
    maintenance_text = MAINTENANCE.read_text()
    pruned = pruner_find_lines(maintenance_text)
    rotated = rotate_targets(maintenance_text)
    mounts = mounted_log_dirs()

    for row in ROWS:
        row_id = f"{row['dir']} ({', '.join(row['globs'])})"
        for glob in row["globs"]:
            if glob.strip("'\"") not in pruned.get(row["dir"], set()):
                findings.append(
                    f"pruner half missing: {MAINTENANCE.relative_to(ROOT)} has "
                    f"no `find {row['dir']} ... -name {glob}` line"
                )
        writer = row["writer"]
        if writer is None:
            # #2826: elasticpot's writer is vendor-internal (baked into the
            # pinned dtagdevsec/elasticpot image), so there is no in-tree
            # token to grep -- the ROWS ledger still requires a
            # "writer_note" explaining how the self-rotation was confirmed
            # (live measurement, not source) rather than silently skipping
            # the proof.
            if not row.get("writer_note"):
                findings.append(
                    f"writer half unproven: row {row_id} has writer=None but "
                    f"no writer_note explaining how self-rotation was confirmed"
                )
        else:
            rel_root, tokens = writer
            for token in tokens:
                if not tree_contains(rel_root, token):
                    findings.append(
                        f"writer half missing: no rotation implementation carrying "
                        f"{token!r} found under {rel_root} (row {row_id})"
                    )

    # #2882: volume-backed sinks outside /logs, checked the same way ROWS
    # proves its writer half -- a grep token the rotation implementation
    # cannot drop without stopping being one.
    for sink in VOLUME_SINKS:
        rel_root, tokens = sink["writer"]
        for token in tokens:
            if not tree_contains(rel_root, token):
                findings.append(
                    f"volume sink writer half missing: no rotation "
                    f"implementation carrying {token!r} found under "
                    f"{rel_root} (sink {sink['name']})"
                )

    # #2826 review: an exemption that asserts a mechanism must prove it, or
    # the ledger becomes a place to write a coverage claim down instead of a
    # place to record one. Deleting the rotate() line these three entries name
    # left the reasons asserting coverage that no longer existed, and the
    # check stayed green -- exactly the failure this script exists to end.
    for exempt_dir, value in sorted(EXEMPT.items()):
        if not exemption_reason(value).strip():
            findings.append(
                f"exemption without a reason: EXEMPT claims {exempt_dir} but "
                f"says nothing about what it holds or why nothing prunes it"
            )
        if isinstance(value, str):
            continue
        for target in value.get("rotates", []):
            if not (target == exempt_dir or target.startswith(exempt_dir + "/")):
                findings.append(
                    f"exemption mis-attributed: EXEMPT[{exempt_dir}] claims "
                    f"rotate {target}, which is not inside {exempt_dir}"
                )
            elif target not in rotated:
                findings.append(
                    f"exemption unproven: EXEMPT[{exempt_dir}] says "
                    f"log-maintenance.sh rotates {target}, but "
                    f"{MAINTENANCE.relative_to(ROOT)} has no `rotate {target}` "
                    f"line -- restore it or reword the exemption"
                )
        writer = value.get("writer")
        if writer:
            rel_root, tokens = writer
            for token in tokens:
                if not tree_contains(rel_root, token):
                    findings.append(
                        f"exemption unproven: EXEMPT[{exempt_dir}] claims a "
                        f"self-bounding writer, but no {token!r} was found "
                        f"under {rel_root}"
                    )

    # Reverse direction: claim every find line the pruner actually carries.
    for find_dir in sorted(pruned):
        if not any(find_dir == row["dir"] or find_dir.startswith(row["dir"] + "/")
                   for row in ROWS):
            findings.append(
                f"unledgered pruner line: log-maintenance.sh runs `find {find_dir}` "
                f"but no ROW claims it -- add a parity row for it"
            )

    # #2216 acceptance criterion 4: a new stack's mount is the thing that
    # cannot be omitted, so start the enumeration there rather than from the
    # halves an author remembered to edit.
    ledgered = {row["dir"] for row in ROWS} | set(EXEMPT) | set(KNOWN_UNCOVERED)
    for mounted, origins in sorted(mounts.items()):
        if mounted in ledgered:
            continue
        findings.append(
            f"unledgered log mount: {origins[0]} bind-mounts {mounted} but "
            f"nothing accounts for it -- add a ROWS entry (it self-rotates "
            f"and is pruned), an EXEMPT reason (it needs neither), or a "
            f"KNOWN_UNCOVERED entry naming the issue that tracks the gap"
        )

    # ...and drop the entry when the stack goes. A ledger nobody prunes
    # starts describing a fleet that no longer exists (wordpot, #2469).
    for stale, source in (("ROWS", {row["dir"] for row in ROWS}),
                          ("EXEMPT", set(EXEMPT)),
                          ("KNOWN_UNCOVERED", set(KNOWN_UNCOVERED))):
        for entry in sorted(source - set(mounts)):
            findings.append(
                f"stale ledger entry: {stale} claims {entry} but no "
                f"arcane/home/*/compose.yml mounts it any more -- remove it"
            )

    if findings:
        print("JSON sink retention parity check failed:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(f"JSON sink retention parity check passed "
          f"({len(ROWS)} rotating directories, both halves present; "
          f"{len(mounts)} mounted log directories all accounted for, "
          f"{len(KNOWN_UNCOVERED)} of them known-uncovered; "
          f"{len(VOLUME_SINKS)} volume-backed sink(s) outside /logs proven).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
