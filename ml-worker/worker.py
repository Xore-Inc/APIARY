#!/usr/bin/env python3
"""
ML Worker — honeypot-stack anomaly detection service.

Polls all honeypot Elasticsearch indices, runs three complementary
unsupervised models, and writes scored anomalies back to ES index
'ml-anomalies'. Notifies the dashboard via Redis pub/sub.

See docs/ml-worker-plan.md for full architecture and roadmap.
"""
import os
import time
import json
import hashlib
from collections import deque
from datetime import datetime, time as dt_time, timezone, timedelta

import numpy as np
import redis
from elasticsearch import Elasticsearch, NotFoundError
from loguru import logger

from models.isolation_forest import (IsoForestModel, MAX_TRAIN_SAMPLES, _get_ip, _get_port,
                                     _get_dst_ip, _get_src_port, _get_transport_proto,
                                     is_our_own_address)
from models.lstm_autoencoder import LSTMAEModel
from models.session_features import SessionFeatureTracker, compute_batch_session_features

# #1971: the poll/checkpoint mechanics below (#168 boundary semantics,
# #188 failure-vs-empty shape, #190 batch caps) are the reference
# implementation of the repo's shared incremental-checkpoint consume
# pattern and now live in the vendored, contract-tested
# analysis/es-consume/es_consume.py (this file carries a byte-identical
# copy -- ml-worker/tests/test_es_consume_vendoring.py enforces that).
# advance_checkpoint()/fetch_new_events() stay as thin wrappers so every
# call site and test keeps its exact signature and log text.
import es_consume  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration (all overridable via env vars)
# ---------------------------------------------------------------------------
ES_HOST          = os.getenv("ES_HOST",           "http://elasticsearch:9200")
# Empty, not a redis:// default: absent unless explicitly configured, and
# best-effort when it is. ml-gpu-coordinated-roadmap.md §1 decision 1 /
# Milestone B step 5 -- Elasticsearch is the authoritative write and the
# initial dashboard transport; Redis is a notification nice-to-have, and the
# base ml-worker/docker-compose.yml no longer runs a Redis service at all
# (#62). A REDIS_URL set on a host that added one back still works.
REDIS_URL        = os.getenv("REDIS_URL",         "")
POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL",   "30"))     # seconds
# #172: explicit UTC wall-clock slots, not a restart-relative interval --
# ml-gpu-coordinated-roadmap.md §1 decision 7: "Explicit UTC slots replace
# restart-relative retraining intervals so GPU workloads can actually be
# separated." A restart-relative timer (the old RETRAIN_INTERVAL-since-
# process-start) can't be scheduled against anything else, since its next
# firing depends on when the process happened to (re)start. Four slots
# roughly matches the old 6h-interval default's cadence, now at fixed,
# predictable times instead.
RETRAIN_SLOTS_UTC = os.getenv("RETRAIN_SLOTS_UTC", "03:00,09:00,15:00,21:00")
# ML_ALERT_THRESHOLD is read further down, immediately before
# _severity_bands() derives SEVERITY_BANDS from it (#1969) -- keeping the
# derivation physically adjacent to the config read is the point.
MODEL_DIR        = os.getenv("MODEL_DIR",         "/models")
LOG_LEVEL        = os.getenv("LOG_LEVEL",         "INFO")

# #1968: retention for the two indices this worker owns (see
# build_ilm_policy / run_worker's bootstrap order). Windows follow #261's
# convention -- every retention decision in this stack is an env knob over a
# stable-named policy, not a hardcoded constant -- and replace the previous
# answer ("no policy at all") with a recorded one: anomaly documents carry
# operator dispositions, the labelled corpus #1794/#1797 feed on, so they
# keep a year; retrain/drift evidence ages much faster.
ML_ANOMALIES_RETENTION_DAYS = int(os.getenv("ML_ANOMALIES_RETENTION_DAYS", "365"))
ML_METRICS_RETENTION_DAYS   = int(os.getenv("ML_METRICS_RETENTION_DAYS",   "90"))

ANOMALY_ILM_POLICY   = "ml-anomalies-retention"
METRICS_ILM_POLICY   = "ml-worker-metrics-retention"

# Operator-owned fields (#1968): written by the dashboard's disposition
# endpoint, never by scoring -- write_anomaly() preserves any previously set
# value across the deterministic-id rewrite instead of letting a checkpoint
# replay silently wipe an analyst's verdict.
DISPOSITION_FIELDS = ("status", "disposition_reason", "disposition_by", "disposed_at")

# Drift detection (#65, docs/ml-worker-plan.md §11.4): a rolling window over
# the last DRIFT_WINDOW composite scores this worker actually computed.
# Exceeding DRIFT_ANOMALY_RATE could mean a real attack campaign or a stale
# model failing to generalize -- this can't tell which, which is why it
# triggers *retraining* (still gated by the acceptance bar, so a bad
# retrain still can't make things worse) rather than any automatic response
# to the traffic itself.
DRIFT_WINDOW       = int(os.getenv("DRIFT_WINDOW", "500"))
DRIFT_ANOMALY_RATE = float(os.getenv("DRIFT_ANOMALY_RATE", "0.15"))
DRIFT_RETRAIN_COOLDOWN_MINUTES = int(os.getenv("DRIFT_RETRAIN_COOLDOWN_MINUTES", "60"))

# #190: the regular poll path had no cap, unlike the retrain path
# (MAX_TRAIN_SAMPLES) -- a backlog large enough to need more than one
# cycle (from downtime, a slow retrain blocking this same loop, or just a
# traffic burst) turned into a single, arbitrarily long scoring pass with
# no checkpoint progress and no crash-safety net until the whole thing
# finished. Capped to the same order of magnitude as one retrain's own
# fetch -- large enough that ordinary cycles still complete in one pass,
# small enough that a real backlog now checkpoints incrementally across
# several cycles instead of one unbounded one.
MAX_POLL_BATCH = int(os.getenv("MAX_POLL_BATCH", "5000"))

# Server-side keep-alive for one poll's scroll context (passed to
# es.search/es.scroll by fetch_new_events's transport adapters below).
SCROLL_KEEPALIVE = "2m"

# #188: fetch_new_events() already retries every POLL_INTERVAL by nature of
# the main loop calling it again next cycle -- no separate backoff/jitter is
# added here, since a fixed retry is simpler and there's no evidence a
# backend that's briefly unreachable benefits from anything more elaborate.
# What was missing was distinguishing "briefly lost ES, recovered" from
# "unreachable for an extended period" -- this many CONSECUTIVE failed
# cycles for one index pattern before it's treated as sustained rather
# than a transient blip (the one blip actually observed, #167/#188's own
# report, self-healed after exactly one cycle).
ES_UNAVAILABLE_ALERT_AFTER = int(os.getenv("ES_UNAVAILABLE_ALERT_AFTER", "3"))

# Source indices to monitor. #61 found these matched zero real indices --
# the actual shape (docs/ml-worker-plan.md §2/§5.3, verified live 2026-07-31)
# is one unified honeypot-v2-* data stream for every sensor (disambiguated
# per-event by extract_features()'s own field reads, not by index name --
# event.sensor isn't reliably set for every sensor, see #132) plus
# suricata-v2-<event_type>-* for network/IDS events.
#
# #1741/#1742: zeek-v1-conn-* is added because Suricata's flow/netflow records
# are being retired -- they are 80.1% of its document volume, and roughly that
# share of the Suricata input this worker trains on. Zeek's conn.log is the
# replacement and is strictly richer per record: duration, bytes and packets in
# both directions, conn_state, history, inferred service, and a Community ID.
#
# Only the conn logs, not zeek-v1-*. The protocol logs (ssl, ssh, http, the
# ICSNPP ones) are per-transaction rather than per-connection, so including
# them would silently reweight the training set toward whichever protocol
# happened to be noisiest that hour.
#
# _resolve_flow_sides() stays necessary and gets *more* correct here, not less:
# conn.log is bidirectional like netflow was, but its orientation is explicit
# originator/responder rather than literal packet direction, which is the exact
# ambiguity #174 was written to work around.
SOURCE_INDICES = [
    "honeypot-v2-*",
    "suricata-v2-*",
    "zeek-v1-conn-*",
]

ANOMALY_INDEX  = "ml-anomalies"
STATE_INDEX    = "ml-worker-state"
METRICS_INDEX  = "ml-worker-metrics"
REDIS_CHANNEL  = "ml-anomaly-events"

def _severity_bands(alert_threshold: float) -> list:
    """Derive the severity bands from ML_ALERT_THRESHOLD (#1969).

    Previously SEVERITY_BANDS were hardcoded absolutes (0.75/0.85/0.95)
    while THRESHOLD was env-configurable -- raise the threshold to 0.85
    and every alert was still labelled by bands calibrated for a 0.75
    deployment, so severity distributions silently changed meaning on any
    threshold move. The bands now derive from it (medium starts AT the
    alerting bar itself, high/critical at fixed offsets above), so the two
    can no longer drift apart. With the default threshold of 0.75 this
    reproduces the historical constants exactly.
    """
    return [
        (alert_threshold + 0.20, "critical"),
        (alert_threshold + 0.10, "high"),
        (alert_threshold,        "medium"),
    ]


THRESHOLD = float(os.getenv("ML_ALERT_THRESHOLD", "0.75"))
SEVERITY_BANDS = _severity_bands(THRESHOLD)

# Ensemble formula, docs/ml-worker-plan.md §4.4. Single source of truth (#63)
# -- previously duplicated verbatim in write_anomaly() and the main loop,
# a silent-drift risk on any future weight tuning.
COMPOSITE_WEIGHTS = {"isolation_forest": 0.4, "lstm_ae": 0.4, "hbos": 0.2}


def compute_composite(scores: dict) -> float:
    """Availability-aware ensemble score (#1969, docs §4.4).

    scores values are the detectors' normalised opinions in [0, 1], or
    None where a detector has NO opinion this event: skipped by its gate,
    untrained, insufficient history, or an inference failure (each
    model's own docstring defines exactly when). A None is excluded from
    BOTH numerator and denominator -- "didn't run" must not read as
    "scored perfectly normal" (the old skipped-LSTM-as-0.0 encoding,
    which acted as an undocumented veto: with THRESHOLD=0.75 and no LSTM
    contribution the composite capped at 0.6, so nothing could ever fire
    without LSTM running), nor as a real vote when a placeholder like an
    untrained IsoForest's constant 0.5 kept its full 0.4 weight (#1959:
    6,669 alerts partly cleared the bar on that floor alone). The
    remaining weights are renormalised to sum to 1, so each contributing
    detector's opinion carries exactly the relative influence its weight
    prescribes.

    Consequence worth stating plainly: single-detector alerts are now
    possible -- e.g. {iso=0.9, everything else absent} composites to 0.9
    -- whereas before they were unreachable below THRESHOLD<=0.6. That is
    deliberate: the honest answer to "one calibrated detector says 0.9"
    is not silence. contributing_detectors() is written onto every anomaly
    document precisely so such alerts are identifiable after the fact.
    """
    present = {k: v for k, v in scores.items() if k in COMPOSITE_WEIGHTS and v is not None}
    total_weight = sum(COMPOSITE_WEIGHTS[k] for k in present)
    if not present or total_weight <= 0:
        return 0.0
    return sum(COMPOSITE_WEIGHTS[k] * v for k, v in present.items()) / total_weight


def contributing_detectors(scores: dict) -> list:
    """Which detectors produced an opinion for this scoring (#1969) --
    sorted keyword list, written verbatim into each ml-anomalies document
    next to model_scores (whose values carry the same information as
    nulls, but aggregations over a flat keyword field beat object-field
    archaeology for the common 'which detector fired this' question).
    """
    return sorted(k for k in scores if k in COMPOSITE_WEIGHTS and scores[k] is not None)


def severity(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"


def ensure_index(es: Elasticsearch, index: str, mapping: dict) -> None:
    if not es.indices.exists(index=index):
        es.indices.create(index=index, body=mapping)
        logger.info(f"Created index {index}")


def _bootstrap_checkpoint() -> dict:
    """First-run default: start from 1 hour ago."""
    return {
        "last_timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "seen_ids": [],
    }


# #2236: last checkpoint read back cleanly from STATE_INDEX, per index
# pattern. Doubles as (a) the fallback when a later read transiently fails,
# and (b) the high-water mark that makes an actual rewind of stored state
# visible instead of silent.
_LAST_GOOD_CHECKPOINT: "dict[str, dict]" = {}


def load_checkpoint(es: Elasticsearch, index_pattern: str) -> "tuple[dict | None, bool]":
    """Return the complete checkpoint tuple for this index pattern as
    (checkpoint, ok), mirroring fetch_new_events()'s convention -- the run
    loop treats ok=False exactly like a failed fetch (#188).

    The checkpoint is {"last_timestamp": str, "seen_ids": [str, ...]}.

    seen_ids are the document IDs already processed exactly AT
    last_timestamp (#168) -- a plain timestamp checkpoint with an exclusive
    `gt` requery silently drops any sibling document that shares the exact
    @timestamp with the checkpointed one but arrived (or was returned by ES)
    after the checkpoint was saved. ml-gpu-coordinated-roadmap.md §1 names
    this explicitly: "timestamp-only checkpoints can skip equal-timestamp
    events." Pairing the timestamp with the set of IDs already handled at
    that exact boundary, and requerying inclusively (see fetch_new_events),
    fixes it without needing a full PIT/search_after implementation.

    #2236: only elasticsearch's NotFoundError -- the state doc genuinely
    not existing yet -- yields the 1-hour bootstrap default. Before this
    fix ANY es.get failure (timeout, 5xx, connection refused mid-run) fell
    into what its comment labelled the first-run default, so one flaky
    read on an hours-old deployment silently rewound scoring to one hour
    ago with no evidence left behind. Now:

    - NotFoundError       -> bootstrap default, ok=True.
    - anything else with  -> last in-memory copy, ok=True: ES flapping
      a cached copy          degrades to score-from-last-known-position,
                           which replays at most the reads ES can't serve
                           rather than everything since N-1h.
    - anything else with  -> ok=False. The loop skips this cycle and lets
      no cache              the existing sustained-outage counter (#188)
                           see it, rather than restarting from the
                           bootstrap position every POLL_INTERVAL.

    A clean read also rewinds-checks against the cache: ISO-8601 stamps
    from our own producers compare correctly enough lexicographically for
    a loud warning (both sort Y-m-dTH:M:S digit by digit; only the zone
    suffix shape differs), so a regressed/deleted state doc is diagnosed
    in the log instead of silently re-read.
    """
    try:
        doc = es.get(index=STATE_INDEX,
                     id=hashlib.md5(index_pattern.encode()).hexdigest())
        source = doc["_source"]
        checkpoint = {
            "last_timestamp": source["last_timestamp"],
            "seen_ids": source.get("seen_ids", []),
        }
    except NotFoundError:
        checkpoint = _bootstrap_checkpoint()
    except Exception as exc:
        cached = _LAST_GOOD_CHECKPOINT.get(index_pattern)
        if cached is not None:
            logger.warning(
                f"{index_pattern}: checkpoint read failed ({exc}); continuing from "
                f"in-memory copy at {cached['last_timestamp']} until the next clean read")
            return dict(cached), True
        logger.warning(
            f"{index_pattern}: checkpoint read failed ({exc}) and no in-memory copy "
            f"exists; failing this poll cycle like a fetch failure (#188) instead of "
            f"silently restarting from one hour ago")
        return None, False

    previous = _LAST_GOOD_CHECKPOINT.get(index_pattern)
    if previous is not None and checkpoint["last_timestamp"] < previous["last_timestamp"]:
        logger.warning(
            f"{index_pattern}: stored checkpoint moved backwards, "
            f"{previous['last_timestamp']} -> {checkpoint['last_timestamp']}; possible "
            f"state-index deletion or rewrite -- events between those positions will be rescored")
    _LAST_GOOD_CHECKPOINT[index_pattern] = checkpoint
    return checkpoint, True


def save_checkpoint(es: Elasticsearch, index_pattern: str, last_timestamp: str, seen_ids: list) -> None:
    doc_id = hashlib.md5(index_pattern.encode()).hexdigest()
    es.index(index=STATE_INDEX, id=doc_id,
             document={
                 "index_pattern": index_pattern,
                 "last_timestamp": last_timestamp,
                 "seen_ids": seen_ids,
             })


def advance_checkpoint(events: list, previous: "dict | None") -> dict:
    """Compute the next checkpoint tuple (#168) from a batch of processed
    events (ascending by @timestamp) and the checkpoint they were fetched
    against. Keeps only the IDs at the NEW max timestamp -- everything
    strictly before it can never be re-queried once the checkpoint advances
    past it (an inclusive requery against the new, later last_timestamp
    excludes anything earlier entirely), so seen_ids stays bounded by
    however many documents happen to share one exact timestamp, not by
    total history.
    """
    # #1971: implementation extracted verbatim into the vendored shared
    # module (analysis/es-consume/es_consume.py); this wrapper keeps the
    # call-site/test-facing name and shape. That module's contract suite
    # drives both this code (as vendored) and a Go port through the same
    # fixture stream -- advance_checkpoint's equal-timestamp semantics are
    # now pinned cross-language, not just by this worker's own tests.
    return es_consume.advance_checkpoint(events, previous)


def fetch_new_events(es: Elasticsearch, index_pattern: str,
                    since: str, page_size: int = 500,
                    max_total: "int | None" = None,
                    exclude_ids: "set | None" = None) -> "tuple[list, bool]":
    """Scroll events from the given index pattern at or after `since`
    (inclusive). Returns (events, ok) -- ok is False when the ES call
    itself failed, distinct from a genuinely empty (events=[], ok=True)
    poll (#188: the caller could not previously tell "nothing new" apart
    from "the fetch failed", since both returned an empty list the same
    way). A scroll that fails partway still returns whatever pages were
    already read with ok=False -- safe to checkpoint against per
    advance_checkpoint's own equal-timestamp handling (#168): every event
    already read sorts at or before anything not yet read, so advancing
    only as far as what's in hand can't skip anything, it just leaves the
    rest for the next poll to pick back up.

    Inclusive (gte) rather than the original exclusive (gt) so a caller
    protecting a persisted checkpoint (#168) can safely re-include the exact
    boundary timestamp and filter out only the specific documents already
    processed there via exclude_ids -- gt alone can never distinguish
    "already handled" from "arrived later with the same timestamp" and
    silently drops the latter. exclude_ids is optional: the retrain path
    below has no persisted checkpoint to protect (it always re-fetches a
    fresh 24h window from a freshly computed wall-clock `since` on every
    call) and leaves it unset.

    max_total bounds how much this pulls into memory in one call -- the
    normal poll path leaves it unset (checkpoints keep each call small
    already), but the retrain path's 24h window across 2 index patterns has
    no other cap, and MAX_TRAIN_SAMPLES only bounds what retrain() fits on
    AFTER everything's already been fetched and held in memory (#62 task 33).
    """
    # #1971: body extracted verbatim into the vendored shared module; the
    # three adapters below are exactly the elasticsearch-py calls this file
    # used to make inline, so behaviour (including the exact log text) is
    # unchanged. The engine's fixture contract additionally pins these
    # semantics cross-language -- see the wrapper note on advance_checkpoint.
    def _warn(message):
        logger.warning(f"Fetch error for {index_pattern}: {message}")

    return es_consume.fetch_events_since(
        lambda query: es.search(index=index_pattern, body=query, scroll=SCROLL_KEEPALIVE),
        lambda scroll_id: es.scroll(scroll_id=scroll_id, scroll=SCROLL_KEEPALIVE),
        lambda scroll_id: es.clear_scroll(scroll_id=scroll_id),
        since,
        page_size=page_size,
        max_total=max_total,
        exclude_ids=exclude_ids,
        warn=_warn,
    )


def write_retrain_metric(es: Elasticsearch, model_name: str, result, dropped_count: int = 0) -> None:
    """Evidence for one retrain() call, accepted or not (#65,
    docs/ml-worker-plan.md §11.1/§11.4). Best-effort like write_anomaly()'s
    Redis publish: a metrics-write failure must never take down the retrain
    cycle that already succeeded or failed on its own terms.

    dropped_count (#2984): how many rows quarantine_retrain_events() dropped
    from this cycle's fetched batch before either model ever saw it -- same
    reviewable-metric contract as write_malformed_event_metric() (#171), just
    surfaced as a count here since a retrain batch is scored as one unit, not
    per-row."""
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "retrain",
        "model": model_name,
        "accepted": result.accepted,
        "reason": result.reason,
        "train_samples": result.train_samples,
        "holdout_samples": result.holdout_samples,
        "anomaly_rate_new": round(result.anomaly_rate_new, 4),
        "anomaly_rate_previous": round(result.anomaly_rate_previous, 4) if result.anomaly_rate_previous is not None else None,
        "dropped_count": dropped_count,
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write retrain metric for {model_name} (non-fatal): {exc}")
    level = logger.info if result.accepted else logger.warning
    level(f"retrain[{model_name}] accepted={result.accepted} reason={result.reason}")


def write_es_unavailable_metric(es: Elasticsearch, index_pattern: str,
                               consecutive_failures: int, downtime_seconds: int) -> None:
    """Retrospective evidence that Elasticsearch was unreachable for a
    sustained period, not a transient blip (#188) -- written on recovery,
    not during the outage. Elasticsearch is unreachable BY DEFINITION for
    as long as this would need to write, so there's no way to surface a
    sustained outage in real time through the only channel this worker has
    (this same ES index); the log's ERROR-level line (see run_worker(),
    logged once the outage crosses ES_UNAVAILABLE_ALERT_AFTER cycles) is
    the real-time signal, this is the durable, after-the-fact record.
    downtime_seconds is an estimate (consecutive_failures * POLL_INTERVAL),
    not measured wall-clock time, since nothing here observes ES going down
    the instant it happens."""
    doc = {
        "@timestamp":           datetime.now(timezone.utc).isoformat(),
        "kind":                 "es_unavailable",
        "source_index":         index_pattern,
        "consecutive_failures": consecutive_failures,
        "downtime_seconds":     downtime_seconds,
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write es_unavailable metric (non-fatal): {exc}")
    logger.warning(
        f"{index_pattern}: Elasticsearch recovered after {consecutive_failures} consecutive "
        f"failed poll cycles (~{downtime_seconds}s) -- treating that as a sustained outage, not a blip"
    )


def backlog_count(es: Elasticsearch, index_pattern: str, since: str) -> "int | None":
    """How many documents are queued at or after this checkpoint (#190) --
    called only when a poll cycle's fetch hit MAX_POLL_BATCH, so this stays
    a signal tied to genuine buildup rather than an every-30s metric write
    regardless of whether there's anything to report (ml-worker-metrics has
    no retention policy of its own; a lag metric worth having in steady
    state is a separate, deliberate addition, not a side effect of this
    fix). None on a query failure -- best-effort, must never take the poll
    cycle down over a metric."""
    try:
        resp = es.count(index=index_pattern, body={"query": {"range": {"@timestamp": {"gte": since}}}})
        return resp.get("count")
    except Exception as exc:
        logger.warning(f"Backlog count failed for {index_pattern} (non-fatal): {exc}")
        return None


def write_backlog_metric(es: Elasticsearch, index_pattern: str, backlog: int) -> None:
    doc = {
        "@timestamp":    datetime.now(timezone.utc).isoformat(),
        "kind":          "backlog",
        "source_index":  index_pattern,
        "backlog_count": backlog,
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write backlog metric (non-fatal): {exc}")
    logger.warning(f"{index_pattern}: {backlog} events still queued past the checkpoint after this cycle's capped batch")


def write_malformed_event_metric(es: Elasticsearch, event: dict, exc: Exception) -> None:
    """Evidence that one event was skipped rather than crashing the batch
    (#171) -- best-effort, same rationale as write_retrain_metric()/
    write_drift_metric(): a metrics-write failure must never make a
    skip-and-continue decision take anything else down with it."""
    doc = {
        "@timestamp":      datetime.now(timezone.utc).isoformat(),
        "kind":            "malformed_event",
        "source_event_id": event.get("_id"),
        "source_index":    event.get("_index"),
        "error":           str(exc),
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as write_exc:
        logger.warning(f"Failed to write malformed-event metric (non-fatal): {write_exc}")
    logger.warning(f"Skipping malformed event {doc['source_event_id']} in {doc['source_index']}: {exc}")


def quarantine_retrain_events(es: Elasticsearch, iso_model, events: list) -> tuple:
    """Per-event guard for the retrain batch (#2984), same quarantine
    contract score_and_write_events() already has for live scoring (#171):
    a source that can't survive extract_features() is dropped and recorded
    as a reviewable metric instead of raising out of retrain().

    Probes with both iso_model.extract_features() and
    compute_batch_session_features() -- the two per-row entry points both
    models' retrain() calls go through (isolation_forest.retrain() and
    lstm_autoencoder.retrain() each call compute_batch_session_features()
    themselves; extract_features() covers the rest of each model's own
    field reads).

    Returns (sources, dropped_count) -- sources is `events` filtered down to
    just the ones that survived, in original order, ready to pass straight
    to IsoForestModel.retrain()/LSTMAEModel.retrain()."""
    sources = []
    dropped = 0
    for event in events:
        src = event.get("_source", {})
        try:
            iso_model.extract_features(src)
            compute_batch_session_features([src])
        except Exception as exc:
            write_malformed_event_metric(es, event, exc)
            dropped += 1
            continue
        sources.append(src)
    return sources, dropped


def score_and_write_events(es: Elasticsearch, rdb, iso_model, lstm_model,
                          events: list, recent_flags, session_tracker=None) -> None:
    """Score every event in one fetched batch, writing anomalies over
    THRESHOLD and updating recent_flags for drift detection. Extracted from
    run_worker()'s loop so a malformed event's failure mode is directly
    testable (#171) rather than only reachable by driving the whole
    infinite polling loop.

    One event's failure (a non-numeric destination.port, any other shape
    extract_features() doesn't defensively handle) is caught, logged with
    enough context to diagnose, and recorded as a best-effort metric --
    never allowed to abort the rest of the batch. run_worker() advances the
    checkpoint after this returns, over the full `events` list regardless
    of which ones failed here, so a malformed event's position is always
    skipped past rather than being re-fetched and failing again forever
    (roadmap baseline: "bad events cannot stop a batch").

    session_tracker (#277): supplies real cmd_count/failed_logins_1h/
    unique_ports_1h, observed exactly once per event here and reused for
    both iso_model.extract_features() and lstm_model.score() -- optional
    (defaults to None, falling back to extract_features()'s own pre-#277
    neutral defaults) only so existing direct callers/tests that don't care
    about these three features don't have to construct a tracker.

    #1227: feature extraction stays a per-event pass (cheap, ~0.2ms/event,
    and this is where a single malformed event's own error is caught and
    isolated per event() -- see the module docstring above), but
    IsolationForest/HBOS scoring is now ONE batched call over every
    successfully-extracted event's features instead of one call per event.
    Confirmed live (see isolation_forest.py's score_batch() docstring) that
    the per-row path cost ~1000x more than the batched one for numerically
    identical scores -- this was ml-worker's actual classification-backlog
    bottleneck (#1227), not a capacity/hardware problem. LSTM stays
    per-event: its own per-IP sliding-window state is inherently
    sequential, and it's already cheap (~3ms/call) next to what
    iso_model.score()/hbos_score() used to cost.
    """
    extracted = []  # (event, features, session_feats) for every event that survived extraction
    for event in events:
        try:
            src = event.get("_source", {})
            session_feats = session_tracker.observe(src) if session_tracker is not None else {}
            features = iso_model.extract_features(src, **session_feats)
            extracted.append((event, features, session_feats))
        except Exception as exc:
            write_malformed_event_metric(es, event, exc)

    if not extracted:
        return

    # One state id per batch (#1968): promotions don't happen inside a
    # scoring batch, so batch-consistent is document-consistent here.
    checkpoint = model_state_id(iso_model, lstm_model)

    matrix = np.vstack([features for _, features, _ in extracted])
    iso_scores = iso_model.score_batch(matrix)
    hbos_scores = iso_model.hbos_score_batch(matrix)  # fast pre-filter
    # None from either batch (#1969) means that detector is untrained and
    # has no opinion on ANY event this cycle -- recorded per event as None,
    # excluded by compute_composite(), and reported via contributing_detectors().

    suppressed_own_address = 0
    for i, (event, features, session_feats) in enumerate(extracted):
        try:
            src = event.get("_source", {})
            # An untrained IsoForest/HBOS batch is None (no opinion), not a
            # constant 0.5 vote carrying its full weight (#1969: the
            # constant floor was indistinguishable from a real middling
            # score -- #1959 measured 6,669 alerts partly clearing the bar
            # on exactly that floor).
            iso_v  = float(iso_scores[i]) if iso_scores is not None else None
            hbos_v = float(hbos_scores[i]) if hbos_scores is not None else None

            lstm_score = None

            # Only run LSTM if HBOS flagged as potentially anomalous. This
            # stays an EXECUTION gate (LSTM costs ~3ms/call; the flag keeps
            # it off clear events) -- it no longer decides MEANING: an
            # LSTM skipped here records None and compute_composite()
            # renormalises over the detectors that did produce opinions,
            # so the old encoding (skipped -> 0.0 -> silent veto capping
            # every composite at 0.6 under the default threshold) is gone.
            if hbos_v is not None and hbos_v > 0.5:
                lstm_score = lstm_model.score(src, cmd_count=session_feats.get("cmd_count", 0))

            scores = {
                "isolation_forest": iso_v,
                "hbos":             hbos_v,
                "lstm_ae":          lstm_score,
            }
            composite = compute_composite(scores)
            recent_flags.append(composite >= THRESHOLD)

            if composite >= THRESHOLD:
                # #1959: an alert about an address we own is not actionable.
                # The event is still scored -- drift detection above stays
                # honest, and suppressing the score too would change what the
                # retrain gate sees -- but no operator-facing anomaly is
                # written for our own loopback, tunnel or LAN traffic.
                own = _get_ip(src)
                if own and is_our_own_address(own):
                    suppressed_own_address += 1
                else:
                    explanation = iso_model.explain(features, scores)
                    write_anomaly(es, rdb, event, scores, explanation,
                                  checkpoint_id=checkpoint)
        except Exception as exc:
            write_malformed_event_metric(es, event, exc)

    if suppressed_own_address:
        # Logged rather than silent: a suppression that hides a real volume
        # problem would be worse than the alerts it removes, and this is the
        # only place the count is visible.
        logger.info(
            f"suppressed {suppressed_own_address} anomal"
            f"{'y' if suppressed_own_address == 1 else 'ies'} on addresses we own "
            f"(loopback/WireGuard/LAN/WAN) out of {len(extracted)} scored events"
        )


def parse_retrain_slots(raw: str) -> list:
    """Parse RETRAIN_SLOTS_UTC (#172) -- comma-separated HH:MM values, UTC
    -- into sorted (hour, minute) tuples. Empty/blank entries are skipped
    so a trailing comma or blank env var doesn't raise."""
    slots = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        hour_str, minute_str = part.split(":")
        slots.append((int(hour_str), int(minute_str)))
    return sorted(slots)


def next_retrain_slot_id(now: datetime, slots: list) -> "str | None":
    """Pure decision function (#172): given the current UTC time and the
    configured slot boundaries, return an identifier (that boundary's own
    ISO timestamp) for the most recent slot that has already passed --
    today's, or yesterday's last one if none have passed yet today. None if
    no slots are configured.

    This identifier is compared against the last one a retrain actually
    fired for (persisted, see load/save_last_fired_slot) to decide whether
    one is due. Because it's derived purely from wall-clock time and the
    configured schedule -- never from when this process happened to start
    -- two workers (or the same worker restarted at any two different
    times) asked "what's due right now?" always agree, which is exactly
    the coordination property a restart-relative interval couldn't offer.
    """
    if not slots:
        return None
    today = now.date()
    candidates = [datetime.combine(today, dt_time(h, m), tzinfo=timezone.utc) for h, m in slots]
    passed = [c for c in candidates if c <= now]
    if passed:
        boundary = max(passed)
    else:
        h, m = slots[-1]
        boundary = datetime.combine(today - timedelta(days=1), dt_time(h, m), tzinfo=timezone.utc)
    return boundary.isoformat()


RETRAIN_SCHEDULE_STATE_ID = "retrain-schedule"


def load_last_fired_slot(es: Elasticsearch) -> "str | None":
    """Persisted (not in-memory) so a restart doesn't immediately re-fire
    the slot it just handled minutes ago -- in-memory-only state would
    reintroduce restart-sensitivity through the back door (#172)."""
    try:
        doc = es.get(index=STATE_INDEX, id=RETRAIN_SCHEDULE_STATE_ID)
        return doc["_source"].get("last_fired_slot_id")
    except Exception:
        return None


def save_last_fired_slot(es: Elasticsearch, slot_id: str) -> None:
    es.index(index=STATE_INDEX, id=RETRAIN_SCHEDULE_STATE_ID,
             document={"last_fired_slot_id": slot_id})
DRIFT_RETRAIN_STATE_ID = "drift-retrain"
def load_last_drift_retrain(es: Elasticsearch) -> "datetime | None":
    """Persisted for the same reason as load_last_fired_slot: a restart
    mid-storm must not reset the cooldown and let the storm resume (#3168)."""
    try:
        doc = es.get(index=STATE_INDEX, id=DRIFT_RETRAIN_STATE_ID)
        return datetime.fromisoformat(doc["_source"]["last_triggered_at"])
    except Exception:
        return None
def save_last_drift_retrain(es: Elasticsearch, when: datetime) -> None:
    es.index(index=STATE_INDEX, id=DRIFT_RETRAIN_STATE_ID,
             document={"last_triggered_at": when.isoformat()})
def drift_retrain_allowed(last_triggered_at: "datetime | None", now: datetime,
                           cooldown_minutes: int) -> bool:
    """Pure gate (#3168): a drift-triggered retrain is allowed only once
    cooldown_minutes have passed since the last one. Without this, a
    sustained drift condition (genuine model churn, not noise) refills the
    DRIFT_WINDOW-sized recent_flags window and re-fires on the very next
    poll cycle -- observed as 50+ retrains in under an hour on 2026-09-08.
    Does not mute drift: once cooldown elapses, a still-elevated rate
    triggers again on the next check."""
    if last_triggered_at is None:
        return True
    return now - last_triggered_at >= timedelta(minutes=cooldown_minutes)


def _persist_best_effort(label: str, fn, *args) -> bool:
    """Run one persistence write inside the poll loop, warning instead of
    raising on failure (#2236). Separated from run_worker()'s loop for the
    same reason drift_rate_if_triggered() is: the loop itself can't be
    unit-tested, and the non-fatal contract has to be.

    Losing one of these writes costs, at worst: a checkpoint -> one batch
    replayed next cycle (findings-safe -- write_anomaly's deterministic
    id= overwrites instead of duplicating); save_buffers/session_tracker ->
    a crash loses only what the next POLL_INTERVAL would have written
    anyway; last_fired_slot -> one scheduled retrain slot may re-attempt
    once after a restart. All bounded; none worth killing the loop over.
    Returns True when the write went through.
    """
    try:
        fn(*args)
        return True
    except Exception as exc:
        logger.warning(f"{label} failed (non-fatal): {exc}")
        return False


def drift_rate_if_triggered(recent_flags, window: int, rate_threshold: float) -> "float | None":
    """Pure decision function (#65): given the rolling window of recent
    composite>=THRESHOLD flags, returns the observed rate if drift should
    trigger, else None. Separated from run_worker()'s loop so the trigger
    condition is testable directly rather than only by driving the whole
    infinite polling loop."""
    if len(recent_flags) < window:
        return None
    rate = sum(recent_flags) / len(recent_flags)
    return rate if rate > rate_threshold else None


def write_drift_metric(es: Elasticsearch, window: int, rate: float) -> None:
    """Evidence for one drift-detection trigger (#65, docs/ml-worker-plan.md
    §11.4). Best-effort, same rationale as write_retrain_metric()."""
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "drift",
        "drift_window": window,
        "drift_rate": round(rate, 4),
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write drift metric (non-fatal): {exc}")


def anomaly_doc_id(source_index: "str | None", source_event_id: "str | None") -> str:
    """Deterministic ES document ID for ml-anomalies (#168), derived from
    the source event's own identity rather than letting Elasticsearch
    assign a random one. source_index is included (not source_event_id
    alone) because that ID is only unique within its own source index --
    honeypot-v2-* and suricata-v2-* auto-generated IDs are not guaranteed
    disjoint from each other."""
    return hashlib.md5(f"{source_index or ''}|{source_event_id or ''}".encode()).hexdigest()


def build_ilm_policy(retention_days: int) -> dict:
    """Pure function (#1968) so the retention contract is unit-testable
    without a live ES: delete-only phases need no rollover on these classic
    (non-data-stream) indices -- min_age counts from index creation, and
    unlike honeypot-30d's data-stream backing index there is no
    write-index-delete ILM structurally cannot perform here."""
    return {"policy": {"phases": {
        "delete": {"min_age": f"{retention_days}d", "actions": {"delete": {}}},
    }}}


def ensure_ilm_policy(es: Elasticsearch, name: str, policy: dict) -> None:
    """Idempotently install one ILM policy (#1968). Attachment order matters:
    run_worker() calls this BEFORE ensure_index(), because an index created
    with index.lifecycle.name referencing a missing policy fails its own
    creation. Stable names + env-tunable windows per #261."""
    try:
        es.ilm.get_lifecycle(name=name)
        return
    except NotFoundError:
        # #2579: elasticsearch-py sends `policy=` as the request body verbatim,
        # and ES >= 9.0 parses PUT _ilm/policy bodies as the policy definition
        # itself -- so the {"policy": ...} envelope build_ilm_policy() returns
        # must be stripped here or the server 400s with
        # [lifecycle_policy] unknown field [policy] and the worker dies at
        # bootstrap before its first batch.
        es.ilm.put_lifecycle(name=name, policy=policy["policy"])
        logger.info(f"Installed ILM policy {name}")


def model_state_id(iso_model, lstm_model) -> "str | None":
    """Identity of the exact checkpoint trio behind this batch's scores
    (#1968), so every historical alert stays interpretable without
    reconstructing model state from process restart times (the #1959
    forensics hole).

    Read from the promotion pointers' realpath basenames, not mtimes:
    _save() promotes via atomic symlink retarget and never edits a promoted
    file in place, so equal ids guarantee equal artifacts regardless of
    filesystem timestamp resolution or container image layer copies.
    None until all three detectors have been promoted at least once -- which
    is itself the signal that IsoForest was serving an untrained/no-op state,
    the exact condition whose invisibility made #1959's constant-0.5 scores
    hard to attribute after the fact.
    """
    links = (
        ("iso",  os.path.join(iso_model.model_dir,  "current_isoforest.joblib")),
        ("hbos", os.path.join(iso_model.model_dir,  "current_hbos.joblib")),
        ("lstm", os.path.join(lstm_model.model_dir, "current_lstm_ae.pt")),
    )
    parts = []
    for prefix, link in links:
        if not os.path.exists(link):
            return None
        stem = os.path.basename(os.path.realpath(link)).rsplit(".", 1)[0]
        parts.append(f"{prefix}:{stem.rsplit('_', 1)[-1]}")
    return "|".join(parts)


def write_anomaly(es: Elasticsearch, rdb: "redis.Redis | None",
                 event: dict, scores: dict, explanation: str,
                 checkpoint_id: "str | None" = None) -> None:
    src = event.get("_source", {})
    composite = compute_composite(scores)
    if composite < THRESHOLD:
        return

    # src_ip/dst_port/proto use the same real-document field reads as
    # extract_features() (#62 task 33) -- src.get("src_ip") etc. never
    # matches a real document's top level, so a correctly-fired anomaly
    # would otherwise still get written with a null src_ip, which is the
    # one field an operator actually needs to act on it.
    src_ip = _get_ip(src) or None
    doc = {
        "@timestamp":        src.get("@timestamp", datetime.now(timezone.utc).isoformat()),
        "source_event_id":   event.get("_id"),
        "source_index":      event.get("_index"),
        "src_ip":            src_ip,
        "src_country":       (src.get("source") or {}).get("geo", {}).get("country_iso_code"),
        "composite_score":   round(composite, 4),
        "severity":          severity(composite),
        # None stays null in the stored doc (#1969): model_scores carries
        # exactly what each detector expressed -- an absent detector reads
        # back as null, not 0.0.
        "model_scores":      {k: (None if v is None else round(v, 4)) for k, v in scores.items()},
        "contributing_detectors": contributing_detectors(scores),
        "explanation":       explanation,
        "event_type":        (src.get("event") or {}).get("category"),
        "dst_port":          _get_port(src) or None,
        "proto":             _get_transport_proto(src),

        # Context that makes the alert actionable without re-querying a
        # source index that expires under honeypot-30d (#1968): which decoy
        # drew it (our side of the flow + its sensor), who connected
        # (remote port), and the flow-level pivot key shared with
        # agent-intrusion-campaigns.
        "dst_ip":            _get_dst_ip(src) or None,
        "src_port":          _get_src_port(src),
        "sensor":            src.get("sensor") or (src.get("event") or {}).get("sensor"),
        "community_id":      (src.get("network") or {}).get("community_id"),

        # Interpretation stamps (#1968): the configuration and model state
        # these scores came from -- ML_ALERT_THRESHOLD is per-deployment,
        # and severity bands only mean something against the day's own
        # threshold; model_state_id pins the checkpoint trio (None =
        # detectors never promoted yet, e.g. IsoForest serving untrained).
        # is_our_own_address is stamped rather than left implicit: while
        # #1959 suppression keeps own-address alerts unwritten this is
        # always false in practice, but if that policy ever changes the
        # historical documents will already carry the classification.
        "alert_threshold":   round(THRESHOLD, 4),
        "model_state_id":    checkpoint_id,
        "src_internal":      bool(src_ip and is_our_own_address(src_ip)),
    }

    # Operator dispositions survive scoring rewrites (#1968): id= is
    # deterministic (#168), and es.index() REPLACES the whole document --
    # without reading back first, a checkpoint replay or crash-retry would
    # silently reset an analyst's verdict to open. Disposition keys are
    # worker-read-only: they change exclusively through the dashboard's
    # partial-update endpoint.
    try:
        existing = es.get(index=ANOMALY_INDEX,
                          id=anomaly_doc_id(doc["source_index"], doc["source_event_id"]))["_source"]
    except NotFoundError:
        existing = {}
    except Exception as exc:
        # A transient read failure must not block the alert itself; treat
        # like absent (dispositions stay untouched only when we cannot see
        # them, which beats suppressing real findings over one GET).
        logger.warning(f"Disposition read-back failed for {doc['source_event_id']} (writing fresh fields): {exc}")
        existing = {}
    for key in DISPOSITION_FIELDS:
        if existing.get(key) is not None:
            doc[key] = existing[key]
    if "status" not in doc:
        doc["status"] = "open"

    # The Elasticsearch write is the authoritative action -- a dashboard
    # polling ml-anomalies will see this finding regardless of what happens
    # below. Redis is a best-effort wake-up only (ml-gpu-coordinated-roadmap.md
    # §1 decision 1), so a broker that is absent, unreachable, or refusing
    # connections must never be able to take an anomaly write down with it.
    #
    # id= is deterministic from the source event (#168), not ES-assigned:
    # the same source event reprocessed -- a checkpoint replay, a
    # crash-retry, or fetch_new_events' own equal-timestamp boundary
    # requery -- overwrites the same anomaly document instead of creating a
    # duplicate finding for something scored exactly once conceptually.
    es.index(index=ANOMALY_INDEX, id=anomaly_doc_id(doc["source_index"], doc["source_event_id"]), document=doc)
    if rdb is not None:
        try:
            rdb.publish(REDIS_CHANNEL, json.dumps({
                "severity": doc["severity"],
                "composite_score": doc["composite_score"],
                "src_ip": doc["src_ip"],
                "explanation": explanation[:120],
            }))
        except Exception as exc:
            logger.warning(f"Redis publish failed (non-fatal, ES write already committed): {exc}")
    logger.info(f"Anomaly [{doc['severity']}] score={composite:.3f} src={doc['src_ip']}")


def run_worker() -> None:
    logger.remove()
    logger.add(lambda m: print(m, end=""), level=LOG_LEVEL)

    logger.info("ML Worker starting...")

    es  = Elasticsearch(ES_HOST, request_timeout=30)
    rdb = redis.from_url(REDIS_URL) if REDIS_URL else None
    if rdb is None:
        logger.info("REDIS_URL not set -- anomaly notifications are ES-only (this is the default, see #62)")

    # Wait for Elasticsearch to be ready
    for attempt in range(30):
        try:
            if es.ping():
                break
        except Exception:
            pass
        logger.info(f"Waiting for Elasticsearch... ({attempt+1}/30)")
        time.sleep(10)
    else:
        logger.error("Elasticsearch not reachable after 5 minutes, exiting.")
        return

    # ILM policies must exist before any index references them (#1968) --
    # creation with a lifecycle.name pointing at a missing policy fails.
    ensure_ilm_policy(es, ANOMALY_ILM_POLICY, build_ilm_policy(ML_ANOMALIES_RETENTION_DAYS))
    ensure_ilm_policy(es, METRICS_ILM_POLICY, build_ilm_policy(ML_METRICS_RETENTION_DAYS))

    # Ensure required indices exist
    ensure_index(es, ANOMALY_INDEX, {
        "settings": {
            # #1968: recorded retention (ML_ANOMALIES_RETENTION_DAYS, default
            # one year) -- source_event_id dangles after honeypot-30d anyway,
            # but operator dispositions stay analysable for label extraction
            # (#1794/#1797) well past that.
            "index.lifecycle.name": ANOMALY_ILM_POLICY,
        },
        "mappings": {
            "properties": {
                "@timestamp":       {"type": "date"},
                "source_event_id":  {"type": "keyword"},
                "source_index":     {"type": "keyword"},
                "src_ip":           {"type": "ip"},
                "src_country":      {"type": "keyword"},
                "composite_score":  {"type": "float"},
                "severity":         {"type": "keyword"},
                "model_scores":     {"type": "object"},
                # Which detectors produced an opinion for this alert
                # (#1969) -- null model_scores values are honest but not
                # aggregatable; this flat keyword list is.
                "contributing_detectors": {"type": "keyword"},
                "explanation":      {"type": "text"},
                "event_type":       {"type": "keyword"},
                "dst_port":         {"type": "integer"},
                "proto":            {"type": "keyword"},

                # #1968 actionability/audit fields:
                "dst_ip":           {"type": "ip"},          # which decoy
                "src_port":         {"type": "integer"},     # remote ephemeral port
                "sensor":           {"type": "keyword"},     # producing honeypot stack
                "community_id":     {"type": "keyword"},     # flow pivot key
                "alert_threshold":  {"type": "float"},       # deployment config of that day
                "model_state_id":   {"type": "keyword"},     # checkpoint trio identity
                "src_internal":     {"type": "boolean"},     # #1959 classification stamp
                "status":           {"type": "keyword"},     # disposition lifecycle
                "disposition_reason": {"type": "text"},
                "disposition_by":   {"type": "keyword"},
                "disposed_at":      {"type": "date"},
            }
        }
    })
    ensure_index(es, STATE_INDEX, {"mappings": {"properties": {}}})
    # #65: METRICS_INDEX was declared but never written to until now --
    # retrain acceptance/rejection evidence (docs/ml-worker-plan.md §11.1)
    # and drift-detection events (§11.4) both land here.
    ensure_index(es, METRICS_INDEX, {
        "settings": {
            # #1968: recorded retention (ML_METRICS_RETENTION_DAYS, default
            # 90d) -- retrain/drift evidence informs the next cycle, not a
            # permanent audit; its own comment below already admitted this
            # index had no retention answer.
            "index.lifecycle.name": METRICS_ILM_POLICY,
        },
        "mappings": {
            "properties": {
                "@timestamp":            {"type": "date"},
                "kind":                  {"type": "keyword"},  # "retrain" | "drift"
                "model":                 {"type": "keyword"},
                "accepted":              {"type": "boolean"},
                "reason":                {"type": "text"},
                "train_samples":         {"type": "integer"},
                "holdout_samples":       {"type": "integer"},
                "anomaly_rate_new":      {"type": "float"},
                "anomaly_rate_previous": {"type": "float"},
                "dropped_count":         {"type": "integer"},  # kind="retrain" (#2984)
                "drift_window":          {"type": "integer"},
                "drift_rate":            {"type": "float"},
                "source_event_id":       {"type": "keyword"},  # kind="malformed_event" (#171)
                "source_index":          {"type": "keyword"},
                "error":                 {"type": "text"},
                "backlog_count":         {"type": "integer"},  # kind="backlog" (#190)
                "consecutive_failures":  {"type": "integer"},  # kind="es_unavailable" (#188)
                "downtime_seconds":      {"type": "integer"},
            }
        }
    })

    # Initialise models
    iso_model      = IsoForestModel(model_dir=MODEL_DIR)
    lstm_model     = LSTMAEModel(model_dir=MODEL_DIR)
    session_tracker = SessionFeatureTracker(model_dir=MODEL_DIR)  # #277: real cmd_count/failed_logins_1h/unique_ports_1h

    retrain_slots = parse_retrain_slots(RETRAIN_SLOTS_UTC)
    last_fired_slot_id = load_last_fired_slot(es)  # #172: persisted, not restart-relative
    last_drift_retrain_at = load_last_drift_retrain(es)  # #3168: persisted, not restart-relative
    recent_flags: "deque[tuple[str, float]]" = deque(maxlen=DRIFT_WINDOW)  # composite >= THRESHOLD, drift detection (#65)
    consecutive_es_failures = {idx: 0 for idx in SOURCE_INDICES}  # #188

    logger.info(f"Worker ready. Poll={POLL_INTERVAL}s Threshold={THRESHOLD}")

    while True:
        cycle_start = time.time()

        for index_pattern in SOURCE_INDICES:
            # #2236: a failed read of the stored position must not silently
            # become "start from one hour ago" -- treat it like the fetch
            # failure it operationally is and let the #188 counter below
            # see it, rather than opening a second accounting channel.
            checkpoint, ckpt_ok = load_checkpoint(es, index_pattern)
            events: list = []
            ok = False
            if ckpt_ok and checkpoint is not None:
                events, ok = fetch_new_events(
                    es, index_pattern, checkpoint["last_timestamp"],
                    exclude_ids=set(checkpoint["seen_ids"]),
                    max_total=MAX_POLL_BATCH,
                )

            # #188: distinguish a transient blip from a sustained outage --
            # both fetch_new_events() and load_checkpoint()'s read of the
            # stored position (#2236) retry next cycle either way (no
            # separate backoff), this only tracks how many cycles in a row
            # have failed for THIS index pattern.
            if not ok:
                consecutive_es_failures[index_pattern] += 1
                n = consecutive_es_failures[index_pattern]
                if n == ES_UNAVAILABLE_ALERT_AFTER:
                    logger.error(
                        f"{index_pattern}: Elasticsearch has failed {n} consecutive poll "
                        f"cycles (~{n * POLL_INTERVAL}s) -- treating as a sustained outage, not a blip"
                    )
            elif consecutive_es_failures[index_pattern] >= ES_UNAVAILABLE_ALERT_AFTER:
                # Recovered after crossing the sustained-outage threshold --
                # this is the only point a durable record of it can be
                # written, since ES itself was unreachable for its duration.
                n = consecutive_es_failures[index_pattern]
                write_es_unavailable_metric(es, index_pattern, n, n * POLL_INTERVAL)
                consecutive_es_failures[index_pattern] = 0
            else:
                consecutive_es_failures[index_pattern] = 0

            if not events:
                continue

            logger.debug(f"{index_pattern}: {len(events)} new events")

            score_and_write_events(es, rdb, iso_model, lstm_model, events, recent_flags, session_tracker)

            # Advance the checkpoint (#168): the new (timestamp, seen_ids)
            # tuple, not just the last event's timestamp -- see
            # advance_checkpoint()'s own docstring for why.
            new_checkpoint = advance_checkpoint(events, checkpoint)
            _persist_best_effort(
                f"save_checkpoint({index_pattern})", save_checkpoint,
                es, index_pattern,
                new_checkpoint["last_timestamp"], new_checkpoint["seen_ids"])

            # #190: MAX_POLL_BATCH being exactly what came back means there's
            # very likely more behind it -- surface that now (a count query,
            # not another fetch) rather than let it stay invisible until an
            # operator happens to query Elasticsearch directly.
            if len(events) >= MAX_POLL_BATCH:
                remaining = backlog_count(es, index_pattern, new_checkpoint["last_timestamp"])
                if remaining:
                    write_backlog_metric(es, index_pattern, remaining)

        # #170: persist LSTM-AE's per-IP sliding windows every cycle, not
        # just on retrain -- a crash/OOM/restart between retrains would
        # otherwise still lose in-progress sessions' temporal state even
        # though the fix exists. Cheap and bounded (MAX_PERSISTED_IPS), so
        # every POLL_INTERVAL is a fine cadence rather than needing a
        # separate timer or graceful-shutdown hook.
        # #2236: the per-cycle in-memory persists went through the same
        # non-fatal contract as every other write in this loop.
        _persist_best_effort("lstm_model.save_buffers", lstm_model.save_buffers)
        _persist_best_effort("session_tracker.save", session_tracker.save)  # #277: cmd_count/rolling-window state

        # Drift detection (#65): a full window of real scores, sustained
        # above DRIFT_ANOMALY_RATE, forces an early retrain regardless of
        # the scheduled slots below -- this stays event-driven (#172 only
        # concerns the *scheduled* path). The window is cleared after
        # triggering so a persistent drift condition retrains once and then
        # re-accumulates a fresh window, rather than firing again every
        # single poll cycle on the same stale evidence.
        #
        # #3168: that assumption breaks under real throughput -- 500 events
        # can refill inside a single POLL_INTERVAL, so sustained (genuine,
        # not noisy) churn re-triggered on the very next cycle with zero
        # spacing (50+ accepted retrains in under an hour on 2026-09-08).
        # drift_retrain_allowed() adds a cooldown floor between accepted
        # drift retrains, same persisted-state shape as last_fired_slot_id.
        # It only delays, never mutes: once cooldown elapses, still-elevated
        # drift triggers again on the next check.
        drift_rate = drift_rate_if_triggered(recent_flags, DRIFT_WINDOW, DRIFT_ANOMALY_RATE)
        drift_due = False
        if drift_rate is not None:
            write_drift_metric(es, DRIFT_WINDOW, drift_rate)
            if drift_retrain_allowed(last_drift_retrain_at, datetime.now(timezone.utc),
                                      DRIFT_RETRAIN_COOLDOWN_MINUTES):
                logger.warning(
                    f"Drift detected: {drift_rate:.1%} anomaly rate over the last "
                    f"{DRIFT_WINDOW} events (threshold {DRIFT_ANOMALY_RATE:.0%}) -- "
                    "triggering an early retrain"
                )
                drift_due = True
                recent_flags.clear()
            else:
                logger.info(
                    f"Drift detected: {drift_rate:.1%} anomaly rate but still within "
                    f"the {DRIFT_RETRAIN_COOLDOWN_MINUTES}min cooldown since the last "
                    "drift-triggered retrain -- skipping this cycle"
                )

        # #172: scheduled retraining now fires at explicit UTC slot
        # boundaries (persisted last_fired_slot_id), not a restart-relative
        # interval -- see parse_retrain_slots()/next_retrain_slot_id()'s own
        # docstrings for why this makes the schedule coordinable rather
        # than dependent on when this process happened to (re)start.
        due_slot_id = next_retrain_slot_id(datetime.now(timezone.utc), retrain_slots)
        scheduled_due = due_slot_id is not None and due_slot_id != last_fired_slot_id

        # #190: this runs synchronously in the same loop as event polling --
        # observed live to block it for ~8 minutes (LSTM fine-tuning on a
        # real 40k-event batch), during which nothing above this line runs
        # at all. Deliberately left this way rather than moved to a
        # background thread: the acceptance gate's promise (a rejected
        # candidate never replaces the active model, #65) and the atomic
        # promotion fix (#169) both assume nothing else is concurrently
        # reading self.iso/self.hbos/self.net while retrain() mutates them
        # in place (LSTM especially -- fine-tuning literally steps the live
        # model's weights before deciding whether to keep them). Making this
        # concurrent needs a real concurrency story for that, not just
        # spawning a thread. Revisit if Milestone I's shared-GPU scheduling
        # (#84) needs retrain and polling decoupled; MAX_POLL_BATCH above at
        # least bounds how large a backlog blocking this causes.
        if drift_due or scheduled_due:
            logger.info("Starting model retraining...")
            # #3097: fetching each index's most-recent MAX_TRAIN_SAMPLES
            # ascending-from-24h-ago systematically starves whichever index
            # sorts first / is smallest (Zeek in practice ends up as a ~2h
            # sliver). Quota each index, then quota each index's quota
            # uniformly across 24 hourly slices, so no single index or hour
            # of day can dominate the training batch.
            per_index_quota = max(1, MAX_TRAIN_SAMPLES // len(SOURCE_INDICES))
            hourly_quota = max(1, per_index_quota // 24)
            now = datetime.now(timezone.utc)
            all_events = []
            index_counts = {}
            for idx in SOURCE_INDICES:
                idx_events = []
                for hour_ago in range(24, 0, -1):
                    since_hour = (now - timedelta(hours=hour_ago)).isoformat()
                    hour_events, _ok = fetch_new_events(
                        es, idx, since_hour, page_size=hourly_quota,
                        max_total=hourly_quota,
                    )
                    idx_events.extend(hour_events)
                index_counts[idx] = len(idx_events)
                all_events.extend(idx_events)

            if len(all_events) > 100:
                sources, dropped_count = quarantine_retrain_events(es, iso_model, all_events)
                iso_result = iso_model.retrain(sources, source_index_counts=index_counts)
                lstm_result = lstm_model.retrain(sources)
                write_retrain_metric(es, "isolation_forest_hbos", iso_result, dropped_count=dropped_count)
                write_retrain_metric(es, "lstm_ae", lstm_result, dropped_count=dropped_count)
                logger.info(f"Retrain cycle on {len(all_events)} events complete ({dropped_count} dropped)")

            if scheduled_due:
                # Mark this slot handled regardless of whether len(all_events)
                # cleared the 100-event floor -- otherwise a quiet slot would
                # keep re-attempting (and re-fetching 24h of events) every
                # single POLL_INTERVAL for the rest of the day instead of
                # waiting for the next slot, same as the old code always
                # resetting last_retrain even on a no-op cycle.
                last_fired_slot_id = due_slot_id
                _persist_best_effort(
                    f"save_last_fired_slot({due_slot_id})", save_last_fired_slot,
                    es, due_slot_id)

            if drift_due:
                # Same reasoning as scheduled_due above: start the cooldown
                # now regardless of the 100-event floor, so a quiet cycle
                # can't immediately re-arm (recent_flags was already
                # cleared above the moment drift was accepted).
                last_drift_retrain_at = datetime.now(timezone.utc)
                _persist_best_effort(
                    "save_last_drift_retrain", save_last_drift_retrain,
                    es, last_drift_retrain_at)

        elapsed = time.time() - cycle_start
        sleep_for = max(0, POLL_INTERVAL - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    run_worker()
