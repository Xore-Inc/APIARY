"""
Fixes applied after the #61 audit (tracked in #62). Separate from
test_worker_audit.py, which characterizes defects found in the original
scaffold -- these tests characterize the corrected behavior instead, so a
regression back to the old behavior fails loudly here rather than silently
un-fixing something the audit already flagged.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from elastic_transport import ApiResponseMeta
from elasticsearch import NotFoundError
from loguru import logger

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402
import fixtures  # noqa: E402
import models.isolation_forest as iso_mod  # noqa: E402


class TestRedisIsOptionalAndBestEffort:
    """ml-worker/docker-compose.yml no longer runs a Redis service at all
    (#62) -- REDIS_URL defaults to empty, and write_anomaly() must never let
    a missing or failing broker take an Elasticsearch write down with it."""

    def test_write_anomaly_succeeds_with_no_redis_client(self):
        es = MagicMock()
        event = {"_id": "1", "_index": "honeypot-v2-test", "_source": {"@timestamp": "2026-07-31T00:00:00Z"}}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}  # composite well above THRESHOLD

        worker.write_anomaly(es, None, event, scores, "test explanation")

        es.index.assert_called_once()
        assert es.index.call_args.kwargs["index"] == worker.ANOMALY_INDEX

    def test_write_anomaly_survives_a_failing_redis_client(self):
        es = MagicMock()
        rdb = MagicMock()
        rdb.publish.side_effect = ConnectionError("redis is not there")
        event = {"_id": "2", "_index": "honeypot-v2-test", "_source": {"@timestamp": "2026-07-31T00:00:00Z"}}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}

        # Must not raise: the ES write already committed by the time
        # rdb.publish is attempted, and a notification failure is not a
        # reason to lose that.
        worker.write_anomaly(es, rdb, event, scores, "test explanation")

        es.index.assert_called_once()
        rdb.publish.assert_called_once()

    def test_below_threshold_events_never_reach_redis_or_es(self):
        es = MagicMock()
        rdb = MagicMock()
        event = {"_id": "3", "_index": "honeypot-v2-test", "_source": {}}
        scores = {"isolation_forest": 0.1, "hbos": 0.1, "lstm_ae": 0.0}  # composite well below THRESHOLD

        worker.write_anomaly(es, rdb, event, scores, "should not fire")

        es.index.assert_not_called()
        rdb.publish.assert_not_called()


class TestWriteAnomalyReadsTheRealSchema:
    """#62 task 33: write_anomaly() used the same broken flat lookups as the
    pre-fix extract_features() (src.get("src_ip"), src.get("dst_port"),
    src.get("proto")) -- a correctly-fired anomaly would still get written
    with src_ip=None, the one field an operator needs to act on it. Fixed to
    reuse the same per-sensor reads extract_features() uses."""

    def test_anomaly_document_gets_the_real_src_ip_and_port(self):
        es = MagicMock()
        event = {"_id": "1", "_index": "honeypot-v2-test", "_source": fixtures.COWRIE_LOGIN_FAILED["_source"]}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}

        worker.write_anomaly(es, None, event, scores, "test explanation")

        doc = es.index.call_args.kwargs["document"]
        assert doc["src_ip"] == "203.0.113.9"
        assert doc["dst_port"] == 22
        assert doc["proto"] == "tcp"


class TestBoundedRetrain:
    """#62 task 33: retrain() must never fit on more than MAX_TRAIN_SAMPLES
    regardless of how many sources the caller collected -- see the
    constant's comment in models/isolation_forest.py for the cost
    rationale (unbounded IsolationForest.fit()/HBOS.fit() cost on a busy
    honeypot's 24h retrain window)."""

    def test_retrain_fits_on_at_most_the_capped_sample_count(self, monkeypatch, tmp_path):
        # #65 split retrain() into train/holdout: MAX_TRAIN_SAMPLES now
        # bounds the total (train + holdout) considered, not what
        # IsolationForest.fit() sees directly (that's train_samples, a
        # sub-slice). HOLDOUT_MIN/HOLDOUT_FRACTION pinned here so the split
        # is exact and the test doesn't depend on their production defaults.
        monkeypatch.setattr(iso_mod, "MAX_TRAIN_SAMPLES", 5)
        monkeypatch.setattr(iso_mod, "HOLDOUT_MIN", 1)
        monkeypatch.setattr(iso_mod, "HOLDOUT_FRACTION", 0.2)
        model = iso_mod.IsoForestModel(model_dir=str(tmp_path))
        sources = [fixtures.COWRIE_LOGIN_FAILED["_source"]] * 50  # far over the patched cap

        fit_sample_counts = []
        orig_fit = iso_mod.IsolationForest.fit

        def spy_fit(self, X, *a, **kw):
            fit_sample_counts.append(X.shape[0])
            return orig_fit(self, X, *a, **kw)

        monkeypatch.setattr(iso_mod.IsolationForest, "fit", spy_fit)
        result = model.retrain(sources)

        assert fit_sample_counts == [4], "IsolationForest.fit() must only see the train split (5 capped - 1 holdout)"
        assert result.train_samples + result.holdout_samples == 5, \
            "MAX_TRAIN_SAMPLES must still bound the total (train + holdout) considered"

    def test_fetch_new_events_stops_scrolling_once_max_total_is_reached(self):
        es = MagicMock()
        # 3 pages of 4 hits each; max_total=5 should stop after page 2 (8
        # collected, trimmed to 5) without ever requesting page 3.
        page = lambda n: {"_scroll_id": "sid", "hits": {"hits": [{"_id": str(i)} for i in range(n)]}}
        es.search.return_value = page(4)
        es.scroll.side_effect = [page(4), page(4)]

        events, ok = worker.fetch_new_events(es, "honeypot-v2-*", "2026-07-31T00:00:00Z", page_size=4, max_total=5)

        assert ok is True
        assert len(events) == 5
        assert es.scroll.call_count == 1, "must stop after the first scroll page already exceeds max_total, not fetch a third page"


class _WarnCapture:
    """Collect loguru records at WARNING+ while active; call stop() when done."""

    def __init__(self):
        self.lines = []
        self._hid = logger.add(lambda m: self.lines.append(m), level="WARNING")

    def stop(self):
        logger.remove(self._hid)

    def has(self, fragment: str) -> bool:
        return any(fragment in line for line in self.lines)


class TestCheckpointReadsSurviveElasticsearchFailures:
    """#2236: load_checkpoint()'s old catch-all treated ANY es.get failure --
    timeout, 5xx, connection refused mid-run -- as "first run", silently
    rewinding scoring to one hour ago with no evidence left in the log. Now
    only a genuine NotFound bootstraps the 1-hour default; a transient read
    failure either falls back to the in-memory copy of the last good
    checkpoint or fails this poll cycle exactly like a fetch failure (#188),
    and a regressed stored checkpoint is diagnosed loudly."""

    @pytest.fixture(autouse=True)
    def _fresh_cache(self, monkeypatch):
        # _LAST_GOOD_CHECKPOINT is module-global; give each test its own
        # instance so seeding for one case can't leak into another.
        monkeypatch.setattr(worker, "_LAST_GOOD_CHECKPOINT", {})

    def test_midrun_timeout_falls_back_to_in_memory_copy(self):
        cached = {"last_timestamp": "2026-08-01T12:00:00+00:00", "seen_ids": ["a", "b"]}
        worker._LAST_GOOD_CHECKPOINT["honeypot-v2-*"] = dict(cached)
        warn = _WarnCapture()
        try:
            es = MagicMock()
            es.get.side_effect = TimeoutError("simulated read timeout")

            checkpoint, ok = worker.load_checkpoint(es, "honeypot-v2-*")
        finally:
            warn.stop()

        assert ok is True, "ES flapping must degrade to last-known-position, not fail"
        assert checkpoint == cached, \
            f"must continue from the in-memory copy, got {checkpoint}"
        assert checkpoint is not cached, "must hand back a copy the loop can't alias-mutate"
        assert warn.has("in-memory copy"), "degraded fallback must be logged loudly"

    def test_unreadable_checkpoint_with_no_cache_fails_like_a_fetch(self):
        warn = _WarnCapture()
        try:
            es = MagicMock()
            es.get.side_effect = TimeoutError("simulated read timeout")

            checkpoint, ok = worker.load_checkpoint(es, "honeypot-v2-*")
        finally:
            warn.stop()

        assert (checkpoint, ok) == (None, False), \
            "with nothing to stand in for the position, the cycle must fail (#188) " \
            "instead of silently restarting from one hour ago"
        assert warn.has("#188"), "failure must reference the sustained-outage path it feeds"

    def test_only_genuine_notfound_bootstraps_one_hour_default(self):
        warn = _WarnCapture()
        try:
            es = MagicMock()
            # es-py 8.x ApiError signature: (message, meta, body).
            not_found_meta = ApiResponseMeta(status=404, http_version="1.1",
                                             headers={}, duration=0.0, node=None)
            es.get.side_effect = NotFoundError("index_not_found_exception",
                                               not_found_meta, {"found": False})

            checkpoint, ok = worker.load_checkpoint(es, "honeypot-v2-*")
        finally:
            warn.stop()

        assert ok is True
        parsed = datetime.fromisoformat(checkpoint["last_timestamp"])
        expected = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
        assert abs(parsed.replace(tzinfo=None) - expected) < timedelta(minutes=5), \
            f"bootstrap default should be ~now-1h, got {checkpoint['last_timestamp']}"
        assert checkpoint["seen_ids"] == []

    def test_regressed_stored_checkpoint_is_loud_but_honored(self):
        # Stored state readable but older than what this process already
        # acted on: keep honoring ES as source of truth (the stored doc may
        # be exactly right after an operator restored it) but say so.
        worker._LAST_GOOD_CHECKPOINT["honeypot-v2-*"] = {
            "last_timestamp": "2026-08-02T00:00:00+00:00", "seen_ids": []}
        warn = _WarnCapture()
        try:
            es = MagicMock()
            es.get.return_value = {"_source": {
                "last_timestamp": "2026-08-01T00:00:00Z",
                "seen_ids": ["old"],
            }}

            checkpoint, ok = worker.load_checkpoint(es, "honeypot-v2-*")
        finally:
            warn.stop()

        assert ok is True
        assert checkpoint["last_timestamp"] == "2026-08-01T00:00:00Z"
        assert warn.has("moved backwards"), "a rewind of stored state must be diagnosable from logs"


class TestPersistenceWritesAreBestEffort:
    """#2236: run_worker()'s persistence writes (checkpoint, save_buffers,
    session_tracker, last_fired_slot) go through _persist_best_effort() --
    extracted so the non-fatal contract is unit-testable despite the loop
    itself being untestable-in-place, same rationale as
    drift_rate_if_triggered()'s extraction. A failing write warns and
    returns instead of propagating into (and killing) the poll loop that
    would otherwise have retried it next cycle."""

    def test_failing_write_returns_false_and_warns_without_raising(self):
        warn = _WarnCapture()

        def exploding_write(*_args):
            raise RuntimeError("simulated state-index write failure")

        try:
            result = worker._persist_best_effort("save_checkpoint(hp)", exploding_write)
        except Exception as exc:  # pragma: no cover -- the assertion failure form
            raise AssertionError(f"_persist_best_effort let {exc!r} propagate") from exc
        finally:
            warn.stop()

        assert result is False
        assert warn.has("non-fatal"), "failure must be visible in the log"

    def test_successful_write_calls_through_and_reports_true(self):
        seen_args = []

        def write(*args):
            seen_args.extend(args)
            return None

        assert worker._persist_best_effort("save_checkpoint(hp)", write, "es", "hp", "ts", []) is True
        assert seen_args == ["es", "hp", "ts", []]


class TestRetrainCooldown:
    """#3168: at ~1300 events/min DRIFT_WINDOW (500) refills within minutes,
    so clearing recent_flags on a drift trigger let the same sustained
    drift re-cross DRIFT_ANOMALY_RATE and fire another "accepted" retrain
    every couple of poll cycles -- 50+ in one hour on 2026-09-08, polluting
    ml-anomalies. retrain_cooldown_active() is the extracted admission
    predicate the drift-triggered path gates on; the driving while-loop in
    run_worker() is untestable in place, same rationale as
    drift_rate_if_triggered()'s extraction."""

    def test_sustained_drift_yields_one_accepted_retrain_per_cooldown_window(self):
        cooldown = worker.RETRAIN_COOLDOWN_SECONDS
        last_accepted = {}
        model = "isolation_forest_hbos"
        accepted_at = []

        # Sustained above-threshold drift: a trigger every poll tick for
        # just over two cooldown windows.
        tick_s = 0
        while tick_s <= 2 * cooldown:
            now_ts = float(tick_s)
            if not worker.retrain_cooldown_active(last_accepted, model, now_ts, cooldown):
                accepted_at.append(now_ts)
                last_accepted[model] = now_ts
            tick_s += 60

        # Exactly one accepted retrain inside the first cooldown window,
        # then exactly one more once it elapses -- not one per tick.
        assert accepted_at == [0.0, cooldown, 2 * cooldown], accepted_at

    def test_still_within_cooldown_stays_suppressed(self):
        cooldown = worker.RETRAIN_COOLDOWN_SECONDS
        last_accepted = {"lstm_ae": 1000.0}

        assert worker.retrain_cooldown_active(last_accepted, "lstm_ae", 1000.0 + cooldown - 1, cooldown) is True
        assert worker.retrain_cooldown_active(last_accepted, "lstm_ae", 1000.0 + cooldown, cooldown) is False
        # A different, never-retrained model is never suppressed.
        assert worker.retrain_cooldown_active(last_accepted, "isolation_forest_hbos", 1000.0, cooldown) is False
