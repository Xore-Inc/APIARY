//! #3756: whole-response snapshots of the two reads that are too slow to
//! aggregate per request, written by the `dashboard-rollups` worker loop
//! next to the other rollups (`rollups.rs`) and read by the handlers.
//!
//! Measured on live Elasticsearch (2026-11-07, read-only `_search` with
//! `profile`):
//!
//!   /api/v1/sources                   8-15 s. One terms over `source.ip`
//!                                     (1000 buckets, six sub-aggregations)
//!                                     across every event index for 10 days:
//!                                     294 shards, about 43 shard-seconds on
//!                                     a 13-thread search pool, and single
//!                                     one-shard indices (zeek modbus_detailed,
//!                                     conn) at 9 s each.
//!   /api/v1/charts/ja4l-fingerprints  9-12 s. `zeek` is a `flattened` field
//!                                     in `zeek-v1-conn-*`, so `zeek.ja4l` is
//!                                     a keyed sub-field: the terms
//!                                     aggregation walks every key of every
//!                                     conn document (~1 µs a document,
//!                                     10.6 M documents a week). Matching the
//!                                     documents takes 0.2 s.
//!
//! Neither has a cheaper exact query shape, and neither result is additive
//! over hours (cardinalities, top-N across the window), so the worker runs
//! the handlers' own request bodies (`aggregates::sources_body`,
//! `charts::ja4l_body`) once per cycle and stores the `aggregations` part of
//! the answer. The handlers parse a snapshot with the same code they use for
//! a live answer, so the payload is the live payload as of `generated_at`.
//!
//! Same house rules as the other rollups: one deterministic id per page,
//! disposable (delete the index and the next cycle rebuilds it), and the
//! live query stays the fallback. A snapshot older than [`max_age`] (three
//! default cycles), from a different [`SCHEMA`], or from a run with failed
//! shards is never served, so a stopped worker degrades to the old live
//! behaviour rather than to old data.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{json, Value};

use crate::AppState;

pub const INDEX: &str = "page-rollup-v1";
pub const SOURCES: &str = "sources";
pub const JA4L_FINGERPRINTS: &str = "ja4l-fingerprints";

/// Bump when the stored request body or the shape the handlers parse
/// changes, so a reader never parses a snapshot written by other code.
const SCHEMA: u64 = 1;

/// Three cycles of the default `ROLLUP_RUN_INTERVAL_SECS` (300 s).
fn max_age() -> Duration {
    Duration::seconds(900)
}

/// A writer clock slightly ahead of the reader's is tolerated; a snapshot
/// from further in the future is not trusted.
fn clock_skew() -> Duration {
    Duration::seconds(60)
}

/// Every snapshot: its id, the indices and the request body of the live
/// handler it stands in for.
fn pages() -> Vec<(&'static str, &'static [&'static str], Value)> {
    vec![
        (
            SOURCES,
            crate::es::EVENT_INDICES,
            crate::aggregates::sources_body(crate::aggregates::SOURCES_CAP),
        ),
        (JA4L_FINGERPRINTS, crate::charts::JA4L_INDICES, crate::charts::ja4l_body()),
    ]
}

fn document(page: &str, generated_at: DateTime<Utc>, result: &Value) -> Value {
    json!({
        "page": page,
        "schema": SCHEMA,
        "generated_at": generated_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "aggregations": result["aggregations"],
    })
}

/// A complete answer: Elasticsearch reports partial results (a failed
/// shard, a timeout) as success, which a live request could not avoid but a
/// snapshot that is served for minutes should not keep.
fn complete(result: &Value) -> bool {
    result["aggregations"].is_object()
        && !result["timed_out"].as_bool().unwrap_or(false)
        && result["_shards"]["failed"].as_u64().unwrap_or(0) == 0
}

/// The stored answer in the shape of a `_search` response (`aggregations`
/// only), or `None` when the document must not be served.
fn usable(doc: &Value, now: DateTime<Utc>) -> Option<Value> {
    if doc["schema"].as_u64() != Some(SCHEMA) || !doc["aggregations"].is_object() {
        return None;
    }
    let generated_at = DateTime::parse_from_rfc3339(doc["generated_at"].as_str()?).ok()?.with_timezone(&Utc);
    let age = now - generated_at;
    (age <= max_age() && age >= -clock_skew()).then(|| json!({"aggregations": doc["aggregations"].clone()}))
}

/// The snapshot for `page` if it may be served; `None` sends the caller to
/// its live query.
pub async fn read(state: &AppState, page: &str) -> Option<Value> {
    match state.es.get_doc(INDEX, page).await {
        Ok(Some(doc)) => usable(&doc, Utc::now()),
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(%error, page, "page rollup unreadable, answering live");
            None
        }
    }
}

/// One refresh of every page, called from `rollups::run_cycle`. A failed or
/// partial run keeps the previous snapshot, which ages out by itself.
pub async fn write_cycle(state: &AppState) {
    for (page, indices, body) in pages() {
        let started = Utc::now();
        let result = match state.es.search_index(indices, body).await {
            Ok(result) if complete(&result) => result,
            Ok(result) => {
                tracing::warn!(
                    page,
                    timed_out = %result["timed_out"],
                    failed_shards = %result["_shards"]["failed"],
                    "page rollup: partial answer, previous snapshot kept"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, page, "page rollup query failed");
                continue;
            }
        };
        if let Err(error) = state.es.index_doc(INDEX, page, document(page, started, &result)).await {
            tracing::warn!(%error, page, "page rollup write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap().with_timezone(&Utc)
    }

    fn answer() -> Value {
        json!({
            "took": 9000,
            "timed_out": false,
            "_shards": {"total": 294, "successful": 294, "failed": 0},
            "hits": {"total": {"value": 10000, "relation": "gte"}},
            "aggregations": {"ja4l": {"buckets": [{"key": "14_64", "doc_count": 3}]}}
        })
    }

    #[test]
    fn a_stored_answer_reads_back_as_its_aggregations() {
        let doc = document(JA4L_FINGERPRINTS, at("2026-11-07T22:00:00Z"), &answer());
        assert_eq!(doc["page"], JA4L_FINGERPRINTS);
        assert!(doc.get("hits").is_none() && doc.get("took").is_none());
        assert_eq!(
            usable(&doc, at("2026-11-07T22:04:00Z")),
            Some(json!({"aggregations": answer()["aggregations"]}))
        );
    }

    #[test]
    fn only_a_recent_snapshot_of_this_schema_is_served() {
        let doc = document(SOURCES, at("2026-11-07T22:00:00Z"), &answer());
        // Up to three cycles old, and a writer clock a little ahead.
        assert!(usable(&doc, at("2026-11-07T22:15:00Z")).is_some());
        assert!(usable(&doc, at("2026-11-07T21:59:30Z")).is_some());
        // Older, or too far in the future: the live query answers instead.
        assert!(usable(&doc, at("2026-11-07T22:15:01Z")).is_none());
        assert!(usable(&doc, at("2026-11-07T21:58:00Z")).is_none());

        let mut other = doc.clone();
        other["schema"] = json!(SCHEMA + 1);
        assert!(usable(&other, at("2026-11-07T22:01:00Z")).is_none());
        let mut empty = doc.clone();
        empty["aggregations"] = Value::Null;
        assert!(usable(&empty, at("2026-11-07T22:01:00Z")).is_none());
        let mut undated = doc;
        undated["generated_at"] = json!("yesterday");
        assert!(usable(&undated, at("2026-11-07T22:01:00Z")).is_none());
    }

    #[test]
    fn partial_answers_are_not_stored() {
        assert!(complete(&answer()));
        let mut failed = answer();
        failed["_shards"]["failed"] = json!(1);
        assert!(!complete(&failed));
        let mut timed_out = answer();
        timed_out["timed_out"] = json!(true);
        assert!(!complete(&timed_out));
        assert!(!complete(&json!({"error": {"type": "search_phase_execution_exception"}})));
    }

    #[test]
    fn each_page_runs_its_handlers_own_request() {
        let pages = pages();
        assert_eq!(pages.len(), 2);
        let (id, indices, body) = &pages[0];
        assert_eq!((*id, *indices), (SOURCES, crate::es::EVENT_INDICES));
        assert_eq!(body, &crate::aggregates::sources_body(1000));
        let (id, indices, body) = &pages[1];
        assert_eq!((*id, *indices), (JA4L_FINGERPRINTS, &["zeek-v1-conn-*"][..]));
        assert_eq!(body, &crate::charts::ja4l_body());
    }

    #[test]
    fn the_index_is_a_checked_write_target() {
        assert!(crate::es::WRITE_TARGET_FAMILIES.contains(&INDEX));
    }
}
