//! #3756: whole-response snapshots of the reads that are too slow to
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
//! #3910 extended the set to the remaining slow parameter-free reads
//! (measured 2026-11-21 after #3908 and the ES resize, direct to the read
//! tier, three runs): tcp-stack-clusters 13.3-13.8 s, ics-functions
//! 7.5-7.9 s, facets/events 2.7-2.9 s, overview/dashboard 2.1-2.6 s,
//! ioc/catalog 0.8-3.9 s, source-health 1.3 s, kill-chain-sankey 0.4-1.3 s,
//! overview/kpis 1.0 s, filter-values 0.5-0.7 s; in production, where they
//! run concurrently, p50 2.3-16.6 s.
//!
//! None of these has a cheaper exact query shape, and none is additive over
//! hours (cardinalities, top-N across the window), so the worker runs the
//! handlers' own request bodies once per cycle and stores the answer. The
//! handlers parse a snapshot with the same code they use for a live answer,
//! so the payload is the live payload as of `generated_at`.
//!
//! Same house rules as the other rollups: one deterministic id per page,
//! disposable (delete the index and the next cycle rebuilds it), and the
//! live query stays the fallback. A snapshot older than [`max_age`] (three
//! default cycles), from a different [`SCHEMA`], from a run with failed
//! shards, or of a different request than the reader would send itself
//! (`request`, see [`fingerprint`]) is never served, so a stopped worker
//! degrades to the old live behaviour rather than to old data.
//!
//! The answer is stored as one JSON string (`answer`), not as an object:
//! the index has no explicit mapping, and dynamically mapping every page's
//! buckets would put the pages in each other's way (one field name, two
//! types) and grow toward the field limit with each page added.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::AppState;

pub const INDEX: &str = "page-rollup-v1";
pub const SOURCES: &str = "sources";
pub const JA4L_FINGERPRINTS: &str = "ja4l-fingerprints";
pub const SOURCE_HEALTH: &str = "source-health";
pub const SOURCE_HEALTH_MODBUS: &str = "source-health-modbus";
pub const OVERVIEW_MAIN: &str = "overview-dashboard-main";
pub const OVERVIEW_BEHAVIOR: &str = "overview-dashboard-behavior";
pub const OVERVIEW_KPIS_WINDOW: &str = "overview-kpis-window";
pub const OVERVIEW_KPIS: &str = "overview-kpis";
pub const FACETS_EVENTS: &str = "facets-events";
pub const FACETS_EVENTS_PROVIDERS: &str = "facets-events-providers";
pub const FILTER_VALUES: &str = "filter-values";
pub const TCP_STACK_CLUSTERS: &str = "tcp-stack-clusters";
pub const IOC_CATALOG: &str = "ioc-catalog";
pub const KILL_CHAIN_SANKEY: &str = "kill-chain-sankey";

/// Bump when the stored document layout changes, so a reader never parses a
/// snapshot written by other code. (A changed request body needs no bump:
/// the `request` fingerprint already tells them apart.)
///
/// 2 (#3910): `answer` string with `aggregations` and `hits.total`, plus
/// `request`; 1 stored `aggregations` as an object.
const SCHEMA: u64 = 2;

/// Three cycles of the default `ROLLUP_RUN_INTERVAL_SECS` (300 s).
fn max_age() -> Duration {
    Duration::seconds(900)
}

/// A writer clock slightly ahead of the reader's is tolerated; a snapshot
/// from further in the future is not trusted.
fn clock_skew() -> Duration {
    Duration::seconds(60)
}

/// One snapshot: its id, and the indices and request body of the live
/// search it stands in for.
#[derive(Clone, Debug, PartialEq)]
pub struct Page {
    pub id: &'static str,
    pub indices: &'static [&'static str],
    pub body: Value,
}

fn page(id: &'static str, indices: &'static [&'static str], body: Value) -> Page {
    Page { id, indices, body }
}

/// Every snapshot, in the order the worker refreshes them.
fn pages() -> Vec<Page> {
    let mut pages = vec![
        page(SOURCES, crate::es::EVENT_INDICES, crate::aggregates::sources_body(crate::aggregates::SOURCES_CAP)),
        page(JA4L_FINGERPRINTS, crate::charts::JA4L_INDICES, crate::charts::ja4l_body()),
        page(SOURCE_HEALTH, crate::es::EVENT_INDICES_AGG, crate::health::all_time_body()),
        page(SOURCE_HEALTH_MODBUS, crate::es::MODBUS_DETAIL_INDICES, crate::health::modbus_pdu_body()),
        page(OVERVIEW_MAIN, crate::es::EVENT_INDICES_AGG, crate::dashboard::main_body()),
        page(OVERVIEW_BEHAVIOR, crate::es::EVENT_INDICES_AGG, crate::dashboard::behavior_body()),
        page(OVERVIEW_KPIS_WINDOW, crate::es::EVENT_INDICES_AGG, crate::overview::live_window_body()),
        page(OVERVIEW_KPIS, crate::es::EVENT_INDICES_AGG, crate::overview::fallback_body()),
        page(FACETS_EVENTS, crate::es::EVENT_INDICES_AGG, crate::facets::default_facet_body()),
        page(FACETS_EVENTS_PROVIDERS, crate::es::EVENT_INDICES_AGG, crate::facets::default_provider_body()),
        page(FILTER_VALUES, crate::es::EVENT_INDICES_AGG, crate::aggregates::filter_values_body()),
        page(TCP_STACK_CLUSTERS, crate::charts::TCP_STACK_INDICES, crate::charts::tcp_stack_body()),
    ];
    for (id, _, index, field) in crate::charts::ICS_FUNCTION_SOURCES {
        pages.push(page(id, std::slice::from_ref(index), crate::charts::ics_function_body(field)));
    }
    pages.push(page(IOC_CATALOG, crate::es::EVENT_INDICES, crate::entity_details::catalog_default_body()));
    pages.push(page(KILL_CHAIN_SANKEY, crate::es::EVENT_INDICES_AGG, crate::kill_chain::sankey_body()));
    pages
}

fn find(id: &str) -> Option<Page> {
    pages().into_iter().find(|page| page.id == id)
}

/// What a snapshot answers: the indices and the body, hashed. The reader
/// computes it from its own `pages()`, so a snapshot written by a worker
/// that builds the request differently (other code, other
/// `HONEYPOT_SELF_IPS`) is never served for this reader's request.
fn fingerprint(page: &Page) -> String {
    let request = json!({"indices": page.indices, "body": page.body});
    Sha256::digest(request.to_string().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn document(page: &Page, generated_at: DateTime<Utc>, result: &Value, elapsed_ms: i64) -> Value {
    let answer = json!({
        "aggregations": result["aggregations"],
        "hits": {"total": result["hits"]["total"]},
    });
    json!({
        "page": page.id,
        "schema": SCHEMA,
        "generated_at": generated_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "request": fingerprint(page),
        // What the refresh cost Elasticsearch, kept for the cycle budget.
        "took_ms": result["took"],
        "elapsed_ms": elapsed_ms,
        "answer": answer.to_string(),
    })
}

/// The document the worker stores for page `id` after `result`, for the
/// handler tests' stand-in Elasticsearch.
#[cfg(test)]
pub(crate) fn snapshot_doc(id: &str, generated_at: DateTime<Utc>, result: &Value) -> Value {
    document(&find(id).expect("known page"), generated_at, result, 0)
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
/// and `hits.total`), or `None` when the document must not be served for
/// `page`.
fn usable(doc: &Value, page: &Page, now: DateTime<Utc>) -> Option<Value> {
    if doc["schema"].as_u64() != Some(SCHEMA) || doc["request"].as_str() != Some(fingerprint(page).as_str()) {
        return None;
    }
    let generated_at = DateTime::parse_from_rfc3339(doc["generated_at"].as_str()?).ok()?.with_timezone(&Utc);
    let age = now - generated_at;
    if age > max_age() || age < -clock_skew() {
        return None;
    }
    let answer: Value = serde_json::from_str(doc["answer"].as_str()?).ok()?;
    answer["aggregations"].is_object().then_some(answer)
}

/// The snapshot for page `id` if it may be served; `None` sends the caller
/// to its live query.
pub async fn read(state: &AppState, id: &str) -> Option<Value> {
    let page = find(id)?;
    read_page(state, &page).await
}

/// The snapshot for page `id`, but only when `indices` and `body` are
/// exactly the request that page stores: the handlers that take parameters
/// (facets, the IOC catalog) pass their own request, so only the default
/// one is answered from the snapshot and every other stays live.
pub async fn read_matching(state: &AppState, id: &str, indices: &[&str], body: &Value) -> Option<Value> {
    let page = matching(id, indices, body)?;
    read_page(state, &page).await
}

/// Page `id` when it stores exactly this request, without asking
/// Elasticsearch: a parameterised request never costs a document read.
fn matching(id: &str, indices: &[&str], body: &Value) -> Option<Page> {
    find(id).filter(|page| page.indices == indices && page.body == *body)
}

async fn read_page(state: &AppState, page: &Page) -> Option<Value> {
    match state.es.get_doc(INDEX, page.id).await {
        Ok(Some(doc)) => usable(&doc, page, Utc::now()),
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(%error, page = page.id, "page rollup unreadable, answering live");
            None
        }
    }
}

/// One refresh of every page, called from `rollups::run_cycle`. A failed or
/// partial run keeps the previous snapshot, which ages out by itself. The
/// pages run one after the other, so the refresh adds at most one search
/// at a time to the cluster's load.
pub async fn write_cycle(state: &AppState) {
    let cycle = std::time::Instant::now();
    let mut took_total: u64 = 0;
    for page in pages() {
        let started = Utc::now();
        let clock = std::time::Instant::now();
        let result = match state.es.search_index(page.indices, page.body.clone()).await {
            Ok(result) if complete(&result) => result,
            Ok(result) => {
                tracing::warn!(
                    page = page.id,
                    timed_out = %result["timed_out"],
                    failed_shards = %result["_shards"]["failed"],
                    "page rollup: partial answer, previous snapshot kept"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, page = page.id, "page rollup query failed");
                continue;
            }
        };
        let elapsed_ms = clock.elapsed().as_millis() as i64;
        let took_ms = result["took"].as_u64().unwrap_or(0);
        took_total += took_ms;
        if let Err(error) = state.es.index_doc(INDEX, page.id, document(&page, started, &result, elapsed_ms)).await {
            tracing::warn!(%error, page = page.id, "page rollup write failed");
            continue;
        }
        tracing::info!(page = page.id, took_ms, elapsed_ms, "page rollup written");
    }
    tracing::info!(took_ms = took_total, elapsed_ms = cycle.elapsed().as_millis() as u64, "page rollup cycle done");
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

    fn ja4l() -> Page {
        find(JA4L_FINGERPRINTS).unwrap()
    }

    #[test]
    fn a_stored_answer_reads_back_as_its_aggregations_and_total() {
        let _env = crate::dashboard::self_ips_env();
        let page = ja4l();
        let doc = document(&page, at("2026-11-07T22:00:00Z"), &answer(), 9100);
        assert_eq!(doc["page"], JA4L_FINGERPRINTS);
        assert_eq!(doc["took_ms"], 9000);
        assert_eq!(doc["elapsed_ms"], 9100);
        assert!(doc.get("hits").is_none() && doc.get("aggregations").is_none(), "only the answer string");
        assert!(doc["answer"].is_string());
        assert_eq!(
            usable(&doc, &page, at("2026-11-07T22:04:00Z")),
            Some(json!({
                "aggregations": answer()["aggregations"],
                "hits": {"total": {"value": 10000, "relation": "gte"}}
            }))
        );
    }

    #[test]
    fn only_a_recent_snapshot_of_this_schema_is_served() {
        let _env = crate::dashboard::self_ips_env();
        let page = find(SOURCES).unwrap();
        let doc = document(&page, at("2026-11-07T22:00:00Z"), &answer(), 1);
        // Up to three cycles old, and a writer clock a little ahead.
        assert!(usable(&doc, &page, at("2026-11-07T22:15:00Z")).is_some());
        assert!(usable(&doc, &page, at("2026-11-07T21:59:30Z")).is_some());
        // Older, or too far in the future: the live query answers instead.
        assert!(usable(&doc, &page, at("2026-11-07T22:15:01Z")).is_none());
        assert!(usable(&doc, &page, at("2026-11-07T21:58:00Z")).is_none());

        let now = at("2026-11-07T22:01:00Z");
        let mut other = doc.clone();
        other["schema"] = json!(SCHEMA + 1);
        assert!(usable(&other, &page, now).is_none());
        // A schema-1 document (aggregations as an object) is not read.
        let mut old = doc.clone();
        old["schema"] = json!(1);
        old["aggregations"] = answer()["aggregations"].clone();
        assert!(usable(&old, &page, now).is_none());
        let mut empty = doc.clone();
        empty["answer"] = json!(json!({"aggregations": null}).to_string());
        assert!(usable(&empty, &page, now).is_none());
        let mut garbled = doc.clone();
        garbled["answer"] = json!("{not json");
        assert!(usable(&garbled, &page, now).is_none());
        let mut undated = doc;
        undated["generated_at"] = json!("yesterday");
        assert!(usable(&undated, &page, now).is_none());
    }

    #[test]
    fn a_snapshot_of_another_request_is_not_served() {
        let _env = crate::dashboard::self_ips_env();
        let page = find(SOURCES).unwrap();
        let doc = document(&page, at("2026-11-07T22:00:00Z"), &answer(), 1);
        let now = at("2026-11-07T22:01:00Z");
        // Written for another page: the fingerprint differs.
        assert!(usable(&doc, &ja4l(), now).is_none());
        // Written by a worker whose request differed (other code, other
        // HONEYPOT_SELF_IPS): same id, other body.
        let mut drifted = page.clone();
        drifted.body["size"] = json!(1);
        assert!(usable(&doc, &drifted, now).is_none());
        let mut narrowed = page.clone();
        narrowed.indices = crate::es::EVENT_INDICES_AGG;
        assert!(usable(&doc, &narrowed, now).is_none());
        let mut unsigned = doc;
        unsigned["request"] = Value::Null;
        assert!(usable(&unsigned, &page, now).is_none());
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
        let _env = crate::dashboard::self_ips_env();
        let pages = pages();
        let ids: Vec<&str> = pages.iter().map(|page| page.id).collect();
        assert_eq!(
            ids,
            vec![
                SOURCES,
                JA4L_FINGERPRINTS,
                SOURCE_HEALTH,
                SOURCE_HEALTH_MODBUS,
                OVERVIEW_MAIN,
                OVERVIEW_BEHAVIOR,
                OVERVIEW_KPIS_WINDOW,
                OVERVIEW_KPIS,
                FACETS_EVENTS,
                FACETS_EVENTS_PROVIDERS,
                FILTER_VALUES,
                TCP_STACK_CLUSTERS,
                "ics-functions-modbus",
                "ics-functions-s7comm",
                "ics-functions-dnp3",
                "ics-functions-iec104",
                IOC_CATALOG,
                KILL_CHAIN_SANKEY,
            ]
        );
        let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "one document per page");
        let by_id = |id: &str| pages.iter().find(|page| page.id == id).unwrap().clone();
        assert_eq!(by_id(SOURCES).indices, crate::es::EVENT_INDICES);
        assert_eq!(by_id(SOURCES).body, crate::aggregates::sources_body(1000));
        assert_eq!(by_id(JA4L_FINGERPRINTS).indices, &["zeek-v1-conn-*"][..]);
        assert_eq!(by_id(JA4L_FINGERPRINTS).body, crate::charts::ja4l_body());
        assert_eq!(by_id(TCP_STACK_CLUSTERS).indices, &["zeek-v1-conn-*"][..]);
        assert_eq!(by_id("ics-functions-modbus").indices, &["zeek-v1-modbus_detailed-*"][..]);
        assert_eq!(by_id(SOURCE_HEALTH_MODBUS).indices, crate::es::MODBUS_DETAIL_INDICES);
        // The fleet-wide reads skip the per-PDU Modbus log (#3908).
        for id in [SOURCE_HEALTH, OVERVIEW_MAIN, OVERVIEW_BEHAVIOR, OVERVIEW_KPIS_WINDOW, OVERVIEW_KPIS, FACETS_EVENTS, FILTER_VALUES, KILL_CHAIN_SANKEY] {
            assert_eq!(by_id(id).indices, crate::es::EVENT_INDICES_AGG, "{id}");
        }
        // Every page is one parameter-free request: rebuilding it gives the
        // same fingerprint, which is what lets the reader trust the writer.
        for page in &pages {
            assert_eq!(fingerprint(page), fingerprint(&find(page.id).unwrap()), "{}", page.id);
        }
    }

    #[test]
    fn only_the_stored_request_matches() {
        let _env = crate::dashboard::self_ips_env();
        let facets = find(FACETS_EVENTS).unwrap();
        assert!(matching(FACETS_EVENTS, facets.indices, &facets.body).is_some());
        let filtered: crate::events::EventsQuery = serde_json::from_value(json!({"sensor": "cowrie"})).unwrap();
        let narrowed = crate::facets::facet_body(crate::events::build_filters(&filtered));
        assert!(matching(FACETS_EVENTS, facets.indices, &narrowed).is_none());
        assert!(matching(FACETS_EVENTS, crate::es::EVENT_INDICES, &facets.body).is_none());
        assert!(matching("no-such-page", facets.indices, &facets.body).is_none());
    }

    #[test]
    fn the_index_is_a_checked_write_target() {
        assert!(crate::es::WRITE_TARGET_FAMILIES.contains(&INDEX));
    }
}
